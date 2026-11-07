//! Встроенный асинхронный прокси-сервер — порт Python-реализации на Tokio.
//!
//! Что умеет (определяется по первому байту соединения, как в оригинале):
//!
//! | Первый байт | Протокол            | Обработчик                  |
//! |-------------|---------------------|-----------------------------|
//! | `0x05`      | SOCKS5 (+UDP ASSOCIATE) | [`socks5::handle`]      |
//! | `0x00`      | H2Mux (сырой)       | [`h2mux::handle`]           |
//! | буква       | HTTP proxy/CONNECT  | [`http::handle`]            |
//!
//! Дополнительно:
//!  * captive-portal-пробники Apple/Microsoft/Firefox/GNOME/KDE отвечаются
//!    локально (иначе Android решит, что интернета нет);
//!  * `GET /generate_204` → 204;
//!  * опциональная авторизация (SOCKS5 user/pass, HTTP Basic);
//!  * H2Mux поверх HTTP/1.1 Upgrade (`Upgrade: h2mux`).
//!
//! Модуль ничего не знает про VPN и TUN: он просто слушает TCP. Именно это
//! позволяет использовать его и на Android (трафик заворачивается в TUN),
//! и на desktop (прямое подключение к 127.0.0.1:1080).
pub mod h2mux;
pub mod hpack;
pub mod hpack_tables;
pub mod http;
pub mod probes;
pub mod relay;
pub mod socks5;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::stats;

/// Таймаут на установку исходящего соединения (как в Python: 20 с).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Таймаут ожидания первого байта от клиента (как в Python: 30 с).
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);

/// Настройки запуска прокси.
#[derive(Debug, Clone)]
pub struct ProxySettings {
    pub host: String,
    pub port: u16,
    /// Логин/пароль (если заданы — включается авторизация).
    pub auth: Option<(String, String)>,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 1080,
            auth: None,
        }
    }
}

/// Общий контекст, который видят все обработчики.
#[derive(Debug, Clone)]
pub struct ProxyContext {
    pub auth: Option<Arc<(String, String)>>,
}

impl ProxyContext {
    pub fn new(settings: &ProxySettings) -> Self {
        Self {
            auth: settings
                .auth
                .clone()
                .map(|(u, p)| Arc::new((u, p))),
        }
    }

    /// Проверка логина/пароля (constant-time сравнение).
    pub fn check_credentials(&self, user: &str, password: &str) -> bool {
        match &self.auth {
            None => true,
            Some(expected) => {
                constant_time_eq(user.as_bytes(), expected.0.as_bytes())
                    & constant_time_eq(password.as_bytes(), expected.1.as_bytes())
            }
        }
    }

    /// Ожидаемая строка `Proxy-Authorization` для Basic-авторизации.
    pub fn basic_expected(&self) -> Option<String> {
        self.auth
            .as_ref()
            .map(|auth| {
                let (u, p) = &**auth;
                format!("Basic {}", base64_encode(format!("{u}:{p}").as_bytes()))
            })
    }
}

/// Сравнение без «раннего выхода» (защита от тайминг-атак).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Хэндл запущенного прокси.
pub struct ProxyHandle {
    pub addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl ProxyHandle {
    /// Адрес, на котором реально слушаем (полезно при port = 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Остановить сервер.
    pub fn stop(self) {
        let _ = self.shutdown.send(true);
        self.task.abort();
    }
}

/// Запустить прокси-сервер и вернуть хэндл сразу после bind.
pub async fn start(settings: ProxySettings) -> io::Result<ProxyHandle> {
    let addr = format!("{}:{}", settings.host, settings.port);
    let listener = TcpListener::bind(&addr).await?;
    let local = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let ctx = Arc::new(ProxyContext::new(&settings));

    crate::flog!("Прокси слушает {local} (SOCKS5 / HTTP / H2Mux)");

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                // Сигнал остановки.
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        crate::flog!("Прокси остановлен");
                        break;
                    }
                }

                // Новое входящее соединение.
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            let ctx = ctx.clone();
                            tokio::spawn(async move {
                                stats::conn_open();
                                let _guard = ConnGuard;
                                if let Err(e) = handle_client(stream, peer, ctx).await {
                                    log_client_error(peer, &e);
                                }
                            });
                        }
                        Err(e) => {
                            crate::flog_warn!("accept(): {e}");

                            // Небольшая пауза, чтобы не крутить цикл при
                            // исчерпании дескрипторов.
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
    });

    Ok(ProxyHandle {
        addr: local,
        shutdown: shutdown_tx,
        task,
    })
}

/// «Ожидаемая» ли ошибка: клиент закрыл соединение, оборвал запрос или
/// прислал обрезанные данные.
///
/// Такие ошибки не должны попадать в WARN: Android открывает и закрывает
/// connectivity-пробники постоянно, и лог бы состоял из них.
fn is_benign(e: &io::Error) -> bool {
    // `InvalidData` сюда НЕ входит: это признак кривого или враждебного
    // запроса, и о нём стоит узнать из лога.
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
    )
}

/// Залогировать ошибку обслуживания клиента с правильным уровнем.
///
/// Обрыв на стороне клиента — обычное дело (пробники Android, закрытые
/// вкладки), поэтому такие ошибки идут в DEBUG, а настоящие сбои — в WARN.
fn log_client_error(peer: SocketAddr, e: &io::Error) {
    if is_benign(e) {
        crate::flog_dbg!("Клиент {peer}: {e}");
    } else {
        crate::flog_warn!("Клиент {peer}: {e}");
    }
}

/// Уменьшает счётчик соединений при выходе из области видимости.
struct ConnGuard;

impl Drop for ConnGuard {
    fn drop(&mut self) {
        stats::conn_close();
    }
}

/// Определить протокол по первому байту и передать управление обработчику.
async fn handle_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
) -> io::Result<()> {
    // Отключаем «липкие» сокеты: nodelay снижает задержки и помогает
    // фрагментации (мелкие сегменты уходят сразу, не склеиваясь).
    let _ = stream.set_nodelay(true);

    // Ждём первый байт не дольше 30 секунд (как в Python).
    let first =
        match tokio::time::timeout(FIRST_BYTE_TIMEOUT, relay::read_first_byte(&mut stream)).await {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()),
        };

    match first {
        // SOCKS5: версия 0x05
        0x05 => socks5::handle(stream, peer, &ctx, first).await,
        // H2Mux «в сыром виде» — соединение сразу начинается с SETTINGS.
        0x00 => h2mux::handle(stream, &ctx, Some(first)).await,
        // HTTP: метод начинается с буквы (GET/POST/CONNECT/HEAD/...)
        b if b.is_ascii_alphabetic() => http::handle(stream, &ctx, first).await,
        _ => Ok(()),
    }
}

/// Разобрать `host:port` / `[v6]:port` / `host`.
pub fn split_host_port(value: &str, default_port: u16) -> (String, u16) {
    let value = value.trim();
    if value.starts_with('[') {
        // IPv6 в скобках: [::1]:8080
        if let Some(end) = value.find(']') {
            let host = value[1..end].to_string();
            let rest = &value[end + 1..];
            let port = rest
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host, port);
        }
    }

    // Ровно одно двоеточие — это host:port.
    if value.matches(':').count() == 1 {
        let (host, raw_port) = value.rsplit_once(':').unwrap();
        let port = raw_port.parse().unwrap_or(default_port);
        return (host.to_string(), port);
    }
    (value.to_string(), default_port)
}

/// Закодировать адрес в формате SOCKS5 (ATYP + адрес + порт).
pub fn encode_address(host: &str, port: u16) -> Vec<u8> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        let mut out = Vec::with_capacity(7);
        out.push(0x01);
        out.extend_from_slice(&ip.octets());
        out.extend_from_slice(&port.to_be_bytes());
        return out;
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        let mut out = Vec::with_capacity(19);
        out.push(0x04);
        out.extend_from_slice(&ip.octets());
        out.extend_from_slice(&port.to_be_bytes());
        return out;
    }

    // Доменное имя: ATYP=3, длина (1 байт), имя (punycode), порт.
    let ascii = idna_encode(host);
    let name = if ascii.len() > 255 { &ascii[..255] } else { &ascii[..] };
    let mut out = Vec::with_capacity(4 + name.len());
    out.push(0x03);
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Простейшая «IDNA»: отдаём ASCII как есть, не-ASCII заменяем на punycode-заглушку.
///
/// Полноценная реализация требует таблиц IDNA; для прокси, работающего с
/// уже нормализованными именами (браузер присылает punycode), достаточно
/// проверить ASCII и вернуть имя без изменений.
fn idna_encode(host: &str) -> String {
    if host.is_ascii() {
        host.to_ascii_lowercase()
    } else {
        // Не-ASCII имя: кодируем каждую метку как "xn--<hex>" (упрощённо).
        host.split('.')
            .map(|label| {
                if label.is_ascii() {
                    label.to_string()
                } else {
                    let hex: String = label
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    format!("xn--{hex}")
                }
            })
            .collect::<Vec<_>>()
            .join(".")
    }
}

/// Разобрать адрес из SOCKS5-запроса (ATYP + адрес + порт).
///
/// Возвращает `(host, port)`, где host — строка (IPv4/IPv6/домен).
pub async fn read_address<R>(reader: &mut R) -> io::Result<(String, u16)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let atyp = reader.read_u8().await?;
    let host = match atyp {
        0x01 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).await?;
            Ipv4Addr::from(buf).to_string()
        }
        0x03 => {
            let len = reader.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            String::from_utf8_lossy(&buf).into_owned()
        }
        0x04 => {
            let mut buf = [0u8; 16];
            reader.read_exact(&mut buf).await?;
            Ipv6Addr::from(buf).to_string()
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad atyp")),
    };
    let port = reader.read_u16().await?;
    Ok((host, port))
}

/// Разобрать адрес из UDP-датаграммы SOCKS5 (offset указывает на ATYP).
pub fn parse_udp_address(data: &[u8], offset: usize) -> io::Result<(String, u16, usize)> {
    let atyp = *data
        .get(offset)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "udp: нет atyp"))?;
    let mut p = offset + 1;
    let host = match atyp {
        0x01 => {
            let b = data
                .get(p..p + 4)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "udp: short ipv4"))?;
            p += 4;
            Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()
        }
        0x03 => {
            let len = *data
                .get(p)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "udp: short len"))?
                as usize;
            p += 1;
            let b = data
                .get(p..p + len)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "udp: short name"))?;
            p += len;
            String::from_utf8_lossy(b).into_owned()
        }
        0x04 => {
            let b = data
                .get(p..p + 16)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "udp: short ipv6"))?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(b);
            p += 16;
            Ipv6Addr::from(octets).to_string()
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad atyp")),
    };
    let pb = data
        .get(p..p + 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "udp: short port"))?;
    let port = u16::from_be_bytes([pb[0], pb[1]]);
    Ok((host, port, p + 2))
}

/// Преобразовать `(host, port)` в `SocketAddr` с разрешением имени.
pub async fn resolve(host: &str, port: u16) -> io::Result<SocketAddr> {
    // Сначала пробуем как IP-литерал (без DNS).
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    // Затем обычное разрешение через системный резолвер.
    let mut addrs = tokio::net::lookup_host((host, port)).await?;
    addrs
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS: адрес не найден"))
}

/// Открыть TCP-соединение с таймаутом.
pub async fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let addr = resolve(host, port).await?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Код ошибки SOCKS5 по типу ошибки (порт `socks_error_code` из Python).
pub fn socks_error_code(e: &io::Error) -> u8 {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => 0x05,
        io::ErrorKind::TimedOut | io::ErrorKind::NotFound => 0x04,
        _ => 0x01,
    }
}

/// Минимальный base64 (для HTTP Basic / SOCKS5 не нужен, но требуется в H2Mux).
pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_reference() {
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    #[test]
    fn split_host_port_variants() {
        assert_eq!(split_host_port("example.com:8080", 80), ("example.com".into(), 8080));
        assert_eq!(split_host_port("example.com", 80), ("example.com".into(), 80));
        assert_eq!(split_host_port("[::1]:8443", 443), ("::1".into(), 8443));
        assert_eq!(split_host_port("2001:db8::1", 443), ("2001:db8::1".into(), 443));
    }

    #[test]
    fn address_encoding() {
        // IPv4
        assert_eq!(encode_address("1.2.3.4", 80), vec![1, 1, 2, 3, 4, 0, 80]);

        // Домен
        let enc = encode_address("a.b", 443);
        assert_eq!(enc[0], 3);
        assert_eq!(enc[1], 3);
        assert_eq!(&enc[2..5], &b"a.b"[..]);
    }
}

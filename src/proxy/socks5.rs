//! SOCKS5-сервер (RFC 1928 + RFC 1929 для авторизации) — порт `handle_socks5`
//! и `handle_udp_associate` из Python-прокси.
//!
//! Что поддерживается:
//!  * `CONNECT` (CMD=0x01) — обычный TCP-туннель;
//!  * `UDP ASSOCIATE` (CMD=0x03) — релей UDP (нужен для DNS и QUIC);
//!  * авторизация по логину/паролю (если задана в настройках);
//!  * коды ошибок как в RFC (0x01..0x08).
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

use crate::proxy::{self, ProxyContext};
use crate::stats;

/// Ответ клиенту: VER(5) REP(1) RSV(0) ATYP+ADDR+PORT.
pub async fn socks_reply(
    stream: &mut TcpStream,
    rep: u8,
    host: &str,
    port: u16,
) -> io::Result<()> {
    let mut out = Vec::with_capacity(16);
    out.push(0x05);
    out.push(rep);
    out.push(0x00);
    out.extend_from_slice(&proxy::encode_address(host, port));
    stream.write_all(&out).await?;
    stream.flush().await?;
    Ok(())
}

/// Обработать SOCKS5-соединение. `first` — уже прочитанный байт версии (0x05).
pub async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    ctx: &Arc<ProxyContext>,
    first: u8,
) -> io::Result<()> {
    debug_assert_eq!(first, 0x05);

    // ------------------------------------------------------------------ //
    // 1) Приветствие: VER=5, NMETHODS, METHODS...
    // ------------------------------------------------------------------ //
    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    // Метод 0x00 — без авторизации, 0x02 — логин/пароль.
    let wanted: u8 = if ctx.auth.is_some() { 0x02 } else { 0x00 };
    if !methods.contains(&wanted) {
        // 0xFF — «нет приемлемых методов».
        stream.write_all(&[0x05, 0xFF]).await?;
        return Ok(());
    }
    stream.write_all(&[0x05, wanted]).await?;
    stream.flush().await?;

    // ------------------------------------------------------------------ //
    // 2) Авторизация (RFC 1929).
    // ------------------------------------------------------------------ //
    if wanted == 0x02 {
        let ver = stream.read_u8().await?;
        let ulen = stream.read_u8().await? as usize;
        let mut ubuf = vec![0u8; ulen];
        stream.read_exact(&mut ubuf).await?;
        let plen = stream.read_u8().await? as usize;
        let mut pbuf = vec![0u8; plen];
        stream.read_exact(&mut pbuf).await?;

        let user = String::from_utf8_lossy(&ubuf);
        let pass = String::from_utf8_lossy(&pbuf);
        if ver != 0x01 || !ctx.check_credentials(&user, &pass) {
            // 0x01 0x01 — «неудачная авторизация».
            stream.write_all(&[0x01, 0x01]).await?;
            return Ok(());
        }
        stream.write_all(&[0x01, 0x00]).await?;
        stream.flush().await?;
    }

    // ------------------------------------------------------------------ //
    // 3) Запрос: VER CMD RSV ATYP ADDR PORT
    // ------------------------------------------------------------------ //
    let mut header = [0u8; 3];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Ok(());
    }
    let cmd = header[1];

    // Адрес читаем всегда (даже для UDP ASSOCIATE — клиент присылает 0.0.0.0:0).
    let (host, port) = proxy::read_address(&mut stream).await?;

    match cmd {
        0x03 => handle_udp_associate(&mut stream, peer, host, port).await,
        // `handle_connect` забирает сокет целиком: так `pipe` может
        // закрыть его по завершении без дублирования дескриптора.
        0x01 => handle_connect(stream, &host, port).await,
        // BIND не поддерживаем — «команда не поддерживается».
        _ => {
            socks_reply(&mut stream, 0x07, "0.0.0.0", 0).await?;
            Ok(())
        }
    }
}

/// CMD = CONNECT: обычный TCP-туннель.
async fn handle_connect(mut stream: TcpStream, host: &str, port: u16) -> io::Result<()> {
    let remote = match proxy::connect(host, port).await {
        Ok(s) => s,
        Err(e) => {
            let code = proxy::socks_error_code(&e);
            socks_reply(&mut stream, code, "0.0.0.0", 0).await?;
            return Ok(());
        }
    };

    // Сообщаем клиенту адрес, к которому подключились.
    let bound = remote
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    socks_reply(&mut stream, 0x00, &bound.ip().to_string(), bound.port()).await?;

    stats::add_up(host.len() + 2);

    // ------------------------------------------------------------------ //
    // ВАЖНО: здесь мы могли бы применить DPI-обход к потоку. Но в текущей
    // архитектуре трафик приложений идёт через TUN (см. `tunnel::stack`),
    // где DPI-модуль уже применяется. Прокси нужен как «внешний» интерфейс
    // (для отладки и для приложений, которые умеют SOCKS5 напрямую),
    // поэтому здесь релей «как есть».
    // ------------------------------------------------------------------ //
    // `pipe` забирает владение обоими сокетами и закрывает их по
    // завершении — поэтому передаём `stream` по значению, без дублирования
    // дескриптора (так не будет «висящих» fd после закрытия).
    crate::proxy::relay::pipe(stream, remote).await
}

/// Пир для UDP-релея: сокет к удалённому серверу и адрес клиента.
type Peers = Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>>;

/// Сколько разных направлений держим одновременно.
///
/// На каждый адрес создаётся отдельный сокет и отдельная задача чтения,
/// которые живут до конца ассоциации. Без ограничения клиент (или вирус на
/// машине) может «раздуть» таблицу до тысяч сокетов — а каждый сокет это
/// файловый дескриптор.
const MAX_PEERS: usize = 256;

/// CMD = UDP ASSOCIATE: выдаём клиенту UDP-адрес и релеим датаграммы.
///
/// Формат датаграммы от клиента (RFC 1928 §7):
/// `RSV(2)=0 | FRAG(1)=0 | ATYP | ADDR | PORT | DATA`
async fn handle_udp_associate(
    stream: &mut TcpStream,
    peer: SocketAddr,
    _host: String,
    _port: u16,
) -> io::Result<()> {
    // Слушаем на локальном адресе того же интерфейса, что и TCP-соединение.
    let bind_ip = match peer.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    };
    let relay = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let relay = Arc::new(relay);
    let relay_addr = relay.local_addr()?;

    // Сначала отвечаем клиенту адресом релея.
    let reply_host = relay_addr.ip().to_string();
    socks_reply(stream, 0x00, &reply_host, relay_addr.port()).await?;

    let peers: Peers = Arc::new(Mutex::new(HashMap::new()));

    // Адрес клиента узнаем из первой датаграммы (порт из запроса обычно 0).
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Задача 1: читаем TCP и ждём, пока клиент закроет «управляющее»
    // соединение (по RFC ассоциация живёт, пока жив TCP).
    let mut control = stream;
    let relay_for_read = relay.clone();
    let peers_for_read = peers.clone();
    let client_for_read = client_addr.clone();

    let udp_task = tokio::spawn(async move {
        udp_loop(relay_for_read, peers_for_read, client_for_read).await
    });

    // Ждём закрытия управляющего канала.
    let mut buf = [0u8; 512];
    loop {
        match control.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    udp_task.abort();
    Ok(())
}

/// Основной цикл UDP-релея.
async fn udp_loop(
    relay: Arc<UdpSocket>,
    peers: Peers,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
) -> io::Result<()> {
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, from) = match relay.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Проверяем «шапку» SOCKS5 UDP.
        if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
            // FRAG != 0 не поддерживаем.
            continue;
        }

        // Запоминаем адрес клиента.
        {
            let mut guard = client_addr.lock().await;
            if guard.is_none() {
                *guard = Some(from);
            }
        }

        // Разбираем целевой адрес.
        let (host, port, offset) = match proxy::parse_udp_address(&buf[..n], 3) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let payload = &buf[offset..n];

        // Находим/создаём сокет к цели.
        let target = match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(mut it) => match it.next() {
                Some(a) => a,
                None => continue,
            },
            Err(_) => continue,
        };

        let socket = {
            let mut guard = peers.lock().await;
            match guard.get(&target) {
                Some(s) => s.clone(),
                None if guard.len() >= MAX_PEERS => {
                    // Достигли лимита: датаграмму молча отбрасываем, чтобы
                    // не исчерпать дескрипторы. Уже открытые направления
                    // продолжают работать.
                    continue;
                }
                None => {
                    let bind_ip = match target {
                        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        SocketAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                    };
                    let sock = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
                    sock.connect(target).await?;
                    let sock = Arc::new(sock);
                    guard.insert(target, sock.clone());

                    // Задача чтения ответов от цели.
                    let sock_clone = sock.clone();
                    let relay_clone = relay.clone();
                    let client_clone = client_addr.clone();
                    tokio::spawn(async move {
                        let mut rbuf = vec![0u8; 65536];
                        loop {
                            let (rn, _) = match sock_clone.recv_from(&mut rbuf).await {
                                Ok(v) => v,
                                Err(_) => break,
                            };
                            let client = *client_clone.lock().await;
                            if let Some(client) = client {
                                // Оборачиваем в SOCKS5 UDP-шапку.
                                let mut out = vec![0u8, 0u8, 0u8];
                                out.extend_from_slice(&proxy::encode_address(
                                    &target.ip().to_string(),
                                    target.port(),
                                ));
                                out.extend_from_slice(&rbuf[..rn]);
                                let _ = relay_clone.send_to(&out, client).await;
                                stats::add_down(rn);
                            }
                        }
                    });
                    sock
                }
            }
        };

        if socket.send(payload).await.is_ok() {
            stats::add_up(payload.len());
        }
    }
}

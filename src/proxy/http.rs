//! HTTP-прокси: CONNECT-туннель, абсолютные URI (как у обычного
//! forward-proxy), H2Mux через `Upgrade`, captive-portal-пробники.
//!
//! Порт `handle_http` из Python-прокси, включая:
//!  * Basic-авторизацию (`Proxy-Authorization`);
//!  * ответы на пробники Apple/Microsoft/Firefox/GNOME/KDE;
//!  * `GET /generate_204` → 204;
//!  * отправку тела (Content-Length / chunked) в удалённый сервер.
//!
//! Соединения к апстриму всегда `Connection: close` — так проще и надёжнее
//! для прокси (не нужно отслеживать keep-alive клиента).
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proxy::{self, h2mux, probes, relay as pio, ProxyContext};
use crate::stats;

/// Максимум заголовков (защита от «header flooding»).
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Ошибка прокси для клиента: `HTTP/1.1 4xx/5xx` + текст.
async fn http_error(
    stream: &mut TcpStream,
    code: u16,
    text: &str,
    extra: &[u8],
) -> std::io::Result<()> {
    let body = text.as_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(format!("HTTP/1.1 {code} {text}\r\n").as_bytes());
    out.extend_from_slice(b"Content-Type: text/plain\r\nContent-Length: ");
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\nConnection: close\r\n");
    out.extend_from_slice(extra);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    stream.write_all(&out).await?;
    stream.flush().await?;
    Ok(())
}

/// Пометить ошибку чтения запроса как «клиент оборвал соединение».
///
/// Клиент закрыл соединение или прислал обрезанный запрос — это обычное
/// событие (Android постоянно открывает и закрывает пробники), а не сбой
/// прокси. `is_benign` в `proxy/mod.rs` по виду ошибки решает, писать ли
/// её в WARN.
fn benign_with(kind: std::io::ErrorKind, e: std::io::Error) -> std::io::Error {
    std::io::Error::new(kind, format!("клиент оборвал запрос: {e}"))
}

/// Сформировать ответ для captive-portal-пробника.
///
/// Возвращает `None`, если запрос не похож на пробник — тогда его нужно
/// проксировать дальше.
pub fn probe_response(host: &str, path: &str) -> Option<Vec<u8>> {
    let clean_path = path.split('?').next().unwrap_or("/");

    // Android/Chrome: /generate_204 — успех = 204 без тела.
    if clean_path.ends_with("/generate_204") || clean_path.ends_with("/gen_204") {
        return Some(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        );
    }

    // ubuntu-пробник: пустой ответ 204.
    if clean_path == "/" && host.eq_ignore_ascii_case("connectivity-check.ubuntu.com") {
        return Some(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        );
    }

    let body = probes::probe_body(host, clean_path)?;
    let mut out = Vec::new();
    out.extend_from_slice(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ",
    );
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n");
    out.extend_from_slice(body.as_bytes());
    Some(out)
}

/// Обработать HTTP-запрос. `first` — уже прочитанный первый байт метода.
pub async fn handle(
    socket: TcpStream,
    ctx: &Arc<ProxyContext>,
    first: u8,
) -> std::io::Result<()> {
    // Владение сокетом остаётся здесь: CONNECT-ветка отдаёт его целиком
    // в `relay::pipe`, остальные ветки работают через `&mut`.
    let mut socket = socket;
    let stream = &mut socket;

    // ------------------------------------------------------------------ //
    // 1) Читаем заголовки целиком (до \r\n\r\n).
    // ------------------------------------------------------------------ //
    let raw = pio::read_until_headers_end(stream, first, MAX_HEADER_BYTES)
        .await
        .map_err(|e| benign_with(e.kind(), e))?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let mut lines = text.split("\r\n");

    let request_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = request_line.split(' ').collect();
    if parts.len() < 2 {
        http_error(stream, 400, "Bad Request", b"").await?;
        return Ok(());
    }
    let method = parts[0].to_ascii_uppercase();
    let target = parts[1];

    // Заголовки в нижнем регистре для поиска + исходный список для пересылки.
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut lookup: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            lookup.insert(name.to_ascii_lowercase(), value.clone());
            headers.push((name, value));
        }
    }

    // ------------------------------------------------------------------ //
    // 2) Авторизация.
    // ------------------------------------------------------------------ //
    if let Some(expected) = ctx.basic_expected() {
        let got = lookup
            .get("proxy-authorization")
            .cloned()
            .unwrap_or_default();
        if got != expected {
            http_error(
                stream,
                407,
                "Proxy Authentication Required",
                b"Proxy-Authenticate: Basic realm=\"proxy\"\r\n",
            )
            .await?;
            return Ok(());
        }
    }

    // ------------------------------------------------------------------ //
    // 3) CONNECT — туннель.
    // ------------------------------------------------------------------ //
    if method == "CONNECT" {
        let (host, port) = proxy::split_host_port(target, 443);
        let remote = match proxy::connect(&host, port).await {
            Ok(s) => s,
            Err(e) => {
                crate::flog_dbg!("CONNECT {host}:{port} не удался: {e}");
                http_error(stream, 502, "Bad Gateway", b"").await?;
                return Ok(());
            }
        };
        // Пишем прямо в сокет: `stream` — это `&mut` на тот же сокет, и
        // после ветки CONNECT владение нужно вернуть целиком.
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|e| benign_with(e.kind(), e))?;
        socket.flush().await.map_err(|e| benign_with(e.kind(), e))?;
        stats::add_up(host.len() + 4);

        // Релей «насквозь». `handle` получает владение, поэтому передаём его
        // в `pipe` целиком — сокет закроется по завершении туннеля.
        return pio::pipe(socket, remote).await;
    }

    // ------------------------------------------------------------------ //
    // 4) Определяем host/port/path.
    // ------------------------------------------------------------------ //
    let (host, port, path);
    if target.contains("://") {
        // Абсолютный URI: http://example.com/path?q=1
        match parse_url(target) {
            Some((h, p, pa)) => {
                host = h;
                port = p;
                path = pa;
            }
            None => {
                http_error(stream, 400, "Bad Request", b"").await?;
                return Ok(());
            }
        }
    } else {
        let host_header = lookup.get("host").map(|s| s.as_str()).unwrap_or("");
        let (h, p) = proxy::split_host_port(host_header, 80);
        host = h;
        port = p;
        path = if target.is_empty() { "/".to_string() } else { target.to_string() };
    }

    if host.is_empty() {
        http_error(stream, 400, "Bad Request", b"").await?;
        return Ok(());
    }

    // ------------------------------------------------------------------ //
    // 5) H2Mux через Upgrade (так клиент ByeByeDPI маскирует свой
    //    мультиплексированный протокол под обычный HTTP).
    // ------------------------------------------------------------------ //
    if lookup
        .get("upgrade")
        .map(|v| v.eq_ignore_ascii_case("h2mux"))
        .unwrap_or(false)
    {
        // Проверяем, что это именно пробник (иначе апгрейд — попытка
        // использовать нас как открытый релей).
        let tokens: std::collections::HashSet<String> = lookup
            .get("connection")
            .map(|v| v.split(',').map(|t| t.trim().to_ascii_lowercase()).collect())
            .unwrap_or_default();
        let key_path = path.split('?').next().unwrap_or("/");
        let is_probe = probes::probe_body(&host, key_path).is_some();
        let content_length_zero = lookup
            .get("content-length")
            .map(|v| v == "0")
            .unwrap_or(true);

        if method != "GET"
            || !tokens.contains("upgrade")
            || !is_probe
            || !content_length_zero
            || lookup.contains_key("transfer-encoding")
        {
            http_error(stream, 400, "Bad Request", b"").await?;
            return Ok(());
        }

        socket
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2mux\r\nCache-Control: no-cache\r\n\r\n",
            )
            .await
            .map_err(|e| benign_with(e.kind(), e))?;
        socket.flush().await.map_err(|e| benign_with(e.kind(), e))?;

        return h2mux::handle(socket, ctx, None).await;
    }

    // ------------------------------------------------------------------ //
    // 6) Пробники — отвечаем локально (иначе Android скажет «нет сети»).
    // ------------------------------------------------------------------ //
    if method == "GET" || method == "HEAD" {
        if let Some(resp) = probe_response(&host, &path) {
            stream.write_all(&resp).await?;
            stream.flush().await?;
            return Ok(());
        }
    }

    // ------------------------------------------------------------------ //
    // 7) Читаем тело запроса (если есть).
    // ------------------------------------------------------------------ //
    let body: Vec<u8> = if lookup
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        pio::read_chunked_body(stream)
            .await
            .map_err(|e| benign_with(e.kind(), e))?
    } else if let Some(cl) = lookup.get("content-length") {
        let len: usize = cl.trim().parse().unwrap_or(0);
        if len > 32 * 1024 * 1024 {
            http_error(stream, 413, "Payload Too Large", b"").await?;
            return Ok(());
        }
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| benign_with(e.kind(), e))?;
        buf
    } else {
        Vec::new()
    };

    // ------------------------------------------------------------------ //
    // 8) Формируем запрос к серверу.
    // ------------------------------------------------------------------ //
    let skipped = [
        "proxy-authorization",
        "proxy-connection",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "content-length",
    ];
    let mut out: Vec<u8> = Vec::with_capacity(512 + body.len());
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    let mut has_host = false;
    for (name, value) in &headers {
        let lower = name.to_ascii_lowercase();
        if skipped.contains(&lower.as_str()) {
            continue;
        }
        if lower == "host" {
            has_host = true;
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    if !has_host {
        if port == 80 {
            out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
        } else {
            out.extend_from_slice(format!("Host: {host}:{port}\r\n").as_bytes());
        }
    }
    if !body.is_empty() || matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(&body);

    // ------------------------------------------------------------------ //
    // 9) Отправляем и релеим ответ.
    // ------------------------------------------------------------------ //
    let mut remote = match proxy::connect(&host, port).await {
        Ok(s) => s,
        Err(e) => {
            crate::flog_dbg!("{method} {host}:{port} не удался: {e}");
            http_error(stream, 502, "Bad Gateway", b"").await?;
            return Ok(());
        }
    };
    stats::add_up(out.len());
    remote.write_all(&out).await?;
    remote.flush().await?;

    // Ответ сервера -> клиент (до EOF; апстрим закрывает соединение).
    let mut buf = vec![0u8; 16384];
    loop {
        let n = match remote.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            // Апстрим оборвал ответ — отдаём клиенту то, что успели.
            Err(_) => break,
        };
        stats::add_down(n);
        if socket.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = socket.flush().await;
    Ok(())
}

/// Разобрать абсолютный URL: `scheme://host[:port]/path?query`.
fn parse_url(url: &str) -> Option<(String, u16, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "https" => 443,
        _ => 80,
    };
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = proxy::split_host_port(authority, default_port);
    Some((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_absolute_url() {
        let (h, p, path) = parse_url("http://example.com/a?b=1").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 80);
        assert_eq!(path, "/a?b=1");
    }

    #[test]
    fn parses_https_url() {
        let (_, p, _) = parse_url("https://example.com").unwrap();
        assert_eq!(p, 443);
    }

    #[test]
    fn probe_generate_204() {
        assert!(probe_response("example.com", "/generate_204").is_some());
    }

    #[test]
    fn probe_apple() {
        let r = probe_response("captive.apple.com", "/hotspot-detect.html").unwrap();
        let text = String::from_utf8_lossy(&r);
        assert!(text.contains("Success"));
    }

    #[test]
    fn non_probe_returns_none() {
        assert!(probe_response("example.com", "/index.html").is_none());
    }
}

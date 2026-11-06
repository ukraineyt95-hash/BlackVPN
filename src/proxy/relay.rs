//! Утилиты ввода-вывода (модуль называется `relay`, чтобы не конфликтовать
//! с `std::io`): релей между двумя TCP-потоками, чтение «до
//! разделителя», чтение chunked-тела, отложенный первый байт.
//!
//! Все функции — аналоги из Python-прокси (`relay`, `pipe`, `read_chunked`),
//! переписанные на Tokio.
use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::stats;

/// Прочитать первый байт, не теряя его (возвращает сам байт).
///
/// В Python это `await reader.readexactly(1)`. В Rust мы не можем «вернуть
/// байт обратно в поток», поэтому обработчики получают его аргументом и
/// при необходимости подставляют в разбор (см. `http::handle`).
pub async fn read_first_byte(stream: &mut TcpStream) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
    }
    Ok(buf[0])
}

/// Прочитать всё до `\r\n\r\n` (включая разделитель), с ограничением размера.
pub async fn read_until_headers_end<R>(
    reader: &mut R,
    first: u8,
    limit: usize,
) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    buf.push(first);

    loop {
        // Проверяем, не закончились ли заголовки.
        if buf.len() >= 4 && buf[buf.len() - 4..] == [b'\r', b'\n', b'\r', b'\n'] {
            return Ok(buf);
        }
        if buf.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "заголовки слишком велики",
            ));
        }
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF до конца заголовков",
            ));
        }
        buf.push(byte[0]);
    }
}

/// Максимальный размер тела, которое готовы собрать в память.
///
/// Без ограничения «сервер» может прислать чанки бесконечно и съесть всю
/// память процесса — а тело мы всё равно сначала копим целиком, чтобы знать
/// `Content-Length`.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// Прочитать chunked-тело (порт `read_chunked`).
pub async fn read_chunked_body<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut body = Vec::new();
    loop {
        // Строка размера: "<hex>[;ext]\r\n"
        let line = read_line(reader).await?;
        if line.is_empty() {
            break;
        }
        let size_str = line.split(|&b| b == b';').next().unwrap_or(b"");
        let size_str = std::str::from_utf8(size_str)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunked: не hex"))?
            .trim();
        let size = usize::from_str_radix(if size_str.is_empty() { "0" } else { size_str }, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunked: не hex"))?;
        if size == 0 {
            // Трейлеры до пустой строки.
            loop {
                let trailer = read_line(reader).await?;
                if trailer.is_empty() {
                    break;
                }
            }
            break;
        }
        if body.len() + size > MAX_BODY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked: тело слишком велико",
            ));
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);

        // Завершающий CRLF после данных — проверяем, а не просто дочитываем:
        // иначе «обрезанный» ответ съел бы байты из следующего фрагмента.
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        if crlf != [b'\r', b'\n'] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked: нет CRLF после данных",
            ));
        }
    }
    Ok(body)
}

/// Прочитать строку до `\n` (без него).
pub async fn read_line<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let mut b = [0u8; 1];
        let n = reader.read(&mut b).await?;
        if n == 0 {
            break;
        }
        if b[0] == b'\n' {
            break;
        }
        if b[0] != b'\r' {
            line.push(b[0]);
        }
        if line.len() > 8192 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "строка слишком длинна"));
        }
    }
    Ok(line)
}

/// Перекачать данные из `reader` в `writer` до EOF (это `relay` из Python).
///
/// Учитывает статистику. В основном пути используется [`pipe`] (два
/// направления сразу), поэтому функция оставлена готовым строительным блоком.
#[allow(dead_code)]
pub async fn relay_to<R, W>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16384];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        stats::add_down(n as usize);
        total += n as u64;
    }
    Ok(total)
}

/// Соединить два потока «насквозь» (порт `pipe`).
///
/// Работает до закрытия любой из сторон; после этого оба потока
/// закрываются (в Python — `asyncio.wait(FIRST_COMPLETED)`).
pub async fn pipe(client: TcpStream, remote: TcpStream) -> io::Result<()> {
    let _ = client.set_nodelay(true);
    // Оба сокета располовиниваем: иначе один и тот же `remote` нужно было бы
    // держать `&mut` сразу в двух футурах (для чтения и для записи) —
    // borrow checker такого не разрешает. `into_split()` даёт независимые
    // половины, которые можно двигать в разные задачи.
    let (mut cr, mut cw) = client.into_split();
    let (mut rr, mut rw) = remote.into_split();

    // client -> remote
    let up = async {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => break Err(e),
            };
            stats::add_up(n);
            if let Err(e) = rw.write_all(&buf[..n]).await {
                break Err(e);
            }
        }
    };

    // remote -> client
    let down = async {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match rr.read(&mut buf).await {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => break Err(e),
            };
            stats::add_down(n);
            if let Err(e) = cw.write_all(&buf[..n]).await {
                break Err(e);
            }
        }
    };

    // Ждём завершения ОБЕИХ половин: если завершилась только одна
    // (например, сервер закрыл передачу, но ещё шлёт данные), вторая
    // должна получить шанс дописать хвост. `join!` не отменяет футуры,
    // в отличие от `select!`.
    let (up_res, down_res) = tokio::join!(up, down);

    // Аккуратно закрываем оба направления (SIGPIPE-подобные ошибки на этом
    // этапе игнорируем — соединение всё равно уже завершено).
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        let _ = rw.shutdown().await;
        let _ = cw.shutdown().await;
    })
    .await;

    match (up_res, down_res) {
        (Err(e), _) if e.kind() != io::ErrorKind::BrokenPipe => Err(e),
        (_, Err(e)) if e.kind() != io::ErrorKind::BrokenPipe => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_headers() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY";
        let mut cursor = &data[1..];
        let head = read_until_headers_end(&mut cursor, b'G', 4096).await.unwrap();
        assert!(head.ends_with(b"\r\n\r\n"));
        assert_eq!(&head[..3], &b"GET"[..]);
    }

    /// CRLF после данных чанка обязателен: без него границы чанков
    /// «плывут» и в тело попадают служебные байты.
    #[tokio::test]
    async fn rejects_chunk_without_crlf() {
        let data = b"5\r\nhelloXX0\r\n\r\n";
        let mut cursor = &data[..];
        assert!(read_chunked_body(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn reads_chunked() {
        let data = b"5\r\nhello\r\n0\r\n\r\n";
        let mut cursor = &data[..];
        let body = read_chunked_body(&mut cursor).await.unwrap();
        assert_eq!(body, b"hello");
    }
}

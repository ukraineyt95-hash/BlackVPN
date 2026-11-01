//! Отправка подготовленного потока байт в TCP-сокет с учётом плана
//! фрагментации (см. [`crate::dpi::plan_stream`]).
//!
//! Ключевая функция — [`send_with_plan`]: она кладёт куски в отправной буфер
//! сокета smoltcp **по одному**, и между ними делает `yield`/небольшую паузу,
//! чтобы стек отправил каждый кусок отдельным TCP-сегментом.
//!
//! Почему нужна пауза: если положить все куски в буфер подряд, smoltcp
//! склеит их в один сегмент (Nagle + накопление в tx-буфере), и DPI увидит
//! цельный ClientHello. Поэтому мы ждём, пока буфер опустеет
//! (`send_queue() == 0` или `may_send()`), прежде чем добавлять следующий
//! кусок.
use std::time::Duration;

use rand::Rng;

use crate::dpi::Chunk;

/// Что делать после отправки куска.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// Всё отправлено.
    Done,
    /// Сокет ещё не готов принять данные (окно закрыто) — надо подождать.
    Blocked,
}

/// Готовый однократный отправитель чанка — оставлен как строительный блок
/// и точка расширения; рабочий путь стека собирает план и выливает его
/// очередью (см. `drain_to_app` в tunnel/stack.rs).
/// Отправить один кусок. Возвращает число реально записанных байт.
///
/// `send` — замыкание, оборачивающее `tcp_socket.send_slice(...)`.
#[allow(dead_code)]
pub fn send_chunk<F>(chunk: &Chunk, data: &[u8], mut send: F) -> Result<Sent, std::io::Error>
where
    F: FnMut(&[u8]) -> Result<usize, std::io::Error>,
{
    match chunk {
        Chunk::Junk(junk) => {
            // Мусор отправляем тем же путём: стек сам сделает из него сегмент.
            let mut off = 0;
            while off < junk.len() {
                match send(&junk[off..]) {
                    Ok(0) => return Ok(Sent::Blocked),
                    Ok(n) => off += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        return Ok(Sent::Blocked)
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(Sent::Done)
        }
        Chunk::Data { start, end } => {
            let slice = &data[*start..*end];
            let mut off = 0;
            while off < slice.len() {
                match send(&slice[off..]) {
                    Ok(0) => return Ok(Sent::Blocked),
                    Ok(n) => off += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        return Ok(Sent::Blocked)
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(Sent::Done)
        }
    }
}

/// Пауза между сегментами.
///
/// 2 мс достаточно, чтобы ядро/стек успели отправить предыдущий сегмент,
/// и при этом не влияет на скорость (это происходит один раз на соединение).
pub const INTER_CHUNK_DELAY: Duration = Duration::from_millis(2);

/// Подготовить «мусорный» префикс заданной длины.
///
/// Простейшая стратегия — случайные байты. Они заставляют активный DPI
/// (который пытается распознать протокол) увидеть «неизвестный протокол»
/// вместо ClientHello.
pub fn make_junk(len: usize, rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut junk = vec![0u8; len];
    rng.fill(&mut junk[..]);
    junk
}

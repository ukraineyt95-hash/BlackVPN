use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;

use super::hpack::HpackDecoder;
use super::probes;
use super::ProxyContext;
use crate::stats;

/// Максимальное количество одновременных потоков (как в Python).
pub const MUX_CONCURRENCY: usize = 8;

/// Размер окна по умолчанию (65535, как в HTTP/2).
const DEFAULT_WINDOW: i64 = 65535;

/// Максимальный размер фрейма, который мы готовы принять и отправить
/// (ровно 16384 — как в эталонной реализации на Python).
const MAX_FRAME_SIZE: usize = 16384;

const MAX_HEADER_BLOCK: usize = 65536;

const MAX_PENDING_IN: usize = 256 * 1024;

/// Таймаут рукопожатия.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// Типы фреймов.
const FRAME_DATA: u8 = 0;
const FRAME_HEADERS: u8 = 1;
const FRAME_PRIORITY: u8 = 2;
const FRAME_RST_STREAM: u8 = 3;
const FRAME_SETTINGS: u8 = 4;
const FRAME_PUSH_PROMISE: u8 = 5;
const FRAME_PING: u8 = 6;
const FRAME_GOAWAY: u8 = 7;
const FRAME_WINDOW_UPDATE: u8 = 8;
const FRAME_CONTINUATION: u8 = 9;

// Флаги.
const FLAG_ACK: u8 = 0x1;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

// Коды RST_STREAM.
const RST_PROTOCOL: u32 = 1;
const RST_INTERNAL: u32 = 2;
const RST_FLOW_CONTROL: u32 = 3;
const RST_STREAM_CLOSED: u32 = 5;
const RST_REFUSED: u32 = 7;

/// Магические ключи протокола H2Mux.
const MAGIC_KEY: u16 = 0x42db;
const SERVER_MAGIC_VALUE: u32 = 0xa2e43c8b;
const CLIENT_MAGIC_VALUE: u32 = 0x1088ebf9;
const RESERVED_KEY: u16 = 0xff20;

/// Отправитель фреймов (один на соединение).
pub type FrameTx = mpsc::UnboundedSender<Vec<u8>>;

fn fmt_u64(mut value: u64, buf: &mut [u8; 20]) -> &str {
    let mut pos = buf.len();
    if value == 0 {
        pos -= 1;
        buf[pos] = b'0';
    }
    while value > 0 {
        pos -= 1;
        buf[pos] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    std::str::from_utf8(&buf[pos..]).unwrap_or("0")
}

/// Собрать фрейм в буфер (без записи в сокет).
fn build_frame(kind: u8, flags: u8, stream_id: u32, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + data.len());
    let len = data.len();
    frame.push(((len >> 16) & 0xff) as u8);
    frame.push(((len >> 8) & 0xff) as u8);
    frame.push((len & 0xff) as u8);
    frame.push(kind);
    frame.push(flags);
    frame.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

/// Общее состояние мультиплексора.
pub struct Mux {
    /// Канал отправки фреймов.
    tx: FrameTx,
    /// Декодер HPACK (только читающий цикл).
    decoder: StdMutex<HpackDecoder>,
    /// Открытые потоки.
    streams: StdMutex<HashMap<u32, Arc<StreamState>>>,
    /// Последний stream_id от клиента.
    last_stream: StdMutex<u32>,
    /// Окно отправки (сколько байт нам разрешено слать в соединение).
    peer_window: AtomicI64,
    /// Максимальный размер фрейма, разрешённый клиентом.
    peer_frame_size: StdMutex<usize>,
    /// Контекст авторизации.
    ctx: Arc<ProxyContext>,
    /// Соединение закрыто.
    closed: AtomicBool,
}

impl StreamState {
    fn new(initial_window: i64) -> Self {
        Self {
            writer: AsyncMutex::new(StreamWriter::Idle),
            pending_in: AsyncMutex::new(PendingIn::default()),
            send_window: AtomicI64::new(initial_window),
            recv_window: AtomicI64::new(DEFAULT_WINDOW),
            task: StdMutex::new(None),
        }
    }

    /// Ставит данные в очередь на отправку в цель. Возвращает число байт,
    /// реально переданных сейчас: за них нужно вернуть клиенту кредит окна.
    /// Если соединение ещё не установлено, байты копятся до CONNECT.
    async fn push_in(&self, data: &[u8]) -> io::Result<usize> {
        let mut guard = self.writer.lock().await;
        match &mut *guard {
            StreamWriter::Ready(half) => {
                half.write_all(data).await?;
                let _ = half.flush().await;
                stats::add_up(data.len());
                Ok(data.len())
            }
            StreamWriter::Idle => {
                // Соединение ещё не открыто: копим данные до CONNECT.
                // Порядок блокировок всегда writer -> pending_in.
                let mut pending = self.pending_in.lock().await;
                pending.chunks.push_back(data.to_vec());
                Ok(0)
            }
            StreamWriter::Closed => Ok(0),
        }
    }

    /// Закрывает направление «клиент -> цель».
    async fn shutdown_upstream(&self) {
        let mut guard = self.writer.lock().await;
        match &mut *guard {
            StreamWriter::Ready(half) => {
                let _ = half.shutdown().await;
            }
            StreamWriter::Idle => {
                let mut pending = self.pending_in.lock().await;
                pending.eof = true;
            }
            StreamWriter::Closed => {}
        }
    }
}

/// Состояние пишущей половины соединения с целью.
enum StreamWriter {
    /// Соединение ещё не установлено (идёт CONNECT).
    Idle,
    /// Соединение установлено, можно писать напрямую.
    Ready(OwnedWriteHalf),
    /// Поток уже закрыт, писать некуда.
    Closed,
}

#[derive(Default)]
struct PendingIn {
    chunks: VecDeque<Vec<u8>>,
    /// Клиент уже прислал END_STREAM раньше, чем открылось соединение.
    eof: bool,
}

/// Состояние одного потока.
pub struct StreamState {
    writer: AsyncMutex<StreamWriter>,
    pending_in: AsyncMutex<PendingIn>,
    /// Окно отправки потока.
    send_window: AtomicI64,
    recv_window: AtomicI64,
    /// Задача релея (для отмены).
    task: StdMutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Mux {
    fn new(tx: FrameTx, ctx: Arc<ProxyContext>) -> Self {
        Self {
            tx,
            decoder: StdMutex::new(HpackDecoder::new()),
            streams: StdMutex::new(HashMap::new()),
            last_stream: StdMutex::new(0),
            peer_window: AtomicI64::new(DEFAULT_WINDOW),
            peer_frame_size: StdMutex::new(MAX_FRAME_SIZE),
            ctx,
            closed: AtomicBool::new(false),
        }
    }

    /// Поставить фрейм в очередь отправки.
    fn send_frame(&self, kind: u8, flags: u8, stream_id: u32, data: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "H2Mux закрыт"));
        }
        self.tx
            .send(build_frame(kind, flags, stream_id, data))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "H2Mux: канал закрыт"))
    }

    /// Отправить заголовки ответа.
    fn send_headers(&self, stream_id: u32, headers: &[(&str, &str)], end: bool) -> io::Result<()> {
        let block = HpackDecoder::encode(headers);
        let mut flags = FLAG_END_HEADERS;
        if end {
            flags |= FLAG_END_STREAM;
        }
        self.send_frame(FRAME_HEADERS, flags, stream_id, &block)
    }

    /// Отправить данные с учётом окна потока и соединения.
    ///
    /// Возвращает `Ok(false)`, если поток больше не существует.
    async fn send_data(&self, stream_id: u32, data: &[u8], end: bool) -> io::Result<bool> {
        let stream = self.stream_state(stream_id);

        if !data.is_empty() {
            let Some(stream) = stream else {
                return Ok(false);
            };
            let mut offset = 0usize;
            while offset < data.len() {
                // Сколько байт можем отправить прямо сейчас.
                let stream_win = stream.send_window.load(Ordering::Relaxed);
                let conn_win = self.peer_window.load(Ordering::Relaxed);
                let peer_max = *self.peer_frame_size.lock().unwrap() as i64;
                let frame_max = peer_max.min(MAX_FRAME_SIZE as i64);
                let allowed = stream_win.min(conn_win).min(frame_max).max(0) as usize;

                if allowed == 0 {
                    // Ждём WINDOW_UPDATE: спим 5 мс и проверяем снова.
                    if self.closed.load(Ordering::Relaxed) {
                        return Ok(false);
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }

                let take = allowed.min(data.len() - offset);
                stream
                    .send_window
                    .fetch_sub(take as i64, Ordering::Relaxed);
                self.peer_window.fetch_sub(take as i64, Ordering::Relaxed);
                self.send_frame(FRAME_DATA, 0, stream_id, &data[offset..offset + take])?;
                offset += take;
            }
        }

        if end {
            self.send_frame(FRAME_DATA, FLAG_END_STREAM, stream_id, &[])?;
        }
        Ok(true)
    }

    /// Взять собственную ссылку на состояние потока.
    ///
    /// Нужно, чтобы избежать гонки при «взял сокет -> await -> положил
    /// обратно»: между `.take()` и обратной записью релей уже мог
    /// подключиться и получить `None`. Поэтому наружу отдаётся `Arc`, а не
    /// заимствование: гард `streams` отпускается сразу.
    fn stream_state(&self, stream_id: u32) -> Option<Arc<StreamState>> {
        self.streams.lock().unwrap().get(&stream_id).cloned()
    }

    /// Сбросить поток: RST_STREAM + освободить ресурсы.
    fn reset(&self, stream_id: u32, code: u32) -> io::Result<()> {
        if let Some(stream) = self.streams.lock().unwrap().remove(&stream_id) {
            if let Some(task) = stream.task.lock().unwrap().take() {
                task.abort();
            }

            // Задача потока уже прервана, поэтому половину на запись можно
            // просто отпустить: соединение с целью закроется при drop.
            if let Ok(mut guard) = stream.writer.try_lock() {
                *guard = StreamWriter::Closed;
            }
        }
        if self.closed.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.send_frame(FRAME_RST_STREAM, 0, stream_id, &code.to_be_bytes())
    }

    /// Применить SETTINGS клиента.
    fn apply_settings(&self, payload: &[u8], handshake: bool) -> Result<(), String> {
        if payload.len() % 6 != 0 {
            return Err("invalid H2Mux settings".into());
        }
        let mut values: HashMap<u16, u32> = HashMap::new();
        for chunk in payload.chunks(6) {
            let key = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            values.insert(key, value);
        }

        if handshake && values.get(&MAGIC_KEY) != Some(&CLIENT_MAGIC_VALUE) {
            return Err("invalid H2Mux client magic".into());
        }

        // SETTINGS_INITIAL_WINDOW_SIZE — стартовое окно новых потоков.
        if let Some(&window) = values.get(&4) {
            if window > 0x7fff_ffff {
                return Err("invalid H2Mux window".into());
            }
            let old = self.peer_window.load(Ordering::Relaxed);
            let delta = window as i64 - old;
            self.peer_window.store(window as i64, Ordering::Relaxed);
            for stream in self.streams.lock().unwrap().values() {
                stream.send_window.fetch_add(delta, Ordering::Relaxed);
            }
        }

        // SETTINGS_MAX_FRAME_SIZE.
        if let Some(&size) = values.get(&5) {
            if !(16384..=16_777_215).contains(&size) {
                return Err("invalid H2Mux frame size".into());
            }
            *self.peer_frame_size.lock().unwrap() = (size as usize).min(65536);
        }

        Ok(())
    }
}

/// Прочитать один фрейм, учитывая заранее прочитанный префикс.
async fn read_frame_prefixed<R>(
    reader: &mut R,
    prefix: &mut Vec<u8>,
) -> io::Result<(u8, u8, u32, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 9];
    let take = prefix.len().min(9);
    header[..take].copy_from_slice(&prefix[..take]);
    prefix.drain(..take);
    if take < 9 {
        reader.read_exact(&mut header[take..]).await?;
    }

    let size = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    if size > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "фрейм H2Mux слишком велик",
        ));
    }
    let kind = header[3];
    let flags = header[4];
    let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;

    let mut payload = vec![0u8; size];
    let take = prefix.len().min(size);
    payload[..take].copy_from_slice(&prefix[..take]);
    prefix.drain(..take);
    if take < size {
        reader.read_exact(&mut payload[take..]).await?;
    }
    Ok((kind, flags, stream_id, payload))
}

/// Точка входа: обработать H2Mux-соединение.
///
/// * `stream` — сокет клиента (может быть уже после HTTP 101);
/// * `ctx` — контекст авторизации;
/// * `prefix` — байты, уже прочитанные диспетчером (например, первый `0x00`).
pub async fn handle(
    stream: TcpStream,
    ctx: &Arc<ProxyContext>,
    prefix_bytes: Option<u8>,
) -> io::Result<()> {
    // Половиним клиентский сокет: читающая половина остаётся здесь,
    // пишущая уезжает в отдельную задачу-писатель (канал фреймов).
    let (read_half, mut writer) = stream.into_split();
    let mut reader = read_half;

    // Канал отправки: отдельная задача пишет в сокет.
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let write_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if writer.write_all(&frame).await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    let mux = Arc::new(Mux::new(tx, ctx.clone()));
    let mut prefix: Vec<u8> = prefix_bytes.into_iter().collect();

    // --- Рукопожатие ---------------------------------------------------- //
    let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        // 1) Наши SETTINGS: магия сервера + служебный ключ + конкурентность.
        let mut payload = Vec::with_capacity(18);
        for (key, value) in [
            (MAGIC_KEY, SERVER_MAGIC_VALUE),
            (RESERVED_KEY, 0u32),
            (3u16, MUX_CONCURRENCY as u32),
        ] {
            payload.extend_from_slice(&key.to_be_bytes());
            payload.extend_from_slice(&value.to_be_bytes());
        }
        mux.send_frame(FRAME_SETTINGS, 0, 0, &payload)?;

        // 2) SETTINGS клиента.
        let (kind, flags, stream_id, payload) = read_frame_prefixed(&mut reader, &mut prefix).await?;
        if kind != FRAME_SETTINGS || flags != 0 || stream_id != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ожидались SETTINGS клиента",
            ));
        }
        mux.apply_settings(&payload, true)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // 3) ACK на SETTINGS клиента.
        mux.send_frame(FRAME_SETTINGS, FLAG_ACK, 0, &[])?;

        // 4) Ожидаем ACK на наши SETTINGS.
        let (kind, flags, stream_id, _) = read_frame_prefixed(&mut reader, &mut prefix).await?;
        if kind != FRAME_SETTINGS || flags != FLAG_ACK || stream_id != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ожидался SETTINGS ACK",
            ));
        }
        Ok(())
    })
    .await;

    match handshake {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            crate::flog_dbg!("H2Mux: рукопожатие не удалось: {e}");
    // --- Уборка --------------------------------------------------------- //
            mux.closed.store(true, Ordering::Relaxed);
            write_task.abort();
            return Ok(());
        }
        Err(_) => {
            crate::flog_dbg!("H2Mux: таймаут рукопожатия");
            mux.closed.store(true, Ordering::Relaxed);
            write_task.abort();
            return Ok(());
        }
    }

    crate::flog_dbg!("H2Mux: соединение установлено");

    let result = frame_loop(&mux, reader, prefix).await;

    mux.closed.store(true, Ordering::Relaxed);
    let tasks: Vec<_> = mux
        .streams
        .lock()
        .unwrap()
        .drain()
        .filter_map(|(_, s)| s.task.lock().unwrap().take())
        .collect();
    for t in tasks {
        t.abort();
    }

    // Даём writer-задаче дописать хвост.
    tokio::time::sleep(Duration::from_millis(20)).await;
    write_task.abort();

    result
}

async fn frame_loop<R>(mux: &Arc<Mux>, mut reader: R, mut prefix: Vec<u8>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let (kind, flags, stream_id, payload) = match read_frame_prefixed(&mut reader, &mut prefix).await {
            Ok(f) => f,
            Err(_) => return Ok(()),
        };

        match kind {
            FRAME_DATA => on_data(mux, flags, stream_id, payload).await?,
            FRAME_HEADERS => {
                on_headers(mux, &mut reader, &mut prefix, flags, stream_id, payload).await?
            }
            FRAME_CONTINUATION => {
                // Продолжение без предшествующего HEADERS — нарушение протокола.
                send_goaway(mux, 1)?;
                return Ok(());
            }
            FRAME_RST_STREAM => {
                if let Some(stream) = mux.streams.lock().unwrap().remove(&stream_id) {
                    if let Some(t) = stream.task.lock().unwrap().take() {
                        t.abort();
                    }
                }
            }
            FRAME_SETTINGS => {
                // ACK с телом и ненулевой stream_id — нарушение протокола.
                if stream_id != 0 || (flags & FLAG_ACK != 0 && !payload.is_empty()) {
                    send_goaway(mux, 1)?;
                    return Ok(());
                }
                if flags & FLAG_ACK == 0 {
                    if mux.apply_settings(&payload, false).is_err() {
                        send_goaway(mux, 1)?;
                        return Ok(());
                    }
                    mux.send_frame(FRAME_SETTINGS, FLAG_ACK, 0, &[])?;
                }
            }
            FRAME_PING => {
                if stream_id != 0 || payload.len() != 8 {
                    send_goaway(mux, 1)?;
                    return Ok(());
                }
                if flags & FLAG_ACK == 0 {
                    mux.send_frame(FRAME_PING, FLAG_ACK, 0, &payload)?;
                }
            }
            FRAME_GOAWAY => {
                crate::flog_dbg!("H2Mux: клиент отправил GOAWAY");
                return Ok(());
            }
            FRAME_WINDOW_UPDATE => {
                if payload.len() != 4 {
                    send_goaway(mux, 1)?;
                    return Ok(());
                }
                let increment =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7fff_ffff;
                if increment == 0 {
                    send_goaway(mux, 1)?;
                    return Ok(());
                }
                if stream_id == 0 {
                    mux.peer_window
                        .fetch_add(increment as i64, Ordering::Relaxed);
                } else if let Some(s) = mux.streams.lock().unwrap().get(&stream_id) {
                    s.send_window.fetch_add(increment as i64, Ordering::Relaxed);
                }
            }

            // PRIORITY и PUSH_PROMISE можно игнорировать.
            FRAME_PRIORITY | FRAME_PUSH_PROMISE => {}
            _ => {
                send_goaway(mux, 1)?;
                return Ok(());
            }
        }
    }
}

/// Отправить GOAWAY и завершить обработку.
fn send_goaway(mux: &Arc<Mux>, code: u32) -> io::Result<()> {
    let last = *mux.last_stream.lock().unwrap();
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&last.to_be_bytes());
    payload.extend_from_slice(&code.to_be_bytes());
    mux.send_frame(FRAME_GOAWAY, 0, 0, &payload)
}

/// Обрабатывает HEADERS. Если блок заголовков не закончился (`END_HEADERS`
/// не выставлен), хвост приходит фреймами CONTINUATION — собираем его здесь,
/// иначе HPACK-контекст разъедется и последующие потоки будут битыми.
async fn on_headers<R>(
    mux: &Arc<Mux>,
    reader: &mut R,
    prefix: &mut Vec<u8>,
    mut flags: u8,
    stream_id: u32,
    mut payload: Vec<u8>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    // stream_id должен быть нечётным и строго возрастать.
    if stream_id == 0 || stream_id & 1 == 0 || stream_id <= *mux.last_stream.lock().unwrap() {
        let _ = mux.reset(stream_id, RST_PROTOCOL);
        return Ok(());
    }
    *mux.last_stream.lock().unwrap() = stream_id;

    let end = flags & FLAG_END_STREAM != 0;
    // Padding.
    if flags & FLAG_PADDED != 0 {
        if payload.is_empty() || payload[0] as usize >= payload.len() {
            let _ = mux.reset(stream_id, RST_PROTOCOL);
            return Ok(());
        }
        let pad = payload[0] as usize;
        payload = payload[1..payload.len() - pad].to_vec();
    }

    // Priority.
    if flags & FLAG_PRIORITY != 0 {
        if payload.len() < 5 {
            let _ = mux.reset(stream_id, RST_PROTOCOL);
            return Ok(());
        }
        payload = payload[5..].to_vec();
    }

    // Блок заголовков может быть разбит на CONTINUATION: собираем его целиком,
    // иначе HPACK-контекст разъедется и все последующие потоки будут битыми.
    let mut block = payload;
    while flags & FLAG_END_HEADERS == 0 {
        let (kind, next_flags, next_id, next_payload) =
            match read_frame_prefixed(&mut *reader, &mut *prefix).await {
                Ok(f) => f,
                // Обрыв соединения посреди блока заголовков: поток закрыт.
                Err(_) => return Ok(()),
            };
        if kind != FRAME_CONTINUATION || next_id != stream_id {
            let _ = mux.reset(stream_id, RST_PROTOCOL);
            return Ok(());
        }
        block.extend_from_slice(&next_payload);
        if block.len() > MAX_HEADER_BLOCK {
            let _ = mux.reset(stream_id, RST_PROTOCOL);
            return Ok(());
        }
        flags = next_flags;
    }

    if block.len() > MAX_HEADER_BLOCK {
        let _ = mux.reset(stream_id, RST_PROTOCOL);
        return Ok(());
    }

    // HPACK.
    let headers = {
        let mut dec = mux.decoder.lock().unwrap();
        match dec.decode(&block) {
            Ok(h) => h,
            Err(e) => {
                crate::flog_dbg!("H2Mux: HPACK {e}");
                let _ = mux.reset(stream_id, RST_PROTOCOL);
                return Ok(());
            }
        }
    };

    // Ограничение конкурентности.
    if mux.streams.lock().unwrap().len() >= MUX_CONCURRENCY {
        let _ = mux.reset(stream_id, RST_REFUSED);
        return Ok(());
    }

    let state = Arc::new(StreamState::new(mux.peer_window.load(Ordering::Relaxed)));
    mux.streams
        .lock()
        .unwrap()
        .insert(stream_id, state.clone());

    // Запускаем обработку потока.
    //
    // `state` после `move` ещё нужен для `task`, поэтому в задачу уходит
    // клон, а `Arc<Mux>` клонируется один раз на задачу (внутрь `multiplexer`
    // передаётся ещё один клон — `Arc` не `Copy`).
    let mux_clone = mux.clone();
    let state_for_task = state.clone();
    let task = tokio::spawn(async move {
        let mux_for_task = mux_clone.clone();
        if let Err(e) = multiplexer(mux_clone, stream_id, state_for_task, headers, end).await {
            crate::flog_dbg!("H2Mux stream {stream_id}: {e}");
            let _ = mux_for_task.reset(stream_id, RST_INTERNAL);
        }
        mux_for_task.streams.lock().unwrap().remove(&stream_id);
    });
    *state.task.lock().unwrap() = Some(task);

    Ok(())
}

/// Обработать DATA: записать в сокет цели.
///
/// Сокет держится внутри `StreamState.remote` и НЕ «вынимается» наружу:
/// `std::sync::Mutex` над `Option<TcpStream>` позволяет держать `&mut`
/// во время `.await` (future остаётся `Send`, т.к. guard создаётся и
/// уничтожается внутри одной задачи). Альтернатива с `take()/put back`
/// давала гонку: релей мог увидеть `None` и решить, что потока нет.
async fn on_data(
    mux: &Arc<Mux>,
    flags: u8,
    stream_id: u32,
    mut payload: Vec<u8>,
) -> io::Result<()> {
    if stream_id == 0 {
        send_goaway(mux, 1)?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "H2Mux DATA с stream_id = 0",
        ));
    }

    let Some(state) = mux.stream_state(stream_id) else {
        let _ = mux.reset(stream_id, RST_STREAM_CLOSED);
        return Ok(());
    };

    // PADDING: первый байт — длина выравнивающего хвоста. Учитывая его в окне
    // приёма, мы не «съедаем» буфер клиента впустую.
    if flags & FLAG_PADDED != 0 {
        if payload.is_empty() || payload[0] as usize >= payload.len() {
            let _ = mux.reset(stream_id, RST_PROTOCOL);
            return Ok(());
        }
        let pad = payload[0] as usize;
        payload = payload[1..payload.len() - pad].to_vec();
        let credit = pad as i64 + 1;
        state.recv_window.fetch_add(credit, Ordering::Relaxed);
        mux.send_frame(FRAME_WINDOW_UPDATE, 0, stream_id, &(credit as u32).to_be_bytes())?;
    }

    // Контроль переполнения окна приёма (аналог RST(FLOW_CONTROL) в эталонном
    // Python-прокси).
    let after = state
        .recv_window
        .fetch_sub(payload.len() as i64, Ordering::Relaxed)
        - payload.len() as i64;
    if after < 0 {
        let _ = mux.reset(stream_id, RST_FLOW_CONTROL);
        return Ok(());
    }

    // Пробрасываем полезную нагрузку в направлении цели. Писатель может быть
    // ещё не готов — тогда данные копятся в очереди потока.
    if !payload.is_empty() {
        let queued = {
            let pending = state.pending_in.lock().await;
            pending.chunks.iter().map(|c| c.len()).sum::<usize>() + payload.len()
        };
        if queued > MAX_PENDING_IN {
            let _ = mux.reset(stream_id, RST_FLOW_CONTROL);
            return Ok(());
        }
        match state.push_in(&payload).await {
            Ok(written) => {
                // Кредит окна возвращаем только за фактически переданные байты:
                // пока данные лежат в очереди, клиент притормаживает.
                refund_window(mux, stream_id, &state, written);
            }
            Err(_) => {
                let _ = mux.reset(stream_id, RST_INTERNAL);
                return Ok(());
            }
        }
    }

            // Конец передачи от клиента — закрываем направление записи.
    if flags & FLAG_END_STREAM != 0 {
        state.shutdown_upstream().await;
    }

    Ok(())
}

/// Возвращает клиенту кредит окна за переданные байты — иначе его
/// `send_window` исчерпается и поток встанет намертво.
fn refund_window(mux: &Arc<Mux>, stream_id: u32, state: &Arc<StreamState>, n: usize) {
    if n == 0 {
        return;
    }
    state.recv_window.fetch_add(n as i64, Ordering::Relaxed);
    let _ = mux.send_frame(
        FRAME_WINDOW_UPDATE,
        0,
        stream_id,
        &(n as u32).to_be_bytes(),
    );
}

/// Обработка одного потока: разбор заголовков, CONNECT и релей.
async fn multiplexer(
    mux: Arc<Mux>,
    stream_id: u32,
    state: Arc<StreamState>,
    headers: Vec<(String, String)>,
    _input_ended: bool,
) -> Result<(), String> {
    // Разбираем заголовки: псевдо-заголовки (`:method`) идут первыми.
    let mut map: HashMap<String, String> = HashMap::new();
    let mut regular = false;
    for (name, value) in headers {
        if name.starts_with(':') {
            if regular {
                return Err("нарушен порядок псевдо-заголовков".into());
            }
        } else {
            regular = true;
        }
        map.insert(name, value);
    }

    // Авторизация.
    if let Some(expected) = mux.ctx.basic_expected() {
        let got = map.get("proxy-authorization").cloned().unwrap_or_default();
        if got != expected {
            mux.send_headers(
                stream_id,
                &[
                    (":status", "407"),
                    ("proxy-authenticate", "Basic realm=\"proxy\""),
                ],
                true,
            )
            .map_err(|e| e.to_string())?;
            return Ok(());
        }
    }

    let method = map.get(":method").cloned().unwrap_or_default();
    let target = map
        .get(":authority")
        .or_else(|| map.get("host"))
        .cloned()
        .unwrap_or_default();

    // GET/HEAD на пробники — отвечаем из памяти.
    if method == "GET" || method == "HEAD" {
        let (host, _) = super::split_host_port(&target, 80);
        let path = map
            .get(":path")
            .cloned()
            .unwrap_or_else(|| "/".to_string());
        let path = path.split('?').next().unwrap_or("/").to_string();

        match probes::probe_body(&host, &path) {
            Some(body) => {
                let mut len_buf = [0u8; 20];
                let len = fmt_u64(body.len() as u64, &mut len_buf);
                mux.send_headers(
                    stream_id,
                    &[
                        (":status", "200"),
                        ("content-type", "text/plain; charset=utf-8"),
                        ("content-length", len),
                        ("cache-control", "no-cache"),
                    ],
                    false,
                )
                .map_err(|e| e.to_string())?;
                if method != "HEAD" {
                    mux.send_data(stream_id, body.as_bytes(), true)
                        .await
                        .map_err(|e| e.to_string())?;
                } else {
                    mux.send_data(stream_id, b"", true)
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
            None => {
                mux.send_headers(stream_id, &[(":status", "404")], true)
                    .map_err(|e| e.to_string())?;
            }
        }
        return Ok(());
    }

    if method != "CONNECT" || target.is_empty() {
        mux.send_headers(stream_id, &[(":status", "400")], true)
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    let (host, port) = super::split_host_port(&target, 443);
    if host.is_empty() || port == 0 {
        return Err("некорректная цель H2Mux".into());
    }

    // Подключаемся.
    let remote = match super::connect(&host, port).await {
        Ok(s) => s,
        Err(_) => {
            mux.send_headers(stream_id, &[(":status", "502")], true)
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
    };
    mux.send_headers(stream_id, &[(":status", "200")], false)
        .map_err(|e| e.to_string())?;

    // Половиним сокет: чтение ответа делает эта задача, запись — `on_data`.
    // `try_clone()` (dup) здесь не нужен и опасен: два fd на одно
    // соединение мешают корректному `shutdown()`.
    let (read_half, write_half) = remote.into_split();
    let mut reader = read_half;

    // Сначала отдаём то, что клиент прислал до установления соединения,
    // и только потом публикуем половину на запись для новых DATA-фреймов.
    let (pending_chunks, pending_eof) = {
        let mut pending = state.pending_in.lock().await;
        (std::mem::take(&mut pending.chunks), pending.eof)
    };

    let mut writer = write_half;
    let mut flushed = 0usize;
    for chunk in pending_chunks {
        if chunk.is_empty() {
            continue;
        }
        if let Err(e) = writer.write_all(&chunk).await {
            return Err(format!("H2Mux: запись в цель: {e}"));
        }
        flushed += chunk.len();
    }
    if flushed > 0 {
        stats::add_up(flushed);
    }
    let _ = writer.flush().await;
    if pending_eof {
        let _ = writer.shutdown().await;
    }
    *state.writer.lock().await = StreamWriter::Ready(writer);

    // Накопленные до CONNECT байты ушли — возвращаем клиенту окно за них.
    refund_window(&mux, stream_id, &state, flushed);

    // Читаем ответ и отправляем клиенту.
    let mut buf = vec![0u8; 16384];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        stats::add_down(n);
        match mux.send_data(stream_id, &buf[..n], false).await {
            Ok(true) => {}
            _ => return Ok(()),
        }
    }
    let _ = mux.send_data(stream_id, b"", true).await;
    Ok(())
}

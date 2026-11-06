//! Простой логгер с кольцевым буфером в памяти.
//!
//! Каждая строка лога:
//!  1. попадает в кольцевой буфер (его читает GUI и показывает на экране «Лог»);
//!  2. транслируется в `log::` (на Android — в logcat через `android_logger`,
//!     на desktop — в stderr);
//!  3. опционально пишется в файл.
//!
//! Модуль намеренно не тянет `tracing`: нужно минимум зависимостей и
//! предсказуемое поведение в NativeActivity.
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// Максимум строк в кольцевом буфере (память: ~200 КБ).
const RING_CAPACITY: usize = 2000;

fn write_line(file: &mut std::fs::File, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    file.write_all(text.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()
}

/// Куда ещё писать, кроме буфера.
struct Sink {
    file: Option<std::fs::File>,
}

static RING: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
static SINK: OnceLock<Mutex<Sink>> = OnceLock::new();

fn ring() -> &'static Mutex<VecDeque<String>> {
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(RING_CAPACITY)))
}

fn sink() -> &'static Mutex<Sink> {
    SINK.get_or_init(|| Mutex::new(Sink { file: None }))
}

/// Включить дублирование лога в файл (например, `/data/data/.../files/app.log`).
pub fn enable_file_logging(path: &Path) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => {
            sink().lock().unwrap().file = Some(f);
            log_line("INFO", &format!("Лог дублируется в файл: {}", path.display()));
        }
        Err(e) => log_line("WARN", &format!("Не удалось открыть файл лога: {e}")),
    }
}

/// Добавить строку в лог.
pub fn log_line(level: &str, message: &str) {
    // Время в формате ЧЧ:ММ:СС от начала процесса (на Android удобнее
    // относительно старта; абсолютное время есть в logcat).
    let secs = crate::platform::elapsed_secs_since_start();
    let stamp = format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    );
    let line = format!("[{stamp}] {level:<5} {message}");

    // 1) кольцевой буфер для GUI
    {
        let mut buf = ring().lock().unwrap();
        if buf.len() == RING_CAPACITY {
            buf.pop_front();
        }
        buf.push_back(line.clone());
    }

    // 3) файл
    let mut guard = sink().lock().unwrap();
    if let Some(file) = guard.file.as_mut() {
        let _ = write_line(file, &line);
    }
}

/// Копия всех строк лога (для отрисовки в GUI).
pub fn snapshot() -> Vec<String> {
    ring().lock().unwrap().iter().cloned().collect()
}

/// Очистить лог (кнопка «Очистить» в GUI).
pub fn clear() {
    ring().lock().unwrap().clear();
}

/// `flog!("текст {}", x)` — обычная запись в лог.
#[macro_export]
macro_rules! flog {
    ($($arg:tt)*) => {
        $crate::logger::log_line("INFO", &format!($($arg)*))
    };
}

/// `flog_warn!` / `flog_err!` / `flog_dbg!`
#[macro_export]
macro_rules! flog_warn {
    ($($arg:tt)*) => {
        $crate::logger::log_line("WARN", &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! flog_err {
    ($($arg:tt)*) => {
        $crate::logger::log_line("ERROR", &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! flog_dbg {
    ($($arg:tt)*) => {
        $crate::logger::log_line("DEBUG", &format!($($arg)*))
    };
}

/// Реализация `log::Log`, перенаправляющая записи сторонних крейтов
/// (eframe/smoltcp/tokio) в наш кольцевой буфер.
///
/// ВАЖНО: чтобы не зациклиться, внутри `log()` мы НЕ вызываем `log::info!`.
struct BridgeLogger;

static BRIDGE: BridgeLogger = BridgeLogger;

impl log::Log for BridgeLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let level = match record.level() {
            log::Level::Error => "ERROR",
            log::Level::Warn => "WARN",
            log::Level::Info => "INFO",
            log::Level::Debug => "DEBUG",
            log::Level::Trace => "DEBUG",
        };
        let message = format!("{}: {}", record.target(), record.args());

        {
            let mut buf = ring().lock().unwrap();
            if buf.len() == RING_CAPACITY {
                buf.pop_front();
            }
            let secs = crate::platform::elapsed_secs_since_start();
            buf.push_back(format!(
                "[{:02}:{:02}:{:02}] {level:<5} {message}",
                secs / 3600,
                (secs % 3600) / 60,
                secs % 60
            ));
        }

        let mut guard = sink().lock().unwrap();
        if let Some(file) = guard.file.as_mut() {
            let _ = write_line(file, &format!("{level:<5} {message}"));
        }
    }

    fn flush(&self) {}
}

/// Установить глобальный логгер. Вызывать один раз при старте.
pub fn init() {
    let _ = log::set_logger(&BRIDGE);
    log::set_max_level(log::LevelFilter::Info);
}

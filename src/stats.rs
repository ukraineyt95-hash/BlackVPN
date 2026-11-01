//! Счётчики трафика для индикатора скорости в GUI.
//!
//! Глобальные атомарные счётчики байт: их увеличивают и TUN-стек, и прокси.
//! Раз в секунду GUI берёт `snapshot()` и получает дельту — это и есть
//! «скорость» (байт/с), которую видит пользователь.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Байты, ушедшие в сеть (upload).
static UP: AtomicU64 = AtomicU64::new(0);

/// Байты, пришедшие из сети (download).
static DOWN: AtomicU64 = AtomicU64::new(0);

/// Количество активных соединений.
static CONNS: AtomicU64 = AtomicU64::new(0);

/// Учесть отправленные байты.
pub fn add_up(n: usize) {
    UP.fetch_add(n as u64, Ordering::Relaxed);
}

/// Учесть полученные байты.
pub fn add_down(n: usize) {
    DOWN.fetch_add(n as u64, Ordering::Relaxed);
}

/// Отметить открытие соединения.
pub fn conn_open() {
    CONNS.fetch_add(1, Ordering::Relaxed);
}

/// Отметить закрытие соединения.
pub fn conn_close() {
    CONNS.fetch_sub(1, Ordering::Relaxed);
}

/// Мгновенный снимок абсолютных значений.
pub fn totals() -> (u64, u64, u64) {
    (
        UP.load(Ordering::Relaxed),
        DOWN.load(Ordering::Relaxed),
        CONNS.load(Ordering::Relaxed),
    )
}

/// Сбрасывать счётчики при старте/остановке VPN.
///
/// Счётчик соединений тоже обнуляется: после остановки все соединения
/// закрыты, и «висящее» положительное значение показывало бы в GUI
/// активные соединения, которых нет.
pub fn reset() {
    UP.store(0, Ordering::Relaxed);
    DOWN.store(0, Ordering::Relaxed);
    CONNS.store(0, Ordering::Relaxed);
}


/// Вычислитель скорости: хранит прошлый снимок и время.
pub struct SpeedMeter {
    last: (u64, u64),
    last_at: Instant,
    pub up_bps: f64,
    pub down_bps: f64,
}

impl Default for SpeedMeter {
    fn default() -> Self {
        Self {
            last: (0, 0),
            last_at: Instant::now(),
            up_bps: 0.0,
            down_bps: 0.0,
        }
    }
}

impl SpeedMeter {
    /// Обновить значения, если с прошлого раза прошло достаточно времени.
    pub fn tick(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_at).as_secs_f64();
        if dt < 0.25 {
            return;
        }
        let (up, down, _) = totals();

        // Дельта может быть отрицательной после reset() — защищаемся saturating.
        let dup = up.saturating_sub(self.last.0) as f64;
        let ddown = down.saturating_sub(self.last.1) as f64;
        self.up_bps = dup / dt;
        self.down_bps = ddown / dt;
        self.last = (up, down);
        self.last_at = now;
    }

    /// Человекочитаемая скорость: «1.2 МБ/с».
    pub fn format_up(&self) -> String {
        format_speed(self.up_bps)
    }

    pub fn format_down(&self) -> String {
        format_speed(self.down_bps)
    }
}

/// Форматирование скорости в удобных единицах.
pub fn format_speed(bps: f64) -> String {
    const KIB: f64 = 1024.0;
    if bps < KIB {
        format!("{bps:.0} Б/с")
    } else if bps < KIB * KIB {
        format!("{:.1} КБ/с", bps / KIB)
    } else {
        format!("{:.2} МБ/с", bps / (KIB * KIB))
    }
}

/// Форматирование объёма.
pub fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let b = bytes as f64;
    if b < KIB {
        format!("{bytes} Б")
    } else if b < KIB * KIB {
        format!("{:.1} КБ", b / KIB)
    } else if b < KIB * KIB * KIB {
        format!("{:.1} МБ", b / (KIB * KIB))
    } else {
        format!("{:.2} ГБ", b / (KIB * KIB * KIB))
    }
}

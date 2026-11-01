//! Модуль обхода DPI (Deep Packet Inspection).
//!
//! Реализованные техники (все включаются чекбоксами в GUI):
//!
//! | Техника              | Что делает                                               |
//! |----------------------|----------------------------------------------------------|
//! | Фрагментация         | Режет первый TCP-сегмент на куски 1..5 байт               |
//! | Микро-сегментация    | Отправляет первые N байт по одному                       |
//! | Разрывание TLS       | Делит ClientHello ровно посреди SNI                      |
//! | Маскировка SNI       | Подменяет имя хоста в ClientHello на «фейковое»          |
//! | Junk-префикс         | Шлёт мусорный сегмент перед полезными данными            |
//!
//! # Где это применяется
//!
//! DPI-системы провайдера анализируют **первые пакеты** TCP-соединения:
//! по ним видно SNI из TLS ClientHello (даже без расшифровки). Если
//! разрезать ClientHello на две TCP-секции так, чтобы имя хоста оказалось
//! в разных пакетах, простой DPI не соберёт его обратно и соединение
//! проходит. Это и есть идея GoodbyeDPI/ByeByeDPI, которую мы повторяем.
//!
//! Модуль работает с *потоками байт*, а не с пакетами: TCP-сокет smoltcp
//! сам нарежет их на сегменты по мере отправки. Поэтому все решения
//! принимаются на уровне «сколько байт отдать в сокет за один вызов
//! `send_slice`».
pub mod fragment;
pub mod sni;
pub mod tls;

use rand::Rng;

use serde::{Deserialize, Serialize};

use crate::config::AppConfig;

/// Набор включённых техник (копия нужных полей конфига для быстрого доступа).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiSettings {
    /// Мастер-выключатель.
    pub enabled: bool,
    /// Фрагментация первого сегмента.
    pub fragment: bool,
    pub fragment_min: usize,
    pub fragment_max: usize,
    /// Микро-сегментация: N первых байт по одному.
    pub microsegmentation: bool,
    pub microseg_bytes: usize,
    /// Разрыв TLS ClientHello.
    pub split_tls: bool,
    /// Рвать именно посреди SNI.
    pub split_at_sni: bool,
    /// Фиксированная позиция разрыва (если `split_at_sni == false`).
    pub split_position: Option<usize>,
    /// Подмена SNI.
    pub fake_sni: bool,
    pub fake_sni_host: String,
    /// Мусорный префикс.
    pub junk_prefix: bool,
}

impl Default for DpiSettings {
    fn default() -> Self {
        Self::from_config(&AppConfig::default())
    }
}

impl DpiSettings {
    /// Взять актуальные настройки из конфигурации приложения.
    pub fn from_config(cfg: &AppConfig) -> Self {
        Self {
            enabled: cfg.bypass_enabled,
            fragment: cfg.fragment_enabled,
            fragment_min: cfg.fragment_size_min,
            fragment_max: cfg.fragment_size_max,
            microsegmentation: cfg.microsegmentation_enabled,
            microseg_bytes: cfg.microsegmentation_bytes,
            split_tls: cfg.split_tls_enabled,
            split_at_sni: cfg.split_tls_at_sni,
            split_position: cfg.split_tls_position,
            fake_sni: cfg.fake_sni_enabled,
            fake_sni_host: cfg.fake_sni_host.clone(),
            junk_prefix: cfg.junk_prefix_enabled,
        }
    }

    /// Нужно ли вообще что-то делать с этим потоком.
    pub fn active(&self) -> bool {
        self.enabled
            && (self.fragment
                || self.microsegmentation
                || self.split_tls
                || self.fake_sni
                || self.junk_prefix)
    }

    /// Человекочитаемое описание активных техник — для лога.
    pub fn describe(&self) -> String {
        if !self.active() {
            return "DPI-обход выключен".to_string();
        }
        let mut parts = Vec::new();
        if self.fragment {
            parts.push(format!("фрагментация {}-{}", self.fragment_min, self.fragment_max));
        }
        if self.microsegmentation {
            parts.push(format!("микро-сегментация {}", self.microseg_bytes));
        }
        if self.split_tls {
            parts.push(if self.split_at_sni {
                "разрыв TLS по SNI".to_string()
            } else {
                format!("разрыв TLS @{:?}", self.split_position)
            });
        }
        if self.fake_sni && !self.fake_sni_host.is_empty() {
            parts.push(format!("маскировка SNI -> {}", self.fake_sni_host));
        }
        if self.junk_prefix {
            parts.push("junk-префикс".to_string());
        }
        parts.join(", ")
    }
}

/// План отправки байт в TCP-сокет: какие куски и в каком порядке шлём.
///
/// Пример: `[Junk(3), Data(1), Data(1), Data(1400)]` — сначала 3 байта мусора,
/// потом два одиночных байта, потом остаток.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk {
    /// Мусорный байт/несколько байт (без полезной нагрузки).
    Junk(Vec<u8>),
    /// Полезные данные (диапазон в исходном буфере).
    Data { start: usize, end: usize },
}

/// Построить план отправки для буфера `data`, который является первым
/// в TCP-соединении (т.е. содержит начало TLS ClientHello или HTTP-запроса).
///
/// `data` уже могла быть изменена маскировкой SNI — тогда план строится
/// по итоговому буферу.
pub fn plan_stream(data: &[u8], cfg: &DpiSettings, rng: &mut impl rand::Rng) -> Vec<Chunk> {
    let mut plan = Vec::new();
    if data.is_empty() {
        return plan;
    }
    let len = data.len();

    if !cfg.active() {
        plan.push(Chunk::Data { start: 0, end: len });
        return plan;
    }

    // 1) Мусорный префикс: помогает против активного зондирования —
    //    сканер видит не ClientHello, а случайные байты, и рвёт соединение.
    if cfg.junk_prefix {
        plan.push(Chunk::Junk(fragment::make_junk(3, rng)));
    }

    // 2) Разрыв TLS: вычисляем позицию раскола.
    //    split_at — сколько БАЙТ отправить в первом сегменте.
    let split_at = if cfg.split_tls {
        let pos = if cfg.split_at_sni {
            // Ищем SNI в ClientHello и берём его середину.
            match tls::parse_client_hello(data) {
                Ok(hello) => hello
                    .sni_range()
                    .map(|(s, e)| s + (e - s) / 2)

                    // SNI не нашлось — режем после 1 байта, эффект тот же.
                    .unwrap_or(1),
                Err(_) => 1,
            }
        } else {
            cfg.split_position.unwrap_or(1)
        };
        Some(pos.clamp(1, len.saturating_sub(1).max(1)))
    } else {
        None
    };

    // 3) Микро-сегментация: первые N байт отправляем по одному.
    //    Одиночные байты в отдельных TCP-сегментах ломают сборку заголовка
    //    у простых DPI.
    let micro = if cfg.microsegmentation {
        cfg.microseg_bytes.min(len)
    } else {
        0
    };

    let mut pos = 0usize;

    // 3.1) одиночные байты
    while pos < micro {
        plan.push(Chunk::Data {
            start: pos,
            end: pos + 1,
        });
        pos += 1;
    }

    // 4) Собственно разрыв.
    if let Some(split) = split_at {
        if split > pos {
            plan.push(Chunk::Data { start: pos, end: split });
            pos = split;
        // Остаток отправляем крупным куском — так соединение не «залипает».
        }
    }

    // 5) Обычная фрагментация остатка: случайный размер 1..=5 (настраивается).
    if pos < len {
        if cfg.fragment && pos == 0 {
            // Режем весь буфер на случайные мелкие куски.
            let mut p = pos;
            while p < len {
                let max = cfg.fragment_max.clamp(1, len - p);
                let min = cfg.fragment_min.clamp(1, max);
                let size = rng.gen_range(min..=max);
                plan.push(Chunk::Data {
                    start: p,
                    end: p + size,
                });
                p += size;
            }
            return plan;
        }

        // Остаток после разрыва TLS: отправляем как есть (или фрагментируем
        // первые fragment_max байт, если фрагментация включена).
        if cfg.fragment && split_at.is_some() {
            let max = cfg.fragment_max.clamp(1, len - pos);
            let min = cfg.fragment_min.clamp(1, max);
            let first = rng.gen_range(min..=max);
            plan.push(Chunk::Data {
                start: pos,
                end: pos + first,
            });
            pos += first;
        }
        if pos < len {
            plan.push(Chunk::Data { start: pos, end: len });
        }
    }

    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn cfg(fragment: bool) -> DpiSettings {
        DpiSettings {
            enabled: true,
            fragment,
            fragment_min: 1,
            fragment_max: 5,
            microsegmentation: false,
            microseg_bytes: 0,
            split_tls: false,
            split_at_sni: false,
            split_position: None,
            fake_sni: false,
            fake_sni_host: String::new(),
            junk_prefix: false,
        }
    }

    #[test]
    fn no_bypass_single_chunk() {
        let c = DpiSettings {
            enabled: false,
            ..cfg(false)
        };
        let mut rng = StdRng::seed_from_u64(1);
        let plan = plan_stream(b"hello", &c, &mut rng);
        assert_eq!(plan, vec![Chunk::Data { start: 0, end: 5 }]);
    }

    #[test]
    fn fragmentation_covers_whole_buffer() {
        let mut rng = StdRng::seed_from_u64(7);
        let data = [0u8; 100];
        let plan = plan_stream(&data, &cfg(true), &mut rng);

        // Проверяем, что куски покрывают весь буфер без пропусков и наложений.
        let mut pos = 0;
        for chunk in &plan {
            if let Chunk::Data { start, end } = chunk {
                assert_eq!(*start, pos);
                assert!(end > start);
                pos = *end;
            }
        }
        assert_eq!(pos, 100);
    }

    #[test]
    fn microsegmentation_single_bytes() {
        let mut c = cfg(false);
        c.microsegmentation = true;
        c.microseg_bytes = 3;
        let mut rng = StdRng::seed_from_u64(3);
        let plan = plan_stream(b"abcdef", &c, &mut rng);
        assert_eq!(plan[0], Chunk::Data { start: 0, end: 1 });
        assert_eq!(plan[1], Chunk::Data { start: 1, end: 2 });
        assert_eq!(plan[2], Chunk::Data { start: 2, end: 3 });
        assert_eq!(plan[3], Chunk::Data { start: 3, end: 6 });
    }
}

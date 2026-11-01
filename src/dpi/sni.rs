//! Маскировка SNI Host: подмена имени хоста в TLS ClientHello перед отправкой.
//!
//! # Идея
//! DPI читает расширение `server_name` из ClientHello и блокирует соединение,
//! если хост в чёрном списке. Если подменить имя на «белое» той же длины,
//! DPI пропустит соединение. Проблема: настоящий сервер получит не своё имя
//! и вернёт другое (или ошибку TLS). Поэтому:
//!
//!  * маскировка работает **вместе с разрывом TLS**: первая секция уходит с
//!    фейковым SNI (её видит DPI), вторая — с настоящими байтами;
//!  * серверного эффекта нет, но DPI уже принял решение «пропустить».
//!
//! # Ограничение
//! ClientHello нельзя менять по длине (иначе сервер отклонит handshake),
//! поэтому фейковое имя обязано совпадать по длине с настоящим. GUI
//! подсказывает пользователю это правило и показывает реальную длину SNI.
use crate::dpi::tls;

/// Результат подготовки маскированного ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskResult {
    /// Реально применённая подмена: (было, стало).
    pub applied: Option<(String, String)>,
    /// Предупреждение для лога (если подменить не удалось).
    pub warning: Option<String>,
}

/// Подменить SNI в буфере «на месте».
///
/// * `data` — начало потока (содержит ClientHello);
/// * `fake_host` — желаемое имя.
///
/// Буфер может быть длиннее, чем ClientHello: замена затрагивает только
/// диапазон имени.
pub fn mask_sni(data: &mut [u8], fake_host: &str) -> MaskResult {
    // 1) Быстрая проверка: это вообще TLS?
    if !tls::looks_like_client_hello(data) {
        return MaskResult {
            applied: None,
            warning: None,
        };
    }

    // 2) Разбираем ClientHello, чтобы узнать настоящее имя.
    let hello = match tls::parse_client_hello(data) {
        Ok(h) => h,
        Err(e) => {
            return MaskResult {
                applied: None,
                warning: Some(format!("SNI не найден: {e}")),
            }
        }
    };

    let original = match hello.sni(data) {
        Some(s) => s.to_string(),
        None => {
            return MaskResult {
                applied: None,
                warning: Some("в ClientHello нет SNI — маскировать нечего".to_string()),
            }
        }
    };

    // 3) Длины должны совпадать.
    if original.len() != fake_host.len() {
        // Пробуем «подогнать» имя: обрезаем или дополняем.
        let fitted = fit_host(fake_host, original.len());
        if fitted.len() != original.len() {
            return MaskResult {
                applied: None,
                warning: Some(format!(
                    "фейковый SNI «{fake_host}» ({} байт) не совпадает по длине с «{original}» ({} байт); \
                     подмена пропущена",
                    fake_host.len(),
                    original.len()
                )),
            };
        }

        // Подменяем подогнанным.
        return match tls::replace_sni(data, &fitted) {
            Ok(_) => {
                if !tls::fix_sni_lengths(data, &fitted) {
                    return MaskResult {
                        applied: None,
                        warning: Some(
                            "не удалось пересчитать длины ClientHello после подгонки SNI"
                                .to_string(),
                        ),
                    };
                }
                MaskResult {
                    applied: Some((original, fitted)),
                    warning: Some(
                        "фейковый SNI подогнан по длине — проверьте, что домен существует"
                            .to_string(),
                    ),
                }
            }
            Err(e) => MaskResult {
                applied: None,
                warning: Some(format!("подмена SNI не удалась: {e}")),
            },
        };
    }

    // 4) Прямая подмена.
    match tls::replace_sni(data, fake_host) {
        Ok(_) => MaskResult {
            applied: Some((original, fake_host.to_string())),
            warning: None,
        },
        Err(e) => MaskResult {
            applied: None,
            warning: Some(format!("подмена SNI не удалась: {e}")),
        },
    }
}

/// Привести `host` к длине `len`, сохранив валидность домена.
///
/// * если имя длиннее — обрезаем по границе метки, добавляя `.co`/`.cm` при
///   необходимости (просто обрезать «example.com» до «example.co» можно,
///   а вот до «example.c» — уже нет);
/// * если короче — добавляем метки `.aa`, `.ab`, ... пока не наберём длину.
fn fit_host(host: &str, len: usize) -> String {
    if len == 0 {
        return String::new();
    }
    let host = host.trim_matches('.');
    if host.len() == len {
        return host.to_string();
    }

    if host.len() > len {
        // `len` может попасть внутрь UTF-8 символа — отступаем к границе,
        // иначе срез запаникует.
        let mut end = len.min(host.len());
        while end > 0 && !host.is_char_boundary(end) {
            end -= 1;
        }
        let mut cut = &host[..end];
        if let Some(dot) = cut.rfind('.') {
            let tld = &cut[dot + 1..];
            if tld.len() < 2 {
                cut = &host[..dot];
            }
        }
        let mut s = cut.trim_end_matches('.').to_string();
        while s.len() > len {
            s.pop();
        }
        return s;
    }

    // Короче: добавляем метки по 2-3 символа.
    let mut s = host.to_string();
    let mut label = 0u32;
    while s.len() < len {
        let need = len - s.len();
        if need == 1 {
            // Один символ — просто буква.
            s.push('a');
            break;
        }
        let tag = format!(".{}", base26(label));
        if s.len() + tag.len() > len {
            // Не влезает целиком — добиваем буквами.
            while s.len() < len {
                s.push('a');
            }
            break;
        }
        s.push_str(&tag);
        label += 1;
    }
    s
}

/// 0 -> "aa", 1 -> "ab", 26 -> "ba" ... (2 символа, только a-z).
fn base26(mut n: u32) -> String {
    let mut out = String::new();
    for _ in 0..2 {
        out.push((b'a' + (n % 26) as u8) as char);
        n /= 26;
    }
    out.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_same_length() {
        assert_eq!(fit_host("example.org", 11), "example.org");
    }

    #[test]
    fn fit_shorter_is_padded() {
        let fitted = fit_host("a.ru", 11);
        assert_eq!(fitted.len(), 11);
        assert!(fitted.starts_with("a.ru"));
    }

    #[test]
    fn fit_longer_is_truncated() {
        let fitted = fit_host("verylongdomainname.example.com", 11);
        assert_eq!(fitted.len(), 11);
        assert!(fitted.starts_with("verylongdom"));
    }

    #[test]
    fn mask_without_tls_does_nothing() {
        let mut buf = b"GET / HTTP/1.1\r\n".to_vec();
        let r = mask_sni(&mut buf, "example.org");
        assert!(r.applied.is_none());
        assert!(r.warning.is_none());
    }
}

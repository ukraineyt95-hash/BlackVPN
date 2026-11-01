//! Декодер и простейший энкодер HPACK (RFC 7541) — порт класса `H2MuxHPACK`
//! из Python-прокси.
//!
//! Зачем это нужно: H2Mux — это «HTTP/2-подобный» мультиплексор, который
//! клиент поднимает поверх обычного HTTP/1.1 Upgrade. Заголовки в нём
//! передаются в формате HPACK-блока: индексы статической/динамической
//! таблицы, литералы и Huffman-сжатие. Без декодера мы не поймём, на какой
//! хост клиент просит туннель (`:authority`).
//!
//! Реализация сознательно «строгая»: любое отклонение от RFC считается
//! ошибкой соединения. Это защищает от попыток спрятать в HPACK-блок
//! что-то постороннее.
use super::hpack_tables::{HUFFMAN_CODES, HUFFMAN_LENGTHS, STATIC_TABLE};

/// Ошибка разбора HPACK-блока.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpackError {
    /// Данные оборвались.
    Truncated(&'static str),
    /// Целое число закодировано некорректно.
    InvalidInteger,
    /// Индекс вне диапазона таблиц.
    InvalidIndex,
    /// Некорректный Huffman-код.
    InvalidHuffman,
    /// Слишком большая таблица (> 4096 байт).
    TableTooLarge,
    /// Обновление таблицы пришло после первой пары заголовков.
    LateTableUpdate,
    /// Заголовок пустой или в верхнем регистре (RFC 7541 §8.1.2).
    InvalidHeader,
    /// Блок заголовков слишком большой.
    BlockTooLarge,
}

impl std::fmt::Display for HpackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HpackError::Truncated(what) => write!(f, "HPACK: обрезанные данные ({what})"),
            HpackError::InvalidInteger => write!(f, "HPACK: некорректное целое"),
            HpackError::InvalidIndex => write!(f, "HPACK: некорректный индекс"),
            HpackError::InvalidHuffman => write!(f, "HPACK: некорректный Huffman-код"),
            HpackError::TableTooLarge => write!(f, "HPACK: таблица больше 4096 байт"),
            HpackError::LateTableUpdate => write!(f, "HPACK: обновление таблицы не в начале блока"),
            HpackError::InvalidHeader => write!(f, "HPACK: некорректный заголовок"),
            HpackError::BlockTooLarge => write!(f, "HPACK: блок заголовков слишком велик"),
        }
    }
}

impl std::error::Error for HpackError {}

/// Максимальный размер динамической таблицы (по умолчанию в HPACK).
const MAX_TABLE_SIZE: usize = 4096;

/// Максимальный суммарный размер разобранных заголовков.
const MAX_HEADER_BYTES: usize = 65536;

/// Декодер с динамической таблицей.
pub struct HpackDecoder {
    dynamic: Vec<(Vec<u8>, Vec<u8>)>,
    table_size: usize,
    used: usize,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackDecoder {
    pub fn new() -> Self {
        Self {
            dynamic: Vec::new(),
            table_size: MAX_TABLE_SIZE,
            used: 0,
        }
    }

    /// Вытеснение старых записей при переполнении таблицы.
    fn evict(&mut self) {
        while self.used > self.table_size {
            if let Some((name, value)) = self.dynamic.pop() {
                self.used -= name.len() + value.len() + 32;
            } else {
                break;
            }
        }
    }

    /// Взять запись по индексу (1-based, сначала статическая таблица).
    fn entry(&self, index: usize) -> Result<(Vec<u8>, Vec<u8>), HpackError> {
        if index == 0 || index > STATIC_TABLE.len() + self.dynamic.len() {
            return Err(HpackError::InvalidIndex);
        }
        if index <= STATIC_TABLE.len() {
            let (n, v) = STATIC_TABLE[index - 1];
            Ok((n.to_vec(), v.to_vec()))
        } else {
            Ok(self.dynamic[index - STATIC_TABLE.len() - 1].clone())
        }
    }

    /// Разобрать блок заголовков.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<(String, String)>, HpackError> {
        let mut result = Vec::new();
        let mut offset = 0usize;
        let mut total = 0usize;

        while offset < data.len() {
            let byte = data[offset];

            let (name, value);

            if byte & 0x80 != 0 {
                // --- 1xxxxxxx: индекс в таблице ------------------------------
                let (index, next) = decode_integer(data, offset, 7)?;
                offset = next;
                let (n, v) = self.entry(index)?;
                name = n;
                value = v;
            } else if byte & 0x20 != 0 && byte & 0x40 == 0 {
                // --- 001xxxxx: изменение размера таблицы --------------------
                if !result.is_empty() {
                    return Err(HpackError::LateTableUpdate);
                }
                let (size, next) = decode_integer(data, offset, 5)?;
                offset = next;
                if size > MAX_TABLE_SIZE {
                    return Err(HpackError::TableTooLarge);
                }
                self.table_size = size;
                self.evict();
                continue;
            } else {
                // --- 01xxxxxx (с индексацией) / 0000xxxx (без индексации) ---
                let indexed = byte & 0x40 != 0;
                let (index, next) = decode_integer(data, offset, if indexed { 6 } else { 4 })?;
                offset = next;

                let n: Vec<u8> = if index != 0 {
                    self.entry(index)?.0
                } else {
                    let (s, next) = decode_string(data, offset)?;
                    offset = next;
                    s
                };
                let (v, next) = decode_string(data, offset)?;
                offset = next;
                name = n;
                value = v;

                if indexed {
                    // В динамическую таблицу кладём копию: `name`/`value`
                    // дальше уходят в результат. Размер записи по RFC 7541
                    // §4.1 — длина имени + длина значения + 32.
                    self.dynamic.insert(0, (name.clone(), value.clone()));
                    self.used += name.len() + value.len() + 32;
                    self.evict();
                }
            }

            // RFC 7541 §8.1.2: имена заголовков — только строчные ASCII.
            total += name.len() + value.len() + 32;
            if total > MAX_HEADER_BYTES
                || name.is_empty()
                || !name.iter().all(|b| b.is_ascii() && !b.is_ascii_uppercase())
            {
                return Err(HpackError::InvalidHeader);
            }

            let name = String::from_utf8(name).map_err(|_| HpackError::InvalidHeader)?;
            let value = String::from_utf8(value).map_err(|_| HpackError::InvalidHeader)?;
            result.push((name, value));
        }

        Ok(result)
    }

    /// Закодировать заголовки без индексации (литералы с нулевым индексом,
    /// без Huffman): `0x00, длина имени, имя, длина значения, значение` —
    /// ровно та же схема, что в эталонном Python-прокси.
    ///
    /// Индексация не используется, поэтому динамическая таблица клиента не
    /// меняется; этого достаточно для ответов — клиент (ByeByeDPI) разбирает
    /// их штатным HPACK-декодером.
    pub fn encode(headers: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, value) in headers {
            out.push(0x00);
            encode_integer(&mut out, name.len(), 7);
            out.extend_from_slice(name.as_bytes());
            encode_integer(&mut out, value.len(), 7);
            out.extend_from_slice(value.as_bytes());
        }
        out
    }
}

/// Декодировать целое HPACK (RFC 7541 §5.1) с префиксом `bits`.
fn decode_integer(data: &[u8], offset: usize, bits: u8) -> Result<(usize, usize), HpackError> {
    if offset >= data.len() {
        return Err(HpackError::Truncated("integer"));
    }
    let mask = ((1u16 << bits) - 1) as u8;
    let mut value = (data[offset] & mask) as usize;
    let mut offset = offset + 1;
    if value == mask as usize {
        let mut shift = 0usize;
        loop {
            if offset >= data.len() || shift > 28 {
                return Err(HpackError::InvalidInteger);
            }
            let byte = data[offset];
            offset += 1;
            value += ((byte & 0x7f) as usize) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
    }
    Ok((value, offset))
}

/// Кодировать целое HPACK.
fn encode_integer(out: &mut Vec<u8>, mut value: usize, bits: u8) {
    let mask = (1u16 << bits) - 1;
    if value < mask as usize {
        out.push(value as u8);
        return;
    }
    out.push(mask as u8);
    value -= mask as usize;
    while value >= 128 {
        out.push(((value & 0x7f) | 0x80) as u8);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Декодировать строку (с Huffman или без) и вернуть (байты, новый offset).
fn decode_string(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize), HpackError> {
    if offset >= data.len() {
        return Err(HpackError::Truncated("string"));
    }
    let huffman = data[offset] & 0x80 != 0;
    let (size, next) = decode_integer(data, offset, 7)?;
    let end = next + size;
    if end > data.len() {
        return Err(HpackError::Truncated("string body"));
    }
    let raw = &data[next..end];
    let value = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    Ok((value, end))
}

/// Распаковать Huffman-строку.
///
/// Реализовано каноническим способом: для каждого символа алфавита строится
/// (длина, код), а декодирование идёт побитово с накоплением кода и проверкой
/// по таблице `(длина, код) -> символ`. Таблица сортируется по коду, поиск —
/// бинарный, поэтому скорость достаточная (это не горячий путь).
fn huffman_decode(raw: &[u8]) -> Result<Vec<u8>, HpackError> {
    // Строим таблицу один раз на процесс.
    static TABLE: std::sync::OnceLock<Vec<(u8, u32, u16)>>> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t: Vec<(u8, u32, u16)> = (0..257u16)
            .map(|sym| {
                (
                    HUFFMAN_LENGTHS[sym as usize],
                    HUFFMAN_CODES[sym as usize],
                    sym,
                )
            })
            .collect();

        // Сортировка по (длина, код) позволяет искать бинарным поиском.
        t.sort_unstable_by_key(|&(len, code, _)| (len, code));
        t
    });

    let mut out = Vec::with_capacity(raw.len());
    let mut code: u32 = 0;
    let mut len: u8 = 0;

    for &byte in raw {
        for shift in (0..8).rev() {
            let bit = (byte >> shift) & 1;
            code = (code << 1) | bit as u32;
            len += 1;
            if len > 30 {
                return Err(HpackError::InvalidHuffman);
            }

            // Ищем (len, code) в таблице.
            if let Ok(pos) = table.binary_search_by_key(&(len, code), |&(l, c, _)| (l, c)) {
                let sym = table[pos].2;
                if sym == 256 {
                    // EOS-символ запрещён внутри строки.
                    return Err(HpackError::InvalidHuffman);
                }
                out.push(sym as u8);
                code = 0;
                len = 0;
            }
        }
    }

    // Хвост должен быть префиксом EOS, т.е. все единицы, не длиннее 7 бит.
    if len > 7 || code != ((1u32 << len) - 1) {
        return Err(HpackError::InvalidHuffman);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7541, C.3.1: запрос без Huffman.
    #[test]
    fn decodes_rfc_example_without_huffman() {
        let block = [
            0x82, 0x86, 0x84, // :method GET, :scheme http, :path /
            0x41, 0x0f, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
            b'c', b'o', b'm',
        ];
        let mut dec = HpackDecoder::new();
        let out = dec.decode(&block).unwrap();
        assert_eq!(
            out,
            vec![
                (":method".to_string(), "GET".to_string()),
                (":scheme".to_string(), "http".to_string()),
                (":path".to_string(), "/".to_string()),
                (":authority".to_string(), "www.example.com".to_string()),
            ]
        );
    }

    /// RFC 7541, C.4.1: то же самое, но значение сжато Huffman-кодом.
    #[test]
    fn decodes_rfc_example_with_huffman() {
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let mut dec = HpackDecoder::new();
        let out = dec.decode(&block).unwrap();
        assert_eq!(out[3].0, ":authority");
        assert_eq!(out[3].1, "www.example.com");
    }

    /// Своя кодировка должна читаться собственным декодером.
    #[test]
    fn encode_decode_roundtrip() {
        let headers = [(":status", "200"), ("content-length", "0")];
        let block = HpackDecoder::encode(&headers);
        let mut dec = HpackDecoder::new();
        let out = dec.decode(&block).unwrap();
        assert_eq!(
            out,
            vec![
                (":status".to_string(), "200".to_string()),
                ("content-length".to_string(), "0".to_string()),
            ]
        );
    }

    /// Байт 0x00 как Huffman-данные — это 8 единичных бит, которые не
    /// складываются в корректный код: блок должен быть отвергнут, а не
    /// превратиться в мусорный заголовок. Проверяем именно декодер строк.
    #[test]
    fn rejects_broken_huffman_padding() {
        // Восемь нулевых бит — это недопустимый паддинг (он должен быть из
        // единиц и не длиннее 7 бит).
        assert!(huffman_decode(&[0x00]).is_err());
        assert!(huffman_decode(&[0xff]).is_err());
        // Корректная строка: 'a' (5 бит, 0b00011) + паддинг из трёх единиц.
        assert_eq!(huffman_decode(&[0b0001_1111]).ok().as_deref(), Some(&b"a"[..]));
    }
}

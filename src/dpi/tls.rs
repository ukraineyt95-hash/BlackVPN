/// Разобранный ClientHello: только интересующие нас смещения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Смещение начала записи TLS (0 для обычного случая).
    pub record_offset: usize,
    /// Полная длина TLS-записи (5 + payload).
    pub record_len: usize,
    /// Смещение начала SNI-имени в буфере.
    pub sni_start: usize,
    /// Смещение конца SNI-имени (не включая).
    pub sni_end: usize,
    /// Длина записи сервера, если она есть (для справки).
    pub version: u16,
}

impl ClientHello {
    /// Диапазон байт имени хоста.
    pub fn sni_range(&self) -> Option<(usize, usize)> {
        if self.sni_end > self.sni_start {
            Some((self.sni_start, self.sni_end))
        } else {
            None
        }
    }

    /// Имя хоста как строка.
    pub fn sni(&self, buf: &[u8]) -> Option<&str> {
        let (s, e) = self.sni_range()?;
        std::str::from_utf8(buf.get(s..e)?).ok()
    }
}

/// Ошибка разбора.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsError(pub &'static str);

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TLS: {}", self.0)
    }
}

impl std::error::Error for TlsError {}

fn need(buf: &[u8], end: usize) -> Result<(), TlsError> {
    if end <= buf.len() {
        Ok(())
    } else {
        Err(TlsError("буфер обрезан"))
    }
}

/// Разобрать первый TLS ClientHello в буфере.
///
/// Формат (RFC 8446 / 5246):
/// ```text
/// record: type=0x16 version(2) length(2) payload
///   handshake: type=0x01 length(3) body
///     body: version(2) random(32) session_id(1+n)
///           cipher_suites(2+n) compression(1+n) extensions(2+n)
///       extension server_name(0x0000): list(2+n) entry: type(1) name_len(2) name
/// ```
pub fn parse_client_hello(buf: &[u8]) -> Result<ClientHello, TlsError> {
    // --- TLS record ------------------------------------------------------- //
    need(buf, 5)?;
    if buf[0] != 0x16 {
        return Err(TlsError("это не handshake-запись"));
    }
    let version = u16::from_be_bytes([buf[1], buf[2]]);
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;

    need(buf, 5 + record_len)?;

    // --- handshake -------------------------------------------------------- //
    let hs = 5;
    need(buf, hs + 4)?;
    if buf[hs] != 0x01 {
        return Err(TlsError("это не ClientHello"));
    }
    let hs_len =
        ((buf[hs + 1] as usize) << 16) | ((buf[hs + 2] as usize) << 8) | buf[hs + 3] as usize;
    let hs_end = hs + 4 + hs_len;

    // Клиент может прислать не весь ClientHello сразу — тогда просто
    // не находим SNI (вызывающая сторона обработает это как «нет SNI»).
    let end = hs_end.min(buf.len());

    let mut p = hs + 4;

    // version(2) + random(32)
    p += 2 + 32;
    if p >= end {
        return Err(TlsError("обрезано до session_id"));
    }

    // session_id
    let sid_len = buf[p] as usize;
    p += 1 + sid_len;
    if p + 2 > end {
        return Err(TlsError("обрезано до cipher_suites"));
    }

    // cipher_suites
    let cs_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2 + cs_len;
    if p >= end {
        return Err(TlsError("обрезано до compression"));
    }

    // compression_methods
    let comp_len = buf[p] as usize;
    p += 1 + comp_len;
    if p + 2 > end {
        // Расширений нет — SNI отсутствует. Не ошибка: SNI бывает не всегда.
        return Err(TlsError("нет расширений (SNI отсутствует)"));
    }

    // extensions
    let ext_total = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(end);

    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ext_len = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        let body = p + 4;
        if body + ext_len > ext_end {
            break;
        }
        if ext_type == 0x0000 {
            // server_name: list_len(2) type(1) name_len(2) name
            if ext_len < 5 {
                return Err(TlsError("короткое расширение server_name"));
            }
            let name_len = u16::from_be_bytes([buf[body + 3], buf[body + 4]]) as usize;
            let start = body + 5;
            let stop = start + name_len;
            if stop > buf.len() {
                return Err(TlsError("SNI выходит за границы буфера"));
            }
            return Ok(ClientHello {
                record_offset: 0,
                record_len: 5 + record_len,
                sni_start: start,
                sni_end: stop,
                version,
            });
        }
        p = body + ext_len;
    }

    Err(TlsError("расширение server_name не найдено"))
}

/// Подменить SNI на `new_host` **той же длины**.
///
/// Возвращает `Err`, если длины не совпадают (иначе сервер отвергнет
/// ClientHello из-за несоответствия длин) или если SNI не найдено.
pub fn replace_sni(buf: &mut [u8], new_host: &str) -> Result<(usize, usize), TlsError> {
    let hello = parse_client_hello(buf)?;
    let (start, end) = hello
        .sni_range()
        .ok_or(TlsError("в ClientHello нет SNI"))?;
    let new_bytes = new_host.as_bytes();
    if new_bytes.len() != end - start {
        return Err(TlsError(
            "длина фейкового SNI не совпадает с исходной (ClientHello нельзя менять по длине)",
        ));
    }
    buf[start..end].copy_from_slice(new_bytes);
    Ok((start, end))
}

pub fn fix_sni_lengths(buf: &mut [u8], new_host: &str) -> bool {
    let new_len = new_host.len();
    let Ok(hello) = parse_client_hello(buf) else {
        return false;
    };
    let old_len = hello.sni_end.saturating_sub(hello.sni_start);
    if old_len == 0 {
        return false;
    }
    if new_len == old_len {
        return true;
    }
    let delta = new_len as isize - old_len as isize;

    let sni = hello.sni_start;
    if sni < 9 || new_len > 255 {
        return false;
    }

    let name_len_pos = sni - 2;
    let list_len_pos = sni - 5;
    let ext_len_pos = sni - 7;

    // Поле длины имени — big-endian u16: старший байт первый, младший второй.
    // Раньше здесь писалось наоборот, и ClientHello становился невалидным.
    buf[name_len_pos] = 0;
    buf[name_len_pos + 1] = new_len as u8;

    let Some(ext_total_pos) = find_ext_total_pos(buf) else {
        return false;
    };

    // Порядок важен: сначала читаем старые значения, потом пишем.
    let mut ok = write_u16_checked(buf, list_len_pos, delta);
    ok &= write_u16_checked(buf, ext_len_pos, delta);
    ok &= write_u16_checked(buf, ext_total_pos, delta);
    ok &= write_u24_checked(buf, 6, delta);
    ok &= write_u16_checked(buf, 3, delta);
    ok
}

fn write_u16_checked(buf: &mut [u8], pos: usize, delta: isize) -> bool {
    let Some(bytes) = buf.get(pos..pos + 2) else {
        return false;
    };
    let value = u16::from_be_bytes([bytes[0], bytes[1]]) as isize + delta;
    if !(0..=u16::MAX as isize).contains(&value) {
        return false;
    }
    let value = value as u16;
    buf[pos] = (value >> 8) as u8;
    buf[pos + 1] = (value & 0xff) as u8;
    true
}

fn write_u24_checked(buf: &mut [u8], pos: usize, delta: isize) -> bool {
    let Some(bytes) = buf.get(pos..pos + 3) else {
        return false;
    };
    let old =
        ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize;
    let value = old as isize + delta;
    if !(0..=0x00ff_ffff).contains(&value) {
        return false;
    }
    let value = value as usize;
    buf[pos] = (value >> 16) as u8;
    buf[pos + 1] = (value >> 8) as u8;
    buf[pos + 2] = value as u8;
    true
}

fn find_ext_total_pos(buf: &[u8]) -> Option<usize> {
    let end = buf.len();
    let mut p = 5 + 4;
    if p + 2 + 32 > end {
        return None;
    }
    p += 2 + 32;
    if p >= end {
        return None;
    }
    let sid = buf[p] as usize;
    p += 1 + sid;
    if p + 2 > end {
        return None;
    }
    let cs = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2 + cs;
    if p >= end {
        return None;
    }
    let comp = buf[p] as usize;
    p += 1 + comp;
    if p + 2 > end {
        return None;
    }
    Some(p)
}

/// Быстрая проверка «похоже на TLS ClientHello».
pub fn looks_like_client_hello(buf: &[u8]) -> bool {
    buf.len() > 6 && buf[0] == 0x16 && buf[5] == 0x01
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собрать минимальный ClientHello с SNI — для тестов.
    fn build_client_hello(host: &str) -> Vec<u8> {
        let mut sni = Vec::new();

        // server_name_list: len(2) type(1)=0 name_len(2) name
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());

        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01);
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn parses_sni() {
        let buf = build_client_hello("example.com");
        let hello = parse_client_hello(&buf).unwrap();
        assert_eq!(hello.sni(&buf), Some("example.com"));
        let (s, e) = hello.sni_range().unwrap();
        assert_eq!(&buf[s..e], b"example.com");
    }

    #[test]
    fn replaces_sni_of_same_length() {
        let mut buf = build_client_hello("example.com");
        replace_sni(&mut buf, "example.org").unwrap();
        let hello = parse_client_hello(&buf).unwrap();
        assert_eq!(hello.sni(&buf), Some("example.org"));
    }

    #[test]
    fn refuses_different_length() {
        let mut buf = build_client_hello("example.com");
        assert!(replace_sni(&mut buf, "google.com").is_err());
    }

    /// Проверяем именно тот случай, для которого существует
    /// `fix_sni_lengths`: длина имени МЕНЯЕТСЯ, и все четыре поля длины
    /// должны быть пересчитаны, иначе ClientHello станет невалидным.
    #[test]
    fn fixes_lengths_when_name_shrinks() {
        let mut buf = build_client_hello("example.com");
        let before = buf.len();
        let new_host = "example.ru";

        // Подменяем имя и убираем разницу в длине.
        let hello = parse_client_hello(&buf).unwrap();
        let (start, end) = hello.sni_range().unwrap();
        assert_eq!(end - start, 11);
        buf.splice(start..end, new_host.bytes());
        let _ = before;

        assert!(fix_sni_lengths(&mut buf, new_host));

        let hello = parse_client_hello(&buf).unwrap();
        assert_eq!(hello.sni(&buf), Some("example.ru"));
        assert_eq!(hello.sni_end - hello.sni_start, new_host.len());
        // record_len обязан описывать новый размер записи.
        assert_eq!(hello.record_len, buf.len());
    }

    #[test]
    fn detects_non_tls() {
        assert!(!looks_like_client_hello(b"GET / HTTP/1.1\r\n"));
    }
}

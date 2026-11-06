//! Устройство `smoltcp::phy::Device` поверх файлового дескриптора
//! Android TUN-интерфейса.
//!
//! # Что здесь происходит
//! `VpnService.Builder.establish()` (см. `platform::android`) вернул нам
//! `ParcelFileDescriptor`, из которого мы вытащили целочисленный `fd`.
//! Этот `fd` — поток IP-пакетов:
//!
//! ```text
//!   приложения ОС --> ядро --> TUN --> read(fd)  --> smoltcp
//!   smoltcp --> write(fd) --> TUN --> ядро --> приложения
//! ```
//!
//! То есть каждый `read()` возвращает **один целый IP-пакет** (от IPv4
//! заголовка до конца полезной нагрузки), а каждый `write()` вставляет пакет
//! в интерфейс так, как будто он пришёл из сети.
//!
//! Транспортный слой получает пакет целиком и отдаёт его smoltcp; обратно
//! сформированные стеком пакеты уходят через `TxToken`.
//!
//! # Зачем «подглядывание» за портами
//! Мы не знаем заранее, на какие порты будут ходить приложения. smoltcp
//! требует отдельный слушающий сокет на каждый порт. Поэтому устройство
//! смотрит на заголовки входящих пакетов и **сообщает** стеку, какие порты
//! нужно открыть (см. [`TunDevice::take_new_ports`]). Пакет при этом не
//! теряется: он остаётся в очереди до следующего опроса.
use std::collections::{HashSet, VecDeque};
use std::io;
use std::os::unix::io::RawFd;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use crate::tunnel::TunFd;

/// Максимальный размер пакета, который мы читаем из TUN.
const MAX_PACKET: usize = 65536;

/// Сколько пакетов читаем за один `receive()` (батчинг ради пропускной
/// способности: один системный вызов на пачку пакетов).
const RX_BATCH: usize = 32;

/// Транспортный протокол пакета (интересует только TCP/UDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Устройство поверх TUN-fd.
pub struct TunDevice {
    /// fd для чтения пакетов от приложений.
    read_fd: RawFd,
    /// fd для записи пакетов приложениям.
    write_fd: RawFd,
    /// MTU интерфейса.
    mtu: usize,
    /// Уже прочитанные, но ещё не отданные стеку пакеты.
    pending: VecDeque<Vec<u8>>,
    /// Порты, для которых у стека уже есть слушающий сокет.
    known_ports: HashSet<(Proto, u16)>,
    /// Порты, которые нужно открыть (заполняется в `receive`).
    new_ports: Vec<(Proto, u16)>,
    /// Счётчики чтения (для статистики в GUI).
    pub rx_packets: u64,
    pub rx_bytes: u64,
    /// Общая статистика записи (разделяется с TxToken).
    tx_stats: std::rc::Rc<std::cell::RefCell<TxStats>>,
    /// Ошибки чтения/записи (EBADF и т.п.).
    pub last_error: Option<io::ErrorKind>,
}

impl TunDevice {
    /// Создать устройство вокруг пары fd.
    pub fn new(fd: &TunFd) -> Self {
        Self {
            read_fd: fd.read_fd,
            write_fd: fd.write_fd,
            mtu: fd.mtu,
            pending: VecDeque::new(),
            known_ports: HashSet::new(),
            new_ports: Vec::new(),
            rx_packets: 0,
            rx_bytes: 0,
            tx_stats: std::rc::Rc::new(std::cell::RefCell::new(TxStats::default())),
            last_error: None,
        }
    }

    /// Сообщить устройству, что порт уже обслуживается стеком
    /// (чтобы оно не просило открыть его повторно).
    pub fn mark_port_known(&mut self, proto: Proto, port: u16) {
        self.known_ports.insert((proto, port));
    }

    /// Забрать список портов, которые нужно открыть.
    pub fn take_new_ports(&mut self) -> Vec<(Proto, u16)> {
        std::mem::take(&mut self.new_ports)
    }

    /// Забыть порт: следующий SYN (или UDP-датаграмма) на него снова создаст
    /// сокет-слушатель. Иначе порт навсегда остался бы «известным», а сокет
    /// уже удалён из SocketSet — соединения на него просто отбрасывались бы.
    pub fn forget_port(&mut self, proto: Proto, port: u16) {
        self.known_ports.remove(&(proto, port));
        self.new_ports.retain(|(p, item)| !(*p == proto && *item == port));
    }

    /// Дочитать пакеты из TUN в очередь (неблокирующе).
    fn fill_pending(&mut self) {
        if self.pending.len() >= RX_BATCH * 4 {
            return;
        }
        for _ in 0..RX_BATCH {
            let mut buf = vec![0u8; MAX_PACKET];

            // SAFETY: buf валиден, длина передана корректно. read() на
            // неблокирующем fd вернёт -1/EAGAIN, когда пакетов нет.
            let n = unsafe {
                libc::read(
                    self.read_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::WouldBlock {
                        self.last_error = Some(err.kind());
                    }
                }
                break;
            }
            buf.truncate(n as usize);
            self.rx_packets += 1;
            self.rx_bytes += n as u64;
            self.pending.push_back(buf);
        }
    }

    /// Итоговая статистика записи: (пакетов, байт) — для диагностики в логе.
    #[allow(dead_code)]
    pub fn tx_totals(&self) -> (u64, u64) {
        let s = self.tx_stats.borrow();
        (s.packets, s.bytes)
    }
}

/// Извлечь (proto, dst_port) из IP-пакета.
///
/// Поддерживаются IPv4 и IPv6; для остального возвращается `None`.
fn packet_destination(packet: &[u8]) -> Option<(Proto, u16)> {
    let version = packet.first()? >> 4;

    // Смещение до транспортного заголовка.
    let l4 = match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if ihl < 20 {
                return None;
            }
            (ihl, packet[9])
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            (40, packet[6])
        }
        _ => return None,
    };
    let (offset, next_header) = l4;
    if packet.len() < offset + 4 {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);

    match next_header {
        // TCP: слушающий сокет нужен только под SYN.
        6 => Some((Proto::Tcp, dst_port)),
        // UDP: игнорируем пакеты «от сервера» (src_port == 0 маловероятен,
        // но защищаемся от петель).
        17 if src_port != 0 => Some((Proto::Udp, dst_port)),
        _ => None,
    }
}

/// Проверить, является ли TCP-пакет SYN'ом (нужно, чтобы не открывать
/// слушающий сокет на промежуточные ACK для неизвестных соединений).
fn is_tcp_syn(packet: &[u8]) -> bool {
    // `?` здесь нельзя: функция возвращает `bool`, а не `Option`.
    let Some(first) = packet.first() else {
        return false;
    };
    let offset = match first >> 4 {
        4 => {
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if packet.len() < ihl + 14 {
                return false;
            }
            ihl
        }
        6 => {
            if packet.len() < 40 + 14 {
                return false;
            }
            40
        }
        _ => return false,
    };

    // flags находятся по смещению 13 в TCP-заголовке.
    let flags = packet[offset + 13];
    flags & 0x02 != 0 && flags & 0x10 == 0
}

/// RxToken: отдаёт один пакет стеку.
pub struct TunRxToken {
    packet: Vec<u8>,
}

impl RxToken for TunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

/// TxToken: собирает пакет, сформированный smoltcp, и сразу пишет его в TUN.
///
/// `TxToken` не может держать ссылку на `TunDevice` (borrow checker: сокет
/// стека уже занял `&mut Interface`, а device передаётся отдельно), поэтому
/// токен несёт только `write_fd` и общий счётчик `Rc<RefCell<TxStats>>`.
/// Этого достаточно: `write()` в TUN — единственное, что нужно при отправке.
pub struct TunTxToken {
    write_fd: RawFd,
    stats: std::rc::Rc<std::cell::RefCell<TxStats>>,
}

#[derive(Default)]
pub struct TxStats {
    pub packets: u64,
    pub bytes: u64,
    pub last_error: Option<io::ErrorKind>,
}

impl TxToken for TunTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);

        // SAFETY: неблокирующий fd; буфер валиден.
        let n = unsafe {
            libc::write(
                self.write_fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            )
        };
        {
            let mut stats = self.stats.borrow_mut();
            if n > 0 {
                stats.packets += 1;
                stats.bytes += n as u64;
            } else if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::WouldBlock {
                    stats.last_error = Some(err.kind());
                }
            }
        }
        result
    }
}

impl Device for TunDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.fill_pending();

        // Ищем пакет, для которого у стека есть слушающий сокет.
        // Пакеты с «неизвестными» портами остаются в очереди до следующего
        // вызова, а порт попадает в `new_ports`.
        loop {
            let packet = self.pending.pop_front()?;

            if let Some((proto, port)) = packet_destination(&packet) {
                let need_listener = match proto {
                    Proto::Tcp => is_tcp_syn(&packet),
                    Proto::Udp => true,
                };
                if need_listener && !self.known_ports.contains(&(proto, port)) {
                    // Просим стек открыть порт и возвращаем пакет в очередь.
                    if !self.new_ports.contains(&(proto, port)) {
                        self.new_ports.push((proto, port));
                    }
                    self.pending.push_front(packet);
                    return None;
                }
            }

            // Пакет можно отдавать стеку.
            return Some((
                TunRxToken { packet },
                TunTxToken {
                    write_fd: self.write_fd,
                    stats: self.tx_stats.clone(),
                },
            ));
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken {
            write_fd: self.write_fd,
            stats: self.tx_stats.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();

        // TUN отдаёт голые IP-пакеты — Medium::Ip (без Ethernet/ARP).
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu.clamp(576, 65535);
        caps.max_burst_size = Some(RX_BATCH);
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собрать минимальный IPv4/TCP пакет.
    fn tcp_packet(dst_port: u16, syn: bool) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 20];
        p[0] = 0x45;
        p[2] = 0;
        p[3] = 40;
        p[9] = 6;
        p[20] = 0x1f;
        p[21] = 0x90;
        p[22] = (dst_port >> 8) as u8;
        p[23] = (dst_port & 0xff) as u8;
        p[33] = if syn { 0x02 } else { 0x10 };
        p
    }

    #[test]
    fn parses_tcp_destination() {
        let p = tcp_packet(443, true);
        assert_eq!(packet_destination(&p), Some((Proto::Tcp, 443)));
        assert!(is_tcp_syn(&p));
    }

    #[test]
    fn non_syn_is_not_syn() {
        let p = tcp_packet(443, false);
        assert!(!is_tcp_syn(&p));
    }

    #[test]
    fn ignores_garbage() {
        assert_eq!(packet_destination(&[0x00; 4]), None);
        assert_eq!(packet_destination(&[]), None);
    }
}

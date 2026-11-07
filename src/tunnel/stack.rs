use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::config::AppConfig;
use crate::dpi::{self, DpiSettings};
use crate::stats;
use crate::tunnel::device::{Proto, TunDevice};
use crate::tunnel::TunFd;

/// Размер буферов TCP-сокета внутри стека.
const TCP_BUFFER: usize = 65536;

/// Размер одного чтения.
const CHUNK: usize = 16384;

/// Максимум одновременных TCP-соединений.
const MAX_CONNECTIONS: usize = 512;

/// Период опроса стека.
const POLL_INTERVAL: Duration = Duration::from_millis(3);

/// Таймаут установки соединения.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Общая шина управления туннелем.
#[derive(Clone)]
pub struct TunnelControl {
    /// Флаг «работаем».
    pub running: Arc<AtomicBool>,
    /// Настройки DPI-обхода.
    pub settings: DpiSettings,
    /// Апстрим-DNS.
    pub upstream_dns: Vec<SocketAddr>,
    /// Использовать TCP для DNS (обход блокировки UDP/53).
    pub dns_over_tcp: bool,
    /// Адрес TUN-интерфейса из настроек (по умолчанию 10.111.222.2).
    pub tun_ip: std::net::Ipv4Addr,
    /// Длина префикса подсети TUN (по умолчанию 24).
    pub tun_prefix: u8,
}

impl TunnelControl {
    pub fn from_config(cfg: &AppConfig) -> Self {
        // Если в настройках указан «наш» DNS (10.111.222.1), его нельзя
        // использовать как апстрим — получится петля. Берём публичные.
        let is_loopback_dns =
            |s: &str| s.starts_with("10.111.222.") || s == "127.0.0.1" || s == "::1";

        let mut upstream = Vec::new();
        for dns in &cfg.dns_servers {
            if is_loopback_dns(dns) {
                continue;
            }
            if let Ok(ip) = dns.parse::<IpAddr>() {
                upstream.push(SocketAddr::new(ip, 53));
            }
        }
        if upstream.is_empty() {
            upstream.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53));
            upstream.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
        }

        Self {
            running: Arc::new(AtomicBool::new(true)),
            settings: DpiSettings::from_config(cfg),
            upstream_dns: upstream,
            dns_over_tcp: cfg.udp_over_tcp_enabled,
            tun_ip: cfg
                .tun_address
                .parse::<std::net::Ipv4Addr>()
                .unwrap_or(std::net::Ipv4Addr::new(10, 111, 222, 2)),
            tun_prefix: cfg.tun_prefix.clamp(1, 32),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

/// Запустить стек на отдельном OS-потоке.
pub fn spawn(fd: TunFd, control: TunnelControl) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("smoltcp-stack".to_string())
        .spawn(move || {
            // Current-thread рантайм: не нужен многопоточный, вся работа
            // последовательна, а `SocketSet` не `Send`.
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    crate::flog_err!("Не удалось создать рантайм стека: {e}");
                    return;
                }
            };
            if let Err(e) = runtime.block_on(run(fd, control)) {
                crate::flog_err!("Стек завершился с ошибкой: {e}");
            }
        })
        .expect("не удалось создать поток стека")
}

/// Одно TCP-соединение.
struct TcpConn {
    handle: SocketHandle,
    port: u16,
    /// Куда подключаемся (из SYN-пакета).
    remote: Option<SocketAddr>,
    /// Реальное соединение (появляется после завершения connect).
    upstream: Option<TcpStream>,
    /// Незавершённое подключение к серверу.
    ///
    /// `TcpStream::connect` — асинхронный, но ждать его прямо в цикле стека
    /// нельзя: пока идёт connect (до 20 секунд), не опрашиваются остальные
    /// соединения и не читается TUN. Поэтому подключение выполняется
    /// отдельной задачей, а цикл лишь проверяет готовность.
    connecting: Option<oneshot::Receiver<io::Result<TcpStream>>>,
    /// Данные приложения, которые ещё не записаны в сеть.
    to_net: Vec<u8>,
    /// Данные из сети, которые ещё не отданы приложению.
    to_app: Vec<u8>,
    /// Применён ли DPI к первому блоку данных.
    dpi_done: bool,
    out_dpi_done: bool,
    out_plan: VecDeque<Vec<u8>>,
    in_plan: VecDeque<Vec<u8>>,
}

impl TcpConn {
    fn new(handle: SocketHandle, port: u16) -> Self {
        Self {
            handle,
            port,
            remote: None,
            upstream: None,
            connecting: None,
            to_net: Vec::new(),
            to_app: Vec::new(),
            dpi_done: false,
            out_dpi_done: false,
            out_plan: VecDeque::new(),
            in_plan: VecDeque::new(),
        }
    }
}

/// Запрос на разрешение DNS, отправляемый в рабочую задачу.
struct DnsRequest {
    port: u16,
    client: IpEndpoint,
    query: Vec<u8>,
}

/// Ответ DNS, возвращаемый рабочей задачей в основной цикл.
struct DnsAnswer {
    port: u16,
    client: IpEndpoint,
    payload: Vec<u8>,
}

/// Запустить подключение к серверу в отдельной задаче.
///
/// Возвращает приёмник результата: `Ok(stream)` — соединение установлено,
/// `Err` — таймаут или отказ. Так цикл стека никогда не блокируется на
/// сетевой операции.
fn spawn_connect(addr: SocketAddr) -> oneshot::Receiver<io::Result<TcpStream>> {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let result = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TCP: таймаут подключения",
            )),
        };
        // Приёмник мог исчезнуть (соединение уже закрыто) — это нормально.
        let _ = tx.send(result);
    });
    rx
}

/// Основной цикл стека.
async fn run(fd: TunFd, control: TunnelControl) -> io::Result<()> {
    crate::flog!(
        "Стек smoltcp запущен: TUN fd={} (dup={}), MTU={}",
        fd.read_fd,
        fd.write_fd,
        fd.mtu
    );

    // ------------------------------------------------------------------ //
    // 1) Интерфейс.
    // ------------------------------------------------------------------ //
    let mut device = TunDevice::new(&fd);
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = rand::thread_rng().gen();
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());

    // AnyIP: интерфейс принимает пакеты на ЛЮБОЙ адрес и считает его своим.
    // Без этого пакеты к 142.250.74.46 были бы отброшены как «чужие».
    iface.set_any_ip(true);

    // Адрес интерфейса берём из конфигурации: AnyIP включён, поэтому стек
    // принимает пакеты на любой адрес, а явный адрес нужен лишь как источник
    // для ответов.
    let tun_ip = control.tun_ip;
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv4(tun_ip),
            control.tun_prefix.min(32),
        ));
    });
    let _ = iface.routes_mut().add_default_ipv4_route(tun_ip);

    let mut sockets: SocketSet<'_> = SocketSet::new(Vec::new());
    let mut tcp_conns: Vec<TcpConn> = Vec::new();
    let mut udp_conns: HashMap<u16, SocketHandle> = HashMap::new();

    // ------------------------------------------------------------------ //
    // 2) Каналы для DNS-воркера.
    // ------------------------------------------------------------------ //
    let (dns_tx, mut dns_rx) = mpsc::channel::<DnsRequest>(64);
    let (ans_tx, mut ans_rx) = mpsc::channel::<DnsAnswer>(64);

    {
        let control = control.clone();

        // Воркер Send-совместим: он не трогает SocketSet.
        tokio::spawn(async move {
            while let Some(req) = dns_rx.recv().await {
                let servers = control.upstream_dns.clone();
                let payload = if control.dns_over_tcp {
                    match dns_over_tcp(&req.query, &servers).await {
                        Ok(v) => v,
                        // Если TCP заблокирован — падаем обратно на UDP.
                        Err(_) => dns_over_udp(&req.query, &servers).await.unwrap_or_default(),
                    }
                } else {
                    match dns_over_udp(&req.query, &servers).await {
                        Ok(v) => v,
                        Err(_) => dns_over_tcp(&req.query, &servers).await.unwrap_or_default(),
                    }
                };
                if payload.is_empty() {
                    continue;
                }
                if ans_tx
                    .send(DnsAnswer {
                        port: req.port,
                        client: req.client,
                        payload,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    crate::flog!("DPI: {}", control.settings.describe());

    // ------------------------------------------------------------------ //
    // 3) Главный цикл.
    // ------------------------------------------------------------------ //
    while control.is_running() {
        let now = SmolInstant::now();
        iface.poll(now, &mut device, &mut sockets);

        // --- 3.1) Новые порты от устройства ---------------------------- //
        for (proto, port) in device.take_new_ports() {
            match proto {
                Proto::Tcp => {
                    if tcp_conns.len() >= MAX_CONNECTIONS {
                        continue;
                    }
                    let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]);
                    let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]);
                    let mut socket = tcp::Socket::new(rx, tx);
                    if socket
                        .listen(smoltcp::wire::IpListenEndpoint { addr: None, port })
                        .is_err()
                    {
                        continue;
                    }
                    let handle = sockets.add(socket);
                    device.mark_port_known(Proto::Tcp, port);
                    tcp_conns.push(TcpConn::new(handle, port));
                    crate::flog_dbg!("TCP: слушаем порт {port}");
                }
                Proto::Udp => {
                    if udp_conns.contains_key(&port) {
                        continue;
                    }
                    let rx = udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; 32],
                        vec![0u8; 65536],
                    );
                    let tx = udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; 32],
                        vec![0u8; 65536],
                    );
                    let mut socket = udp::Socket::new(rx, tx);
                    if socket
                        .bind(smoltcp::wire::IpListenEndpoint { addr: None, port })
                        .is_err()
                    {
                        continue;
                    }
                    let handle = sockets.add(socket);
                    device.mark_port_known(Proto::Udp, port);
                    udp_conns.insert(port, handle);
                    crate::flog_dbg!("UDP: слушаем порт {port}");
                }
            }
        }

        let udp_ports: Vec<(u16, SocketHandle)> =
            udp_conns.iter().map(|(p, h)| (*p, *h)).collect();
        for (port, handle) in udp_ports {
            let socket = sockets.get_mut::<udp::Socket>(handle);
            let mut buf = vec![0u8; 4096];
            loop {
                match socket.recv_slice(&mut buf) {
                    Ok((n, meta)) => {
                        stats::add_up(n);
                        if dns_tx
                            .try_send(DnsRequest {
                                port,
                                client: meta.endpoint,
                                query: buf[..n].to_vec(),
                            })
                            .is_err()
                        {
                            crate::flog_dbg!("DNS: очередь переполнена");
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        // --- 3.3) UDP: ответы воркера вставляем в стек --------------- //
        while let Ok(answer) = ans_rx.try_recv() {
            if let Some(handle) = udp_conns.get(&answer.port).copied() {
                let socket = sockets.get_mut::<udp::Socket>(handle);
                let _ = socket.send_slice(&answer.payload, answer.client);
            }
        }

        // --- 3.4) TCP-соединения ------------------------------------- //
        let mut i = 0;
        while i < tcp_conns.len() {
            // Узнаём удалённый адрес и состояние.
            let (state, remote) = {
                let socket = sockets.get_mut::<tcp::Socket>(tcp_conns[i].handle);
                let remote = socket
                    .remote_endpoint()
                    .map(|ep| SocketAddr::new(ip_to_std(ep.addr), ep.port))
                    .or(tcp_conns[i].remote);
                (socket.state(), remote)
            };
            tcp_conns[i].remote = remote;

            let closed_port = tcp_conns[i].port;

            if state == tcp::State::Closed {
                // Полузакрытие не ждём: `shutdown` на неблокирующем сокете
                // только ставит FIN в очередь ядра. `await` здесь задерживал
                // бы опрос всего стека.
                if let Some(mut up) = tcp_conns[i].upstream.take() {
                    let _ = up.shutdown();
                }
                sockets.remove(tcp_conns[i].handle);
                tcp_conns.swap_remove(i);
                // Порт остаётся в known_ports, поэтому сокет-слушатель для
                // следующего соединения на тот же порт нужно создать заново.
                device.forget_port(Proto::Tcp, closed_port);
                continue;
            }

            if state == tcp::State::Established {
                // --- подключение к реальному серверу ------------------- //
                if tcp_conns[i].upstream.is_none() {
                    if tcp_conns[i].connecting.is_none() {
                        let Some(addr) = tcp_conns[i].remote else {
                            // Не знаем адрес (например, RST) — пропускаем.
                            i += 1;
                            continue;
                        };
                        tcp_conns[i].connecting = Some(spawn_connect(addr));
                        // Соединение появится на следующей итерации: ждать
                        // подключения здесь нельзя, иначе встанет весь стек.
                        i += 1;
                        continue;
                    }

                    match tcp_conns[i].connecting.as_mut() {
                        Some(rx) => match rx.try_recv() {
                            Ok(Ok(stream)) => {
                                // tokio-сокет всегда неблокирующий, а
                                // `set_nonblocking` у `tokio::net::TcpStream`
                                // нет — только `nodelay`.
                                let _ = stream.set_nodelay(true);
                                tcp_conns[i].upstream = Some(stream);
                                tcp_conns[i].connecting = None;
                                let addr = tcp_conns[i].remote;
                                crate::flog_dbg!("TCP -> {addr:?}: соединение открыто");
                            }
                            Ok(Err(e)) => {
                                let addr = tcp_conns[i].remote;
                                crate::flog_dbg!("TCP -> {addr:?}: соединение не удалось: {e}");
                                tcp_conns[i].connecting = None;
                                sockets.get_mut::<tcp::Socket>(tcp_conns[i].handle).abort();
                                i += 1;
                                continue;
                            }
                            Err(oneshot::error::TryRecvError::Empty) => {
                                // Ещё подключаемся — ничего не делаем.
                                i += 1;
                                continue;
                            }
                            Err(oneshot::error::TryRecvError::Closed) => {
                                tcp_conns[i].connecting = None;
                                sockets.get_mut::<tcp::Socket>(tcp_conns[i].handle).abort();
                                i += 1;
                                continue;
                            }
                        },
                        None => {
                            i += 1;
                            continue;
                        }
                    }
                }

                // --- приложение -> сеть ------------------------------- //
                let mut read_buf = vec![0u8; CHUNK];
                {
                    let socket = sockets.get_mut::<tcp::Socket>(tcp_conns[i].handle);
                    loop {
                        match socket.recv_slice(&mut read_buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                tcp_conns[i].to_net.extend_from_slice(&read_buf[..n]);
                                stats::add_up(n);
                            }
                        }
                    }
                }
                // Первый блок данных на соединение отправляем по DPI-плану:
                // режем на фрагменты и добавляем junk-префикс. План собираем в
                // готовые буферы и отдаём общему неблокирующему писателю ниже —
                // так частичная запись (WouldBlock) не рвёт соединение.
                if !tcp_conns[i].to_net.is_empty()
                    && !tcp_conns[i].out_dpi_done
                    && tcp_conns[i].out_plan.is_empty()
                    && control.settings.active()
                {
                    let plan = {
                        let mut rng = rand::thread_rng();
                        dpi::plan_stream(&tcp_conns[i].to_net, &control.settings, &mut rng)
                    };
                    crate::flog_dbg!("DPI: {} сегмент(ов)", plan.len());
                    let mut consumed = 0usize;
                    // Куски складываем во временный список: `plan` заимствует
                    // `to_net`, поэтому писать в `out_plan` прямо в цикле нельзя.
                    let mut pieces: Vec<Vec<u8>> = Vec::with_capacity(plan.len());
                    for chunk in &plan {
                        match chunk {
                            dpi::Chunk::Junk(j) => {
                                if !j.is_empty() {
                                    pieces.push(j.clone());
                                }
                            }
                            dpi::Chunk::Data { start, end } => {
                                if end > start {
                                    pieces.push(tcp_conns[i].to_net[*start..*end].to_vec());
                                    consumed = consumed.max(*end);
                                }
                            }
                        }
                    }
                    for piece in pieces {
                        tcp_conns[i].out_plan.push_back(piece);
                    }
                    tcp_conns[i].to_net.drain(..consumed);
                    tcp_conns[i].out_dpi_done = true;
                }

                if tcp_conns[i].upstream.is_some() {
                    // Сначала выливаем подготовленный DPI-план, затем сырые данные.
                    // Поток берём на время одного `try_write`: если держать
                    // `&TcpConn`, изменение `out_plan` в том же цикле не даст
                    // одолжить запись (E0502).
                    let mut broken = false;
                    while !tcp_conns[i].out_plan.is_empty() {
                        let written = {
                            let up = tcp_conns[i].upstream.as_ref().expect("проверено выше");
                            let front = tcp_conns[i].out_plan.front().expect("не пусто");
                            up.try_write(front)
                        };
                        match written {
                            Ok(0) => break,
                            Ok(n) if n == tcp_conns[i].out_plan.front().map_or(0, Vec::len) => {
                                tcp_conns[i].out_plan.pop_front();
                            }
                            Ok(n) => {
                                if let Some(front) = tcp_conns[i].out_plan.front_mut() {
                                    front.drain(..n);
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => {
                                broken = true;
                                break;
                            }
                        }
                    }
                    if broken {
                        sockets.get_mut::<tcp::Socket>(tcp_conns[i].handle).abort();
                        i += 1;
                        continue;
                    }
                }

                if let Some(up) = tcp_conns[i].upstream.as_ref() {
                    // Пишем столько, сколько примет сокет.
                    let mut written = 0usize;
                    while written < tcp_conns[i].to_net.len() {
                        match up.try_write(&tcp_conns[i].to_net[written..]) {
                            Ok(0) => break,
                            Ok(n) => written += n,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => {
                                sockets.get_mut::<tcp::Socket>(tcp_conns[i].handle).abort();
                                break;
                            }
                        }
                    }
                    if written > 0 {
                        tcp_conns[i].to_net.drain(..written);
                    }
                }

                // --- сеть -> приложение ------------------------------- //
                if let Some(up) = tcp_conns[i].upstream.as_ref() {
                    let mut net_buf = vec![0u8; CHUNK];
                    match up.try_read(&mut net_buf) {
                        Ok(0) => {
                            // Сервер закрыл соединение.
                            sockets.get_mut::<tcp::Socket>(tcp_conns[i].handle).close();
                        }
                        Ok(n) => {
                            stats::add_down(n);
                            tcp_conns[i].to_app.extend_from_slice(&net_buf[..n]);
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            sockets.get_mut::<tcp::Socket>(tcp_conns[i].handle).abort();
                        }
                    }
                }

                // Первый блок в сторону приложения тоже проходит через DPI:
                // маскируем SNI и режем поток на фрагменты. Готовые куски
                // складываем в очередь, чтобы частичная отправка не приводила
                // к повторной передаче уже ушедших байт.
                if !tcp_conns[i].to_app.is_empty()
                    && !tcp_conns[i].dpi_done
                    && tcp_conns[i].in_plan.is_empty()
                    && control.settings.active()
                {
                    if control.settings.fake_sni && !control.settings.fake_sni_host.is_empty() {
                        let host = control.settings.fake_sni_host.as_str();
                        let result = dpi::sni::mask_sni(&mut tcp_conns[i].to_app, host);
                        if let Some((from, to)) = result.applied {
                            crate::flog_dbg!("SNI подменён: {from} -> {to}");
                        } else if let Some(w) = result.warning {
                            crate::flog_dbg!("SNI: {w}");
                        }
                    }

                    let plan = {
                        let mut rng = rand::thread_rng();
                        dpi::plan_stream(&tcp_conns[i].to_app, &control.settings, &mut rng)
                    };
                    crate::flog_dbg!("DPI (в приложение): {} сегмент(ов)", plan.len());
                    let mut consumed = 0usize;
                    // См. комментарий в направлении «приложение -> сеть».
                    let mut pieces: Vec<Vec<u8>> = Vec::with_capacity(plan.len());
                    for chunk in &plan {
                        match chunk {
                            dpi::Chunk::Junk(j) => {
                                if !j.is_empty() {
                                    pieces.push(j.clone());
                                }
                            }
                            dpi::Chunk::Data { start, end } => {
                                if end > start {
                                    pieces.push(tcp_conns[i].to_app[*start..*end].to_vec());
                                    consumed = consumed.max(*end);
                                }
                            }
                        }
                    }
                    for piece in pieces {
                        tcp_conns[i].in_plan.push_back(piece);
                    }
                    tcp_conns[i].to_app.drain(..consumed);
                    tcp_conns[i].dpi_done = true;
                }

                if !tcp_conns[i].in_plan.is_empty() || !tcp_conns[i].to_app.is_empty() {
                    let conn = &mut tcp_conns[i];
                    let socket = sockets.get_mut::<tcp::Socket>(conn.handle);
                    drain_to_app(socket, &mut conn.in_plan, &mut conn.to_app);
                }
            }

            i += 1;
        }

        // --- 3.5) Пауза ---------------------------------------------- //
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // ------------------------------------------------------------------ //
    // 4) Уборка.
    // ------------------------------------------------------------------ //
    for conn in tcp_conns {
        if let Some(mut up) = conn.upstream {
            let _ = up.shutdown();
        }
        sockets.remove(conn.handle);
    }
    crate::flog!("Стек smoltcp остановлен");
    Ok(())
}

/// Выливает очередь готовых кусков в сокет smoltcp, затем остаток «сырых»
/// данных. Ничего не блокирует: как только в буфере сокета нет места,
/// остаток остаётся в очереди до следующей итерации. Такой подход исключает
/// повторную отправку уже ушедших байт (в отличие от повторного вызова
/// send_slice с тем же срезом).
fn drain_to_app(socket: &mut tcp::Socket, plan: &mut VecDeque<Vec<u8>>, raw: &mut Vec<u8>) {
    while let Some(front) = plan.front_mut() {
        match socket.send_slice(front) {
            Ok(0) | Err(_) => return,
            Ok(n) if n == front.len() => {
                plan.pop_front();
            }
            Ok(n) => {
                front.drain(..n);
            }
        }
    }

    let mut written = 0usize;
    while written < raw.len() {
        match socket.send_slice(&raw[written..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => written += n,
        }
    }
    raw.drain(..written);
}

/// Переслать DNS-запрос по TCP (RFC 7766): 2 байта длины + сообщение.
pub async fn dns_over_tcp(query: &[u8], servers: &[SocketAddr]) -> io::Result<Vec<u8>> {
    let mut last_err = io::Error::new(io::ErrorKind::NotFound, "нет DNS-серверов");
    for server in servers {
        let attempt = async {
            let mut stream =
                tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(server))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS: таймаут TCP"))??;
            stream.set_nodelay(true)?;

            let mut msg = Vec::with_capacity(query.len() + 2);
            msg.extend_from_slice(&(query.len() as u16).to_be_bytes());
            msg.extend_from_slice(query);
            stream.write_all(&msg).await?;
            stream.flush().await?;

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let len = u16::from_be_bytes(len_buf) as usize;
            if len == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS: пустой ответ"));
            }
            let mut resp = vec![0u8; len];
            stream.read_exact(&mut resp).await?;
            Ok::<_, io::Error>(resp)
        }
        .await;

        match attempt {
            Ok(resp) => return Ok(resp),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Переслать DNS-запрос по UDP.
pub async fn dns_over_udp(query: &[u8], servers: &[SocketAddr]) -> io::Result<Vec<u8>> {
    let mut last_err = io::Error::new(io::ErrorKind::NotFound, "нет DNS-серверов");
    for server in servers {
        let attempt = async {
            let bind: SocketAddr = match server {
                SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
                SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
            };
            let sock = tokio::net::UdpSocket::bind(bind).await?;
            sock.connect(server).await?;
            sock.send(query).await?;
            let mut buf = vec![0u8; 65535];
            let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS: таймаут UDP"))??;
            buf.truncate(n);
            Ok::<_, io::Error>(buf)
        }
        .await;

        match attempt {
            Ok(resp) => return Ok(resp),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// smoltcp `IpAddress` -> `std::net::IpAddr`.
fn ip_to_std(addr: IpAddress) -> IpAddr {
    // В smoltcp 0.14 адреса — это core::net::{Ipv4Addr, Ipv6Addr}, которые
    // совпадают по типу со std::net, поэтому есть готовый From.
    IpAddr::from(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_ipv4() {
        let a = ip_to_std(IpAddress::v4(1, 2, 3, 4));
        assert_eq!(a, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn dns_loopback_is_replaced() {
        let cfg = AppConfig::default();
        let control = TunnelControl::from_config(&cfg);
        assert!(!control.upstream_dns.is_empty());
        assert!(control
            .upstream_dns
            .iter()
            .all(|s| !s.ip().to_string().starts_with("10.111.222")));
    }
}

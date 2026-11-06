use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::AppConfig;
use crate::platform::{self, VpnStart};
use crate::proxy::{self, ProxyHandle, ProxySettings};
use crate::tunnel::{stack::TunnelControl, TunnelRuntime, TunFd};

/// Состояние VPN-сервиса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnState {
    Stopped,
    /// Показан системный диалог согласия — ждём пользователя.
    WaitingConsent,
    /// Идёт запуск.
    Starting,
    /// Работает.
    Running,
    /// Ошибка (текст — в [`VpnController::last_error`]).
    Error,
}

impl VpnState {
    fn to_u8(self) -> u8 {
        match self {
            VpnState::Stopped => 0,
            VpnState::WaitingConsent => 1,
            VpnState::Starting => 2,
            VpnState::Running => 3,
            VpnState::Error => 4,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => VpnState::WaitingConsent,
            2 => VpnState::Starting,
            3 => VpnState::Running,
            4 => VpnState::Error,
            _ => VpnState::Stopped,
        }
    }

    /// Подпись на большой кнопке.
    pub fn label(self) -> &'static str {
        match self {
            VpnState::Stopped => "СТАРТ",
            VpnState::WaitingConsent => "ПОДТВЕРДИТЕ VPN",
            VpnState::Starting => "ЗАПУСК…",
            VpnState::Running => "СТОП",
            VpnState::Error => "ПОВТОРИТЬ",
        }
    }

    /// Пояснение под кнопкой.
    pub fn hint(self) -> &'static str {
        match self {
            VpnState::Stopped => "Нажмите «Старт», чтобы включить обход блокировок",
            VpnState::WaitingConsent => {
                "Разрешите подключение VPN в системном окне, затем нажмите «Старт» ещё раз"
            }
            VpnState::Starting => "Поднимаем туннель и сетевой стек…",
            VpnState::Running => "Трафик идёт через локальный DPI-обход",
            VpnState::Error => "Что-то пошло не так — подробности ниже",
        }
    }
}

/// Разделяемый контроллер (дешёвый `Clone`).
#[derive(Clone)]
pub struct VpnController {
    inner: Arc<Inner>,
}

struct Inner {
    state: AtomicU8,
    last_error: Mutex<Option<String>>,
    /// Запущенный прокси-сервер (слот заполняется асинхронно).
    proxy: Mutex<Option<Arc<Mutex<Option<ProxyHandle>>>>>,
    /// Запущенный TUN-стек.
    tunnel: Mutex<Option<TunnelRuntime>>,
    /// Tokio-рантайм приложения.
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
    /// Сколько раз стартовали (для лога).
    starts: Mutex<u64>,
}

impl Default for VpnController {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnController {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: AtomicU8::new(VpnState::Stopped.to_u8()),
                last_error: Mutex::new(None),
                proxy: Mutex::new(None),
                tunnel: Mutex::new(None),
                runtime: Mutex::new(None),
                starts: Mutex::new(0),
            }),
        }
    }

    pub fn state(&self) -> VpnState {
        VpnState::from_u8(self.inner.state.load(Ordering::Relaxed))
    }

    pub fn is_running(&self) -> bool {
        self.state() == VpnState::Running
    }

    pub fn last_error(&self) -> Option<String> {
        self.inner.last_error.lock().unwrap().clone()
    }

    /// Инициализировать tokio-рантайм (один раз).
    pub fn init_runtime(&self) -> Result<(), String> {
        let mut guard = self.inner.runtime.lock().unwrap();
        if guard.is_some() {
            return Ok(());
        }
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("byebyedpi")
            .build()
            .map_err(|e| format!("Tokio runtime: {e}"))?;
        *guard = Some(rt);
        Ok(())
    }

    /// Запустить всё.
    ///
    /// Возвращает `true`, если запуск инициирован.
    pub fn start(&self, cfg: &AppConfig) -> bool {
        if matches!(self.state(), VpnState::Running | VpnState::Starting) {
            return false;
        }

        *self.inner.last_error.lock().unwrap() = None;
        self.set_state(VpnState::Starting);

        if let Err(e) = self.init_runtime() {
            self.fail(&e);
            return false;
        }
        {
            let mut n = self.inner.starts.lock().unwrap();
            *n += 1;
            crate::flog!("=== Запуск VPN #{} ===", *n);
        }
        crate::stats::reset();

        // 1) Прокси-сервер. Он полезен даже без TUN (например, если
        //    пользователь настроит приложения на SOCKS5 напрямую).
        self.start_proxy(cfg);

        // 2) Платформа поднимает VpnService и отдаёт fd.
        match platform::start_vpn(cfg) {
            VpnStart::Ready(tun) => {
                crate::flog!("VPN: получен дескриптор TUN (fd={})", tun.read_fd);
                self.attach_tunnel(tun, cfg);
                true
            }
            VpnStart::NeedConsent => {
                self.set_state(VpnState::WaitingConsent);
                crate::flog_warn!(
                    "VPN: нужно подтверждение пользователя. Подтвердите системный диалог и нажмите «Старт» ещё раз."
                );
                false
            }
            VpnStart::Failed(msg) => {
                // На Android штатный путь: сервис запущен, fd придёт
                // асинхронно из nativeCreate. Это не ошибка.
                if msg.contains("nativeCreate") {
                    crate::flog!("VPN: {msg}");
                    true
                } else {
                    self.fail(&msg);
                    false
                }
            }
        }
    }

    /// Запустить прокси на tokio-рантайме.
    fn start_proxy(&self, cfg: &AppConfig) {
        let handle = {
            let guard = self.inner.runtime.lock().unwrap();
            match guard.as_ref() {
                Some(rt) => rt.handle().clone(),
                None => {
                    self.fail("Tokio-рантайм не инициализирован");
                    return;
                }
            }
        };

        let settings = ProxySettings {
            host: cfg.proxy_host.clone(),
            port: cfg.proxy_port,
            auth: cfg
                .proxy_auth()
                .map(|(u, p)| (u.to_string(), p.to_string())),
        };

        // Слот заполнится, когда `bind` завершится.
        let slot: Arc<Mutex<Option<ProxyHandle>>> = Arc::new(Mutex::new(None));
        *self.inner.proxy.lock().unwrap() = Some(slot.clone());

        handle.spawn(async move {
            match proxy::start(settings).await {
                Ok(proxy) => {
                    crate::flog!("Прокси: слушает {}", proxy.local_addr());
                    *slot.lock().unwrap() = Some(proxy);
                }
                Err(e) => {
                    crate::flog_err!("Прокси не запустился: {e}");
                }
            }
        });
    }

    pub fn register_config(&self, cfg: &AppConfig) {
        crate::update_app_config(cfg.clone());
    }

    /// Присоединить TUN к стеку.
    pub fn attach_tunnel(&self, tun: TunFd, cfg: &AppConfig) {
        if let Some(previous) = self.inner.tunnel.lock().unwrap().take() {
            drop(previous);
        }
        let control = TunnelControl::from_config(cfg);
        let runtime = TunnelRuntime::start(tun, control);
        *self.inner.tunnel.lock().unwrap() = Some(runtime);
        self.set_state(VpnState::Running);
        crate::flog!(
            "VPN: туннель поднят (TUN fd={}, MTU={})",
            tun.read_fd,
            tun.mtu
        );
    }

    /// Остановить всё.
    pub fn stop(&self) {
        if let Some(mut tunnel) = self.inner.tunnel.lock().unwrap().take() {
            tunnel.stop();
        }
        if let Some(slot) = self.inner.proxy.lock().unwrap().take() {
            if let Some(proxy) = slot.lock().unwrap().take() {
                proxy.stop();
            }
        }
        platform::stop_vpn();

        self.set_state(VpnState::Stopped);
        crate::flog!("VPN: остановлен пользователем");
    }

    fn fail(&self, message: &str) {
        crate::flog_err!("{message}");
        *self.inner.last_error.lock().unwrap() = Some(message.to_string());
        self.set_state(VpnState::Error);
    }

    fn set_state(&self, state: VpnState) {
        self.inner.state.store(state.to_u8(), Ordering::Relaxed);
    }
}

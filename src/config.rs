//! Конфигурация приложения: структура настроек, значения по умолчанию и
//! сохранение/загрузка в локальный JSON-файл на устройстве.
//!
//! Путь к файлу настроек запрашивается у Android через JNI
//! (`Context.getFilesDir()`) в модуле [`crate::platform::android`]. На desktop
//! используется `./byebyedpi-config.json`. Модуль не зависит от платформы:
//! он просто получает `PathBuf`.
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Все настройки приложения. Сериализуются в JSON «как есть», поэтому
/// добавлять новые поля можно без миграций (используется `#[serde(default)]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    // ------------------------- Прокси-сервер ------------------------- //
    /// Адрес, на котором слушает встроенный прокси (SOCKS5/HTTP/H2Mux).
    pub proxy_host: String,
    /// Порт встроенного прокси. 1080 — стандартный SOCKS5.
    pub proxy_port: u16,
    /// Логин для SOCKS5/HTTP-авторизации (пусто = без авторизации).
    pub proxy_user: String,
    /// Пароль для SOCKS5/HTTP-авторизации.
    pub proxy_password: String,
    // ------------------------- DPI-обход ----------------------------- //
    /// Мастер-переключатель всех техник обхода.
    pub bypass_enabled: bool,
    /// Фрагментация TCP: первый сегмент после рукопожатия режется на
    /// куски `fragment_size_min..=fragment_size_max` байт.
    pub fragment_enabled: bool,
    pub fragment_size_min: usize,
    pub fragment_size_max: usize,
    /// Микро-сегментация: отправка по одному байту N первых байт.
    pub microsegmentation_enabled: bool,
    pub microsegmentation_bytes: usize,
    /// Разрывание TLS ClientHello (SNI) на две TCP-секции посреди имени хоста.
    pub split_tls_enabled: bool,
    /// Позиция разрыва ClientHello. `None` — автоматически (середина SNI).
    pub split_tls_position: Option<usize>,
    /// Разрывать именно посреди SNI (а не просто «после 1 байта»).
    pub split_tls_at_sni: bool,
    /// Маскировка SNI: подменять имя хоста в ClientHello на `fake_sni_host`.
    pub fake_sni_enabled: bool,
    /// Значение «фейкового» SNI Host (например, `www.google.com`).
    pub fake_sni_host: String,
    /// UDP-over-TCP: заворачивать UDP-датаграммы (в первую очередь DNS)
    /// в TCP-поток, чтобы провайдер не мог их отфильтровать по типу.
    pub udp_over_tcp_enabled: bool,
    /// Отправлять «мусорный» префикс перед первым полезным пакетом
    /// (простая защита от активного зондирования).
    pub junk_prefix_enabled: bool,
    // ------------------------- TUN / VPN ----------------------------- //
    /// Адрес TUN-интерфейса (адрес приложения внутри туннеля).
    pub tun_address: String,
    /// Маска/префикс TUN-интерфейса.
    pub tun_prefix: u8,
    /// MTU виртуального интерфейса.
    pub tun_mtu: u16,
    /// DNS-серверы, которые получат приложения через VPN.
    /// 10.111.222.1 — «наш» адрес: запросы к нему перехватываются стеком.
    pub dns_servers: Vec<String>,
    /// Вести лог в файл (в дополнение к экрану).
    pub log_to_file: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 1080,
            proxy_user: String::new(),
            proxy_password: String::new(),
            bypass_enabled: true,
            fragment_enabled: true,
            fragment_size_min: 1,
            fragment_size_max: 5,
            microsegmentation_enabled: true,
            microsegmentation_bytes: 2,
            split_tls_enabled: true,
            split_tls_position: None,
            split_tls_at_sni: true,
            fake_sni_enabled: false,
            fake_sni_host: "www.google.com".to_string(),
            udp_over_tcp_enabled: false,
            junk_prefix_enabled: false,
            tun_address: "10.111.222.2".to_string(),
            tun_prefix: 24,
            tun_mtu: 1500,
            dns_servers: vec!["10.111.222.1".to_string()],
            log_to_file: false,
        }
    }
}

impl AppConfig {
    /// Проверка/нормализация значений, введённых пользователем в GUI.
    /// Никогда не паникует: некорректные значения молча правятся.
    pub fn sanitize(&mut self) {
        if self.proxy_port == 0 {
            self.proxy_port = 1080;
        }
        if self.proxy_host.trim().is_empty() {
            self.proxy_host = "127.0.0.1".to_string();
        }

        // Параметры фрагментации должны быть осмысленными.
        self.fragment_size_min = self.fragment_size_min.clamp(1, 128);
        self.fragment_size_max = self.fragment_size_max.clamp(self.fragment_size_min, 1024);
        self.microsegmentation_bytes = self.microsegmentation_bytes.clamp(1, 16);

        // MTU: 576 — минимальный разумный, 9000 — jumbo.
        self.tun_mtu = self.tun_mtu.clamp(576, 9000);
        self.tun_prefix = self.tun_prefix.clamp(8, 30);
        if self.tun_address.parse::<Ipv4Addr>().is_err() {
            self.tun_address = "10.111.222.2".to_string();
        }
        if self.dns_servers.is_empty() {
            self.dns_servers.push("10.111.222.1".to_string());
        }

        // Авторизация: либо обе строки, либо ни одной.
        if self.proxy_user.trim().is_empty() {
            self.proxy_user.clear();
            self.proxy_password.clear();
        }
        self.fake_sni_host = self.fake_sni_host.trim().to_string();
    }

    /// Есть ли логин/пароль для прокси.
    pub fn proxy_auth(&self) -> Option<(&str, &str)> {
        if self.proxy_user.is_empty() {
            None
        } else {
            Some((&self.proxy_user, &self.proxy_password))
        }
    }

    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str::<Self>(&text) {
                Ok(mut cfg) => {
                    cfg.sanitize();
                    cfg
                }
                Err(e) => {
                    log::warn!("Не удалось разобрать {}: {e}. Используются значения по умолчанию.", path.display());
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Атомарная запись: сначала во временный файл, потом rename.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp: PathBuf = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, path)
    }
}

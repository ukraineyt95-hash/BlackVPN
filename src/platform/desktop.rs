//! Desktop-реализация платформенного слоя.
//!
//! Нужна для двух вещей:
//!   1. отладка GUI и прокси-сервера на обычном Linux/Windows без телефона;
//!   2. `cargo check` в CI — среда без Android SDK всё равно должна
//!      проверять бизнес-логику.
//!
//! VPN здесь не поднимается (на Desktop нет `android.net.VpnService`),
//! но прокси-сервер запускается как обычный локальный SOCKS5/HTTP — этого
//! достаточно для тестов.
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

use crate::config::AppConfig;
use crate::platform::VpnStart;

static START: OnceLock<Instant> = OnceLock::new();

fn start_instant() -> &'static Instant {
    START.get_or_init(Instant::now)
}

pub fn elapsed_secs_since_start() -> u64 {
    start_instant().elapsed().as_secs()
}

pub struct DesktopPlatform {
    pub config_path: PathBuf,
}

impl Default for DesktopPlatform {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("byebyedpi-config.json"),
        }
    }
}

impl crate::platform::Platform for DesktopPlatform {
    fn save_config(&self, cfg: &AppConfig) -> Result<(), String> {
        cfg.save(&self.config_path).map_err(|e| e.to_string())
    }

    fn load_config(&self) -> AppConfig {
        AppConfig::load(&self.config_path)
    }

    fn log_file_path(&self) -> Option<PathBuf> {
        Some(PathBuf::from("byebyedpi.log"))
    }
}

/// На desktop туннель не создаётся — возвращаем понятную ошибку.
/// (Реальный TUN на Linux можно сделать через `smoltcp::phy::TunTapInterface`,
/// но это выходит за рамки задачи: там нужны права root и `ip tuntap`.)
pub fn start_vpn(_cfg: &AppConfig) -> VpnStart {
    VpnStart::Failed(
        "Демонстрационный режим desktop: VPN-туннель доступен только на Android. \
         Прокси-сервер (SOCKS5/HTTP) при этом работает."
            .to_string(),
    )
}

pub fn stop_vpn() {}

/// Открыть системный диалог согласия — на desktop нечего открывать.
#[allow(dead_code)]
pub fn request_vpn_consent() {}

/// На desktop разрешения не нужны.
#[allow(dead_code)]
pub fn has_vpn_permission() -> bool {
    true
}

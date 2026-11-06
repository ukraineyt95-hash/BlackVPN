//! Платформенный слой: всё, что зависит от ОС.
//!
//! Приложение не вызывает Android API напрямую — только через этот модуль.
//! На Android реализация целиком построена на JNI (см. `android.rs`),
//! на desktop — заглушки, чтобы проект собирался и отлаживался локально.
//!
//! Контракт (одинаков на обеих платформах):
//!   * [`start_vpn`]        — инициализировать VpnService, собрать Builder,
//!                            вызвать `establish()` и вернуть TUN-дескриптор;
//!   * [`stop_vpn`]         — закрыть дескриптор и остановить сервис;
//!   * [`save_config`]      — сохранить настройки;
//!   * [`elapsed_secs_since_start`] — монотонное время для логов.
use std::path::PathBuf;

use crate::config::AppConfig;
use crate::tunnel::TunFd;

/// Promotion сервиса в foreground через JNI (только Android).
#[cfg(target_os = "android")]
mod android;

/// Запросить разрешение POST_NOTIFICATIONS (API 33+). На desktop — no-op.
#[cfg(target_os = "android")]
pub mod foreground;

#[cfg(target_os = "android")]
pub fn request_notification_permission() {
    let Some(vm) = java_vm() else { return };
    let Ok(mut env) = vm.attach_current_thread() else {
        return;
    };
    let Some(activity) = activity() else { return };
    if let Err(e) = foreground::request_notification_permission(&mut env, activity.as_obj()) {
        crate::flog_warn!("POST_NOTIFICATIONS: {e}");
    }
}

#[cfg(not(target_os = "android"))]
pub fn request_notification_permission() {}

#[cfg(not(target_os = "android"))]
mod desktop;

#[cfg(target_os = "android")]
pub use android::*;

#[cfg(not(target_os = "android"))]
pub use desktop::*;

/// Результат попытки поднять VPN.
#[derive(Debug)]
pub enum VpnStart {
    /// Туннель поднят, дескриптор готов к передаче в smoltcp.
    Ready(TunFd),
    /// Нужно согласие пользователя: показать системный диалог по этому Intent.
    /// (На Android это `android.net.VpnService.prepare()`.)
    NeedConsent,
    /// Ошибка с человекочитаемым описанием.
    Failed(String),
}

/// Единый интерфейс платформы.
pub trait Platform {
    /// Сохранить настройки в приватную директорию приложения.
    fn save_config(&self, cfg: &AppConfig) -> Result<(), String>;

    /// Загрузить настройки; при отсутствии файла — значения по умолчанию.
    fn load_config(&self) -> AppConfig;

    /// Путь к файлу лога (если включено логирование в файл).
    fn log_file_path(&self) -> Option<PathBuf>;
}

/// Сколько секунд прошло с момента старта процесса.
///
/// Используется в штампах времени лога. Реализация не должна зависеть от
/// системных часов (они могут прыгать при синхронизации NTP).
pub fn elapsed_secs_since_start() -> u64 {
    #[cfg(target_os = "android")]
    {
        android::elapsed_secs_since_start()
    }
    #[cfg(not(target_os = "android"))]
    {
        desktop::elapsed_secs_since_start()
    }
}

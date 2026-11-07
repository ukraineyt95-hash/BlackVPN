//! Desktop-точка входа.
//!
//! Нужна для разработки и отладки: на обычном компьютере поднимается тот же
//! GUI и тот же прокси-сервер, но без VPN-туннеля (TUN есть только на
//! Android). Это позволяет проверять интерфейс и логику прокси без телефона.
//!
//! Запуск: `cargo run --bin byebyedpi-desktop`

#[cfg(not(target_os = "android"))]
use byebyedpi::{
    config::AppConfig,
    gui::{ByeByeDpiApp, PlatformHolder},
    logger,
    platform::{DesktopPlatform, Platform},
    vpn::VpnController,
    AppHandles,
};

#[cfg(target_os = "android")]
fn main() {
    eprintln!("На Android приложение запускается через android_main (NativeActivity).");
}

#[cfg(not(target_os = "android"))]
fn main() -> eframe::Result<()> {
    // 1) Логи в stderr + кольцевой буфер для GUI.
    env_logger_init();
    logger::init();

    // 2) Платформа: конфиг рядом с бинарником.
    let platform = DesktopPlatform::default();
    let cfg = AppConfig::load(&platform.config_path);
    if let Some(log_path) = platform.log_file_path() {
        logger::enable_file_logging(&log_path);
    }

    // 3) Контроллер VPN (на desktop поднимет только прокси).
    let controller = VpnController::new();
    let _ = controller.init_runtime();
    byebyedpi::set_app_handles(AppHandles {
        controller,
        config: cfg,
    });

    let app = ByeByeDpiApp::new(PlatformHolder::Desktop(platform));

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([420.0, 820.0])
            .with_min_inner_size([360.0, 600.0])
            .with_title("ByeByeDPI-Rust"),
        ..Default::default()
    };

    eframe::run_native(
        "ByeByeDPI-Rust",
        options,
        Box::new(move |_cc| Ok(Box::new(app))),
    )
}

/// Простейшая инициализация вывода логов в stderr.
#[cfg(not(target_os = "android"))]
fn env_logger_init() {
    // Не тянем env_logger ради одной функции: пишем свой формат.
    struct StderrLogger;
    impl log::Log for StderrLogger {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            eprintln!(
                "[{:5}] {}: {}",
                record.level(),
                record.target(),
                record.args()
            );
        }
        fn flush(&self) {}
    }
    static LOGGER: StderrLogger = StderrLogger;

    // Игнорируем ошибку: логгер мог быть уже установлен библиотекой.
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info);
}

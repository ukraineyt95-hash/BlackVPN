//! # ByeByeDPI-Rust
//!
//! Клиент обхода блокировок для Android, написанный **полностью на Rust**:
//! ни одной строки Java/Kotlin, ни Gradle, ни Android Studio.
//!
//! ## Точки входа
//!
//! | Платформа | Функция                       | Кто вызывает                     |
//! |-----------|-------------------------------|----------------------------------|
//! | Android   | [`android_main`]              | `NativeActivity` (через android-activity) |
//! | Android   | [`Java_com_example_byebyedpi_RustVpnService_nativeCreate`] | наш же Java-сервис через JNI |
//! | Desktop   | `main.rs`                     | обычный `main()`                 |
//!
//! ## Как устроена работа без Java
//!
//! 1. Манифест объявляет `android.app.NativeActivity` — она загружает
//!    `libbyebyedpi.so` и вызывает `android_main(app)`.
//! 2. При нажатии «Старт» Rust через JNI вызывает
//!    `VpnService.prepare()`, `Context.startForegroundService()`, а затем —
//!    уже на объекте сервиса — `VpnService.Builder.{setSession, setMtu,
//!    addAddress, addRoute, addDnsServer, establish}`.
//! 3. Из `ParcelFileDescriptor` берётся `fd` (`detachFd()`) и отдаётся в
//!    `smoltcp`.
//!
//! Подробности и требования к манифесту — в `docs/ANDROID_VPN_HOST.md`.
#![allow(clippy::too_many_arguments)]

pub mod apk;
pub mod config;
pub mod dpi;
pub mod gui;
pub mod logger;
pub mod platform;
pub mod proxy;
pub mod stats;
pub mod tunnel;
pub mod vpn;

use std::sync::Mutex;

/// Глобальное состояние, доступное из JNI-колбэков.
static APP: Mutex<Option<AppHandles>> = Mutex::new(None);

/// То, что нужно держать живым всё время работы приложения.
pub struct AppHandles {
    /// Контроллер VPN (нужен для `nativeCreate`).
    pub controller: vpn::VpnController,
    /// Актуальные настройки (для создания туннеля из колбэка).
    pub config: config::AppConfig,
}

/// Сохранить контроллер, чтобы JNI-колбэки могли им пользоваться.
pub fn set_app_handles(handles: AppHandles) {
    *APP.lock().unwrap() = Some(handles);
}

/// Получить контроллер (если приложение уже инициализировано).
pub fn app_controller() -> Option<vpn::VpnController> {
    APP.lock().unwrap().as_ref().map(|h| h.controller.clone())
}

/// Получить копию настроек.
pub fn app_config() -> Option<config::AppConfig> {
    APP.lock().unwrap().as_ref().map(|h| h.config.clone())
}

pub fn update_app_config(cfg: config::AppConfig) {
    if let Some(handles) = APP.lock().unwrap().as_mut() {
        handles.config = cfg;
    }
}

/// Точка входа Android (вызывается `android.app.NativeActivity`).
///
/// Символ `android_main` объявлен в android-activity как `extern "Rust"`,
/// поэтому и определять его нужно с Rust-ABI (атрибут `no_mangle` оставляет
/// имя без искажения — экспортируется `ANativeActivity_onCreate`).
#[cfg(target_os = "android")]
#[no_mangle]
pub fn android_main(app: winit::platform::android::activity::AndroidApp) {
    use std::ffi::c_void;

    // 1) Логи — в logcat (тег byebyedpi).
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("byebyedpi"),
    );
    logger::init();

    // 2) Инициализируем JNI-контекст: JavaVM + global ref на Activity.
    //    app.vm_as_ptr() / app.activity_as_ptr() возвращают сырые указатели,
    //    которые android-activity держит валидными всё время жизни `app`.
    let vm_ptr = app.vm_as_ptr() as *mut c_void;
    let activity_ptr = app.activity_as_ptr() as *mut c_void;
    unsafe {
        if let Err(e) = platform::init_context(vm_ptr, activity_ptr) {
            crate::flog_err!("JNI init: {e}");
        }
    }

    // 3) Узнаём приватную директорию приложения (для конфига и лога).
    let mut files_dir = std::path::PathBuf::from("/data/data/com.example.byebyedpi/files");
    if let Some(vm) = platform::java_vm() {
        if let Ok(mut env) = vm.attach_current_thread() {
            if let Some(activity) = platform::activity() {
                if let Ok(dir) = platform::files_dir(&mut env, activity.as_obj()) {
                    files_dir = dir;
                }
            }
        }
    }

    // 4) Конфигурация и логирование в файл.
    let mut cfg = config::AppConfig::load(&files_dir.join("config.json"));
    cfg.sanitize();
    if cfg.log_to_file {
        logger::enable_file_logging(&files_dir.join("byebyedpi.log"));
    }
    crate::flog!("Файлы приложения: {}", files_dir.display());
    crate::flog!("Android API level: {}", platform::api_level());

    // 4b) Разрешение на уведомления (Android 13+): без него уведомление
    //     foreground-сервиса не покажется, но VPN продолжит работать.
    platform::request_notification_permission();

    // 5) Контроллер + регистрация для JNI-колбэков.
    let controller = vpn::VpnController::new();
    if let Err(e) = controller.init_runtime() {
        crate::flog_err!("{e}");
    }
    set_app_handles(AppHandles {
        controller,
        config: cfg.clone(),
    });

    // 6) Запускаем egui.
    let platform_data = platform::AndroidPlatform { files_dir };
    let app_ui = gui::ByeByeDpiApp::new(gui::PlatformHolder::Android(platform_data));

    let options = eframe::NativeOptions {
        android_app: Some(app),
        ..Default::default()
    };

    if let Err(e) = eframe::run_native(
        "ByeByeDPI-Rust",
        options,
        Box::new(move |_cc| Ok(Box::new(app_ui))),
    ) {
        crate::flog_err!("eframe: {e}");
    }
}

/// Нативная функция, которую вызывает `RustVpnService.onCreate()`.
///
/// Имя соответствует соглашению JNI:
/// `Java_<пакет с '_'>_<Класс>_<метод>`.
///
/// Сигнатура Java-стороны:
/// ```java
/// package com.example.byebyedpi;
/// public class RustVpnService extends android.net.VpnService {
///     private native void nativeCreate();
/// }
/// ```
///
/// # Что делает
/// 1. Достаёт `this` (объект `android.net.VpnService`).
/// 2. Строит `VpnService.Builder` и вызывает `establish()` — см.
///    [`platform::build_vpn_interface`].
/// 3. Получает `fd` и поднимает `smoltcp`-стек.
///
/// # Безопасность
/// Мы не вызываем `env.throw_new` при ошибке: сервис всё равно должен
/// завершиться, а исключение в `onCreate` уронило бы приложение. Вместо
/// этого пишем в лог и вызываем `stopSelf()`.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_example_byebyedpi_RustVpnService_nativeCreate<'local>(
    mut env: jni::JNIEnv<'local>,
    service: jni::objects::JObject<'local>,
) {
    crate::flog!("VpnService: nativeCreate() вызван Java-стороной");

    // Настройки, сохранённые при запуске GUI. Если приложение ещё не
    // инициализировало их (сервис поднят системой — always-on VPN после
    // перезагрузки), берём значения по умолчанию.
    let cfg = app_config().unwrap_or_default();

    // Восстанавливаем JNI-контекст, если сервис создала сама система
    // (always-on VPN после перезагрузки): тогда `android_main` ещё не
    // выполнялся, а JavaVM нужен любому фоновому потоку.
    if platform::java_vm().is_none() {
        if let Err(e) = platform::init_context_from_service(&mut env) {
            crate::flog_err!("nativeCreate: контекст JNI: {e}");
        }
    }

    let req = platform::VpnRequest {
        address: cfg.tun_address.clone(),
        prefix: cfg.tun_prefix,
        mtu: cfg.tun_mtu,
        dns: cfg.dns_servers.clone(),
        session: "ByeByeDPI-Rust".to_string(),
    };

    // Строим интерфейс (Builder + establish + detachFd).
    let tun = match platform::build_vpn_interface(&mut env, &service, &req) {
        Ok(tun) => tun,
        Err(e) => {
            crate::flog_err!("nativeCreate: {e}");

            // Пытаемся корректно остановить сервис.
            let _ = env.call_method(&service, "stopSelf", "()V", &[]);
            return;
        }
    };

    crate::flog!("VpnService: TUN готов, fd={}", tun.read_fd);

    // Поднимаем стек и переводим GUI в состояние «работает».
    if let Some(controller) = app_controller() {
        controller.attach_tunnel(tun, &cfg);
    } else {
        crate::flog_err!("nativeCreate: контроллер не инициализирован");
        platform::stop_vpn();
    }
}

/// Колбэк `RustVpnService.onRevoke()`: система отключила VPN.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_example_byebyedpi_RustVpnService_nativeRevoke<'local>(
    _env: jni::JNIEnv<'local>,
    _service: jni::objects::JObject<'local>,
) {
    crate::flog_warn!("VpnService: VPN отозван системой");
    platform::on_service_revoked();
    if let Some(controller) = app_controller() {
        controller.stop();
    }
}

// ---------------------------------------------------------------------------
//  Desktop: заглушка android_main, чтобы код собирался без Android
// ---------------------------------------------------------------------------
#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub fn android_main() {}

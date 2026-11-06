//! Android-реализация платформенного слоя — **целиком на JNI, без Java/Kotlin**.
//!
//! # Как это работает (важно понять перед чтением кода)
//!
//! `android.net.VpnService.Builder` — это **внутренний (non-static) класс**.
//! Его конструктор и все методы (`addAddress`, `addRoute`, `addDnsServer`,
//! `establish`) неявно требуют `this` — то есть экземпляр `android.net.VpnService`.
//! Более того, `establish()` внутри вызывает `getService().establishVpn(mConfig)`,
//! а системный `Vpn.java` проверяет `Binder.getCallingUid() != mOwnerUID` —
//! то есть право создавать интерфейс есть **только у процесса, который прошёл
//! `VpnService.prepare()`** (получил app-op ACTIVATE_VPN), и `VpnService`
//! обязан быть объявлен в манифесте (`<service ... android:permission=
//! "android.permission.BIND_VPN_SERVICE">` + intent-filter
//! `android.net.VpnService`), иначе `establish()` вернёт `null`.
//!
//! Поэтому «правильный» путь в проекте такой (см. `docs/ANDROID_VPN_HOST.md`):
//!
//!  1. в манифесте объявлен сервис `com.example.byebyedpi.RustVpnService`,
//!     который наследует `android.net.VpnService`;
//!  2. при «Старте» мы через JNI вызываем `Context.startService(...)`,
//!     система создаёт сервис, который **грузит нашу же `.so`** и в
//!     `onCreate()` вызывает экспортированную нативную функцию
//!     `Java_com_example_byebyedpi_RustVpnService_nativeCreate` (см. `src/lib.rs`);
//!  3. из этой функции мы получаем `jobject` сервиса и уже на нём строим
//!     `VpnService.Builder` и вызываем `establish()` — ровно так, как требует ТЗ;
//!  4. из `ParcelFileDescriptor` достаём `fd` и отдаём его в `smoltcp`.
//!
//! Весь код ниже — это «кирпичики» шага 3-4. Каждый вызов JNI снабжён
//! комментарием: какой Java-метод вызывается и почему это нужно.
use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use jni::objects::{GlobalRef, JObject, JValue};
use jni::sys::{jint, jobject};
use jni::{JNIEnv, JavaVM};

use crate::config::AppConfig;
use crate::platform::VpnStart;
use crate::tunnel::TunFd;

// ---------------------------------------------------------------------------
//  Глобальное состояние
// ---------------------------------------------------------------------------
static START: OnceLock<Instant> = OnceLock::new();

/// Глобальная ссылка на JavaVM. Нужна, чтобы из любого фонового потока
/// (tokio-таски, поток чтения TUN) можно было сделать `attach_current_thread`
/// и вызвать Java-методы.
static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

/// Глобальная ссылка на объект `Activity`.
/// `activity_as_ptr()` в android-activity возвращает *непринадлежащий нам*
/// global ref, поэтому мы делаем свою копию через `NewGlobalRef` — так
/// указатель живёт столько, сколько нужно нам, и не зависит от JSVM.
static ACTIVITY: Mutex<Option<GlobalRef>> = Mutex::new(None);

/// Global ref на созданный `VpnService` (появляется в `nativeCreate`).
static VPN_SERVICE: Mutex<Option<GlobalRef>> = Mutex::new(None);

/// Global ref на `ParcelFileDescriptor` — держим его, чтобы система
/// не закрыла TUN, пока мы работаем. Закрывается в `stop_vpn`.
static TUN_PFD: Mutex<Option<GlobalRef>> = Mutex::new(None);

/// Последний выданный системой fd (для закрытия, если PFD уже потерян).
static TUN_FD: AtomicI32 = AtomicI32::new(-1);

/// Номер API Android (Build.VERSION.SDK_INT), узнаётся один раз.
static API_LEVEL: AtomicI32 = AtomicI32::new(0);

/// Ждём ли мы согласия пользователя на VPN.
static PENDING_CONSENT: AtomicI32 = AtomicI32::new(0);

/// Счётчик «эпох» запуска VPN: позволяет отбросить устаревший `nativeCreate`,
/// если пользователь успел нажать «Стоп» до старта сервиса.
static VPN_EPOCH: AtomicU64 = AtomicU64::new(0);

pub fn elapsed_secs_since_start() -> u64 {
    START.get_or_init(Instant::now).elapsed().as_secs()
}

/// Параметры, которые передаются Java-сервису при старте.
/// Упаковываются в `Intent` как extras (см. [`build_service_intent`]).
#[derive(Debug, Clone, Default)]
pub struct VpnRequest {
    pub address: String,
    pub prefix: u8,
    pub mtu: u16,
    pub dns: Vec<String>,
    pub session: String,
}

// ---------------------------------------------------------------------------
//  Данные платформы (конфиг, пути)
// ---------------------------------------------------------------------------
pub struct AndroidPlatform {
    /// `Context.getFilesDir()` — приватная директория приложения
    /// (`/data/data/com.example.byebyedpi/files`).
    pub files_dir: PathBuf,
}

impl crate::platform::Platform for AndroidPlatform {
    fn save_config(&self, cfg: &AppConfig) -> Result<(), String> {
        cfg.save(&self.files_dir.join("config.json"))
            .map_err(|e| e.to_string())
    }

    fn load_config(&self) -> AppConfig {
        AppConfig::load(&self.files_dir.join("config.json"))
    }

    fn log_file_path(&self) -> Option<PathBuf> {
        Some(self.files_dir.join("byebyedpi.log"))
    }
}

/// Сохранить JavaVM и превратить activity-указатель в собственный global ref.
///
/// Вызывается **один раз** из `android_main` (см. `src/lib.rs`), сразу после
/// того, как android-activity передал нам `AndroidApp`.
///
/// # Safety
/// `vm_ptr` — валидный `JavaVM*`, `activity_ptr` — валидный `jobject`
/// (глобальная ссылка, принадлежащая android-activity).
pub unsafe fn init_context(vm_ptr: *mut c_void, activity_ptr: *mut c_void) -> Result<(), String> {
    START.get_or_init(Instant::now);

    // 1) JavaVM. android-activity отдаёт `*mut c_void`, который на самом деле
    //    `*mut jni::sys::JavaVM`. `JavaVM::from_raw` — unsafe, потому что
    //    проверять валидность указателя нечем.
    // OnceLock::get_or_init здесь не подходит: инициализация может вернуть
    // ошибку, а замыкание обязано вернуть JavaVM. Поэтому «set, затем get».
    if JAVA_VM.get().is_none() {
        let vm = unsafe { JavaVM::from_raw(vm_ptr.cast()) }
            .map_err(|e| format!("JavaVM::from_raw: {e}"))?;
        let _ = JAVA_VM.set(vm);
    }
    let vm = JAVA_VM
        .get()
        .cloned()
        .ok_or_else(|| "JavaVM не сохранился".to_string())?;

    // 2) Присоединяемся к JVM (поток UI ещё не присоединён как «наш» поток,
    //    но attach безопасен и идемпотентен).
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| format!("attach_current_thread: {e}"))?;

    // 3) Делаем собственную глобальную ссылку на Activity.
    //    `NewGlobalRef` увеличивает счётчик ссылок JVM, поэтому объект
    //    не будет собран GC, пока мы её не удалим.
    let activity_obj = unsafe { JObject::from_raw(activity_ptr as jobject) };
    let global = env
        .new_global_ref(activity_obj)
        .map_err(|e| format!("NewGlobalRef(Activity): {e}"))?;
    *ACTIVITY.lock().unwrap() = Some(global);

    // 4) Узнаём Build.VERSION.SDK_INT — от него зависит набор API
    //    (например, `setMetered` появился в API 29).
    let sdk = read_api_level(&mut env).unwrap_or(0);
    API_LEVEL.store(sdk, Ordering::Relaxed);

    Ok(())
}

/// Восстановить контекст, когда сервис создала сама система.
///
/// Штатный путь (`android_main`) сохраняет JavaVM и Activity при старте
/// GUI. Но сервис может быть создан и без него — always-on VPN после
/// перезагрузки, а также «Блокировать соединения без VPN». В этом случае
/// Activity нет, а `VpnService` уже есть: он сам является `Context`, и его
/// достаточно, чтобы построить `Builder` и показать уведомление.
pub fn init_context_from_service(env: &mut JNIEnv) -> Result<(), String> {
    if JAVA_VM.get().is_none() {
        let vm = env
            .get_java_vm()
            .map_err(|e| format!("get_java_vm: {e}"))?;
        let _ = JAVA_VM.set(vm);
    }

    // Activity недоступна — запоминаем сам сервис как «контекст» для
    // foreground-уведомления (он вызывается уже на объекте сервиса).
    if ACTIVITY.lock().unwrap().is_none() {
        crate::flog_warn!(
            "Activity недоступна (сервис создан системой): работаем только через VpnService"
        );
    }

    if API_LEVEL.load(Ordering::Relaxed) == 0 {
        let sdk = read_api_level(env).unwrap_or(0);
        API_LEVEL.store(sdk, Ordering::Relaxed);
    }
    Ok(())
}

/// Вернуть JavaVM (для фоновых потоков).
pub fn java_vm() -> Option<JavaVM> {
    JAVA_VM.get().cloned()
}

/// Вернуть global ref на Activity.
pub fn activity() -> Option<GlobalRef> {
    ACTIVITY.lock().unwrap().clone()
}

/// Номер API Android (24..35), 0 если неизвестен.
pub fn api_level() -> i32 {
    API_LEVEL.load(Ordering::Relaxed)
}

/// Прочитать `android.os.Build$VERSION.SDK_INT`.
fn read_api_level(env: &mut JNIEnv) -> Result<i32, String> {
    // `SDK_INT` есть с API 1, его можно читать как у класса, так и у
    // объекта. Работаем через FindClass: это рекомендуемый путь из
    // нативного потока (классы загружает загрузчик приложения).
    let value = env
        .get_static_field(
            "android/os/Build$VERSION",
            "SDK_INT",
            "I",
        )
        .map_err(|e| format!("getStaticField(SDK_INT): {e}"))?
        .i()
        .map_err(|e| format!("SDK_INT is not int: {e}"))?;
    Ok(value as i32)
}

/// Получить `/data/data/<package>/files` через JNI.
///
/// Java-эквивалент:
/// ```java
/// File dir = activity.getFilesDir();
/// String path = dir.getAbsolutePath();
/// ```
pub fn files_dir(env: &mut JNIEnv, activity: &JObject) -> Result<PathBuf, String> {
    // Context.getFilesDir() -> java.io.File
    let file = env
        .call_method(activity, "getFilesDir", "()Ljava/io/File;", &[])
        .map_err(|e| format!("getFilesDir: {e}"))?
        .l()
        .map_err(|e| format!("getFilesDir returned non-object: {e}"))?;
    if file.is_null() {
        return Err("getFilesDir() вернул null".to_string());
    }

    // File.getAbsolutePath() -> String
    let path_obj = env
        .call_method(&file, "getAbsolutePath", "()Ljava/lang/String;", &[])
        .map_err(|e| format!("getAbsolutePath: {e}"))?
        .l()
        .map_err(|e| format!("getAbsolutePath returned non-string: {e}"))?;

    // `get_string` принимает именно `&JString` (в 0.21 нет Into).
    let jstr = jni::objects::JString::from(path_obj);
    let path = env
        .get_string(&jstr)
        .map_err(|e| format!("getString(absolutePath): {e}"))?;
    Ok(PathBuf::from(String::from(path)))
}

/// Пакет приложения: `Context.getPackageName()`.
#[allow(dead_code)]
pub fn package_name(env: &mut JNIEnv, activity: &JObject) -> Result<String, String> {
    let obj = env
        .call_method(activity, "getPackageName", "()Ljava/lang/String;", &[])
        .map_err(|e| format!("getPackageName: {e}"))?
        .l()
        .map_err(|e| format!("getPackageName returned non-string: {e}"))?;
    let jstr = jni::objects::JString::from(obj);
    let name = env
        .get_string(&jstr)
        .map_err(|e| format!("getString(packageName): {e}"))?;
    Ok(String::from(name))
}

/// Уже выдано ли согласие на VPN (app-op ACTIVATE_VPN).
///
/// Достоверно узнать это без вызова `VpnService.prepare()` нельзя, поэтому
/// функция возвращает `true`, только если мы уже прошли prepare в этой сессии
/// (`PENDING_CONSENT == 0` и сервис создан). GUI использует её лишь для
/// подсказки пользователю — реальная проверка всегда идёт через
/// [`prepare_vpn`] перед стартом.
#[allow(dead_code)]
pub fn has_vpn_permission() -> bool {
    PENDING_CONSENT.load(Ordering::Relaxed) == 0
}

/// Показать системный диалог согласия на VPN.
///
/// Java-эквивалент:
/// ```java
/// Intent intent = VpnService.prepare(context);
/// if (intent != null) activity.startActivityForResult(intent, REQ);
/// ```
///
/// `prepare()` возвращает:
///  * `null` — согласие уже есть, можно стартовать сервис;
///  * `Intent` — нужно показать пользователю системный экран подтверждения.
///
/// Мы всегда вызываем `prepare()` при старте: если он вернул Intent —
/// запускаем его через `Activity.startActivity` и просим пользователя
/// нажать «Старт» повторно после подтверждения.
pub fn prepare_vpn() -> Result<bool, String> {
    with_env_and_activity(|env, activity| {
        // VpnService.prepare(Context) — статический метод, возвращает Intent|null.
        let intent = env
            .call_static_method(
                "android/net/VpnService",
                "prepare",
                "(Landroid/content/Context;)Landroid/content/Intent;",
                &[JValue::from(activity)],
            )
            .map_err(|e| format!("VpnService.prepare: {e}"))?
            .l()
            .map_err(|e| format!("prepare returned non-object: {e}"))?;

        if intent.is_null() {
            // Согласие уже есть.
            PENDING_CONSENT.store(0, Ordering::Relaxed);
            return Ok(true);
        }

        // Показываем системный диалог.
        //
        // Activity.startActivity(Intent) — обычный запуск активити.
        // (Для результата нужен startActivityForResult, но нам результат не
        // нужен: после подтверждения пользователь нажимает «Старт» снова,
        // и prepare() вернёт null.)
        env.call_method(
            activity,
            "startActivity",
            "(Landroid/content/Intent;)V",
            &[JValue::from(&intent)],
        )
        .map_err(|e| format!("startActivity(prepare): {e}"))?;

        PENDING_CONSENT.store(1, Ordering::Relaxed);
        Ok(false)
    })
}

/// Имя нашего Java-класса сервиса (он объявлен в манифесте и наследует
/// `android.net.VpnService`; Java-кода в проекте нет — класс создаётся
/// только как точка входа в нативную библиотеку).
pub const VPN_SERVICE_CLASS: &str = "com.example.byebyedpi.RustVpnService";

/// Собрать `Intent` для запуска сервиса и вызвать `startService`.
///
/// Java-эквивалент:
/// ```java
/// Intent i = new Intent();
/// i.setClassName("com.example.byebyedpi", "com.example.byebyedpi.RustVpnService");
/// i.putExtra("address", "10.111.222.2"); ...
/// context.startService(i);
/// ```
///
/// На Android 8+ (API 26) фоновые сервисы запрещены, поэтому для VPN
/// используется `startForegroundService` (сервис обязан вызвать
/// `startForeground()` в первые 5 секунд — это делает системный VpnService
/// при `establish()`); для API ≥ 26 выбираем именно его.
pub fn start_vpn_service(req: &VpnRequest) -> Result<(), String> {
    with_env_and_activity(|env, activity| {
        // --- 1) new Intent() ------------------------------------------------
        let intent = env
            .new_object("android/content/Intent", "()V", &[])
            .map_err(|e| format!("new Intent(): {e}"))?;

        // --- 2) packageName = Context.getPackageName() ----------------------
        let pkg_obj = env
            .call_method(activity, "getPackageName", "()Ljava/lang/String;", &[])
            .map_err(|e| format!("getPackageName: {e}"))?
            .l()
            .map_err(|e| format!("getPackageName non-string: {e}"))?;

        // --- 3) intent.setClassName(pkg, "com.example.byebyedpi.RustVpnService")
        let cls_name = env
            .new_string(VPN_SERVICE_CLASS)
            .map_err(|e| format!("newString(service class): {e}"))?;
        env.call_method(
            &intent,
            "setClassName",
            "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
            &[JValue::from(&pkg_obj), JValue::from(&cls_name)],
        )
        .map_err(|e| format!("setClassName: {e}"))?;

        // --- 4) intent.putExtra(...) — параметры интерфейса ---------------- //
        // Сервис прочитает их в onCreate и передаст в нативный код.
        for (key, value) in [
            ("address", req.address.as_str()),
            ("session", req.session.as_str()),
        ] {
            let k = env.new_string(key).map_err(|e| e.to_string())?;
            let v = env.new_string(value).map_err(|e| e.to_string())?;
            env.call_method(
                &intent,
                "putExtra",
                "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
                &[JValue::from(&k), JValue::from(&v)],
            )
            .map_err(|e| format!("putExtra({key}): {e}"))?;
        }

        let k = env.new_string("mtu").map_err(|e| e.to_string())?;
        env.call_method(
            &intent,
            "putExtra",
            "(Ljava/lang/String;I)Landroid/content/Intent;",
            &[JValue::from(&k), JValue::Int(req.mtu as jint)],
        )
        .map_err(|e| format!("putExtra(mtu): {e}"))?;

        let k = env.new_string("prefix").map_err(|e| e.to_string())?;
        env.call_method(
            &intent,
            "putExtra",
            "(Ljava/lang/String;I)Landroid/content/Intent;",
            &[JValue::from(&k), JValue::Int(req.prefix as jint)],
        )
        .map_err(|e| format!("putExtra(prefix): {e}"))?;

        let k = env.new_string("dns").map_err(|e| e.to_string())?;
        let joined = env
            .new_string(req.dns.join(","))
            .map_err(|e| e.to_string())?;
        env.call_method(
            &intent,
            "putExtra",
            "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
            &[JValue::from(&k), JValue::from(&joined)],
        )
        .map_err(|e| format!("putExtra(dns): {e}"))?;

        // --- 5) startService / startForegroundService ---------------------- //
        // Context.startService(Intent) -> ComponentName
        // На API >= 26 используем startForegroundService: иначе система
        // запретит запуск фонового сервиса. Сам foreground-режим включает
        // наш nativeCreate через `startForeground()` (см. platform::foreground).
        let method = if api_level() >= 26 {
            "startForegroundService"
        } else {
            "startService"
        };
        env.call_method(
            activity,
            method,
            "(Landroid/content/Intent;)Landroid/content/ComponentName;",
            &[JValue::from(&intent)],
        )
        .map_err(|e| format!("{method}: {e}"))?;

        Ok(())
    })
}

/// Создать `VpnService.Builder`, сконфигурировать его и вызвать `establish()`.
///
/// **Это сердце JNI-интеграции.** Каждый вызов повторяет Java-код:
///
/// ```java
/// Builder builder = service.new Builder();            // внутренний класс!
/// builder.setSession("ByeByeDPI-Rust");
/// builder.setMtu(mtu);
/// builder.addAddress("10.111.222.2", 24);
/// builder.addRoute("0.0.0.0", 0);                     // весь IPv4 в туннель
/// builder.addRoute("::", 0);                          // и IPv6
/// builder.addDnsServer("10.111.222.1");
/// ParcelFileDescriptor pfd = builder.establish();
/// int fd = pfd.detachFd();                            // забираем владение
/// ```
///
/// Возвращает готовый [`TunFd`] с двумя дескрипторами:
///  * `read_fd` — для чтения исходящих пакетов (приложения -> сеть);
///  * `write_fd` — для записи входящих пакетов (сеть -> приложения).
///
/// # Почему два fd
/// `VpnService.Builder.establish()` возвращает один `ParcelFileDescriptor`.
/// Его нельзя читать и писать одновременно из двух потоков без гонок: TUN
/// на Linux — это character device, а Android поверх него добавляет
/// мультиплексирование. Поэтому мы делаем `dup()` (через `AsRawFd` +
/// `libc::dup`) и получаем два независимых дескриптора, каждый со своим
/// файловым «смещением» в таблице файлов процесса. Это стандартная практика
/// в Android-VPN клиентах (hev-socks5-tunnel, tun2socks и др.).
pub fn build_vpn_interface(
    env: &mut JNIEnv,
    service: &JObject,
    req: &VpnRequest,
) -> Result<TunFd, String> {
    // ------------------------------------------------------------------ //
    // 1) new VpnService.Builder() — ВНУТРЕННИЙ класс.
    //    JNI-имя внутреннего класса пишется через '$':
    //    android.net.VpnService$Builder
    //    Конструктор объявлен как `public Builder()` — значит дескриптор "()V".
    //    Так как класс внутренний (не static), `NewObject` передаёт
    //    внешний экземпляр (service) как нулевой аргумент конструктора —
    //    ровно это делает и Java-компилятор.
    // ------------------------------------------------------------------ //
    let builder_class = env
        .find_class("android/net/VpnService$Builder")
        .map_err(|e| format!("find_class(VpnService$Builder): {e}"))?;

    let builder = env
        .new_object(
            &builder_class,
            "(Landroid/net/VpnService;)V",
            &[JValue::from(service)],
        )
        .map_err(|e| format!("new VpnService$Builder(service): {e}"))?;
    if builder.is_null() {
        return Err(
            "Не удалось создать VpnService$Builder: сервис не является VpnService \
             или процесс не прошёл VpnService.prepare()"
                .to_string(),
        );
    }

    let call_builder = |env: &mut JNIEnv<'_>,
                        name: &str,
                        sig: &str,
                        args: &[JValue]|
     -> Result<(), String> {
        env.call_method(&builder, name, sig, args)
            .map_err(|e| format!("Builder.{name}{sig}: {e}"))
    };

    // ------------------------------------------------------------------ //
    // 2) setSession("ByeByeDPI-Rust") — имя сессии в системном диалоге.
    // ------------------------------------------------------------------ //
    let session = env
        .new_string(&req.session)
        .map_err(|e| format!("newString(session): {e}"))?;
    call_builder(
        env,
        "setSession",
        "(Ljava/lang/String;)Landroid/net/VpnService$Builder;",
        &[JValue::from(&session)],
    )?;

    // ------------------------------------------------------------------ //
    // 3) setMtu(mtu) — размер пакета на виртуальном интерфейсе.
    //    1500 — стандарт Ethernet; некоторые сети требуют 1400/1280.
    // ------------------------------------------------------------------ //
    call_builder(
        env,
        "setMtu",
        "(I)Landroid/net/VpnService$Builder;",
        &[JValue::Int(req.mtu as jint)],
    )?;

    // ------------------------------------------------------------------ //
    // 4) addAddress("10.111.222.2", 24) — адрес нашего конца туннеля.
    //    Приложения будут считать, что это их IP.
    // ------------------------------------------------------------------ //
    let addr = env
        .new_string(&req.address)
        .map_err(|e| format!("newString(address): {e}"))?;
    call_builder(
        env,
        "addAddress",
        "(Ljava/lang/String;I)Landroid/net/VpnService$Builder;",
        &[JValue::from(&addr), JValue::Int(req.prefix as jint)],
    )?;

    // ------------------------------------------------------------------ //
    // 5) addRoute("0.0.0.0", 0) — заворачиваем ВЕСЬ IPv4-трафик в туннель.
    //    Это ключевой вызов: без него в TUN не попадёт ничего.
    // ------------------------------------------------------------------ //
    let v4_any = env.new_string("0.0.0.0").map_err(|e| e.to_string())?;
    call_builder(
        env,
        "addRoute",
        "(Ljava/lang/String;I)Landroid/net/VpnService$Builder;",
        &[JValue::from(&v4_any), JValue::Int(0)],
    )?;

    // ------------------------------------------------------------------ //
    // 6) addRoute("::", 0) — то же для IPv6.
    //    Если устройство/сеть не поддерживает IPv6, вызов просто игнорируется
    //    системой (ошибки не будет), поэтому оборачиваем в `let _ =`.
    // ------------------------------------------------------------------ //
    if let Ok(v6_any) = env.new_string("::") {
        let _ = call_builder(
            env,
            "addRoute",
            "(Ljava/lang/String;I)Landroid/net/VpnService$Builder;",
            &[JValue::from(&v6_any), JValue::Int(0)],
        );
    }

    // ------------------------------------------------------------------ //
    // 7) addDnsServer(...) — DNS, который получат приложения.
    //    Мы отдаём «свой» адрес 10.111.222.1: запросы к нему попадут в наш
    //    smoltcp-стек, где их перехватит UDP-прокси (это позволяет
    //    применять DPI-обход и к DNS).
    // ------------------------------------------------------------------ //
    for dns in &req.dns {
        if let Ok(dns_obj) = env.new_string(dns) {
            call_builder(
                env,
                "addDnsServer",
                "(Ljava/lang/String;)Landroid/net/VpnService$Builder;",
                &[JValue::from(&dns_obj)],
            )?;
        }
    }

    // ------------------------------------------------------------------ //
    // 8) (API >= 29) setMetered(false) — не считать трафик «платным»:
    //    иначе система может ограничить фоновую передачу в VPN.
    // ------------------------------------------------------------------ //
    if api_level() >= 29 {
        let _ = call_builder(
            env,
            "setMetered",
            "(Z)Landroid/net/VpnService$Builder;",
            &[JValue::Bool(0)],
        );
    }

    let pfd = env
        .call_method(&builder, "establish", "()Landroid/os/ParcelFileDescriptor;", &[])
        .map_err(|e| format!("establish(): {e}"))?
        .l()
        .map_err(|e| format!("establish returned non-object: {e}"))?;

    if pfd.is_null() {
        return Err("establish() вернул null: нет согласия VPN, сервис не объявлен \
                    в манифесте с BIND_VPN_SERVICE или приложение не прошло prepare()"
            .to_string());
    }

    // Держим PFD живым до «Стопа».
    let pfd_global = env
        .new_global_ref(&pfd)
        .map_err(|e| format!("NewGlobalRef(ParcelFileDescriptor): {e}"))?;
    *TUN_PFD.lock().unwrap() = Some(pfd_global);

    // ------------------------------------------------------------------ //
    // 10) Достаём целочисленный fd.
    //
    //     Вариант A (API >= 24): detachFd() — «отвязывает» fd от PFD и
    //     передаёт владение нам: закрывать нужно самостоятельно, PFD.close()
    //     больше не закроет его. Это то, что требует ТЗ.
    //
    //     Вариант B (fallback): getFd() — только читает номер, владение
    //     остаётся у PFD; тогда закрывать надо через PFD.close().
    // ------------------------------------------------------------------ //
    let raw_fd: jint = if api_level() >= 24 {
        env.call_method(&pfd, "detachFd", "()I", &[])
            .map_err(|e| format!("detachFd: {e}"))?
            .i()
            .map_err(|e| format!("detachFd returned non-int: {e}"))?
    } else {
        env.call_method(&pfd, "getFd", "()I", &[])
            .map_err(|e| format!("getFd: {e}"))?
            .i()
            .map_err(|e| format!("getFd returned non-int: {e}"))?
    };

    if raw_fd < 0 {
        return Err(format!("Некорректный fd от ParcelFileDescriptor: {raw_fd}"));
    }
    TUN_FD.store(raw_fd, Ordering::Relaxed);

    // ------------------------------------------------------------------ //
    // 11) dup() — второй дескриптор для записи.
    //
    //     TUN-устройство Android (через /dev/tun) — это поток пакетов:
    //     read() забирает исходящие пакеты, write() вставляет входящие.
    //     Один и тот же fd нельзя одновременно читать в одном потоке и
    //     писать в другом без блокировок на уровне драйвера, поэтому
    //     делаем dup: оба дескриптора указывают на одно устройство, но
    //     имеют независимую позицию/флаги.
    // ------------------------------------------------------------------ //
    let dup_fd = unsafe { libc::dup(raw_fd) };
    if dup_fd < 0 {
        unsafe { libc::close(raw_fd) };
        return Err(format!(
            "dup({raw_fd}) не удался: {}",
            std::io::Error::last_os_error()
        ));
    }

    // ------------------------------------------------------------------ //
    // 12) Переводим оба fd в НЕблокирующий режим.
    //     smoltcp + tokio опрашивают устройство по таймеру; блокирующий
    //     read() подвесил бы весь поток. Ставим O_NONBLOCK, а ожидание
    //     делаем через tokio::time::sleep в `tunnel::run`.
    // ------------------------------------------------------------------ //
    for fd in [raw_fd, dup_fd] {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
    }

    Ok(TunFd {
        read_fd: raw_fd,
        write_fd: dup_fd,
        mtu: req.mtu as usize,
    })
}

/// Полный цикл запуска VPN: prepare -> startService.
///
/// * `Ok(VpnStart::Ready(fd))` — сервис уже был запущен и сразу отдал fd
///   (быстрый путь, когда `nativeCreate` успел выполниться);
/// * `Ok(VpnStart::NeedConsent)` — показан системный диалог;
/// * `Ok(VpnStart::Failed)` / `Err` — ошибка.
pub fn start_vpn(cfg: &AppConfig) -> VpnStart {
    // 1) Согласие пользователя.
    match prepare_vpn() {
        Ok(true) => {}
        Ok(false) => {
            return VpnStart::NeedConsent;
        }
        Err(e) => return VpnStart::Failed(e),
    }

    // 2) Новая «эпоха» — старые nativeCreate будут проигнорированы.
    VPN_EPOCH.fetch_add(1, Ordering::SeqCst);

    // 3) Стартуем сервис; он сам вызовет наш nativeCreate, откуда придёт fd.
    let req = VpnRequest {
        address: cfg.tun_address.clone(),
        prefix: cfg.tun_prefix,
        mtu: cfg.tun_mtu,
        dns: cfg.dns_servers.clone(),
        session: "ByeByeDPI-Rust".to_string(),
    };

    match start_vpn_service(&req) {
        Ok(()) => VpnStart::Failed(
            "Сервис VPN запущен. Дескриптор туннеля придёт асинхронно \
             (см. nativeCreate); GUI переключится в состояние «Работает»."
                .to_string(),
        ),
        Err(e) => VpnStart::Failed(e),
    }
}

/// Остановить VPN: закрыть TUN и попросить систему остановить сервис.
pub fn stop_vpn() {
    // 1) Отзываем все «эпохи» — новые nativeCreate игнорируются.
    VPN_EPOCH.fetch_add(1, Ordering::SeqCst);

    // 2) Закрываем fd.
    let fd = TUN_FD.swap(-1, Ordering::Relaxed);
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
    *TUN_PFD.lock().unwrap() = None;
    *VPN_SERVICE.lock().unwrap() = None;

    // 3) Останавливаем сервис: Context.stopService(Intent).
    let _ = with_env_and_activity(|env, activity| {
        let intent = env
            .new_object("android/content/Intent", "()V", &[])
            .map_err(|e| e.to_string())?;
        let pkg = env
            .call_method(activity, "getPackageName", "()Ljava/lang/String;", &[])
            .map_err(|e| e.to_string())?
            .l()
            .map_err(|e| e.to_string())?;
        let cls = env.new_string(VPN_SERVICE_CLASS).map_err(|e| e.to_string())?;
        env.call_method(
            &intent,
            "setClassName",
            "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
            &[JValue::from(&pkg), JValue::from(&cls)],
        )
        .map_err(|e| e.to_string())?;
        env.call_method(
            activity,
            "stopService",
            "(Landroid/content/Intent;)Z",
            &[JValue::from(&intent)],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    });
}

/// Выполнить замыкание с `JNIEnv` и global ref на Activity.
fn with_env_and_activity<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce(&mut JNIEnv, &JObject) -> Result<T, String>,
{
    let vm = java_vm().ok_or_else(|| "JavaVM не инициализирован".to_string())?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| format!("attach_current_thread: {e}"))?;
    let activity = activity().ok_or_else(|| "Activity недоступна".to_string())?;
    f(&mut env, activity.as_obj())
}

/// Настройка сервиса после его создания системой.
///
/// Сейчас этот путь не используется: `nativeCreate` умеет всё сам через
/// [`build_vpn_interface`], а лишний глобальный ref на сервис держать
/// незачем. Функция оставлена как документированный вход для случая, когда
/// сервис создаётся системой (always-on VPN после перезагрузки).
#[allow(dead_code)]
pub fn on_service_created<'local>(
    service: JObject<'local>,
    req: VpnRequest,
) -> Result<TunFd, String> {
    let vm = java_vm().ok_or_else(|| "JavaVM не инициализирован".to_string())?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| format!("attach_current_thread: {e}"))?;

    let service_global = env
        .new_global_ref(&service)
        .map_err(|e| format!("NewGlobalRef(VpnService): {e}"))?;
    *VPN_SERVICE.lock().unwrap() = Some(service_global.clone());

    let tun = build_vpn_interface(&mut env, service_global.as_obj(), &req)?;

    // ВАЖНО: переводим сервис в foreground. Android требует этого для
    // любого VPN-приложения (FGS), иначе процесс будет «усыплён».
    // Делаем это ПОСЛЕ establish(): к этому моменту система уже разрешила
    // сервису быть foreground (Type.SPECIAL_USE из манифеста).
    match super::foreground::start_foreground(&mut env, service_global.as_obj()) {
        Ok(true) => {}
        Ok(false) => crate::flog_warn!(
            "startForeground не выполнен: VPN будет работать, пока приложение на экране"
        ),
        Err(e) => crate::flog_warn!("startForeground: {e}"),
    }

    Ok(tun)
}

/// Вызывается из `RustVpnService.onRevoke()`: система принудительно
/// отключила VPN (пользователь нажал «Отключить» в системных настройках).
pub fn on_service_revoked() {
    let fd = TUN_FD.swap(-1, Ordering::Relaxed);
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
    *TUN_PFD.lock().unwrap() = None;
    *VPN_SERVICE.lock().unwrap() = None;
}

/// Текущая «эпоха» VPN — чтобы GUI мог понять, что сервис ещё актуален.
#[allow(dead_code)]
pub fn current_epoch() -> u64 {
    VPN_EPOCH.load(Ordering::SeqCst)
}

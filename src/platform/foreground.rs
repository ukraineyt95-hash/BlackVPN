//! Promotion сервиса в foreground — через JNI, без Java-кода.
//!
//! # Зачем
//! Начиная с Android 8 любое приложение, удерживающее VPN, обязано держать
//! **foreground-сервис** с постоянным уведомлением, иначе система «усыпит»
//! процесс и соединение развалится. `android.net.VpnService` сама этого НЕ
//! делает: в AOSP `establish()` нет вызова `startForeground()` — это
//! ответственность приложения.
//!
//! Здесь мы вызываем из Rust:
//! ```java
//! NotificationChannel ch = new NotificationChannel(
//!         "byebyedpi", "VPN", NotificationManager.IMPORTANCE_LOW);
//! manager.createNotificationChannel(ch);
//! Notification n = new Notification.Builder(this, "byebyedpi")
//!         .setContentTitle("ByeByeDPI-Rust")
//!         .setContentText("Обход блокировок активен")
//!         .setSmallIcon(icon)
//!         .setOngoing(true)
//!         .build();
//! startForeground(1, n);
//! ```
//!
//! # Иконка
//! Ресурсов в APK нет (мы не тащим `res/`), поэтому id иконки достаётся
//! рефлексией из `android.R$drawable` — берём первый доступный
//! системный drawable из списка кандидатов. Если ничего не нашли —
//! возвращаем `None`, и вызывающая сторона просто пропускает уведомление
//! (VPN при этом продолжает работать, пока приложение на экране).
use jni::objects::{JObject, JValue};
use jni::JNIEnv;

/// Идентификатор канала уведомлений.
const CHANNEL_ID: &str = "byebyedpi_vpn";

/// Идентификатор уведомления (id в `startForeground`).
const NOTIFICATION_ID: i32 = 0x42;

/// Кандидаты на системную иконку (в порядке предпочтения).
const ICON_CANDIDATES: &[&str] = &[
    "stat_sys_vpn",
    "stat_sys_download",
    "stat_notify_sync",
    "ic_dialog_info",
    "sym_def_app_icon",
];

/// Поднять сервис в foreground.
///
/// Возвращает `Ok(true)`, если уведомление показано, `Ok(false)` — если
/// не удалось (нет иконки/нет разрешения), `Err` — при ошибке JNI.
pub fn start_foreground(env: &mut JNIEnv, service: &JObject) -> Result<bool, String> {
    // ------------------------------------------------------------------ //
    // 1) NotificationManager: service.getSystemService(Context.NOTIFICATION_SERVICE)
    // ------------------------------------------------------------------ //
    let service_name = env
        .get_static_field(
            "android/content/Context",
            "NOTIFICATION_SERVICE",
            "Ljava/lang/String;",
        )
        .map_err(|e| format!("NOTIFICATION_SERVICE: {e}"))?
        .l()
        .map_err(|e| format!("NOTIFICATION_SERVICE non-object: {e}"))?;

    let manager = env
        .call_method(
            service,
            "getSystemService",
            "(Ljava/lang/String;)Ljava/lang/Object;",
            &[JValue::from(&service_name)],
        )
        .map_err(|e| format!("getSystemService: {e}"))?
        .l()
        .map_err(|e| format!("getSystemService non-object: {e}"))?;

    if manager.is_null() {
        return Err("getSystemService(NOTIFICATION_SERVICE) вернул null".into());
    }

    // ------------------------------------------------------------------ //
    // 2) Канал уведомлений (только API 26+; ниже каналы не нужны).
    // ------------------------------------------------------------------ //
    if super::api_level() >= 26 {
        create_channel(env, &manager)?;
    }

    // ------------------------------------------------------------------ //
    // 3) Иконка (рефлексия по android.R$drawable).
    // ------------------------------------------------------------------ //
    let icon = match find_system_icon(env) {
        Ok(id) => id,
        Err(e) => {
            crate::flog_warn!("Не удалось найти системную иконку: {e}");
            return Ok(false);
        }
    };

    // ------------------------------------------------------------------ //
    // 4) text = "ByeByeDPI-Rust" (название приложения)
    //    Используем строку из ресурсов системы не будем — просто литерал.
    // ------------------------------------------------------------------ //
    let title = env
        .new_string("ByeByeDPI-Rust")
        .map_err(|e| format!("newString(title): {e}"))?;
    let text = env
        .new_string("Обход блокировок активен")
        .map_err(|e| format!("newString(text): {e}"))?;
    let channel = env
        .new_string(CHANNEL_ID)
        .map_err(|e| format!("newString(channel): {e}"))?;

    // ------------------------------------------------------------------ //
    // 5) Notification.Builder
    //    API 26+: new Notification.Builder(Context, String channelId)
    //    API <26 : new Notification.Builder(Context)
    // ------------------------------------------------------------------ //
    let builder = if super::api_level() >= 26 {
        env.new_object(
            "android/app/Notification$Builder",
            "(Landroid/content/Context;Ljava/lang/String;)V",
            &[JValue::from(service), JValue::from(&channel)],
        )
    } else {
        env.new_object(
            "android/app/Notification$Builder",
            "(Landroid/content/Context;)V",
            &[JValue::from(service)],
        )
    }
    .map_err(|e| format!("new Notification.Builder: {e}"))?;

    for (name, sig, args) in [
        (
            "setContentTitle",
            "(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;",
            vec![JValue::from(&title)],
        ),
        (
            "setContentText",
            "(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;",
            vec![JValue::from(&text)],
        ),
        (
            "setSmallIcon",
            "(I)Landroid/app/Notification$Builder;",
            vec![JValue::Int(icon)],
        ),
        (
            "setOngoing",
            "(Z)Landroid/app/Notification$Builder;",
            vec![JValue::Bool(1)],
        ),
        (
            "setShowWhen",
            "(Z)Landroid/app/Notification$Builder;",
            vec![JValue::Bool(0)],
        ),
    ] {
        env.call_method(&builder, name, sig, &args)
            .map_err(|e| format!("Notification.Builder.{name}: {e}"))?;
    }

    // ------------------------------------------------------------------ //
    // 6) Notification n = builder.build()
    // ------------------------------------------------------------------ //
    let notification = env
        .call_method(&builder, "build", "()Landroid/app/Notification;", &[])
        .map_err(|e| format!("Notification.build: {e}"))?
        .l()
        .map_err(|e| format!("build returned non-object: {e}"))?;

    if notification.is_null() {
        return Err("Notification.Builder.build() вернул null".into());
    }

    // ------------------------------------------------------------------ //
    // 7) service.startForeground(NOTIFICATION_ID, notification)
    //
    //    На API 29+ есть перегрузка с foregroundServiceType; используем
    //    простую — тип берётся из манифеста (specialUse).
    // ------------------------------------------------------------------ //
    env.call_method(
        service,
        "startForeground",
        "(ILandroid/app/Notification;)V",
        &[JValue::Int(NOTIFICATION_ID), JValue::from(&notification)],
    )
    .map_err(|e| format!("startForeground: {e}"))?;

    crate::flog!("Сервис переведён в foreground (уведомление показано)");
    Ok(true)
}

fn create_channel(env: &mut JNIEnv, manager: &JObject) -> Result<(), String> {
    // IMPORTANCE_LOW = 2: без звука, но видно в шторке.
    let channel_id = env
        .new_string(CHANNEL_ID)
        .map_err(|e| e.to_string())?;
    let name = env.new_string("VPN").map_err(|e| e.to_string())?;

    let channel = env
        .new_object(
            "android/app/NotificationChannel",
            "(Ljava/lang/String;Ljava/lang/CharSequence;I)V",
            &[
                JValue::from(&channel_id),
                JValue::from(&name),
                JValue::Int(2),
            ],
        )
        .map_err(|e| format!("new NotificationChannel: {e}"))?;

    // setDescription — необязательно, но полезно.
    let desc = env
        .new_string("Уведомление о работе VPN")
        .map_err(|e| e.to_string())?;
    let _ = env.call_method(
        &channel,
        "setDescription",
        "(Ljava/lang/String;)V",
        &[JValue::from(&desc)],
    );

    env.call_method(
        manager,
        "createNotificationChannel",
        "(Landroid/app/NotificationChannel;)V",
        &[JValue::from(&channel)],
    )
    .map_err(|e| format!("createNotificationChannel: {e}"))?;

    Ok(())
}

/// Найти id публичного системного drawable через рефлексию.
fn find_system_icon(env: &mut JNIEnv) -> Result<i32, String> {
    // Field f = android.R$drawable.class.getField(name);  int id = f.getInt(null);
    let class = env
        .find_class("android/R$drawable")
        .map_err(|e| format!("find_class(android.R$drawable): {e}"))?;

    for candidate in ICON_CANDIDATES {
        let field_name = match env.new_string(candidate) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // getField(String) -> java.lang.reflect.Field
        let field = match env.call_method(
            &class,
            "getField",
            "(Ljava/lang/String;)Ljava/lang/reflect/Field;",
            &[JValue::from(&field_name)],
        ) {
            Ok(v) => match v.l() {
                Ok(f) => f,
                Err(_) => continue,
            },
            Err(_) => {
                // Поле отсутствует — сбрасываем возможное исключение.
                let _ = env.exception_clear();
                continue;
            }
        };

        match env.call_method(
            &field,
            "getInt",
            "(Ljava/lang/Object;)I",
            &[JValue::from(&JObject::null())],
        ) {
            Ok(v) => {
                if let Ok(id) = v.i() {
                    if id != 0 {
                        crate::flog_dbg!("Иконка уведомления: android.R.drawable.{candidate} = {id}");
                        return Ok(id);
                    }
                }
            }
            Err(_) => {
                let _ = env.exception_clear();
            }
        }
    }

    Err("ни один системный drawable не найден".into())
}

/// Запросить разрешение POST_NOTIFICATIONS (API 33+).
///
/// Без него уведомление foreground-сервиса не показывается (но сервис
/// продолжает работать). Вызывается один раз при старте GUI.
pub fn request_notification_permission(env: &mut JNIEnv, activity: &JObject) -> Result<(), String> {
    if super::api_level() < 33 {
        return Ok(());
    }

    // Строковый массив из одного элемента: {"android.permission.POST_NOTIFICATIONS"}
    let perm = env
        .new_string("android.permission.POST_NOTIFICATIONS")
        .map_err(|e| e.to_string())?;
    let array = env
        .new_object_array(1, "java/lang/String;", JObject::from(perm))
        .map_err(|e| format!("newObjectArray: {e}"))?;

    // Activity.requestPermissions(String[], int)
    env.call_method(
        activity,
        "requestPermissions",
        "([Ljava/lang/String;I)V",
        &[JValue::from(&array), JValue::Int(0x50)],
    )
    .map_err(|e| format!("requestPermissions: {e}"))?;

    Ok(())
}

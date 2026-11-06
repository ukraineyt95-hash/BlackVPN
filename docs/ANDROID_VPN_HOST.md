# Как это работает: Android VPN из чистого Rust

Документ объясняет, почему в проекте нет Java/Kotlin, как всё-таки удалось
поднять настоящий Android VPN и где проходят границы «чистого Rust».

---

## 1. Проблема: `VpnService.Builder` нельзя просто создать

По ТЗ нужно вызвать из Rust:

```rust
builder.addRoute("0.0.0.0", 0);
builder.addAddress("10.111.222.2", 24);
let pfd = builder.establish();   // -> ParcelFileDescriptor -> fd
```

Но у этого вызова есть жёсткие требования платформы (проверено по исходникам
AOSP `core/java/android/net/VpnService.java` и
`services/core/java/com/android/server/connectivity/Vpn.java`):

| Требование AOSP | Что это значит на практике |
|---|---|
| `Builder` — **внутренний (non-static) класс** `VpnService$Builder` | `NewObject` обязан передать внешний экземпляр `VpnService` как аргумент JNI-конструктора |
| `establish()` вызывает `getService().establishVpn(mConfig)` | Вызов идёт в системный `connectivity`-сервис по binder |
| `if (Binder.getCallingUid() != mOwnerUID) return null;` | Право создать туннель есть **только у UID владельца**, который прошёл `prepare()` |
| `if (!isVpnServicePreConsented(...)) return null;` | Нужен app-op `ACTIVATE_VPN` (выдаётся диалогом `VpnService.prepare()`) |
| `packageManager.resolveService(intent)` + проверка `BIND_VPN_SERVICE` | В манифесте **обязан** быть `<service>` с `android:permission="android.permission.BIND_VPN_SERVICE"` и `<action android:name="android.net.VpnService"/>` |
| `mConfig.user = VpnService.this.getClass().getName()` | Класс сервиса, который передаётся системе, — это класс **пользовательского наследника** |

Из последнего пункта следует главное: **сервис должен быть собственным
классом-наследником `android.net.VpnService`**. Объявить в манифесте
`android:name="android.net.VpnService"` нельзя — система создаёт экземпляр
через `Class.newInstance()` от имени приложения, а классы фреймворка живут
в чужом CLASSPATH и не являются «нашими» сервисами.

Итого нужен ровно один маленький класс:

```java
package com.example.byebyedpi;
public class RustVpnService extends android.net.VpnService {
    private native void nativeCreate();   // → Rust
    private native void nativeRevoke();   // → Rust
    @Override public void onCreate() { nativeCreate(); super.onCreate(); }
    @Override public void onRevoke() { nativeRevoke(); super.onRevoke(); }
}
```

---

## 2. Решение: этот класс генерируется из Rust

В репозитории **нет ни одного файла `.java` или `.kt`**. Класс-мост
создаётся как байткод DEX программно — модуль
[`src/apk/dex.rs`](../src/apk/dex.rs):

* `build_bridge_dex()` собирает валидный `classes.dex`
  (magic `dex\n035\0`, `string_ids`, `type_ids`, `proto_ids`, `method_ids`,
  `class_defs`, `code_item`, `class_data_item`, `map_list`, SHA-1 + Adler-32);
* байткод — 4 коротких метода:
  `invoke-direct {v0}` (конструктор), `invoke-virtual {v0}` (вызов нативного
  метода), `invoke-super {v0}` (вызов реализации базового класса),
  `return-void`;
* нативные методы `nativeCreate`/`nativeRevoke` объявлены с флагом
  `ACC_NATIVE` — их реализует наш `.so`.

DEX-файл попадает в APK при сборке утилитой
`cargo run --bin packager` (см. `src/bin/packager.rs`):
`aapt package` → `aapt add classes.dex lib/<abi>/libbyebyedpi.so` →
`zipalign` → `apksigner`.

> **Важно про `android:hasCode`.** Атрибут `hasCode="false"` в манифесте
> **убирается**, когда в APK появляется `classes.dex` (иначе система
> проигнорирует DEX). `packager` подставляет это автоматически по наличию
> `classes.dex`.

### Что в этом коде «не Rust»

Только DEX-байткод из четырёх инструкций, которые ничего не делают, кроме
передачи управления в Rust. Вся логика — выбор адресов, маршрутов, DNS,
`establish()`, закрытие `fd`, foreground-уведомление — выполняется
Rust-кодом через JNI. Исходников на Java/Kotlin в проекте нет.

---

## 3. Полный путь «Старт» → работающий туннель

```
Gtk/egui кнопка «Старт»
   │
   ├─(1) VpnService.prepare(activity)                     [Rust → JNI]
   │       null  → согласие уже есть
   │       Intent→ startActivity(Intent), ждём пользователя
   │
   ├─(2) Context.startForegroundService(Intent)           [Rust → JNI]
   │       Intent.setClassName(pkg, "com.example.byebyedpi.RustVpnService")
   │       + extras (address, prefix, mtu, dns, session)
   │
   │   ... система поднимает сервис ...
   │
   ├─(3) RustVpnService.onCreate() → nativeCreate()        [DEX → Rust]
   │       └─ Java_com_example_byebyedpi_RustVpnService_nativeCreate()
   │
   ├─(4) new VpnService$Builder()                          [Rust → JNI]
   │       (внутренний класс; JNI передаёт service как this)
   │
   ├─(5) setSession / setMtu / addAddress / addRoute /
   │     addDnsServer / setMetered                         [Rust → JNI]
   │
   ├─(6) ParcelFileDescriptor establish()                  [Rust → JNI]
   │       └─ int fd = pfd.detachFd()   ← нативный дескриптор TUN
   │
   ├─(7) dup(fd) + O_NONBLOCK → TunFd{read_fd, write_fd}   [Rust]
   │
   ├─(8) startForeground(1, notification)                  [Rust → JNI]
   │       (Android требует FGS для VPN)
   │
   └─(9) smoltcp::Interface::poll(...) поверх fd           [Rust]
           TCP/UDP из fd → DPI-модуль (фрагментация/SNI) → реальная сеть
```

Соответствие кода:

| Шаг | Файл | Функция |
|---|---|---|
| 1 | `src/platform/android.rs` | `prepare_vpn` |
| 2 | `src/platform/android.rs` | `start_vpn_service` |
| 3 | `src/lib.rs` | `Java_com_example_byebyedpi_RustVpnService_nativeCreate` |
| 4–6 | `src/platform/android.rs` | `build_vpn_interface` |
| 7 | `src/tunnel/mod.rs` | `TunFd` |
| 8 | `src/platform/foreground.rs` | `start_foreground` |
| 9 | `src/tunnel/stack.rs` | `run`, `drain_to_app` |

---

## 4. Разрешения и манифест

`android/AndroidManifest.xml` содержит:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

<service
    android:name="com.example.byebyedpi.RustVpnService"
    android:permission="android.permission.BIND_VPN_SERVICE"
    android:foregroundServiceType="specialUse"
    android:exported="true">
    <intent-filter>
        <action android:name="android.net.VpnService" />
    </intent-filter>
</service>
```

`BIND_VPN_SERVICE` — разрешение уровня `signature`, поэтому его объявляют
**атрибутом сервиса**, а не в `<uses-permission>`: приложение не может само
себе его выдать, но система проверяет, что сервис им защищён.

`Cargo.toml` объявляет то же самое в `[package.metadata.android]` для
`cargo apk` (базовый вариант сборки без `classes.dex`, только для отладки
GUI/прокси).

---

## 5. Сборка

### Быстрая (dev, без VPN-сервиса)

```bash
cargo install cargo-apk
cargo apk build --release --lib      # APK из metadata (NativeActivity, без .dex)
```

### Полная (с VPN)

```bash
export ANDROID_NDK_HOME=$ANDROID_SDK_ROOT/ndk/27.0.12077973
cargo run --release --bin packager -- \
    --ndk "$ANDROID_NDK_HOME" --sdk "$ANDROID_SDK_ROOT"
```

В GitHub Actions собираются оба варианта (`.github/workflows/build.yml`), но
**релизным считается APK пакера**: `cargo-apk` не умеет описывать
`<service>` в метаданных `Cargo.toml`, поэтому его APK не содержит
`classes.dex` и не может поднять VPN — он остаётся дымовой проверкой сборки.
В Artifacts уезжают только подписанные APK пакера.

---

## 6. Ограничения текущей версии

1. **IPv6-маршрут добавляется, но стек проксирует только IPv4.**
   IPv6-пакеты приходят в TUN и отбрасываются. Для стабильности DNS
   принудительно возвращает IPv4 через upstream-резолвер.
2. **UDP (не-DNS) не проксируется.** QUIC/игровой трафик уйдёт в
   TUN и будет отброшен. Для UDP-приложений есть SOCKS5 `UDP ASSOCIATE`
   (встроенный прокси на `127.0.0.1:1080`).
3. **Подмена SNI не меняет длину ClientHello.** Если фейковый хост короче
   или длиннее, он подгоняется под исходную длину (`fit_host` в
   `src/dpi/sni.rs`), а поля длин внутри записи пересчитываются
   (`fix_sni_lengths`). Имя при этом всё равно должно быть валидным
   доменом, поэтому GUI предупреждает о подгонке.
4. **Always-on VPN и «Блокировать соединения без VPN»** работают, но при
   перезагрузке сервис поднимает система — наш `nativeCreate` вызывается
   заново, поэтому туннель восстанавливается.
5. **safe-area**: статус-бар Android перекрывает верх интерфейса на
   устройствах с вырезом; используется фиксированный отступ 28 px
   (winit пока не отдаёт insets в стабильном API).

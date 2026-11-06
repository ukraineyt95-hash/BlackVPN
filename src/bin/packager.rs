//! `packager` — сборщик APK на чистом Rust.
//!
//! # Зачем он нужен
//! `cargo apk` умеет собирать APK из `[package.metadata.android]`, но **не
//! умеет объявлять `<service>`** — а без этого сервиса Android не даст
//! поднять VPN. Писать Java/Kotlin нельзя по условию задачи, поэтому мы
//! генерируем `AndroidManifest.xml` сами (файл `android/AndroidManifest.xml`)
//! и упаковываем APK теми же утилитами из Android SDK, что использует
//! `cargo apk`:
//!
//! ```text
//!   cargo build --target aarch64-linux-android --release
//!   aapt package -M AndroidManifest.xml -I android.jar -F base.apk
//!   aapt add base.apk lib/arm64-v8a/libbyebyedpi.so
//!   zipalign -f -v 4 base.apk aligned.apk
//!   apksigner sign --ks debug.keystore aligned.apk
//! ```
//!
//! Логика повторяет `ndk-build/src/apk.rs` из cargo-apk (проверено по
//! исходникам), поэтому результат совместим с обычной сборкой.
//!
//! # Ключи
//! Для отладочных APK Android SDK содержит готовый `~/.android/debug.keystore`
//! (пароль `android`, alias `androiddebugkey`). Если файла нет — утилита
//! создаёт его через `keytool` (входит в JDK) или берёт ключ из
//! `--keystore`.
//!
//! Запуск (из workflow):
//! ```text
//! cargo run --release --bin packager -- \
//!     --ndk "$ANDROID_NDK_HOME" --sdk "$ANDROID_SDK_ROOT"
//! ```
use std::path::{Path, PathBuf};

use byebyedpi::apk::build_bridge_dex;
use std::process::{Command, ExitCode};

/// Соответствие Rust-таргета и ABI-каталога в APK.
const TARGETS: &[(&str, &str)] = &[
    ("aarch64-linux-android", "arm64-v8a"),
    ("armv7-linux-androideabi", "armeabi-v7a"),
    ("x86_64-linux-android", "x86_64"),
    ("i686-linux-android", "x86"),
];

/// Имя библиотеки (== `[lib] name`).
const LIB_NAME: &str = "byebyedpi";

/// Имя итогового APK.
const APK_NAME: &str = "ByeByeDPI-Rust";

/// Минимальная версия Android, для которой берём android.jar.
const TARGET_PLATFORM: &str = "android-34";

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("✓ Готово");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("✗ {e}");
            ExitCode::FAILURE
        }
    }
}

/// Аргументы командной строки.
struct Args {
    ndk: PathBuf,
    sdk: PathBuf,
    manifest: PathBuf,
    out: PathBuf,
    keystore: Option<PathBuf>,
    keystore_password: String,
    keystore_alias: String,
    build_tools: String,
    release: bool,
    targets: Vec<(String, String)>,
}

fn parse_args() -> Result<Args, String> {
    let mut ndk = std::env::var("ANDROID_NDK_HOME")
        .or_else(|_| std::env::var("ANDROID_NDK_ROOT"))
        .map(PathBuf::from)
        .map_err(|_| "не задан ANDROID_NDK_HOME (или --ndk)")?;
    let mut sdk = std::env::var("ANDROID_SDK_ROOT")
        .or_else(|_| std::env::var("ANDROID_HOME"))
        .map(PathBuf::from)
        .map_err(|_| "не задан ANDROID_SDK_ROOT (или --sdk)")?;
    let mut manifest = PathBuf::from("android/AndroidManifest.xml");
    let mut out = PathBuf::from("target/byebyedpi-apk");
    let mut keystore = None;
    let mut keystore_password = "android".to_string();
    let mut keystore_alias = "androiddebugkey".to_string();
    let mut build_tools = String::new();
    let mut release = true;
    let mut targets: Vec<(String, String)> = TARGETS
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let next = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("ожидалось значение после {}", args[*i - 1]))
        };
        match args[i].as_str() {
            "--ndk" => ndk = PathBuf::from(next(&mut i)?),
            "--sdk" => sdk = PathBuf::from(next(&mut i)?),
            "--manifest" => manifest = PathBuf::from(next(&mut i)?),
            "--out" => out = PathBuf::from(next(&mut i)?),
            "--keystore" => keystore = Some(PathBuf::from(next(&mut i)?)),
            "--ks-pass" => keystore_password = next(&mut i)?,
            "--ks-alias" => keystore_alias = next(&mut i)?,
            "--build-tools" => build_tools = next(&mut i)?,
            "--debug" => release = false,
            "--targets" => {
                let list = next(&mut i)?;
                targets.clear();
                for triple in list.split(',') {
                    let triple = triple.trim();
                    if let Some((t, abi)) = TARGETS.iter().find(|(t, _)| *t == triple) {
                        targets.push((t.to_string(), abi.to_string()));
                    } else {
                        return Err(format!("неизвестный таргет: {triple}"));
                    }
                }
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("неизвестный аргумент: {other}")),
        }
        i += 1;
    }

    if build_tools.is_empty() {
        build_tools = detect_build_tools(&sdk)?;
    }

    Ok(Args {
        ndk,
        sdk,
        manifest,
        out,
        keystore,
        keystore_password,
        keystore_alias,
        build_tools,
        release,
        targets,
    })
}

fn print_help() {
    println!(
        "packager — сборка APK без Gradle и без Java-кода\n\
         \n\
         Аргументы:\n\
           --ndk <путь>          ANDROID_NDK_HOME\n\
           --sdk <путь>          ANDROID_SDK_ROOT\n\
           --manifest <путь>     AndroidManifest.xml (по умолчанию android/AndroidManifest.xml)\n\
           --out <каталог>       куда положить APK\n\
           --keystore <путь>     keystore (по умолчанию ~/.android/debug.keystore)\n\
           --ks-pass <пароль>    пароль keystore (по умолчанию android)\n\
             --ks-alias <alias>    alias ключа (по умолчанию androiddebugkey)\n\
           --build-tools <версия> версия build-tools (по умолчанию — последняя)\n\
           --targets <список>    через запятую: aarch64-linux-android,armv7-linux-androideabi\n\
           --debug               debug-сборка\n"
    );
}

/// Найти самую свежую версию build-tools.
fn detect_build_tools(sdk: &Path) -> Result<String, String> {
    let dir = sdk.join("build-tools");
    let mut versions: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| format!("нет каталога build-tools ({}): {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    // Сортировка по «версии» (простое сравнение компонентов).
    versions.sort_by_key(|v| {
        let mut parts = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
        (
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
        )
    });
    versions
        .pop()
        .ok_or_else(|| format!("в {} нет версий build-tools", dir.display()))
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    println!("== ByeByeDPI-Rust packager ==");
    println!("NDK:          {}", args.ndk.display());
    println!("SDK:          {}", args.sdk.display());
    println!("build-tools:  {}", args.build_tools);
    println!("manifest:     {}", args.manifest.display());

    let build_tools_dir = args.sdk.join("build-tools").join(&args.build_tools);
    let aapt = build_tools_dir.join(bin("aapt"));
    let zipalign = build_tools_dir.join(bin("zipalign"));
    let apksigner = build_tools_dir.join(bin("apksigner"));
    let android_jar = args
        .sdk
        .join("platforms")
        .join(TARGET_PLATFORM)
        .join("android.jar");

    for (path, what) in [
        (&aapt, "aapt"),
        (&zipalign, "zipalign"),
        (&apksigner, "apksigner"),
        (&android_jar, "android.jar"),
    ] {
        if !path.exists() {
            return Err(format!("не найден {what}: {}", path.display()));
        }
    }

    std::fs::create_dir_all(&args.out).map_err(|e| e.to_string())?;
    let work = args.out.join("work");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;

    // ------------------------------------------------------------------ //
    // 1) Копируем манифест в рабочий каталог (aapt ожидает относительный
    //    путь и запускается с current_dir = work).
    // ------------------------------------------------------------------ //
    let manifest_copy = work.join("AndroidManifest.xml");
    std::fs::copy(&args.manifest, &manifest_copy)
        .map_err(|e| format!("копирование манифеста: {e}"))?;

    // ------------------------------------------------------------------ //
    // 1b) Генерируем classes.dex с классом-мостом VpnService.
    //
    //     В проекте нет .java/.kt, но Android не запустит VPN без сервиса,
    //     который наследует android.net.VpnService. Поэтому байткод
    //     создаётся программно (см. byebyedpi::apk::dex):
    //
    //         public class RustVpnService extends android.net.VpnService {
    //             private native void nativeCreate();   // -> Rust JNI
    //             private native void nativeRevoke();
    //             public void onCreate()  { nativeCreate(); super.onCreate(); }
    //             public void onRevoke()  { nativeRevoke(); super.onRevoke(); }
    //         }
    //
    //     Логики в этом классе нет: он только передаёт управление в Rust.
    // ------------------------------------------------------------------ //
    let dex = build_bridge_dex();
    let dex_path = work.join("classes.dex");
    std::fs::write(&dex_path, &dex).map_err(|e| format!("запись classes.dex: {e}"))?;
    println!("-- classes.dex сгенерирован ({} байт)", dex.len());

    // В APK появился байткод => android:hasCode должен быть "true",
    // иначе система не станет загружать classes.dex и сервис не найдётся.
    fix_manifest_for_dex(&manifest_copy)?;

    // ------------------------------------------------------------------ //
    // 2) Собираем нативные библиотеки.
    // ------------------------------------------------------------------ //
    let profile = if args.release { "release" } else { "debug" };
    let mut built: Vec<(String, PathBuf)> = Vec::new();

    for (triple, abi) in &args.targets {
        println!("-- cargo build --target {triple} ({abi})");
        let mut cmd = Command::new("cargo");
        cmd.arg("build")
            .arg("--lib")
            .arg("--target")
            .arg(triple)
            .arg("--profile")
            .arg(profile);

        // Переменные окружения для линковки с NDK (cc-rs / rustc).
        let clang = args
            .ndk
            .join("toolchains")
            .join("llvm")
            .join("prebuilt")
            .join(host_tag())
            .join("bin")
            .join(clang_name(triple));
        if clang.exists() {
            let var = match *abi {
                "arm64-v8a" => "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER",
                "armeabi-v7a" => "CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER",
                "x86_64" => "CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER",
                "x86" => "CARGO_TARGET_I686_LINUX_ANDROID_LINKER",
                _ => "",
            };
            if !var.is_empty() {
                cmd.env(var, &clang);
            }
        }

        let status = cmd
            .status()
            .map_err(|e| format!("не удалось запустить cargo: {e}"))?;
        if !status.success() {
            return Err(format!("cargo build для {triple} завершился с ошибкой"));
        }

        let so = PathBuf::from("target")
            .join(triple)
            .join(profile)
            .join(format!("lib{LIB_NAME}.so"));
        if !so.exists() {
            return Err(format!("не найден {}. Проверьте crate-type=[\"cdylib\"]", so.display()));
        }
        let size = std::fs::metadata(&so).map(|m| m.len()).unwrap_or(0);
        println!("   {} ({:.1} МБ)", so.display(), size as f64 / 1_048_576.0);
        built.push((abi.clone(), so));
    }

    // ------------------------------------------------------------------ //
    // 3) aapt package — создаём APK с манифестом.
    // ------------------------------------------------------------------ //
    let unaligned = work.join(format!("{APK_NAME}-unaligned.apk"));
    println!("-- aapt package");
    let status = Command::new(&aapt)
        .current_dir(&work)
        .arg("package")
        .arg("-f")
        .arg("-F")
        .arg(&unaligned)
        .arg("-M")
        .arg("AndroidManifest.xml")
        .arg("-I")
        .arg(&android_jar)

        // Не сжимать .so: так библиотеки можно грузить напрямую из APK
        // (extractNativeLibs=false) и zipalign сохраняет выравнивание.
        .arg("-0")
        .arg("so")
        .status()
        .map_err(|e| format!("aapt: {e}"))?;
    if !status.success() {
        return Err("aapt package завершился с ошибкой".into());
    }

    // Манифест содержит extractNativeLibs="true", поэтому сжатые .so
    // допустимы: система распакует их при установке. Переупаковка через
    // aapt2 не требуется.

    // ------------------------------------------------------------------ //
    // 4) aapt add — добавляем .so в lib/<abi>/.
    // ------------------------------------------------------------------ //
    std::fs::create_dir_all(work.join("lib")).map_err(|e| e.to_string())?;
    for (abi, so) in &built {
        let dir = work.join("lib").join(abi);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        std::fs::copy(so, dir.join(format!("lib{LIB_NAME}.so")))
            .map_err(|e| format!("копирование .so: {e}"))?;
    }

    println!("-- aapt add (нативные библиотеки + classes.dex)");
    let mut add = Command::new(&aapt);
    add.current_dir(&work)
        .arg("add")
        .arg(&unaligned)

        // classes.dex должен лежать в корне APK и НЕ быть сжатым
        // (aapt add сохраняет способ упаковки исходного файла; dex
        // добавляем как есть).
        .arg("classes.dex");
    for (abi, _) in &built {
        add.arg(format!("lib/{abi}/lib{LIB_NAME}.so"));
    }
    let status = add.status().map_err(|e| format!("aapt add: {e}"))?;
    if !status.success() {
        return Err("aapt add завершился с ошибкой".into());
    }

    // ------------------------------------------------------------------ //
    // 5) zipalign — выравнивание (обязательно для Android 11+).
    // ------------------------------------------------------------------ //
    let aligned = args.out.join(format!("{APK_NAME}-{profile}-aligned.apk"));
    println!("-- zipalign");
    let status = Command::new(&zipalign)
        .arg("-f")
        .arg("-v")
        .arg("4")
        .arg(&unaligned)
        .arg(&aligned)
        .status()
        .map_err(|e| format!("zipalign: {e}"))?;
    if !status.success() {
        return Err("zipalign завершился с ошибкой".into());
    }

    // ------------------------------------------------------------------ //
    // 6) Определяем ключ и подписываем.
    // ------------------------------------------------------------------ //
    let keystore = match args.keystore.clone() {
        Some(k) => k,
        None => ensure_debug_keystore()?,
    };
    println!("-- apksigner (ключ: {})", keystore.display());

    let status = Command::new(&apksigner)
        .arg("sign")
        .arg("--ks")
        .arg(&keystore)
        .arg("--ks-pass")
        .arg(format!("pass:{}", args.keystore_password))
        .arg("--ks-key-alias")
        .arg(&args.keystore_alias)

        // v1+v2+v3 подписи: v2+ нужны для API 30+.
        .arg("--v1-signing-enabled")
        .arg("true")
        .arg("--v2-signing-enabled")
        .arg("true")
        .arg(&aligned)
        .status()
        .map_err(|e| format!("apksigner: {e}"))?;
    if !status.success() {
        return Err("apksigner завершился с ошибкой".into());
    }

    // Итог.
    let final_apk = aligned.clone();
    let size = std::fs::metadata(&final_apk).map(|m| m.len()).unwrap_or(0);
    println!();
    println!("APK:  {}", final_apk.display());
    println!("Размер: {:.1} МБ", size as f64 / 1_048_576.0);
    println!("ABI:  {}", built.iter().map(|(a, _)| a.as_str()).collect::<Vec<_>>().join(", "));
    println!();
    println!("Установка: adb install -r '{}'", final_apk.display());

    Ok(())
}

/// Выставить `android:hasCode="true"` в манифесте.
///
/// Исходный `android/AndroidManifest.xml` держит `hasCode="false"`
/// (в проекте нет Java-кода), но как только мы кладём в APK
/// `classes.dex` с классом-мостом, атрибут обязан стать `true` —
/// иначе ART не загрузит DEX и `RustVpnService` будет «не найден».
fn fix_manifest_for_dex(path: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    if !text.contains("android:hasCode") {
        return Ok(());
    }
    let patched = text
        .replace("android:hasCode=\"false\"", "android:hasCode=\"true\"")
        .replace("android:hasCode='false'", "android:hasCode=\"true\"");
    if patched != text {
        std::fs::write(path, patched).map_err(|e| e.to_string())?;
        println!("-- манифест: android:hasCode -> true (в APK есть classes.dex)");
    }
    Ok(())
}

/// Имя бинарника с учётом ОС хоста.
fn bin(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.bat")
    } else {
        name.to_string()
    }
}

/// Тег хоста для NDK prebuilt (`linux-x86_64`, `darwin-x86_64`, ...).
fn host_tag() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin-x86_64"
    } else if cfg!(windows) {
        "windows-x86_64"
    } else {
        "linux-x86_64"
    }
}

/// Имя clang-обёртки NDK для таргета.
fn clang_name(triple: &str) -> String {
    let prefix = if cfg!(windows) { "clang.exe" } else { "clang" };
    match triple {
        "aarch64-linux-android" => format!("aarch64-linux-android24-{prefix}"),
        "armv7-linux-androideabi" => format!("armv7a-linux-androideabi24-{prefix}"),
        "x86_64-linux-android" => format!("x86_64-linux-android24-{prefix}"),
        "i686-linux-android" => format!("i686-linux-android24-{prefix}"),
        _ => prefix.to_string(),
    }
}

/// Убедиться, что отладочный ключ существует; при необходимости создать.
///
/// Стандартный путь Android SDK: `~/.android/debug.keystore`,
/// пароль `android`, alias `androiddebugkey`, CN=Android Debug.
fn ensure_debug_keystore() -> Result<PathBuf, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "не удалось определить домашний каталог")?;
    let path = PathBuf::from(home).join(".android").join("debug.keystore");
    if path.exists() {
        return Ok(path);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    println!("-- создаём отладочный ключ {}", path.display());
    let status = Command::new("keytool")
        .arg("-genkeypair")
        .arg("-keystore")
        .arg(&path)
        .arg("-storepass")
        .arg("android")
        .arg("-keypass")
        .arg("android")
        .arg("-alias")
        .arg("androiddebugkey")
        .arg("-keyalg")
        .arg("RSA")
        .arg("-keysize")
        .arg("2048")
        .arg("-validity")
        .arg("10000")
        .arg("-dname")
        .arg("CN=Android Debug,O=Android,C=US")
        .status()
        .map_err(|e| format!("keytool не найден (нужен JDK): {e}"))?;
    if !status.success() {
        return Err("keytool завершился с ошибкой".into());
    }
    Ok(path)
}

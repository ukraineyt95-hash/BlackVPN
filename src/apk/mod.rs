//! Сборка APK «с нуля» на Rust: сгенерированный DEX + манифест + `.so`.
//!
//! Модуль используется утилитой `cargo run --bin packager`, которая
//! упаковывает приложение тем же способом, что и `cargo apk`
//! (`aapt` -> `zipalign` -> `apksigner`), но дополнительно кладёт в APK
//! `classes.dex` с классом-мостом `RustVpnService` (см. [`dex`]).
pub mod dex;

pub use dex::build_bridge_dex;

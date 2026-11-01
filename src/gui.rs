use eframe::egui;

use crate::config::AppConfig;
use crate::logger;
use crate::stats::{self, SpeedMeter};
use crate::vpn::{VpnController, VpnState};

/// Активная вкладка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Main,
    Settings,
}

/// Что нужно сделать после отрисовки кадра (чтобы не вызывать тяжёлые
/// операции внутри UI-замыканий).
enum Action {
    None,
    Start,
    Stop,
    SaveConfig,
}

/// Приложение egui.
pub struct ByeByeDpiApp {
    cfg: AppConfig,
    controller: VpnController,
    tab: Tab,
    /// Кэш строк лога, чтобы не блокировать мьютекс логгера каждый кадр.
    log_lines: Vec<String>,
    log_dirty_at: f64,
    speed: SpeedMeter,
    /// Показывать пароль прокси открытым текстом.
    show_password: bool,
    /// Статус последнего сохранения.
    save_status: Option<(String, f64)>,
    /// Ошибка валидации полей.
    field_error: Option<String>,
    /// Ссылка на платформу (пути к файлам).
    platform: PlatformHolder,
    /// Автопрокрутка лога.
    autoscroll: bool,
}

/// Хранилище платформенного объекта (разное на Android и desktop).
pub enum PlatformHolder {
    #[cfg(target_os = "android")]
    Android(crate::platform::AndroidPlatform),
    #[cfg(not(target_os = "android"))]
    Desktop(crate::platform::DesktopPlatform),
}

impl PlatformHolder {
    pub fn save(&self, cfg: &AppConfig) -> Result<(), String> {
        match self {
            #[cfg(target_os = "android")]
            PlatformHolder::Android(p) => {
                use crate::platform::Platform;
                p.save_config(cfg)
            }
            #[cfg(not(target_os = "android"))]
            PlatformHolder::Desktop(p) => {
                use crate::platform::Platform;
                p.save_config(cfg)
            }
        }
    }

    pub fn load(&self) -> AppConfig {
        match self {
            #[cfg(target_os = "android")]
            PlatformHolder::Android(p) => {
                use crate::platform::Platform;
                p.load_config()
            }
            #[cfg(not(target_os = "android"))]
            PlatformHolder::Desktop(p) => {
                use crate::platform::Platform;
                p.load_config()
            }
        }
    }

    pub fn log_path(&self) -> Option<std::path::PathBuf> {
        match self {
            #[cfg(target_os = "android")]
            PlatformHolder::Android(p) => {
                use crate::platform::Platform;
                p.log_file_path()
            }
            #[cfg(not(target_os = "android"))]
            PlatformHolder::Desktop(p) => {
                use crate::platform::Platform;
                p.log_file_path()
            }
        }
    }
}

impl ByeByeDpiApp {
    /// Создать приложение.
    pub fn new(platform: PlatformHolder) -> Self {
        // 1) Загружаем конфигурацию.
        let mut cfg = platform.load();
        cfg.sanitize();

        // 2) Логирование в файл (если включено).
        if cfg.log_to_file {
            if let Some(path) = platform.log_path() {
                logger::enable_file_logging(&path);
            }
        }

        let controller = match crate::app_controller() {
            Some(existing) => existing,
            None => {
                let fresh = VpnController::new();
                if let Err(e) = fresh.init_runtime() {
                    crate::flog_err!("{e}");
                }
                fresh
            }
        };

        crate::flog!("ByeByeDPI-Rust запущен");
        crate::flog!(
            "Прокси: {}:{}",
            cfg.proxy_host,
            cfg.proxy_port
        );

        Self {
            cfg,
            controller,
            tab: Tab::Main,
            log_lines: Vec::new(),
            log_dirty_at: 0.0,
            speed: SpeedMeter::default(),
            show_password: false,
            save_status: None,
            field_error: None,
            platform,
            autoscroll: true,
        }
    }

    /// Обновить кэш лога не чаще раза в 0.25 с.
    fn refresh_log(&mut self, now: f64) {
        if now - self.log_dirty_at >= 0.25 {
            self.log_lines = logger::snapshot();
            self.log_dirty_at = now;
        }
    }

    // ------------------------------------------------------------------ //
    //  Вкладка «Главная»
    // ------------------------------------------------------------------ //
    fn ui_main(&mut self, ui: &mut egui::Ui, now: f64) -> Option<Action> {
        let mut action = None;
        let state = self.controller.state();

        // --- Кнопка Старт/Стоп ------------------------------------------ //
        // Иконка и цвет — здесь, текст — из `VpnState::label`, чтобы подписи
        // не расходились с моделью состояния.
        let (icon, button_color) = match state {
            VpnState::Running => ("⏹", egui::Color32::from_rgb(200, 60, 60)),
            VpnState::Starting => ("⏳", egui::Color32::from_rgb(180, 140, 40)),
            VpnState::WaitingConsent => ("🔐", egui::Color32::from_rgb(180, 140, 40)),
            VpnState::Error => ("↻", egui::Color32::from_rgb(150, 90, 160)),
            VpnState::Stopped => ("▶", egui::Color32::from_rgb(50, 150, 90)),
        };
        let button_text = format!("{icon}  {}", state.label());

        ui.add_space(6.0);
        let button = egui::Button::new(
            egui::RichText::new(&button_text)
                .size(24.0)
                .strong()
                .color(egui::Color32::WHITE),
        )
        .fill(button_color)
        .min_size(egui::vec2(ui.available_width(), 64.0));

        if ui.add(button).clicked() {
            action = Some(match state {
                VpnState::Running | VpnState::Starting => Action::Stop,
                _ => Action::Start,
            });
        }

        ui.add_space(4.0);
        ui.label(egui::RichText::new(state.hint()).size(13.0).weak());

        // Ошибка последнего запуска.
        if let Some(err) = self.controller.last_error() {
            ui.add_space(4.0);
            ui.colored_label(egui::Color32::from_rgb(220, 90, 90), format!("⚠ {err}"));
        }

        ui.add_space(10.0);
        ui.separator();

        let (up_total, down_total, conns) = stats::totals();

        egui::Grid::new("speed-grid")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label(egui::RichText::new("↑ Отдача").weak());
                ui.label(egui::RichText::new(self.speed.format_up()).strong());
                ui.end_row();

                ui.label(egui::RichText::new("↓ Загрузка").weak());
                ui.label(egui::RichText::new(self.speed.format_down()).strong());
                ui.end_row();

                ui.label(egui::RichText::new("Всего").weak());
                ui.label(format!(
                    "↑ {}   ↓ {}",
                    stats::format_bytes(up_total),
                    stats::format_bytes(down_total)
                ));
                ui.end_row();

                ui.label(egui::RichText::new("Соединений").weak());
                ui.label(conns.to_string());
                ui.end_row();
            });

        ui.add_space(8.0);

        let dpi = crate::dpi::DpiSettings::from_config(&self.cfg);
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new("Обход:").weak());
            if dpi.active() {
                ui.colored_label(egui::Color32::from_rgb(90, 200, 120), dpi.describe());
            } else {
                ui.colored_label(egui::Color32::from_rgb(200, 160, 60), "выключен");
            }
        });

        ui.add_space(6.0);
        ui.separator();

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Лог").strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Очистить").clicked() {
                    logger::clear();
                    self.log_lines.clear();
                }
                ui.checkbox(&mut self.autoscroll, "Автопрокрутка");
            });
        });

        self.refresh_log(now);

        let available = ui.available_height().max(120.0);
        egui::ScrollArea::vertical()
            .max_height(available)
            .stick_to_bottom(self.autoscroll)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.style_mut().spacing.item_spacing.y = 0.0;
                for line in &self.log_lines {
                    let color = if line.contains("ERROR") {
                        egui::Color32::from_rgb(230, 120, 120)
                    } else if line.contains("WARN") {
                        egui::Color32::from_rgb(220, 190, 110)
                    } else {
                        ui.visuals().text_color()
                    };
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(line)
                                .monospace()
                                .size(11.0)
                                .color(color),
                        )
                        .wrap(),
                    );
                }
            });

        action
    }

    fn ui_settings(&mut self, ui: &mut egui::Ui) -> Option<Action> {
        let mut action = None;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.heading("Прокси-сервер");
                ui.label(
                    egui::RichText::new(
                        "Локальный прокси (SOCKS5 / HTTP CONNECT / H2Mux). \
                         Приложение поднимает его при старте.",
                    )
                    .size(12.0)
                    .weak(),
                );

                egui::Grid::new("proxy-grid")
                    .num_columns(2)
                    .spacing([8.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("IP-адрес");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.cfg.proxy_host)
                                .desired_width(f32::INFINITY)
                                .hint_text("127.0.0.1"),
                        );
                        ui.end_row();

                        ui.label("Порт");
                        let mut port = self.cfg.proxy_port as i32;
                        if ui
                            .add(egui::DragValue::new(&mut port).range(1..=65535).speed(1.0))
                            .changed()
                        {
                            self.cfg.proxy_port = port.clamp(1, 65535) as u16;
                        }
                        ui.end_row();

                        ui.label("Логин");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.cfg.proxy_user)
                                .desired_width(f32::INFINITY)
                                .hint_text("без авторизации"),
                        );
                        ui.end_row();

                        ui.label("Пароль");
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.cfg.proxy_password)
                                    .password(!self.show_password)
                                    .desired_width(ui.available_width() - 90.0),
                            );
                            ui.checkbox(&mut self.show_password, "показать");
                        });
                        ui.end_row();
                    });

                ui.add_space(10.0);
                ui.separator();

                ui.heading("Обход DPI");
                ui.checkbox(&mut self.cfg.bypass_enabled, "Включить обход блокировок");

                ui.add_enabled_ui(self.cfg.bypass_enabled, |ui| {
                    ui.checkbox(&mut self.cfg.fragment_enabled, "Фрагментация TCP");
                    ui.add_enabled_ui(self.cfg.fragment_enabled, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Размер фрагмента:");
                            ui.add(
                                egui::DragValue::new(&mut self.cfg.fragment_size_min)
                                    .range(1..=64)
                                    .prefix("от "),
                            );
                            ui.add(
                                egui::DragValue::new(&mut self.cfg.fragment_size_max)
                                    .range(1..=1024)
                                    .prefix("до "),
                            );
                            ui.label("байт");
                        });
                    });

                    ui.checkbox(
                        &mut self.cfg.microsegmentation_enabled,
                        "Микро-сегментация (по 1 байту)",
                    );
                    ui.add_enabled_ui(self.cfg.microsegmentation_enabled, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Байт микро-сегментации:");
                            ui.add(
                                egui::DragValue::new(&mut self.cfg.microsegmentation_bytes)
                                    .range(1..=16),
                            );
                        });
                    });

                    ui.checkbox(&mut self.cfg.split_tls_enabled, "Разрывать TLS ClientHello");
                    ui.add_enabled_ui(self.cfg.split_tls_enabled, |ui| {
                        ui.checkbox(&mut self.cfg.split_tls_at_sni, "Именно посреди SNI");
                        if !self.cfg.split_tls_at_sni {
                            ui.horizontal(|ui| {
                                ui.label("Позиция разрыва:");
                                let mut pos = self.cfg.split_tls_position.unwrap_or(1) as i32;
                                if ui
                                    .add(egui::DragValue::new(&mut pos).range(1..=4096))
                                    .changed()
                                {
                                    self.cfg.split_tls_position = Some(pos.max(1) as usize);
                                }
                            });
                        }
                    });

                    ui.checkbox(&mut self.cfg.fake_sni_enabled, "Маскировать SNI Host");
                    ui.add_enabled_ui(self.cfg.fake_sni_enabled, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Фейковый SNI:");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.cfg.fake_sni_host)
                                    .desired_width(f32::INFINITY)
                                    .hint_text("www.google.com"),
                            );
                        });
                        ui.label(
                            egui::RichText::new(
                                "Имя подгоняется под длину настоящего SNI, а поля длин \
                                 в ClientHello пересчитываются (см. dpi::sni::fit_host). \
                                 Фейковый домен должен существовать, иначе TLS не \
                                 поздоровается.",
                            )
                            .size(11.0)
                            .weak(),
                        );
                    });

                    ui.checkbox(
                        &mut self.cfg.udp_over_tcp_enabled,
                        "UDP-over-TCP (DNS через TCP)",
                    );
                    ui.checkbox(&mut self.cfg.junk_prefix_enabled, "Junk-префикс перед данными");
                });

                ui.add_space(10.0);
                ui.separator();

                ui.heading("Туннель");
                egui::Grid::new("tun-grid")
                    .num_columns(2)
                    .spacing([8.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Адрес TUN");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.cfg.tun_address)
                                .desired_width(f32::INFINITY)
                                .hint_text("10.111.222.2"),
                        );
                        ui.end_row();

                        ui.label("Маска (префикс)");
                        let mut prefix = self.cfg.tun_prefix as i32;
                        if ui
                            .add(egui::DragValue::new(&mut prefix).range(8..=30))
                            .changed()
                        {
                            self.cfg.tun_prefix = prefix as u8;
                        }
                        ui.end_row();

                        ui.label("MTU");
                        let mut mtu = self.cfg.tun_mtu as i32;
                        if ui
                            .add(egui::DragValue::new(&mut mtu).range(576..=9000).speed(10.0))
                            .changed()
                        {
                            self.cfg.tun_mtu = mtu as u16;
                        }
                        ui.end_row();

                        ui.label("DNS");
                        if self.cfg.dns_servers.is_empty() {
                            self.cfg.dns_servers.push("10.111.222.1".to_string());
                        }
                        ui.add(
                            egui::TextEdit::singleline(&mut self.cfg.dns_servers[0])
                                .desired_width(f32::INFINITY)
                                .hint_text("10.111.222.1"),
                        );
                        ui.end_row();
                    });
                ui.label(
                    egui::RichText::new(
                        "10.111.222.1 — «наш» адрес: запросы к нему перехватывает стек \
                         и пересылает на настоящий DNS (с обходом блокировок).",
                    )
                    .size(11.0)
                    .weak(),
                );

                ui.add_space(10.0);
                ui.separator();

                ui.heading("Прочее");
                ui.checkbox(&mut self.cfg.log_to_file, "Писать лог в файл");

                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    let save = egui::Button::new(
                        egui::RichText::new("💾  Сохранить").strong(),
                    )
                    .min_size(egui::vec2(150.0, 44.0));
                    if ui.add(save).clicked() {
                        action = Some(Action::SaveConfig);
                    }

                    let reset = egui::Button::new("↺  Сбросить").min_size(egui::vec2(120.0, 44.0));
                    if ui.add(reset).clicked() {
                        self.cfg = AppConfig::default();
                        action = Some(Action::SaveConfig);
                    }
                });

                if let Some((msg, _)) = &self.save_status {
                    ui.add_space(4.0);
                    ui.colored_label(egui::Color32::from_rgb(90, 200, 120), msg);
                }
                if let Some(err) = &self.field_error {
                    ui.add_space(4.0);
                    ui.colored_label(egui::Color32::from_rgb(220, 90, 90), err);
                }

                ui.add_space(16.0);
                ui.label(
                    egui::RichText::new(concat!(
                        "ByeByeDPI-Rust ",
                        env!("CARGO_PKG_VERSION"),
                        " — 100% Rust (NativeActivity + egui + smoltcp). \
                         Без Java/Kotlin и без Android Studio."
                    ))
                    .size(10.0)
                    .weak(),
                );
                ui.add_space(24.0);
            });

        action
    }
}

impl eframe::App for ByeByeDpiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let now = ctx.input(|i| i.time);
        // --- Скорость и объём ------------------------------------------- //
        self.speed.tick();

        if let Some((_, at)) = &self.save_status {
            if now - at > 3.0 {
                self.save_status = None;
            }
        }

        let repaint_after = if self.controller.is_running() {
            0.2
        } else {
            0.5
        };
        ctx.request_repaint_after(std::time::Duration::from_secs_f64(repaint_after));

        let mut action = Action::None;

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            // Отступ под статус-бар Android (safe-area winit не отдаёт).
            ui.add_space(crate::gui::STATUS_BAR_PADDING);

            // --- Заголовок и индикатор состояния ------------------------ //
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("ByeByeDPI").size(18.0).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (text, color) = match self.controller.state() {
                        VpnState::Running => ("● работает", egui::Color32::from_rgb(90, 200, 120)),
                        VpnState::Stopped => ("○ выключено", egui::Color32::GRAY),
                        VpnState::Starting => ("◐ запуск", egui::Color32::from_rgb(220, 190, 110)),
                        VpnState::WaitingConsent => {
                            ("◐ ждёт VPN", egui::Color32::from_rgb(220, 190, 110))
                        }
                        VpnState::Error => ("✕ ошибка", egui::Color32::from_rgb(220, 90, 90)),
                    };
                    ui.colored_label(color, text);
                });
            });

            // --- Переключатель вкладок ---------------------------------- //
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Main, "  Главная  ");
                ui.selectable_value(&mut self.tab, Tab::Settings, "  Настройки  ");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            let result = match self.tab {
                Tab::Main => self.ui_main(ui, now),
                Tab::Settings => self.ui_settings(ui),
            };
            if let Some(a) = result {
                action = a;
            }
        });

        // --- Обработка действий после отрисовки ------------------------- //
        match action {
            Action::Start => {
                // Нормализуем поля, сохраняем и отдаём актуальные настройки
                // в JNI-слой (он заберёт их в nativeCreate).
                self.cfg.sanitize();
                match self.platform.save(&self.cfg) {
                    Ok(()) => self.field_error = None,
                    Err(e) => self.field_error = Some(format!("Не удалось сохранить: {e}")),
                }
                self.controller.register_config(&self.cfg);
                self.controller.start(&self.cfg);
            }
            Action::Stop => {
                self.controller.stop();
            }
            Action::SaveConfig => {
                self.cfg.sanitize();
                match self.platform.save(&self.cfg) {
                    Ok(()) => {
                        self.field_error = None;
                        self.save_status = Some(("Настройки сохранены".to_string(), now));
                        // Держим копию в глобальном APP в актуальном состоянии:
                        // её читает nativeCreate() при поднятии VpnService.
                        self.controller.register_config(&self.cfg);
                        crate::flog!("Настройки сохранены");
                    }
                    Err(e) => {
                        self.save_status = None;
                        self.field_error = Some(format!("Не удалось сохранить: {e}"));
                    }
                }
            }
            Action::None => {}
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.controller.stop();
    }
}

/// Отступ под системный статус-бар Android.
///
/// winit пока не отдаёт safe-area insets, поэтому берём фиксированное
/// значение, как в hello_android-примере egui.
pub const STATUS_BAR_PADDING: f32 = 28.0;


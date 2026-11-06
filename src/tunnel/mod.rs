//! Модуль виртуального туннеля: TUN-дескриптор, устройство smoltcp и стек.
pub mod device;
pub mod stack;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Пара дескрипторов TUN-интерфейса, полученных из Android VpnService.
///
/// * `read_fd` — читаем исходящие пакеты приложений;
/// * `write_fd` — пишем входящие пакеты приложениям (это `dup()` первого);
/// * `mtu` — размер пакета, согласованный с системой.
#[derive(Debug, Clone, Copy)]
pub struct TunFd {
    pub read_fd: i32,
    pub write_fd: i32,
    pub mtu: usize,
}

impl TunFd {
    // Дескрипторы принадлежат объекту ParcelFileDescriptor на Java-стороне,
    // поэтому закрывать их вручную из Rust не нужно: это сделает GC/система.
    // Метод оставлен для аварийной очистки (например, при отладке на десктопе).
    /// Закрыть оба дескриптора (идемпотентно, ошибки игнорируются).
    ///
    /// Вызывать только когда стек уже остановлен.
    #[allow(dead_code)]
    pub fn close(&self) {
        for fd in [self.read_fd, self.write_fd] {
            if fd >= 0 {
                // SAFETY: fd получен из JNI/dup и принадлежит нам.
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

/// «Рантайм» туннеля: держит поток стека и флаг остановки.
pub struct TunnelRuntime {
    control: stack::TunnelControl,
    thread: Option<std::thread::JoinHandle<()>>,
    pub tun: TunFd,
    started: Arc<AtomicBool>,
}

impl TunnelRuntime {
    /// Запустить стек поверх уже полученного fd.
    pub fn start(tun: TunFd, control: stack::TunnelControl) -> Self {
        let thread = stack::spawn(tun, control.clone());
        Self {
            control,
            thread: Some(thread),
            tun,
            started: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.started.load(Ordering::Relaxed) && self.control.is_running()
    }

    /// Остановить стек (поток завершится сам).
    ///
    /// Мы НЕ вызываем `join()`: остановка происходит из UI-потока, а стек
    /// может быть в середине сетевой операции. Флаг `running` гарантирует,
    /// что поток завершится в течение одного периода опроса (~3 мс).
    /// Дескрипторы закрывает вызывающая сторона ([`crate::platform::stop_vpn`]).
    pub fn stop(&mut self) {
        self.control.stop();
        self.started.store(false, Ordering::Relaxed);

        // Отсоединяем поток: он завершится сам, блокировать UI нельзя.
        self.thread.take();
    }
}

impl Drop for TunnelRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

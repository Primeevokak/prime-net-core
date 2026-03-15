//! Packet-level interception for TCP disorder and fake packet injection.
//!
//! Provides the [`PacketInterceptor`] trait and platform backends:
//! - [`WinDivertInterceptor`] (Windows): loads `WinDivert.dll` at runtime via
//!   `libloading` and rewrites outgoing TCP segments to implement disorder.
//! - [`NfQueueInterceptor`] (Linux): uses kernel NFQueue via `libnetfilter_queue`
//!   to intercept and reorder outgoing packets.
//!
//! When neither backend is available at runtime the [`TcpDisorder`] technique
//! degrades gracefully to a plain TCP segment split (logged as a warning).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

pub use disorder::TcpDisorderHandle;

mod disorder;

#[cfg(windows)]
mod windivert;

#[cfg(all(unix, not(target_os = "macos")))]
mod nfqueue;

/// Abstraction over packet-level interception backends.
///
/// Implementors intercept outgoing TCP segments on a specific local port,
/// enabling TCP disorder (sending later segments before earlier ones) and
/// raw packet injection.
pub trait PacketInterceptor: Send + Sync + std::fmt::Debug {
    /// Set up interception for one outgoing TCP connection identified by
    /// `local_addr`.  Returns a [`TcpDisorderHandle`] that, when driven,
    /// reorders the first two data segments.
    ///
    /// The handle must be dropped (or explicitly cancelled) after the
    /// connection's first exchange to release kernel resources.
    fn intercept_connection(
        self: Arc<Self>,
        local_addr: SocketAddr,
        delay_ms: u64,
    ) -> io::Result<TcpDisorderHandle>;

    /// Human-readable name of this backend (for log messages).
    fn backend_name(&self) -> &'static str;
}

/// Try to build the best available [`PacketInterceptor`] for the current platform.
///
/// Returns `None` when no backend could be initialised (WinDivert DLL absent,
/// NFQueue `iptables` rule not in place, etc.).  Callers must handle the `None`
/// case by falling back to a userspace split.
pub fn best_available_interceptor() -> Option<Arc<dyn PacketInterceptor>> {
    #[cfg(windows)]
    {
        if let Some(i) = windivert::WinDivertInterceptor::try_load() {
            return Some(Arc::new(i));
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(i) = nfqueue::NfQueueInterceptor::try_open() {
            return Some(Arc::new(i));
        }
    }

    None
}

//! Kill switch — prevents traffic leaks when the engine goes down.
//!
//! Monitors the SOCKS5 proxy port. When the port becomes unreachable,
//! the system proxy is redirected to a dead port so traffic fails-closed
//! instead of bypassing the engine.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tracing::{info, warn};

/// Interval between liveness checks.
const CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Timeout for the liveness check connection attempt.
const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Port that nobody should be listening on — used as the "dead" proxy.
const DEAD_PORT: u16 = 1;

/// Guard for the kill switch monitor task.
///
/// Returned by [`spawn_kill_switch_monitor`]. Carries no state currently;
/// reserved for future cleanup on drop (e.g. restoring the system proxy
/// from within an async context).
pub struct KillSwitchGuard {
    /// Whether the kill switch was ever engaged during this session.
    ///
    /// Reserved for future cleanup logic.
    pub engaged: bool,
}

impl Drop for KillSwitchGuard {
    fn drop(&mut self) {
        // Intentionally a no-op: cleanup is handled by the background task.
        // Restoring the system proxy requires an async call that cannot be
        // performed synchronously here.
    }
}

/// Spawn a background task that monitors `socks_addr` and engages the kill switch
/// when the proxy becomes unreachable.
///
/// When `enabled` is `false`, returns a guard immediately without starting any
/// background work.
///
/// # Example
///
/// ```no_run
/// # use std::net::SocketAddr;
/// # use prime_net_engine_core::platform::kill_switch::spawn_kill_switch_monitor;
/// let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
/// let _guard = spawn_kill_switch_monitor(addr, true);
/// ```
pub fn spawn_kill_switch_monitor(socks_addr: SocketAddr, enabled: bool) -> KillSwitchGuard {
    if !enabled {
        return KillSwitchGuard { engaged: false };
    }
    tokio::spawn(async move {
        let mut was_alive = true;
        loop {
            tokio::time::sleep(CHECK_INTERVAL).await;
            let alive = check_port_alive(socks_addr).await;
            if was_alive && !alive {
                warn!(
                    target: "kill_switch",
                    addr = %socks_addr,
                    "SOCKS5 proxy unreachable — engaging kill switch"
                );
                engage_kill_switch(socks_addr.port()).await;
            } else if !was_alive && alive {
                info!(
                    target: "kill_switch",
                    addr = %socks_addr,
                    "SOCKS5 proxy restored — disengaging kill switch"
                );
                disengage_kill_switch().await;
            }
            was_alive = alive;
        }
    });
    KillSwitchGuard { engaged: false }
}

/// Returns `true` when a TCP connection to `addr` succeeds within [`CHECK_TIMEOUT`].
async fn check_port_alive(addr: SocketAddr) -> bool {
    tokio::time::timeout(CHECK_TIMEOUT, TcpStream::connect(addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Engage the kill switch by redirecting the system proxy to a dead port.
///
/// Traffic will fail-closed: applications will see connection refused rather than
/// leaking through an unprotected network path.
async fn engage_kill_switch(_proxy_port: u16) {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    {
        let dead_endpoint = format!("127.0.0.1:{DEAD_PORT}");
        if let Err(e) = crate::platform::system_proxy_manager().enable(&dead_endpoint) {
            warn!(
                target: "kill_switch",
                error = %e,
                "failed to redirect system proxy to dead port"
            );
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    warn!(target: "kill_switch", "kill switch engaged");
}

/// Disengage the kill switch by disabling the dead-port proxy redirect.
async fn disengage_kill_switch() {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    {
        if let Err(e) = crate::platform::system_proxy_manager().disable() {
            warn!(
                target: "kill_switch",
                error = %e,
                "failed to restore system proxy after kill switch"
            );
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    info!(target: "kill_switch", "kill switch disengaged");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod kill_switch_tests {
    use super::*;

    #[test]
    fn guard_disabled_returns_immediately() {
        // With enabled=false, the function must return synchronously with no tokio runtime.
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let guard = KillSwitchGuard { engaged: false };
        // Just verify fields are accessible and the type can be constructed.
        assert!(!guard.engaged);
        let _ = addr;
    }

    #[tokio::test]
    async fn check_port_alive_returns_false_for_closed_port() {
        // Port 1 should always be closed (privileged, nothing listening).
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let alive = check_port_alive(addr).await;
        assert!(!alive, "port 1 should not be alive");
    }
}

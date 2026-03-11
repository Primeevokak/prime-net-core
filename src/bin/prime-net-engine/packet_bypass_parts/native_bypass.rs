use std::sync::Arc;
use prime_net_engine_core::evasion::tcp_desync::TcpDesyncEngine;

/// Native (in-process) DPI bypass guard.
///
/// Drop-in replacement for [`PacketBypassGuard`] that works entirely in Rust
/// without launching external processes.  Uses [`TcpDesyncEngine`] to apply
/// TLS record split, TCP segment split, and OOB techniques directly inside
/// the relay pipeline.
///
/// When `socks5_addrs()` returns an empty slice the relay engine uses the
/// `native_bypass` path instead of an external SOCKS5 pool.
pub struct NativeBypassGuard {
    engine: Arc<TcpDesyncEngine>,
}

impl NativeBypassGuard {
    /// Build a guard with the default set of 12 native desync profiles.
    pub fn start_with_defaults() -> Self {
        let engine = TcpDesyncEngine::with_default_profiles();
        info!(
            target: "native_bypass",
            profiles = engine.profile_count(),
            "native bypass engine started (userspace-only mode)"
        );
        Self {
            engine: Arc::new(engine),
        }
    }

    /// Returns an empty list — native bypass does not use an external SOCKS5 pool.
    /// The caller detects this and enables the `native_bypass` relay path instead.
    pub fn socks5_addrs(&self) -> Vec<std::net::SocketAddr> {
        vec![]
    }

    /// Returns the underlying desync engine for use in [`RelayOptions::native_bypass`].
    pub fn tcp_engine(&self) -> Arc<TcpDesyncEngine> {
        self.engine.clone()
    }
}

/// Try to start the native bypass engine.  Always succeeds (no external dependencies).
pub fn maybe_start_native_bypass(enabled: bool) -> Option<NativeBypassGuard> {
    if !enabled {
        return None;
    }
    Some(NativeBypassGuard::start_with_defaults())
}

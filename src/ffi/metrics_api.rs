//! FFI bindings for engine metrics and privacy statistics.
//!
//! Exposes C-compatible snapshot structs and getter functions so that
//! GUI frontends and monitoring tools can poll engine state.

use std::sync::atomic::Ordering;

use crate::ffi::{
    engine_opaque_mut, ffi_guard, set_last_error_text, PrimeEngine, PRIME_ERR_INVALID_REQUEST,
    PRIME_ERR_NULL_PTR, PRIME_ERR_RUNTIME, PRIME_OK,
};

/// Snapshot of core engine metrics, laid out for C interop.
///
/// All counters are cumulative for the lifetime of the engine handle
/// unless otherwise noted.  `active_connections` is a point-in-time gauge.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PrimeMetrics {
    /// Number of currently open relay connections (gauge).
    pub active_connections: u32,
    /// Total connections established since engine start.
    pub total_connections: u64,
    /// Total bytes sent through the proxy (application payload).
    pub bytes_sent: u64,
    /// Total bytes received through the proxy (application payload).
    pub bytes_received: u64,
    /// Total requests blocked by privacy / blocklist rules.
    pub blocked_requests: u64,
    /// Subset of `blocked_requests` attributed to ad domains.
    pub blocked_ads: u64,
    /// Subset of `blocked_requests` attributed to tracker domains.
    pub blocked_trackers: u64,
    /// Connections where DPI evasion was applied.
    pub dpi_bypassed: u64,
    /// Connections that fell back to a VPN / PT tunnel.
    pub vpn_fallback: u64,
    /// Total DNS queries handled by the resolver chain.
    pub dns_queries: u64,
    /// Seconds since engine initialisation completed.
    pub uptime_secs: u64,
}

/// Fill `out` with the current engine metrics.
///
/// Returns `0` on success, or a positive error code on failure.
///
/// # Safety
///
/// * `engine` must be a valid pointer returned by `prime_engine_new`.
/// * `out` must point to a writable `PrimeMetrics` instance.
#[no_mangle]
pub unsafe extern "C" fn prime_metrics_get(
    engine: *mut PrimeEngine,
    out: *mut PrimeMetrics,
) -> i32 {
    ffi_guard(
        "prime_metrics_get",
        || PRIME_ERR_RUNTIME,
        || {
            if engine.is_null() {
                set_last_error_text("engine pointer is null");
                return PRIME_ERR_NULL_PTR;
            }
            if out.is_null() {
                set_last_error_text("out pointer is null");
                return PRIME_ERR_NULL_PTR;
            }

            // SAFETY: engine was validated non-null; magic check inside engine_opaque_mut.
            let Some(opaque) = (unsafe { engine_opaque_mut(engine) }) else {
                set_last_error_text("invalid engine handle pointer");
                return PRIME_ERR_INVALID_REQUEST;
            };

            let m = &opaque.metrics;
            let uptime = opaque.start_instant.elapsed().as_secs();

            let snapshot = PrimeMetrics {
                active_connections: m.active_connections.load(Ordering::Relaxed),
                total_connections: m.total_connections.load(Ordering::Relaxed),
                bytes_sent: m.bytes_sent.load(Ordering::Relaxed),
                bytes_received: m.bytes_received.load(Ordering::Relaxed),
                blocked_requests: m.blocked_requests.load(Ordering::Relaxed),
                blocked_ads: m.blocked_ads.load(Ordering::Relaxed),
                blocked_trackers: m.blocked_trackers.load(Ordering::Relaxed),
                dpi_bypassed: m.dpi_bypassed.load(Ordering::Relaxed),
                vpn_fallback: m.vpn_fallback.load(Ordering::Relaxed),
                dns_queries: m.dns_queries.load(Ordering::Relaxed),
                uptime_secs: uptime,
            };

            // SAFETY: out was validated non-null and caller guarantees it points to
            // a writable PrimeMetrics allocation with correct alignment.
            unsafe {
                std::ptr::write(out, snapshot);
            }
            PRIME_OK
        },
    )
}

/// Aggregated privacy statistics for display in a dashboard.
///
/// Contains session-scoped and all-time blocked request counters.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PrimePrivacyStats {
    /// Blocked requests in the current engine session.
    pub session_blocked: u64,
    /// Lifetime blocked requests (persisted across restarts if enabled).
    pub total_blocked: u64,
}

/// Fill `out` with current privacy statistics.
///
/// Returns `0` on success, or a positive error code on failure.
///
/// # Safety
///
/// * `engine` must be a valid pointer returned by `prime_engine_new`.
/// * `out` must point to a writable `PrimePrivacyStats` instance.
#[no_mangle]
pub unsafe extern "C" fn prime_privacy_stats(
    engine: *mut PrimeEngine,
    out: *mut PrimePrivacyStats,
) -> i32 {
    ffi_guard(
        "prime_privacy_stats",
        || PRIME_ERR_RUNTIME,
        || {
            if engine.is_null() {
                set_last_error_text("engine pointer is null");
                return PRIME_ERR_NULL_PTR;
            }
            if out.is_null() {
                set_last_error_text("out pointer is null");
                return PRIME_ERR_NULL_PTR;
            }

            // SAFETY: engine was validated non-null; magic check inside engine_opaque_mut.
            let Some(opaque) = (unsafe { engine_opaque_mut(engine) }) else {
                set_last_error_text("invalid engine handle pointer");
                return PRIME_ERR_INVALID_REQUEST;
            };

            let m = &opaque.metrics;
            let session = m.blocked_requests.load(Ordering::Relaxed);
            let total = m.total_blocked_persistent.load(Ordering::Relaxed);

            let stats = PrimePrivacyStats {
                session_blocked: session,
                total_blocked: total,
            };

            // SAFETY: out was validated non-null and caller guarantees it points to
            // a writable PrimePrivacyStats allocation with correct alignment.
            unsafe {
                std::ptr::write(out, stats);
            }
            PRIME_OK
        },
    )
}

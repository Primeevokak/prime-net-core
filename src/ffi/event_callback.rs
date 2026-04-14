//! FFI event notification system.
//!
//! Allows C consumers to register a callback that is invoked whenever
//! a notable engine event occurs (connection, route selection, DPI bypass,
//! ad/tracker block, DNS query, error, config change).
//!
//! Only one callback may be active at a time per engine handle.
//! The callback may be invoked from **any** thread.

use std::ffi::{c_char, c_void};
use std::ptr;

use crate::ffi::{
    engine_opaque_mut, ffi_guard, set_last_error_text, to_cstring, PrimeEngine,
    PRIME_ERR_INVALID_REQUEST, PRIME_ERR_NULL_PTR, PRIME_ERR_RUNTIME, PRIME_OK,
};

/// Categories of events reported through the callback.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimeEventType {
    /// A new relay connection was fully established.
    ConnectionEstablished = 1,
    /// A relay connection was closed (normally or on error).
    ConnectionClosed = 2,
    /// The route-race selected a winning route arm.
    RouteSelected = 3,
    /// A DPI evasion technique was applied to outbound data.
    DpiBypassApplied = 4,
    /// An ad-domain request was blocked.
    AdBlocked = 5,
    /// A tracker-domain request was blocked.
    TrackerBlocked = 6,
    /// A DNS query was resolved by the engine's resolver chain.
    DnsQuery = 7,
    /// An internal error occurred.
    Error = 8,
    /// The engine configuration was modified at runtime.
    ConfigChanged = 9,
}

/// Payload delivered to the registered event callback.
///
/// All string pointers are valid only for the duration of the callback
/// invocation.  The caller **must not** store or free them.
#[repr(C)]
pub struct PrimeEvent {
    /// What kind of event this is.
    pub event_type: PrimeEventType,
    /// Unix-epoch milliseconds when the event occurred.
    pub timestamp_ms: u64,
    /// Human-readable message (may be null).
    pub message: *const c_char,
    /// Domain associated with the event (may be null).
    pub domain: *const c_char,
    /// Opaque key-value JSON string with extra detail (may be null).
    pub extra: *const c_char,
}

/// Signature for the C event callback function pointer.
///
/// * `event` points to a `PrimeEvent` valid for the duration of the call.
/// * `user_data` is the opaque pointer passed to [`prime_set_event_callback`].
pub type PrimeEventCallback =
    Option<unsafe extern "C" fn(event: *const PrimeEvent, user_data: *mut c_void)>;

/// Register (or unregister) the engine event callback.
///
/// Only one callback can be active at a time; calling this replaces any
/// previously registered callback.  Pass a null `callback` to unregister.
///
/// The callback may be invoked from **any** thread, so the implementation
/// must be thread-safe.
///
/// Returns `0` on success, or a positive error code on failure.
///
/// # Safety
///
/// * `engine` must be a valid pointer returned by `prime_engine_new`.
/// * `user_data` must remain valid for as long as the callback is registered.
#[no_mangle]
pub unsafe extern "C" fn prime_set_event_callback(
    engine: *mut PrimeEngine,
    callback: PrimeEventCallback,
    user_data: *mut c_void,
) -> i32 {
    ffi_guard(
        "prime_set_event_callback",
        || PRIME_ERR_RUNTIME,
        || {
            if engine.is_null() {
                set_last_error_text("engine pointer is null");
                return PRIME_ERR_NULL_PTR;
            }

            // SAFETY: engine was validated non-null; magic check inside engine_opaque_mut.
            let Some(opaque) = (unsafe { engine_opaque_mut(engine) }) else {
                set_last_error_text("invalid engine handle pointer");
                return PRIME_ERR_INVALID_REQUEST;
            };

            let mut guard = opaque.event_cb.lock();
            match callback {
                Some(cb) => {
                    *guard = Some(EventCallbackSlot {
                        callback: cb,
                        user_data_bits: user_data as usize,
                    });
                    tracing::debug!("FFI: event callback registered");
                }
                None => {
                    *guard = None;
                    tracing::debug!("FFI: event callback unregistered");
                }
            }
            PRIME_OK
        },
    )
}

/// Internal storage for a registered event callback.
///
/// Stored inside `PrimeEngineOpaque` behind a `parking_lot::Mutex`.
pub(crate) struct EventCallbackSlot {
    /// The raw C function pointer.
    pub callback: unsafe extern "C" fn(event: *const PrimeEvent, user_data: *mut c_void),
    /// The `user_data` pointer bits, stored as `usize` so the slot is `Send`.
    pub user_data_bits: usize,
}

// SAFETY: The callback is an extern "C" fn pointer (inherently Send/Sync).
// user_data_bits is a plain usize copy of the raw pointer; the FFI contract
// requires the caller to keep the underlying data alive and thread-safe.
unsafe impl Send for EventCallbackSlot {}
unsafe impl Sync for EventCallbackSlot {}

/// Fire an event to the currently registered callback, if any.
///
/// Called from engine subsystems (SOCKS5, DNS, adblock) to notify the
/// FFI consumer.  If no callback is registered the call is a no-op.
///
/// Accepts the event callback mutex directly so subsystems don't need
/// the full `PrimeEngineOpaque` reference.
pub(crate) fn fire_event(
    event_cb: &parking_lot::Mutex<Option<EventCallbackSlot>>,
    event_type: PrimeEventType,
    message: Option<&str>,
    domain: Option<&str>,
    extra: Option<&str>,
) {
    let guard = event_cb.lock();
    let Some(slot) = guard.as_ref() else {
        return;
    };

    let message_c = message.and_then(to_cstring);
    let domain_c = domain.and_then(to_cstring);
    let extra_c = extra.and_then(to_cstring);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let event = PrimeEvent {
        event_type,
        timestamp_ms: now_ms,
        message: message_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
        domain: domain_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
        extra: extra_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
    };

    // SAFETY: The callback function pointer was validated at registration time.
    // user_data was provided by the caller and guaranteed valid per FFI contract.
    // The PrimeEvent and all its string pointers are stack-local and valid for
    // the duration of this call.
    unsafe {
        (slot.callback)(&event, slot.user_data_bits as *mut c_void);
    }
}

#[cfg(test)]
mod event_callback_tests {
    use super::*;

    static CALL_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    unsafe extern "C" fn test_cb(_event: *const PrimeEvent, _user_data: *mut c_void) {
        CALL_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn fire_event_invokes_callback() {
        use parking_lot::Mutex;
        use std::sync::atomic::Ordering;

        let event_cb = Mutex::new(Some(EventCallbackSlot {
            callback: test_cb,
            user_data_bits: 0,
        }));

        CALL_COUNT.store(0, Ordering::SeqCst);
        fire_event(
            &event_cb,
            PrimeEventType::AdBlocked,
            Some("test"),
            Some("ads.com"),
            None,
        );
        assert_eq!(CALL_COUNT.load(Ordering::SeqCst), 1);
    }
}

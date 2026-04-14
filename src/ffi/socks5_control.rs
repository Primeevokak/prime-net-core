//! FFI bindings for SOCKS5 proxy server lifecycle control.
//!
//! Provides start/stop/status/bound-address operations that C consumers
//! can call to manage the built-in SOCKS5 listener from any language.

use std::ffi::c_char;
use std::ptr;

use crate::ffi::event_callback::{fire_event, PrimeEventType};
use crate::ffi::{
    engine_opaque_mut, ffi_guard, parse_cstr, set_last_error, set_last_error_text, PrimeEngine,
    PRIME_ERR_INVALID_REQUEST, PRIME_ERR_NULL_PTR, PRIME_ERR_RUNTIME, PRIME_OK,
};

/// Start the SOCKS5 proxy server on the specified bind address.
///
/// `bind_addr` must be a NUL-terminated C string in `"host:port"` form
/// (e.g. `"127.0.0.1:1080"`).
///
/// Returns `0` on success, or a positive error code on failure.
/// Call `prime_last_error_message` for a human-readable description.
///
/// # Safety
///
/// * `engine` must be a valid pointer returned by `prime_engine_new`.
/// * `bind_addr` must point to a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn prime_socks5_start(
    engine: *mut PrimeEngine,
    bind_addr: *const c_char,
) -> i32 {
    ffi_guard(
        "prime_socks5_start",
        || PRIME_ERR_RUNTIME,
        || {
            if engine.is_null() {
                set_last_error_text("engine pointer is null");
                return PRIME_ERR_NULL_PTR;
            }
            if bind_addr.is_null() {
                set_last_error_text("bind_addr pointer is null");
                return PRIME_ERR_NULL_PTR;
            }

            let addr_str = match parse_cstr(bind_addr, "bind_addr") {
                Ok(v) => v,
                Err(e) => {
                    set_last_error(e);
                    return PRIME_ERR_INVALID_REQUEST;
                }
            };

            // SAFETY: engine was validated non-null; magic check inside engine_opaque_mut.
            let Some(opaque) = (unsafe { engine_opaque_mut(engine) }) else {
                set_last_error_text("invalid engine handle pointer");
                return PRIME_ERR_INVALID_REQUEST;
            };

            let addr: std::net::SocketAddr = match addr_str.parse() {
                Ok(a) => a,
                Err(e) => {
                    set_last_error_text(&format!("invalid bind address: {e}"));
                    return PRIME_ERR_INVALID_REQUEST;
                }
            };

            let mut guard = opaque.socks5_state.lock();
            if guard.running {
                set_last_error_text("SOCKS5 server is already running");
                return PRIME_ERR_INVALID_REQUEST;
            }

            guard.running = true;
            guard.bound_addr_c = crate::ffi::to_cstring(&addr.to_string());
            drop(guard);

            fire_event(
                &opaque.event_cb,
                PrimeEventType::ConnectionEstablished,
                Some("SOCKS5 server started"),
                None,
                Some(&format!("{{\"bind_addr\":\"{addr}\"}}")),
            );

            tracing::info!(%addr, "FFI: SOCKS5 server start requested");
            PRIME_OK
        },
    )
}

/// Stop the SOCKS5 proxy server.
///
/// Returns `0` on success, or a positive error code on failure.
///
/// # Safety
///
/// `engine` must be a valid pointer returned by `prime_engine_new`.
#[no_mangle]
pub unsafe extern "C" fn prime_socks5_stop(engine: *mut PrimeEngine) -> i32 {
    ffi_guard(
        "prime_socks5_stop",
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

            let mut guard = opaque.socks5_state.lock();
            if !guard.running {
                set_last_error_text("SOCKS5 server is not running");
                return PRIME_ERR_INVALID_REQUEST;
            }

            guard.running = false;
            guard.bound_addr_c = None;
            drop(guard);

            fire_event(
                &opaque.event_cb,
                PrimeEventType::ConnectionClosed,
                Some("SOCKS5 server stopped"),
                None,
                None,
            );

            tracing::info!("FFI: SOCKS5 server stop requested");
            PRIME_OK
        },
    )
}

/// Check whether the SOCKS5 server is currently running.
///
/// Returns `1` if running, `0` if stopped, or a negative error code.
///
/// # Safety
///
/// `engine` must be a valid pointer returned by `prime_engine_new`.
#[no_mangle]
pub unsafe extern "C" fn prime_socks5_status(engine: *mut PrimeEngine) -> i32 {
    ffi_guard(
        "prime_socks5_status",
        || -PRIME_ERR_RUNTIME,
        || {
            if engine.is_null() {
                return -PRIME_ERR_NULL_PTR;
            }

            // SAFETY: engine was validated non-null; magic check inside engine_opaque_mut.
            let Some(opaque) = (unsafe { engine_opaque_mut(engine) }) else {
                return -PRIME_ERR_INVALID_REQUEST;
            };

            let guard = opaque.socks5_state.lock();
            i32::from(guard.running)
        },
    )
}

/// Get the actual bound address of the running SOCKS5 server.
///
/// Returns a pointer to a NUL-terminated C string (e.g. `"127.0.0.1:1080"`),
/// or null if the server is not running.
///
/// The returned pointer is owned by the engine and **must not** be freed
/// by the caller.  It remains valid until the next call to
/// `prime_socks5_start` or `prime_socks5_stop`.
///
/// # Safety
///
/// `engine` must be a valid pointer returned by `prime_engine_new`.
#[no_mangle]
pub unsafe extern "C" fn prime_socks5_bound_addr(engine: *mut PrimeEngine) -> *const c_char {
    ffi_guard("prime_socks5_bound_addr", ptr::null, || {
        if engine.is_null() {
            return ptr::null();
        }

        // SAFETY: engine was validated non-null; magic check inside engine_opaque_mut.
        let Some(opaque) = (unsafe { engine_opaque_mut(engine) }) else {
            return ptr::null();
        };

        let guard = opaque.socks5_state.lock();
        match &guard.bound_addr_c {
            Some(cstr) => cstr.as_ptr(),
            None => ptr::null(),
        }
    })
}

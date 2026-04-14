//! FFI bindings for engine configuration management.
//!
//! Allows C consumers to load, inspect, and modify the engine config
//! at runtime via TOML strings or file paths.

use std::ffi::{c_char, CString};
use std::ptr;

use crate::config::EngineConfig;
use crate::ffi::{
    engine_opaque_mut, ffi_guard, parse_cstr, set_last_error, set_last_error_text, PrimeEngine,
    PRIME_ERR_INVALID_REQUEST, PRIME_ERR_NULL_PTR, PRIME_ERR_RUNTIME, PRIME_OK,
};

/// Load engine configuration from a TOML file at `path`.
///
/// The file is read, parsed, validated, and stored in the engine handle.
/// Returns `0` on success, or a positive error code on failure.
///
/// # Safety
///
/// * `engine` must be a valid pointer returned by `prime_engine_new`.
/// * `path` must point to a valid NUL-terminated UTF-8 file path.
#[no_mangle]
pub unsafe extern "C" fn prime_config_load(engine: *mut PrimeEngine, path: *const c_char) -> i32 {
    ffi_guard(
        "prime_config_load",
        || PRIME_ERR_RUNTIME,
        || {
            if engine.is_null() {
                set_last_error_text("engine pointer is null");
                return PRIME_ERR_NULL_PTR;
            }
            if path.is_null() {
                set_last_error_text("path pointer is null");
                return PRIME_ERR_NULL_PTR;
            }

            let path_str = match parse_cstr(path, "path") {
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

            let config = match EngineConfig::from_file(&path_str) {
                Ok(c) => c,
                Err(e) => {
                    set_last_error(e);
                    return PRIME_ERR_INVALID_REQUEST;
                }
            };

            *opaque.config.lock() = config;
            tracing::info!(path = %path_str, "FFI: config loaded from file");
            PRIME_OK
        },
    )
}

/// Load engine configuration from a TOML string.
///
/// The string is parsed, validated, and stored in the engine handle.
/// Returns `0` on success, or a positive error code on failure.
///
/// # Safety
///
/// * `engine` must be a valid pointer returned by `prime_engine_new`.
/// * `toml_str` must point to a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn prime_config_load_toml(
    engine: *mut PrimeEngine,
    toml_str: *const c_char,
) -> i32 {
    ffi_guard(
        "prime_config_load_toml",
        || PRIME_ERR_RUNTIME,
        || {
            if engine.is_null() {
                set_last_error_text("engine pointer is null");
                return PRIME_ERR_NULL_PTR;
            }
            if toml_str.is_null() {
                set_last_error_text("toml_str pointer is null");
                return PRIME_ERR_NULL_PTR;
            }

            let raw = match parse_cstr(toml_str, "toml_str") {
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

            let mut config: EngineConfig = match toml::from_str(&raw) {
                Ok(c) => c,
                Err(e) => {
                    set_last_error_text(&format!("TOML parse error: {e}"));
                    return PRIME_ERR_INVALID_REQUEST;
                }
            };

            let _ = config.apply_compat_repairs();
            if let Err(e) = config.validate() {
                set_last_error(e);
                return PRIME_ERR_INVALID_REQUEST;
            }

            *opaque.config.lock() = config;
            tracing::info!("FFI: config loaded from TOML string");
            PRIME_OK
        },
    )
}

/// Serialize the current engine configuration as a TOML string.
///
/// Returns a newly-allocated NUL-terminated C string, or null on error.
/// The caller **must** free the returned pointer with [`prime_string_free`].
///
/// # Safety
///
/// `engine` must be a valid pointer returned by `prime_engine_new`.
#[no_mangle]
pub unsafe extern "C" fn prime_config_get_toml(engine: *mut PrimeEngine) -> *mut c_char {
    ffi_guard("prime_config_get_toml", ptr::null_mut, || {
        if engine.is_null() {
            set_last_error_text("engine pointer is null");
            return ptr::null_mut();
        }

        // SAFETY: engine was validated non-null; magic check inside engine_opaque_mut.
        let Some(opaque) = (unsafe { engine_opaque_mut(engine) }) else {
            set_last_error_text("invalid engine handle pointer");
            return ptr::null_mut();
        };

        let config = opaque.config.lock();
        let toml_text = match toml::to_string_pretty(&*config) {
            Ok(s) => s,
            Err(e) => {
                set_last_error_text(&format!("TOML serialization error: {e}"));
                return ptr::null_mut();
            }
        };

        match CString::new(toml_text) {
            Ok(cs) => cs.into_raw(),
            Err(e) => {
                set_last_error_text(&format!("config contains interior NUL byte: {e}"));
                ptr::null_mut()
            }
        }
    })
}

/// Set a single configuration value by dot-separated key path.
///
/// Merges the key/value into the current config via a TOML fragment
/// (e.g. key `"evasion.prime_mode"`, value `"true"`).
///
/// Returns `0` on success, or a positive error code on failure.
///
/// # Safety
///
/// * `engine` must be a valid pointer returned by `prime_engine_new`.
/// * `key` and `value` must point to valid NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn prime_config_set(
    engine: *mut PrimeEngine,
    key: *const c_char,
    value: *const c_char,
) -> i32 {
    ffi_guard(
        "prime_config_set",
        || PRIME_ERR_RUNTIME,
        || {
            if engine.is_null() {
                set_last_error_text("engine pointer is null");
                return PRIME_ERR_NULL_PTR;
            }
            if key.is_null() {
                set_last_error_text("key pointer is null");
                return PRIME_ERR_NULL_PTR;
            }
            if value.is_null() {
                set_last_error_text("value pointer is null");
                return PRIME_ERR_NULL_PTR;
            }

            let key_str = match parse_cstr(key, "key") {
                Ok(v) => v,
                Err(e) => {
                    set_last_error(e);
                    return PRIME_ERR_INVALID_REQUEST;
                }
            };
            let value_str = match parse_cstr(value, "value") {
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

            // Build a minimal TOML document from the dot-path key and value,
            // then merge it into the existing config by re-serializing.
            let mut config_guard = opaque.config.lock();
            let current_toml = match toml::to_string_pretty(&*config_guard) {
                Ok(s) => s,
                Err(e) => {
                    set_last_error_text(&format!("failed to serialize current config: {e}"));
                    return PRIME_ERR_RUNTIME;
                }
            };

            let mut table: toml::Table = match current_toml.parse() {
                Ok(t) => t,
                Err(e) => {
                    set_last_error_text(&format!("internal config re-parse failed: {e}"));
                    return PRIME_ERR_RUNTIME;
                }
            };

            // Parse the user-supplied value as a TOML value.
            let parsed_value: toml::Value = match value_str.parse::<toml::Value>() {
                Ok(v) => v,
                Err(_) => {
                    // Treat as a bare string if it doesn't parse as a TOML literal.
                    toml::Value::String(value_str.clone())
                }
            };

            // Walk the dot-separated path, creating intermediate tables as needed.
            let segments: Vec<&str> = key_str.split('.').collect();
            if segments.is_empty() || segments.iter().any(|s| s.is_empty()) {
                set_last_error_text("key must be a non-empty dot-separated path");
                return PRIME_ERR_INVALID_REQUEST;
            }

            let mut current: &mut toml::Table = &mut table;
            for &segment in &segments[..segments.len() - 1] {
                let entry = current
                    .entry(segment.to_owned())
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()));
                match entry {
                    toml::Value::Table(ref mut t) => current = t,
                    _ => {
                        set_last_error_text(&format!(
                            "key path segment '{segment}' is not a table"
                        ));
                        return PRIME_ERR_INVALID_REQUEST;
                    }
                }
            }
            let last_segment = segments[segments.len() - 1];
            current.insert(last_segment.to_owned(), parsed_value);

            // Re-parse the modified table back into EngineConfig.
            let toml_text = match toml::to_string_pretty(&table) {
                Ok(s) => s,
                Err(e) => {
                    set_last_error_text(&format!("failed to serialize modified config table: {e}"));
                    return PRIME_ERR_RUNTIME;
                }
            };
            let mut new_config: EngineConfig = match toml::from_str(&toml_text) {
                Ok(c) => c,
                Err(e) => {
                    set_last_error_text(&format!(
                        "config invalid after setting {key_str}={value_str}: {e}"
                    ));
                    return PRIME_ERR_INVALID_REQUEST;
                }
            };

            let _ = new_config.apply_compat_repairs();
            if let Err(e) = new_config.validate() {
                set_last_error(e);
                return PRIME_ERR_INVALID_REQUEST;
            }

            *config_guard = new_config;
            tracing::debug!(key = %key_str, value = %value_str, "FFI: config key set");
            PRIME_OK
        },
    )
}

/// Free a C string previously returned by [`prime_config_get_toml`]
/// or any other `prime_*` function that documents caller-must-free semantics.
///
/// Passing null is a safe no-op.
///
/// # Safety
///
/// `ptr` must be null or a pointer previously returned by a `prime_*`
/// function that allocates via `CString::into_raw`.
#[no_mangle]
pub unsafe extern "C" fn prime_string_free(ptr: *mut c_char) {
    ffi_guard(
        "prime_string_free",
        || (),
        || {
            if ptr.is_null() {
                return;
            }
            // SAFETY: ptr was allocated by CString::into_raw in prime_config_get_toml
            // or similar functions. Caller guarantees single-free semantics.
            unsafe {
                let _ = CString::from_raw(ptr);
            }
        },
    );
}

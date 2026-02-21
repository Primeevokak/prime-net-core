use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use reqwest::Method;
use tokio::task::AbortHandle;

use crate::config::EngineConfig;
use crate::core::chunk_manager::ProgressHook;
use crate::core::{parse_header_line, RequestData, ResponseData};
use crate::engine::PrimeEngine as RustPrimeEngine;
use crate::error::EngineError;
use crate::ffi::callbacks::{FfiProgressContext, ProgressCallback};

pub mod callbacks;

static LAST_ERROR: Lazy<Mutex<Option<CString>>> = Lazy::new(|| Mutex::new(None));

#[repr(C)]
pub struct PrimeEngine {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PrimeRequestHandle {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimeRequestStatus {
    PENDING = 0,
    RUNNING = 1,
    COMPLETED = 2,
    CANCELLED = 3,
    FAILED = 4,
}

struct PrimeRequestHandleInner {
    rx: parking_lot::Mutex<std::sync::mpsc::Receiver<Result<ResponseData, EngineError>>>,
    tx: std::sync::mpsc::Sender<Result<ResponseData, EngineError>>,
    status: Arc<AtomicU8>,
    abort: parking_lot::Mutex<Option<AbortHandle>>,
}

struct FfiTask {
    request: RequestData,
    progress: Option<ProgressHook>,
    result_tx: std::sync::mpsc::Sender<Result<ResponseData, EngineError>>,
    status: Arc<AtomicU8>,
    abort_tx: std::sync::mpsc::Sender<AbortHandle>,
}

enum EngineMsg {
    Task(FfiTask),
    Shutdown,
}

struct PrimeEngineHandle {
    msg_tx: tokio::sync::mpsc::UnboundedSender<EngineMsg>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for PrimeEngineHandle {
    fn drop(&mut self) {
        // Best-effort: signal shutdown and join the runtime thread.
        let _ = self.msg_tx.send(EngineMsg::Shutdown);
        if let Some(j) = self.worker.take() {
            let _ = j.join();
        }
    }
}

#[repr(C)]
pub struct PrimeRequest {
    pub url: *const c_char,
    pub method: *const c_char,
    pub headers: *const *const c_char,
    pub headers_count: usize,
    pub body: *const u8,
    pub body_len: usize,
}

#[repr(C)]
pub struct PrimeResponse {
    pub status_code: u16,
    pub headers: *const *const c_char,
    pub headers_count: usize,
    pub body: *const u8,
    pub body_len: usize,
    pub error_code: i32,
    pub error_message: *const c_char,
    pub owner: *mut c_void,
}

struct OwnedPrimeResponse {
    _headers: Vec<CString>,
    header_ptrs: Vec<*const c_char>,
    body: Vec<u8>,
    error_message: Option<CString>,
}

const PRIME_OK: i32 = 0;
const PRIME_ERR_NULL_PTR: i32 = 1;
const PRIME_ERR_INVALID_UTF8: i32 = 2;
const PRIME_ERR_INVALID_REQUEST: i32 = 3;
const PRIME_ERR_RUNTIME: i32 = 4;

#[no_mangle]
pub extern "C" fn prime_engine_new(config_path: *const c_char) -> *mut PrimeEngine {
    let result = create_engine(config_path);
    match result {
        Ok(handle) => Box::into_raw(Box::new(handle)) as *mut PrimeEngine,
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
/// # Safety
/// `engine` must be a pointer previously returned by `prime_engine_new`, not yet freed.
pub unsafe extern "C" fn prime_engine_free(engine: *mut PrimeEngine) {
    if engine.is_null() {
        return;
    }
    // SAFETY: pointer was created by prime_engine_new and is unique here.
    unsafe {
        let _ = Box::from_raw(engine as *mut PrimeEngineHandle);
    }
}

#[no_mangle]
/// # Safety
/// `engine` must be a valid pointer from `prime_engine_new`, and `request` must point to a valid
/// `PrimeRequest` whose referenced buffers remain alive for the duration of this call.
pub unsafe extern "C" fn prime_engine_fetch(
    engine: *mut PrimeEngine,
    request: *const PrimeRequest,
    callback: ProgressCallback,
    user_data: *mut c_void,
) -> *mut PrimeResponse {
    if engine.is_null() {
        return pack_error(PRIME_ERR_NULL_PTR, "engine pointer is null");
    }
    if request.is_null() {
        return pack_error(PRIME_ERR_NULL_PTR, "request pointer is null");
    }

    let parsed_request = match parse_request(unsafe { &*request }) {
        Ok(req) => req,
        Err(err) => return pack_error(error_code_from(&err), &err.to_string()),
    };

    let progress_context = FfiProgressContext {
        callback,
        user_data_bits: user_data as usize,
    };
    let progress_hook: Option<ProgressHook> = if callback.is_some() {
        let ctx = progress_context;
        Some(Arc::new(move |downloaded, total, speed_mbps| {
            ctx.emit(downloaded, total, speed_mbps);
        }))
    } else {
        None
    };

    let eng = unsafe { &*(engine as *mut PrimeEngineHandle) };
    let (tx, rx) = std::sync::mpsc::channel();
    let (abort_tx, _abort_rx) = std::sync::mpsc::channel::<AbortHandle>();
    let status = Arc::new(AtomicU8::new(PrimeRequestStatus::PENDING as u8));
    let task = FfiTask {
        request: parsed_request,
        progress: progress_hook,
        result_tx: tx,
        status,
        abort_tx,
    };
    if eng.msg_tx.send(EngineMsg::Task(task)).is_err() {
        return pack_error(PRIME_ERR_RUNTIME, "engine runtime thread is not running");
    }

    match rx.recv() {
        Ok(Ok(response)) => pack_ok(response),
        Ok(Err(err)) => pack_error(error_code_from(&err), &err.to_string()),
        Err(_) => pack_error(PRIME_ERR_RUNTIME, "request was cancelled (engine dropped)"),
    }
}

#[no_mangle]
/// # Safety
/// `engine` must be a valid pointer from `prime_engine_new`, and `request` must point to a valid
/// `PrimeRequest` whose referenced buffers remain alive for the duration of this call.
pub unsafe extern "C" fn prime_engine_fetch_async(
    engine: *mut PrimeEngine,
    request: *const PrimeRequest,
    callback: ProgressCallback,
    user_data: *mut c_void,
) -> *mut PrimeRequestHandle {
    if engine.is_null() {
        set_last_error(EngineError::NullPointer("engine"));
        return ptr::null_mut();
    }
    if request.is_null() {
        set_last_error(EngineError::NullPointer("request"));
        return ptr::null_mut();
    }

    let parsed_request = match parse_request(unsafe { &*request }) {
        Ok(req) => req,
        Err(err) => {
            set_last_error(err);
            return ptr::null_mut();
        }
    };

    let progress_context = FfiProgressContext {
        callback,
        user_data_bits: user_data as usize,
    };
    let progress_hook: Option<ProgressHook> = if callback.is_some() {
        let ctx = progress_context;
        Some(Arc::new(move |downloaded, total, speed_mbps| {
            ctx.emit(downloaded, total, speed_mbps);
        }))
    } else {
        None
    };

    // SAFETY: validated non-null pointer created by prime_engine_new.
    let eng = unsafe { &*(engine as *mut PrimeEngineHandle) };

    let (tx, rx) = std::sync::mpsc::channel();
    let (abort_tx, abort_rx) = std::sync::mpsc::channel::<AbortHandle>();
    let status = Arc::new(AtomicU8::new(PrimeRequestStatus::PENDING as u8));
    let task = FfiTask {
        request: parsed_request,
        progress: progress_hook,
        result_tx: tx.clone(),
        status: status.clone(),
        abort_tx,
    };
    if eng.msg_tx.send(EngineMsg::Task(task)).is_err() {
        set_last_error(EngineError::Internal(
            "engine runtime thread is not running".to_owned(),
        ));
        return ptr::null_mut();
    }

    let abort = match abort_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(v) => v,
        Err(_) => {
            set_last_error(EngineError::Internal(
                "engine did not acknowledge async request (abort handle missing)".to_owned(),
            ));
            return ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(PrimeRequestHandleInner {
        rx: parking_lot::Mutex::new(rx),
        tx,
        status,
        abort: parking_lot::Mutex::new(Some(abort)),
    })) as *mut PrimeRequestHandle
}

#[no_mangle]
/// # Safety
/// `handle` must be a valid pointer returned by `prime_engine_fetch_async` and not previously
/// freed via `prime_request_free` or consumed by a successful `prime_request_wait`.
pub unsafe extern "C" fn prime_request_wait(
    handle: *mut PrimeRequestHandle,
    timeout_ms: u64,
) -> *mut PrimeResponse {
    if handle.is_null() {
        return pack_error(PRIME_ERR_NULL_PTR, "request handle pointer is null");
    }
    // SAFETY: pointer was allocated by prime_engine_fetch_async.
    let inner = unsafe { &*(handle as *mut PrimeRequestHandleInner) };

    // Best-effort: if already cancelled, return immediately.
    if inner.status.load(Ordering::SeqCst) == PrimeRequestStatus::CANCELLED as u8 {
        unsafe { drop(Box::from_raw(handle as *mut PrimeRequestHandleInner)) };
        return pack_error(PRIME_ERR_RUNTIME, "cancelled");
    }

    let res =
        if timeout_ms == 0 {
            inner.rx.lock().recv().map_err(|_| {
                EngineError::Internal("request was cancelled (engine dropped)".to_owned())
            })
        } else {
            inner
                .rx
                .lock()
                .recv_timeout(Duration::from_millis(timeout_ms))
                .map_err(|e| match e {
                    std::sync::mpsc::RecvTimeoutError::Timeout => {
                        EngineError::Internal("timeout".to_owned())
                    }
                    std::sync::mpsc::RecvTimeoutError::Disconnected => {
                        EngineError::Internal("request was cancelled (engine dropped)".to_owned())
                    }
                })
        };

    match res {
        Ok(Ok(response)) => {
            inner
                .status
                .store(PrimeRequestStatus::COMPLETED as u8, Ordering::SeqCst);
            // SAFETY: we are done with the handle; free it.
            unsafe { drop(Box::from_raw(handle as *mut PrimeRequestHandleInner)) };
            pack_ok(response)
        }
        Ok(Err(err)) => {
            inner
                .status
                .store(PrimeRequestStatus::FAILED as u8, Ordering::SeqCst);
            unsafe { drop(Box::from_raw(handle as *mut PrimeRequestHandleInner)) };
            pack_error(error_code_from(&err), &err.to_string())
        }
        Err(EngineError::Internal(msg)) if msg == "timeout" => {
            // Keep handle alive so caller can wait again later.
            pack_error(PRIME_ERR_RUNTIME, "timeout")
        }
        Err(err) => {
            inner
                .status
                .store(PrimeRequestStatus::FAILED as u8, Ordering::SeqCst);
            unsafe { drop(Box::from_raw(handle as *mut PrimeRequestHandleInner)) };
            pack_error(error_code_from(&err), &err.to_string())
        }
    }
}

#[no_mangle]
/// # Safety
/// `handle` must be a valid pointer returned by `prime_engine_fetch_async`.
pub unsafe extern "C" fn prime_request_cancel(handle: *mut PrimeRequestHandle) -> i32 {
    if handle.is_null() {
        return PRIME_ERR_NULL_PTR;
    }
    // SAFETY: pointer was allocated by prime_engine_fetch_async.
    let inner = unsafe { &*(handle as *mut PrimeRequestHandleInner) };

    let cur = inner.status.load(Ordering::SeqCst);
    if cur == PrimeRequestStatus::COMPLETED as u8 || cur == PrimeRequestStatus::FAILED as u8 {
        return PRIME_OK;
    }
    if cur == PrimeRequestStatus::CANCELLED as u8 {
        return PRIME_OK;
    }

    inner
        .status
        .store(PrimeRequestStatus::CANCELLED as u8, Ordering::SeqCst);

    if let Some(abort) = inner.abort.lock().as_ref() {
        abort.abort();
    }

    // Wake any waiter (best-effort). The runtime task may still deliver a result if it already finished.
    let _ = inner
        .tx
        .send(Err(EngineError::Internal("cancelled".to_owned())));

    PRIME_OK
}

#[no_mangle]
/// # Safety
/// `handle` must be a valid pointer returned by `prime_engine_fetch_async`.
pub unsafe extern "C" fn prime_request_status(
    handle: *mut PrimeRequestHandle,
) -> PrimeRequestStatus {
    if handle.is_null() {
        return PrimeRequestStatus::FAILED;
    }
    // SAFETY: pointer was allocated by prime_engine_fetch_async.
    let inner = unsafe { &*(handle as *mut PrimeRequestHandleInner) };
    match inner.status.load(Ordering::SeqCst) {
        0 => PrimeRequestStatus::PENDING,
        1 => PrimeRequestStatus::RUNNING,
        2 => PrimeRequestStatus::COMPLETED,
        3 => PrimeRequestStatus::CANCELLED,
        _ => PrimeRequestStatus::FAILED,
    }
}

#[no_mangle]
/// # Safety
/// `handle` must be a valid pointer returned by `prime_engine_fetch_async` and not already freed.
pub unsafe extern "C" fn prime_request_free(handle: *mut PrimeRequestHandle) {
    if handle.is_null() {
        return;
    }
    // Best-effort: cancel underlying task to avoid background network activity after handle free.
    let _ = unsafe { prime_request_cancel(handle) };
    unsafe {
        drop(Box::from_raw(handle as *mut PrimeRequestHandleInner));
    }
}

#[no_mangle]
/// # Safety
/// `response` must be a pointer previously returned by `prime_engine_fetch` or `prime_request_wait`
/// and not already freed via `prime_response_free`.
pub unsafe extern "C" fn prime_response_free(response: *mut PrimeResponse) {
    if response.is_null() {
        return;
    }
    // SAFETY: response pointer was allocated in pack_response.
    unsafe {
        let boxed = Box::from_raw(response);
        if !boxed.owner.is_null() {
            let _ = Box::from_raw(boxed.owner as *mut OwnedPrimeResponse);
        }
    }
}

#[no_mangle]
pub extern "C" fn prime_last_error_message() -> *const c_char {
    let guard = LAST_ERROR.lock();
    guard.as_ref().map_or(ptr::null(), |msg| msg.as_ptr())
}

fn create_engine(config_path: *const c_char) -> Result<PrimeEngineHandle, EngineError> {
    let config = if config_path.is_null() {
        EngineConfig::default()
    } else {
        let path = parse_cstr(config_path, "config_path")?;
        EngineConfig::from_file(path)?
    };

    let (msg_tx, mut msg_rx) = tokio::sync::mpsc::unbounded_channel::<EngineMsg>();
    let (init_tx, init_rx) = std::sync::mpsc::channel::<Result<(), EngineError>>();

    let worker = std::thread::Builder::new()
        .name("prime-engine-runtime".to_owned())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(v) => v,
                Err(_) => return,
            };

            rt.block_on(async move {
                let engine = match RustPrimeEngine::new(config).await {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = init_tx.send(Err(e));
                        return;
                    }
                };
                let client = engine.client();
                let _keep_alive = engine;
                let _ = init_tx.send(Ok(()));

                while let Some(msg) = msg_rx.recv().await {
                    match msg {
                        EngineMsg::Task(task) => {
                            let client = client.clone();
                            task.status
                                .store(PrimeRequestStatus::RUNNING as u8, Ordering::SeqCst);
                            let status = task.status.clone();
                            let result_tx = task.result_tx;
                            let request = task.request;
                            let progress = task.progress;
                            let j = tokio::spawn(async move {
                                let res = client.fetch(request, progress).await;
                                match &res {
                                    Ok(_) => status.store(
                                        PrimeRequestStatus::COMPLETED as u8,
                                        Ordering::SeqCst,
                                    ),
                                    Err(_) => status
                                        .store(PrimeRequestStatus::FAILED as u8, Ordering::SeqCst),
                                };
                                let _ = result_tx.send(res);
                            });
                            let _ = task.abort_tx.send(j.abort_handle());
                        }
                        EngineMsg::Shutdown => break,
                    }
                }
            });
        })
        .map_err(|e| EngineError::Internal(format!("runtime thread spawn failed: {e}")))?;

    // Wait for runtime initialization (including PT setup if configured).
    match init_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            return Err(EngineError::Internal(
                "engine initialization timed out".to_owned(),
            ));
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            return Err(EngineError::Internal(
                "engine initialization failed (runtime thread exited)".to_owned(),
            ));
        }
    }

    Ok(PrimeEngineHandle {
        msg_tx,
        worker: Some(worker),
    })
}

fn parse_request(input: &PrimeRequest) -> Result<RequestData, EngineError> {
    let url = parse_cstr(input.url, "request.url")?;
    let method_str = if input.method.is_null() {
        "GET".to_owned()
    } else {
        parse_cstr(input.method, "request.method")?
    };
    let method = Method::from_bytes(method_str.as_bytes())
        .map_err(|e| EngineError::InvalidInput(format!("invalid method: {e}")))?;

    let mut headers = Vec::new();
    if !input.headers.is_null() && input.headers_count > 0 {
        for idx in 0..input.headers_count {
            // SAFETY: headers points to an array of pointers with headers_count length.
            let ptr = unsafe { *input.headers.add(idx) };
            if ptr.is_null() {
                continue;
            }
            let line = parse_cstr(ptr, "request.headers[*]")?;
            if let Some((name, value)) = parse_header_line(&line) {
                headers.push((name, value));
            }
        }
    }

    let body = if input.body.is_null() || input.body_len == 0 {
        Vec::new()
    } else {
        // SAFETY: body pointer is expected to be valid for body_len bytes.
        unsafe { std::slice::from_raw_parts(input.body, input.body_len).to_vec() }
    };

    Ok(RequestData {
        url,
        method,
        headers,
        body,
    })
}

fn parse_cstr(ptr: *const c_char, field: &'static str) -> Result<String, EngineError> {
    if ptr.is_null() {
        return Err(EngineError::NullPointer(field));
    }
    // SAFETY: caller guarantees C string pointer is valid and NUL terminated.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str()
        .map(|v| v.to_owned())
        .map_err(|_| EngineError::Ffi(format!("invalid UTF-8 in {field}")))
}

fn pack_ok(response: ResponseData) -> *mut PrimeResponse {
    pack_response(
        response.status_code,
        response.headers,
        response.body,
        PRIME_OK,
        None,
    )
}

fn pack_error(code: i32, message: &str) -> *mut PrimeResponse {
    pack_response(0, Vec::new(), Vec::new(), code, Some(message.to_owned()))
}

fn pack_response(
    status_code: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    error_code: i32,
    error_message: Option<String>,
) -> *mut PrimeResponse {
    let header_strings: Vec<CString> = headers
        .into_iter()
        .filter_map(|(k, v)| to_cstring(&format!("{k}: {v}")))
        .collect();
    let header_ptrs: Vec<*const c_char> = header_strings.iter().map(|s| s.as_ptr()).collect();
    let error_message = error_message.and_then(|s| to_cstring(&s));

    let owned = Box::new(OwnedPrimeResponse {
        _headers: header_strings,
        header_ptrs,
        body,
        error_message,
    });

    let response = Box::new(PrimeResponse {
        status_code,
        headers: owned.header_ptrs.as_ptr(),
        headers_count: owned.header_ptrs.len(),
        body: owned.body.as_ptr(),
        body_len: owned.body.len(),
        error_code,
        error_message: owned
            .error_message
            .as_ref()
            .map_or(ptr::null(), |s| s.as_ptr()),
        owner: ptr::null_mut(),
    });

    let mut response = response;
    response.owner = Box::into_raw(owned) as *mut c_void;
    Box::into_raw(response)
}

fn set_last_error(err: EngineError) {
    let message = to_cstring(&err.to_string());
    let mut guard = LAST_ERROR.lock();
    *guard = message;
}

fn to_cstring(value: &str) -> Option<CString> {
    CString::new(value.replace('\0', " ")).ok()
}

fn error_code_from(error: &EngineError) -> i32 {
    match error {
        EngineError::NullPointer(_) => PRIME_ERR_NULL_PTR,
        EngineError::Utf8(_) | EngineError::Ffi(_) => PRIME_ERR_INVALID_UTF8,
        EngineError::InvalidInput(_) | EngineError::Config(_) => PRIME_ERR_INVALID_REQUEST,
        _ => PRIME_ERR_RUNTIME,
    }
}

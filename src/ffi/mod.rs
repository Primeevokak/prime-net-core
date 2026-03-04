use std::cell::RefCell;
use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use reqwest::Method;
use tokio::task::AbortHandle;

use crate::config::EngineConfig;
use crate::core::chunk_manager::ProgressHook;
use crate::core::{parse_header_line, RequestData, ResponseData};
use crate::engine::PrimeEngine as RustPrimeEngine;
use crate::error::EngineError;
use crate::ffi::callbacks::{FfiProgressContext, ProgressCallback};

pub mod callbacks;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

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
    abort_rx: parking_lot::Mutex<Option<std::sync::mpsc::Receiver<AbortHandle>>>,
}

#[derive(Clone, Copy, Default)]
struct RequestLifecycle {
    in_flight: u32,
    freed: bool,
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

struct PrimeEngineOpaque {
    magic: u64,
    handle: PrimeEngineHandle,
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
    magic: u64,
}

const PRIME_RESPONSE_MAGIC: u64 = 0x5052_494D_455F_5245; // "PRIME_RE"
const PRIME_OK: i32 = 0;
struct OwnedPrimeResponse {
    _headers: Vec<CString>,
    header_ptrs: Vec<*const c_char>,
    body: Vec<u8>,
    error_message: Option<CString>,
}

const PRIME_ERR_NULL_PTR: i32 = 1;
const PRIME_ERR_INVALID_UTF8: i32 = 2;
const PRIME_ERR_INVALID_REQUEST: i32 = 3;
const PRIME_ERR_RUNTIME: i32 = 4;
const PRIME_ENGINE_MAGIC: u64 = 0x5052_494D_455F_454E; // "PRIME_EN"
static REQUEST_LIFECYCLE: OnceLock<
    parking_lot::Mutex<std::collections::HashMap<usize, RequestLifecycle>>,
> = OnceLock::new();

fn request_lifecycle_map(
) -> &'static parking_lot::Mutex<std::collections::HashMap<usize, RequestLifecycle>> {
    REQUEST_LIFECYCLE.get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()))
}

fn register_request_handle(ptr: *mut PrimeRequestHandle) {
    request_lifecycle_map()
        .lock()
        .insert(ptr as usize, RequestLifecycle::default());
}

fn begin_request_op(ptr: *mut PrimeRequestHandle) -> bool {
    if ptr.is_null() {
        return false;
    }
    let mut guard = request_lifecycle_map().lock();
    let Some(state) = guard.get_mut(&(ptr as usize)) else {
        return false;
    };
    if state.freed {
        return false;
    }
    state.in_flight = state.in_flight.saturating_add(1);
    true
}

fn end_request_op(ptr: *mut PrimeRequestHandle) -> bool {
    let mut guard = request_lifecycle_map().lock();
    let Some(state) = guard.get_mut(&(ptr as usize)) else {
        return false;
    };
    state.in_flight = state.in_flight.saturating_sub(1);
    if state.freed && state.in_flight == 0 {
        guard.remove(&(ptr as usize));
        return true;
    }
    false
}

fn try_hydrate_abort_handle(inner: &PrimeRequestHandleInner) {
    if inner.abort.lock().is_some() {
        return;
    }
    let mut rx_slot = inner.abort_rx.lock();
    let Some(rx) = rx_slot.as_ref() else {
        return;
    };
    match rx.try_recv() {
        Ok(abort) => {
            *inner.abort.lock() = Some(abort);
            *rx_slot = None;
        }
        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
            *rx_slot = None;
        }
        Err(std::sync::mpsc::TryRecvError::Empty) => {}
    }
}

fn mark_request_freed(ptr: *mut PrimeRequestHandle) {
    let mut guard = request_lifecycle_map().lock();
    if let Some(state) = guard.get_mut(&(ptr as usize)) {
        state.freed = true;
    }
}

struct RequestOpGuard {
    ptr: *mut PrimeRequestHandle,
    active: bool,
}

impl RequestOpGuard {
    fn acquire(ptr: *mut PrimeRequestHandle) -> Option<Self> {
        if !begin_request_op(ptr) {
            return None;
        }
        Some(Self { ptr, active: true })
    }

    fn finish(&mut self) -> bool {
        if !self.active {
            return false;
        }
        self.active = false;
        end_request_op(self.ptr)
    }
}

impl Drop for RequestOpGuard {
    fn drop(&mut self) {
        if self.finish() {
            // SAFETY: lifecycle map guarantees single final drop point.
            unsafe {
                drop(Box::from_raw(self.ptr as *mut PrimeRequestHandleInner));
            }
        }
    }
}

unsafe fn engine_from_ptr<'a>(engine: *mut PrimeEngine) -> Option<&'a PrimeEngineHandle> {
    if engine.is_null() {
        return None;
    }
    // SAFETY: caller provides an opaque pointer from FFI boundary.
    let opaque = unsafe { &*(engine as *mut PrimeEngineOpaque) };
    if opaque.magic != PRIME_ENGINE_MAGIC {
        return None;
    }
    Some(&opaque.handle)
}

#[no_mangle]
pub extern "C" fn prime_engine_new(config_path: *const c_char) -> *mut PrimeEngine {
    ffi_guard("prime_engine_new", ptr::null_mut, || {
        let result = create_engine(config_path);
        match result {
            Ok(handle) => Box::into_raw(Box::new(PrimeEngineOpaque {
                magic: PRIME_ENGINE_MAGIC,
                handle,
            })) as *mut PrimeEngine,
            Err(err) => {
                set_last_error(err);
                ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
/// # Safety
/// `engine` must be a pointer previously returned by `prime_engine_new`, not yet freed.
pub unsafe extern "C" fn prime_engine_free(engine: *mut PrimeEngine) {
    ffi_guard(
        "prime_engine_free",
        || (),
        || {
            if engine.is_null() {
                return;
            }
            let opaque = engine as *mut PrimeEngineOpaque;
            unsafe {
                if (*opaque).magic != PRIME_ENGINE_MAGIC {
                    set_last_error(EngineError::InvalidInput(
                        "invalid PrimeEngine handle pointer".to_owned(),
                    ));
                    return;
                }
                (*opaque).magic = 0;
                let _ = Box::from_raw(opaque);
            }
        },
    );
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
    ffi_guard(
        "prime_engine_fetch",
        || {
            pack_error(
                PRIME_ERR_RUNTIME,
                "Rust panic occurred in prime_engine_fetch",
            )
        },
        || {
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

            let Some(eng) = (unsafe { engine_from_ptr(engine) }) else {
                return pack_error(PRIME_ERR_INVALID_REQUEST, "invalid engine handle pointer");
            };
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
        },
    )
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
    ffi_guard("prime_engine_fetch_async", ptr::null_mut, || {
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

        // SAFETY: pointer validation includes magic check.
        let Some(eng) = (unsafe { engine_from_ptr(engine) }) else {
            set_last_error(EngineError::InvalidInput(
                "invalid engine handle pointer".to_owned(),
            ));
            return ptr::null_mut();
        };

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
            Ok(v) => Some(v),
            Err(_) => {
                // Do not drop the request on this edge case: return a live handle so caller
                // can still wait for completion and avoid orphaned background work.
                set_last_error(EngineError::Internal(
                    "engine did not acknowledge async request in time; continuing without abort handle"
                        .to_owned(),
                ));
                None
            }
        };
        let abort_rx = if abort.is_some() {
            None
        } else {
            Some(abort_rx)
        };

        let ptr = Box::into_raw(Box::new(PrimeRequestHandleInner {
            rx: parking_lot::Mutex::new(rx),
            tx,
            status,
            abort: parking_lot::Mutex::new(abort),
            abort_rx: parking_lot::Mutex::new(abort_rx),
        })) as *mut PrimeRequestHandle;
        register_request_handle(ptr);
        ptr
    })
}

#[no_mangle]
/// # Safety
/// `handle` must be a valid pointer returned by `prime_engine_fetch_async` and not previously
/// freed via `prime_request_free`.
pub unsafe extern "C" fn prime_request_wait(
    handle: *mut PrimeRequestHandle,
    timeout_ms: u64,
) -> *mut PrimeResponse {
    ffi_guard(
        "prime_request_wait",
        || {
            pack_error(
                PRIME_ERR_RUNTIME,
                "Rust panic occurred in prime_request_wait",
            )
        },
        || {
            if handle.is_null() {
                return pack_error(PRIME_ERR_NULL_PTR, "request handle pointer is null");
            }
            let Some(_guard) = RequestOpGuard::acquire(handle) else {
                return pack_error(
                    PRIME_ERR_INVALID_REQUEST,
                    "request handle is freed or invalid",
                );
            };
            // SAFETY: pointer was allocated by prime_engine_fetch_async.
            // SAFETY: Lifecycle map ensures pointer is valid and not already freed.
            let inner = unsafe { &*(handle as *mut PrimeRequestHandleInner) };

            // If already cancelled, return immediately.
            if inner.status.load(Ordering::SeqCst) == PrimeRequestStatus::CANCELLED as u8 {
                return pack_error(PRIME_ERR_RUNTIME, "cancelled");
            }

            let res = if timeout_ms == 0 {
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
                        std::sync::mpsc::RecvTimeoutError::Disconnected => EngineError::Internal(
                            "request was cancelled (engine dropped)".to_owned(),
                        ),
                    })
            };

            match res {
                Ok(Ok(response)) => {
                    inner
                        .status
                        .store(PrimeRequestStatus::COMPLETED as u8, Ordering::SeqCst);
                    mark_request_freed(handle);
                    pack_ok(response)
                }
                Ok(Err(err)) => {
                    let mut code = error_code_from(&err);
                    if err.to_string() == "timeout" {
                        code = PRIME_ERR_RUNTIME;
                        pack_error(code, "timeout")
                    } else {
                        inner
                            .status
                            .store(PrimeRequestStatus::FAILED as u8, Ordering::SeqCst);
                        mark_request_freed(handle);
                        pack_error(code, &err.to_string())
                    }
                }
                Err(EngineError::Internal(msg)) if msg == "timeout" => {
                    pack_error(PRIME_ERR_RUNTIME, "timeout")
                }
                Err(err) => {
                    inner
                        .status
                        .store(PrimeRequestStatus::FAILED as u8, Ordering::SeqCst);
                    mark_request_freed(handle);
                    pack_error(error_code_from(&err), &err.to_string())
                }
            }
        },
    )
}

#[no_mangle]
/// # Safety
/// `handle` must be a valid pointer returned by `prime_engine_fetch_async`.
pub unsafe extern "C" fn prime_request_cancel(handle: *mut PrimeRequestHandle) -> i32 {
    ffi_guard(
        "prime_request_cancel",
        || PRIME_ERR_RUNTIME,
        || {
            if handle.is_null() {
                return PRIME_ERR_NULL_PTR;
            }
            let Some(_guard) = RequestOpGuard::acquire(handle) else {
                return PRIME_ERR_INVALID_REQUEST;
            };
            // SAFETY: pointer was allocated by prime_engine_fetch_async.
            // SAFETY: Lifecycle map ensures pointer is valid and not already freed.
            let inner = unsafe { &*(handle as *mut PrimeRequestHandleInner) };

            let cur = inner.status.load(Ordering::SeqCst);
            if cur == PrimeRequestStatus::COMPLETED as u8 || cur == PrimeRequestStatus::FAILED as u8
            {
                return PRIME_OK;
            }
            if cur == PrimeRequestStatus::CANCELLED as u8 {
                return PRIME_OK;
            }

            inner
                .status
                .store(PrimeRequestStatus::CANCELLED as u8, Ordering::SeqCst);
            try_hydrate_abort_handle(inner);

            if let Some(abort) = inner.abort.lock().as_ref() {
                abort.abort();
            }

            // Wake any waiter (best-effort). The runtime task may still deliver a result if it already finished.
            let _ = inner
                .tx
                .send(Err(EngineError::Internal("cancelled".to_owned())));

            PRIME_OK
        },
    )
}

#[no_mangle]
/// # Safety
/// `handle` must be a valid pointer returned by `prime_engine_fetch_async`.
pub unsafe extern "C" fn prime_request_status(
    handle: *mut PrimeRequestHandle,
) -> PrimeRequestStatus {
    ffi_guard(
        "prime_request_status",
        || PrimeRequestStatus::FAILED,
        || {
            if handle.is_null() {
                return PrimeRequestStatus::FAILED;
            }
            let Some(_guard) = RequestOpGuard::acquire(handle) else {
                return PrimeRequestStatus::FAILED;
            };
            // SAFETY: pointer was allocated by prime_engine_fetch_async.
            // SAFETY: Lifecycle map ensures pointer is valid and not already freed.
            let inner = unsafe { &*(handle as *mut PrimeRequestHandleInner) };
            match inner.status.load(Ordering::SeqCst) {
                0 => PrimeRequestStatus::PENDING,
                1 => PrimeRequestStatus::RUNNING,
                2 => PrimeRequestStatus::COMPLETED,
                3 => PrimeRequestStatus::CANCELLED,
                _ => PrimeRequestStatus::FAILED,
            }
        },
    )
}

#[no_mangle]
/// # Safety
/// `handle` must be a valid pointer returned by `prime_engine_fetch_async` and not already freed.
pub unsafe extern "C" fn prime_request_free(handle: *mut PrimeRequestHandle) {
    ffi_guard(
        "prime_request_free",
        || (),
        || {
            if handle.is_null() {
                return;
            }
            let Some(mut guard) = RequestOpGuard::acquire(handle) else {
                return;
            };
            // Best-effort: cancel underlying task to avoid background network activity after handle free.
            // SAFETY: Lifecycle map ensures pointer is valid and not already freed.
            let inner = unsafe { &*(handle as *mut PrimeRequestHandleInner) };
            let cur = inner.status.load(Ordering::SeqCst);
            if cur != PrimeRequestStatus::COMPLETED as u8
                && cur != PrimeRequestStatus::FAILED as u8
                && cur != PrimeRequestStatus::CANCELLED as u8
            {
                inner
                    .status
                    .store(PrimeRequestStatus::CANCELLED as u8, Ordering::SeqCst);
                try_hydrate_abort_handle(inner);
                if let Some(abort) = inner.abort.lock().as_ref() {
                    abort.abort();
                }
                let _ = inner
                    .tx
                    .send(Err(EngineError::Internal("cancelled".to_owned())));
            }
            mark_request_freed(handle);
            if guard.finish() {
                // SAFETY: lifecycle map guarantees single final drop point.
                unsafe {
                    drop(Box::from_raw(handle as *mut PrimeRequestHandleInner));
                }
            }
        },
    );
}

#[no_mangle]
/// # Safety
/// `response` must be a pointer previously returned by `prime_engine_fetch` or `prime_request_wait`
/// and not already freed via `prime_response_free`.
pub unsafe extern "C" fn prime_response_free(response: *mut PrimeResponse) {
    ffi_guard(
        "prime_response_free",
        || (),
        || {
            if response.is_null() {
                return;
            }
            // SAFETY: response pointer was allocated in pack_response.
            unsafe {
                if (*response).magic != PRIME_RESPONSE_MAGIC {
                    return;
                }
                (*response).magic = 0;
                let boxed = Box::from_raw(response);
                if !boxed.owner.is_null() {
                    let _ = Box::from_raw(boxed.owner as *mut OwnedPrimeResponse);
                }
            }
        },
    );
}

#[no_mangle]
pub extern "C" fn prime_last_error_message() -> *const c_char {
    ffi_guard("prime_last_error_message", ptr::null, || {
        LAST_ERROR.with(|last| match *last.borrow() {
            Some(ref msg) => msg.as_ptr(),
            None => ptr::null(),
        })
    })
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
    let init_tx_panic = init_tx.clone();

    let worker = std::thread::Builder::new()
        .name("prime-engine-runtime".to_owned())
        .spawn(move || {
            let result = std::panic::catch_unwind(move || {
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
                                        Err(_) => status.store(
                                            PrimeRequestStatus::FAILED as u8,
                                            Ordering::SeqCst,
                                        ),
                                    };
                                    let _ = result_tx.send(res);
                                });
                                let _ = task.abort_tx.send(j.abort_handle());
                            }
                            EngineMsg::Shutdown => break,
                        }
                    }
                });
            });

            if let Err(panic_info) = result {
                let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                tracing::error!(panic = %msg, "FFI runtime thread panicked");
                let _ = init_tx_panic.send(Err(EngineError::Internal(format!("Runtime panic: {msg}"))));
            }
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
        magic: PRIME_RESPONSE_MAGIC,
    });

    let mut response = response;
    response.owner = Box::into_raw(owned) as *mut c_void;
    Box::into_raw(response)
}

fn set_last_error(err: EngineError) {
    set_last_error_text(&err.to_string());
}

fn set_last_error_text(message: &str) {
    let message = to_cstring(message);
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = message;
    });
}

fn ffi_guard<T, F, P>(fn_name: &'static str, on_panic: P, f: F) -> T
where
    P: FnOnce() -> T,
    F: FnOnce() -> T,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => {
            set_last_error_text(&format!("Rust panic occurred in {fn_name}"));
            on_panic()
        }
    }
}

fn to_cstring(value: &str) -> Option<CString> {
    if !value.as_bytes().contains(&0) {
        return CString::new(value).ok();
    }
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch == '\0' {
            sanitized.push(' ');
        } else {
            sanitized.push(ch);
        }
    }
    CString::new(sanitized).ok()
}

fn error_code_from(error: &EngineError) -> i32 {
    match error {
        EngineError::NullPointer(_) => PRIME_ERR_NULL_PTR,
        EngineError::Utf8(_) | EngineError::Ffi(_) => PRIME_ERR_INVALID_UTF8,
        EngineError::InvalidInput(_) | EngineError::Config(_) => PRIME_ERR_INVALID_REQUEST,
        _ => PRIME_ERR_RUNTIME,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handle() -> *mut PrimeRequestHandle {
        let (tx, rx) = std::sync::mpsc::channel();
        let ptr = Box::into_raw(Box::new(PrimeRequestHandleInner {
            rx: parking_lot::Mutex::new(rx),
            tx,
            status: Arc::new(AtomicU8::new(PrimeRequestStatus::PENDING as u8)),
            abort: parking_lot::Mutex::new(None),
            abort_rx: parking_lot::Mutex::new(None),
        })) as *mut PrimeRequestHandle;
        register_request_handle(ptr);
        ptr
    }

    #[test]
    fn request_lifecycle_prevents_new_ops_after_free_mark() {
        let ptr = make_handle();
        assert!(begin_request_op(ptr));
        mark_request_freed(ptr);
        assert!(!begin_request_op(ptr));
        // First end: in_flight goes to zero and object becomes droppable.
        assert!(end_request_op(ptr));
        // SAFETY: lifecycle reached terminal state, this is final drop.
        unsafe {
            drop(Box::from_raw(ptr as *mut PrimeRequestHandleInner));
        }
    }

    #[test]
    fn to_cstring_sanitizes_nul_bytes() {
        let s = to_cstring("a\0b").expect("cstring");
        assert_eq!(s.to_str().expect("utf8"), "a b");
    }
}

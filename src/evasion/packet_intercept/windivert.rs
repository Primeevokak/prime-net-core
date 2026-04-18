//! WinDivert 2.x backend for TCP disorder on Windows.
//!
//! Loads `WinDivert.dll` at runtime via `libloading`.  Returns `None` from
//! [`WinDivertInterceptor::try_load`] when the DLL cannot be found (e.g. WinDivert
//! is not installed).  Callers fall back to userspace split in that case.
//!
//! # WinDivert installation
//! WinDivert must be installed separately — see <https://reqrypt.org/windivert.html>.
//! The `WinDivert.dll` and `WinDivert64.sys` files must be in `PATH` or the
//! same directory as the `prime-net-engine` binary.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tracing::{debug, warn};

use super::disorder::TcpDisorderHandle;
use super::PacketInterceptor;

// ── WinDivert raw FFI types ───────────────────────────────────────────────────

/// Opaque WinDivert handle (equivalent to `HANDLE` = `*mut c_void`).
type WinDivertHandle = *mut std::ffi::c_void;

/// WinDivert layer constants.
const WINDIVERT_LAYER_NETWORK: u32 = 0;

/// WinDivert flags.
const WINDIVERT_FLAG_DROP: u64 = 1 << 2;

/// Minimum WinDivert packet buffer size (65 535 bytes = max IP packet).
const PACKET_BUF_LEN: usize = 65_535;

// WinDivert address structure — 80 bytes as of WinDivert 2.x.
// We only need a correctly-sized opaque buffer for recv/send.
#[repr(C)]
struct WinDivertAddress {
    _data: [u8; 80],
}

impl WinDivertAddress {
    fn zeroed() -> Self {
        Self { _data: [0u8; 80] }
    }
}

// ── Function pointer types ────────────────────────────────────────────────────

type FnOpen = unsafe extern "C" fn(*const i8, u32, i16, u64) -> WinDivertHandle;
type FnClose = unsafe extern "C" fn(WinDivertHandle) -> bool;
type FnRecv =
    unsafe extern "C" fn(WinDivertHandle, *mut u8, u32, *mut u32, *mut WinDivertAddress) -> bool;
type FnSend = unsafe extern "C" fn(
    WinDivertHandle,
    *const u8,
    u32,
    *mut u32,
    *const WinDivertAddress,
) -> bool;
type FnHelperCalcChecksums = unsafe extern "C" fn(*mut u8, u32, *mut WinDivertAddress, u64) -> bool;

/// Runtime-loaded WinDivert 2.x library.
struct WinDivertLib {
    _lib: libloading::Library,
    open: FnOpen,
    close: FnClose,
    recv: FnRecv,
    send: FnSend,
    calc_checksums: FnHelperCalcChecksums,
}

// SAFETY: WinDivert function pointers are thread-safe (the library is
// stateless per-handle; each handle is only used from one thread at a time).
unsafe impl Send for WinDivertLib {}
unsafe impl Sync for WinDivertLib {}

impl WinDivertLib {
    /// Try to load `WinDivert.dll` from `PATH`.
    fn try_load() -> Option<Self> {
        // SAFETY: loading a well-known system DLL; all symbol lookups are
        // guarded by the `Option` return.
        let lib = unsafe { libloading::Library::new("WinDivert.dll").ok()? };

        macro_rules! sym {
            ($name:expr, $ty:ty) => {
                // SAFETY: symbol name and type match WinDivert 2.x public API.
                // Double-deref: Symbol<T> -> &T -> T (fn pointer copy).
                **unsafe { lib.get::<$ty>($name).ok()? }
            };
        }

        Some(Self {
            open: sym!(b"WinDivertOpen\0", libloading::Symbol<FnOpen>),
            close: sym!(b"WinDivertClose\0", libloading::Symbol<FnClose>),
            recv: sym!(b"WinDivertRecv\0", libloading::Symbol<FnRecv>),
            send: sym!(b"WinDivertSend\0", libloading::Symbol<FnSend>),
            calc_checksums: sym!(
                b"WinDivertHelperCalcChecksums\0",
                libloading::Symbol<FnHelperCalcChecksums>
            ),
            _lib: lib,
        })
    }
}

// ── Interceptor ───────────────────────────────────────────────────────────────

/// WinDivert-backed [`PacketInterceptor`].
///
/// Loads `WinDivert.dll` once and reuses the library for all connections.
/// Each call to [`intercept_connection`] opens a short-lived WinDivert handle
/// scoped to a single TCP 4-tuple.
///
/// [`intercept_connection`]: PacketInterceptor::intercept_connection
#[derive(Debug)]
pub(super) struct WinDivertInterceptor {
    /// Held for the lifetime of the interceptor — dropping unloads the DLL.
    lib: Arc<WinDivertLib>,
}

impl WinDivertInterceptor {
    /// Try to load WinDivert.  Returns `None` when the DLL is not present.
    pub(super) fn try_load() -> Option<Self> {
        let lib = WinDivertLib::try_load()?;
        debug!("WinDivert.dll loaded — TCP disorder available");
        Some(Self { lib: Arc::new(lib) })
    }
}

impl std::fmt::Debug for WinDivertLib {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinDivertLib").finish_non_exhaustive()
    }
}

impl PacketInterceptor for WinDivertInterceptor {
    fn backend_name(&self) -> &'static str {
        "WinDivert"
    }

    fn intercept_connection(
        self: Arc<Self>,
        local_addr: SocketAddr,
        delay_ms: u64,
    ) -> io::Result<TcpDisorderHandle> {
        let lib = Arc::clone(&self.lib);
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

        // Spawn a blocking thread — WinDivert Recv/Send are synchronous C calls.
        std::thread::spawn(move || {
            run_disorder_thread(lib, local_addr, delay_ms, cancel_rx);
        });

        Ok(TcpDisorderHandle::new(cancel_tx, self))
    }
}

/// Hard timeout for each `WinDivertRecv` call.  If a TCP segment has not
/// arrived within this window the watchdog closes the handle, unblocking recv.
const RECV_TIMEOUT: Duration = Duration::from_secs(5);

/// Blocking disorder thread: intercepts the first two outgoing data segments
/// for `local_addr` and sends them in reversed order with `delay_ms` between.
fn run_disorder_thread(
    lib: Arc<WinDivertLib>,
    local_addr: SocketAddr,
    delay_ms: u64,
    mut cancel_rx: oneshot::Receiver<()>,
) {
    let local_port = local_addr.port();

    // Build a narrow WinDivert filter: outbound TCP packets from our local port
    // with non-empty payload (data segments, not SYN/ACK/FIN).
    let filter = format!(
        "outbound && tcp && tcp.SrcPort == {local_port} \
         && tcp.PayloadLength > 0"
    );
    let filter_cstr = match std::ffi::CString::new(filter) {
        Ok(s) => s,
        Err(e) => {
            warn!("WinDivert: bad filter string: {e}");
            return;
        }
    };

    // SAFETY: filter_cstr is valid NUL-terminated ASCII; layer and flags are
    // well-known WinDivert constants; priority 0 is the default.
    let handle: WinDivertHandle = unsafe {
        (lib.open)(
            filter_cstr.as_ptr(),
            WINDIVERT_LAYER_NETWORK,
            0, // priority
            WINDIVERT_FLAG_DROP,
        )
    };

    if handle.is_null() || handle == usize::MAX as WinDivertHandle {
        warn!("WinDivert: WinDivertOpen failed (handle={handle:?})");
        return;
    }

    // Shared flag: set to `true` once the handle is closed, preventing
    // double-close between the main thread and the watchdog.
    let handle_closed = Arc::new(AtomicBool::new(false));

    // ── Watchdog for recv #1 ────────────────────────────────────────────
    let watchdog1 = spawn_recv_watchdog(Arc::clone(&lib), handle, Arc::clone(&handle_closed));

    let mut buf1 = vec![0u8; PACKET_BUF_LEN];
    let mut addr1 = WinDivertAddress::zeroed();
    let mut len1: u32 = 0;

    // SAFETY: handle is a valid open WinDivert handle; buf1 is large enough
    // for the maximum IP packet.  If the watchdog closes the handle while we
    // are inside recv, WinDivert returns `false` — which we handle below.
    let ok1 = unsafe {
        (lib.recv)(
            handle,
            buf1.as_mut_ptr(),
            PACKET_BUF_LEN as u32,
            &mut len1,
            &mut addr1,
        )
    };

    // Recv returned — cancel the watchdog.
    watchdog1.signal_done();

    // Check cancel before waiting for segment 2.
    if cancel_rx.try_recv().is_ok() {
        close_handle_once(&lib, handle, &handle_closed);
        return;
    }

    if !ok1 || len1 == 0 {
        close_handle_once(&lib, handle, &handle_closed);
        return;
    }

    // ── Watchdog for recv #2 ────────────────────────────────────────────
    let watchdog2 = spawn_recv_watchdog(Arc::clone(&lib), handle, Arc::clone(&handle_closed));

    let mut buf2 = vec![0u8; PACKET_BUF_LEN];
    let mut addr2 = WinDivertAddress::zeroed();
    let mut len2: u32 = 0;

    // SAFETY: same as recv #1 — handle may be closed by watchdog mid-call,
    // which is safe (WinDivert returns false on a closed handle).
    let ok2 = unsafe {
        (lib.recv)(
            handle,
            buf2.as_mut_ptr(),
            PACKET_BUF_LEN as u32,
            &mut len2,
            &mut addr2,
        )
    };

    watchdog2.signal_done();

    if !ok2 || len2 == 0 {
        // Only one segment seen — re-inject it and exit.
        if !handle_closed.load(Ordering::Acquire) {
            // SAFETY: buf1[..len1] is a valid captured packet; handle is
            // still open (checked above).
            unsafe {
                (lib.calc_checksums)(buf1.as_mut_ptr(), len1, &mut addr1, 0);
                (lib.send)(handle, buf1.as_ptr(), len1, std::ptr::null_mut(), &addr1);
            }
        }
        close_handle_once(&lib, handle, &handle_closed);
        return;
    }

    // Send segment 2 first — this is the disorder.
    // SAFETY: buf2[..len2] is a valid captured packet; handle is open.
    unsafe {
        (lib.calc_checksums)(buf2.as_mut_ptr(), len2, &mut addr2, 0);
        (lib.send)(handle, buf2.as_ptr(), len2, std::ptr::null_mut(), &addr2);
    }

    // Delay, then send segment 1.
    std::thread::sleep(Duration::from_millis(delay_ms.clamp(10, 200)));

    // SAFETY: buf1[..len1] is a valid captured packet; handle is open.
    unsafe {
        (lib.calc_checksums)(buf1.as_mut_ptr(), len1, &mut addr1, 0);
        (lib.send)(handle, buf1.as_ptr(), len1, std::ptr::null_mut(), &addr1);
    }
    close_handle_once(&lib, handle, &handle_closed);
}

/// Close the WinDivert handle exactly once using an atomic flag.
fn close_handle_once(lib: &WinDivertLib, handle: WinDivertHandle, closed: &AtomicBool) {
    if !closed.swap(true, Ordering::AcqRel) {
        // SAFETY: we are the first (and only) caller to set the flag —
        // the handle is still valid and has not been closed yet.
        unsafe {
            (lib.close)(handle);
        }
    }
}

/// Newtype wrapper so we can send a raw `WinDivertHandle` across threads.
///
/// Used by [`spawn_recv_watchdog`] to move a `WinDivertHandle` into a
/// spawned thread.  Thread-safety is ensured by the `handle_closed` atomic
/// flag — at most one thread will ever call `WinDivertClose`.
struct HandleWrapper(WinDivertHandle);

// SAFETY: The raw handle is just a pointer value.  Thread-safety of actual
// usage is ensured by the `handle_closed` atomic flag — at most one thread
// will ever call `WinDivertClose` on it.
unsafe impl Send for HandleWrapper {}

impl HandleWrapper {
    /// Extract the inner handle.
    fn get(&self) -> WinDivertHandle {
        self.0
    }
}

/// A lightweight watchdog that closes the WinDivert handle after
/// [`RECV_TIMEOUT`] unless signalled that the recv completed in time.
struct RecvWatchdog {
    /// Sending `()` tells the watchdog thread to exit without closing.
    done_tx: Option<oneshot::Sender<()>>,
}

impl RecvWatchdog {
    /// Signal the watchdog that recv finished — no need to close the handle.
    fn signal_done(mut self) {
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Spawn a background thread that waits [`RECV_TIMEOUT`] and then closes
/// `handle` (via the atomic flag) if the recv has not finished.
fn spawn_recv_watchdog(
    lib: Arc<WinDivertLib>,
    handle: WinDivertHandle,
    handle_closed: Arc<AtomicBool>,
) -> RecvWatchdog {
    let (done_tx, mut done_rx) = oneshot::channel::<()>();

    let wrapper = HandleWrapper(handle);

    std::thread::spawn(move || {
        // Park for RECV_TIMEOUT.  If `done_rx` fires before the timeout,
        // the recv completed and we exit without closing.
        std::thread::sleep(RECV_TIMEOUT);
        if done_rx.try_recv().is_ok() {
            return; // recv finished in time
        }
        // Timeout — force-close the handle so the blocking recv returns.
        warn!(
            "WinDivert: recv watchdog fired after {RECV_TIMEOUT:?} \
             — closing handle"
        );
        close_handle_once(&lib, wrapper.get(), &handle_closed);
    });

    RecvWatchdog {
        done_tx: Some(done_tx),
    }
}

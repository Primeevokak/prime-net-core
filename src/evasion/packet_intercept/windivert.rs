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
    #[allow(dead_code)] // held for lifetime
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
    let filter = format!("outbound && tcp && tcp.SrcPort == {local_port} && tcp.PayloadLength > 0");
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

    let mut buf1 = vec![0u8; PACKET_BUF_LEN];
    let mut buf2 = vec![0u8; PACKET_BUF_LEN];
    let mut addr1 = WinDivertAddress::zeroed();
    let mut addr2 = WinDivertAddress::zeroed();
    let mut len1: u32 = 0;
    let mut len2: u32 = 0;

    // Intercept segment 1 (hold it).
    let ok1 = unsafe {
        (lib.recv)(
            handle,
            buf1.as_mut_ptr(),
            PACKET_BUF_LEN as u32,
            &mut len1,
            &mut addr1,
        )
    };

    // Check cancel before waiting for segment 2.
    if cancel_rx.try_recv().is_ok() {
        unsafe { (lib.close)(handle) };
        return;
    }

    if !ok1 || len1 == 0 {
        unsafe { (lib.close)(handle) };
        return;
    }

    // Intercept segment 2.
    let ok2 = unsafe {
        (lib.recv)(
            handle,
            buf2.as_mut_ptr(),
            PACKET_BUF_LEN as u32,
            &mut len2,
            &mut addr2,
        )
    };

    if !ok2 || len2 == 0 {
        // Only one segment seen — send it and exit.
        unsafe {
            (lib.calc_checksums)(buf1.as_mut_ptr(), len1, &mut addr1, 0);
            (lib.send)(handle, buf1.as_ptr(), len1, std::ptr::null_mut(), &addr1);
            (lib.close)(handle);
        }
        return;
    }

    // Send segment 2 first — this is the disorder.
    unsafe {
        (lib.calc_checksums)(buf2.as_mut_ptr(), len2, &mut addr2, 0);
        (lib.send)(handle, buf2.as_ptr(), len2, std::ptr::null_mut(), &addr2);
    }

    // Delay, then send segment 1.
    std::thread::sleep(Duration::from_millis(delay_ms.clamp(10, 200)));

    unsafe {
        (lib.calc_checksums)(buf1.as_mut_ptr(), len1, &mut addr1, 0);
        (lib.send)(handle, buf1.as_ptr(), len1, std::ptr::null_mut(), &addr1);
        (lib.close)(handle);
    }
}

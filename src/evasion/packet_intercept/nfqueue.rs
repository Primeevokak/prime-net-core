//! Linux NFQueue backend for TCP disorder.
//!
//! Uses the `libnetfilter_queue` C library via `libc` FFI.  Requires an
//! `iptables` / `nftables` OUTPUT rule to redirect packets to the queue:
//!
//! ```text
//! iptables -I OUTPUT -p tcp --sport <port> -m conntrack --ctstate ESTABLISHED \
//!          -j NFQUEUE --queue-num 1337 --queue-bypass
//! ```
//!
//! The queue number defaults to [`NFQUEUE_NUM`].  The rule is NOT installed
//! automatically — the caller (or a privileged helper script) must set it up
//! before connecting.
//!
//! Returns `None` from [`NfQueueInterceptor::try_open`] when `libnetfilter_queue`
//! cannot be opened (library not installed or insufficient privileges).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tracing::{debug, warn};

use super::disorder::TcpDisorderHandle;
use super::PacketInterceptor;

/// Default NFQueue queue number.  Must match the `--queue-num` in the iptables rule.
const NFQUEUE_NUM: u16 = 1337;

// ── libnetfilter_queue FFI types (opaque handles) ─────────────────────────────

#[allow(non_camel_case_types)]
type nfq_handle = std::ffi::c_void;
#[allow(non_camel_case_types)]
type nfq_q_handle = std::ffi::c_void;
#[allow(non_camel_case_types)]
type nfq_data = std::ffi::c_void;

type NfqCallback = unsafe extern "C" fn(
    *mut nfq_q_handle,
    *mut std::ffi::c_void, // nfgenmsg
    *mut nfq_data,
    *mut std::ffi::c_void, // user data
) -> std::ffi::c_int;

type FnNfqOpen = unsafe extern "C" fn() -> *mut nfq_handle;
type FnNfqClose = unsafe extern "C" fn(*mut nfq_handle) -> std::ffi::c_int;
type FnNfqCreateQueue = unsafe extern "C" fn(
    *mut nfq_handle,
    u16,
    NfqCallback,
    *mut std::ffi::c_void,
) -> *mut nfq_q_handle;
type FnNfqDestroyQueue = unsafe extern "C" fn(*mut nfq_q_handle) -> std::ffi::c_int;
type FnNfqFd = unsafe extern "C" fn(*mut nfq_handle) -> std::ffi::c_int;
type FnNfqHandlePacket =
    unsafe extern "C" fn(*mut nfq_handle, *mut u8, std::ffi::c_int) -> std::ffi::c_int;
type FnNfqGetPayload = unsafe extern "C" fn(*mut nfq_data, *mut *mut u8) -> std::ffi::c_int;
type FnNfqGetPacketHdr = unsafe extern "C" fn(*mut nfq_data) -> *mut NfqnlMsgPacketHdr;
type FnNfqSetVerdict =
    unsafe extern "C" fn(*mut nfq_q_handle, u32, u32, u32, *const u8) -> std::ffi::c_int;

/// Packet header from `nfq_get_msg_packet_hdr`.
#[repr(C)]
struct NfqnlMsgPacketHdr {
    packet_id: u32,
    hw_protocol: u16,
    hook: u8,
}

const NF_ACCEPT: u32 = 1;
const NF_DROP: u32 = 0;

struct NfqLib {
    _lib: libloading::Library,
    open: FnNfqOpen,
    close: FnNfqClose,
    create_queue: FnNfqCreateQueue,
    destroy_queue: FnNfqDestroyQueue,
    fd: FnNfqFd,
    handle_packet: FnNfqHandlePacket,
    get_payload: FnNfqGetPayload,
    get_pkt_hdr: FnNfqGetPacketHdr,
    set_verdict: FnNfqSetVerdict,
}

impl std::fmt::Debug for NfqLib {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfqLib").finish_non_exhaustive()
    }
}

// SAFETY: libnetfilter_queue handles are per-thread; we only access them from
// the dedicated blocking thread.
unsafe impl Send for NfqLib {}
unsafe impl Sync for NfqLib {}

impl NfqLib {
    fn try_load() -> Option<Self> {
        // SAFETY: loading a well-known system library by soname.
        let lib = unsafe { libloading::Library::new("libnetfilter_queue.so.1").ok()? };

        macro_rules! sym {
            ($name:expr, $ty:ty) => {
                // SAFETY: symbol name and type match libnetfilter_queue public API.
                *unsafe { lib.get::<$ty>($name).ok()? }
            };
        }

        Some(Self {
            open: sym!(b"nfq_open\0", FnNfqOpen),
            close: sym!(b"nfq_close\0", FnNfqClose),
            create_queue: sym!(b"nfq_create_queue\0", FnNfqCreateQueue),
            destroy_queue: sym!(b"nfq_destroy_queue\0", FnNfqDestroyQueue),
            fd: sym!(b"nfq_fd\0", FnNfqFd),
            handle_packet: sym!(b"nfq_handle_packet\0", FnNfqHandlePacket),
            get_payload: sym!(b"nfq_get_payload\0", FnNfqGetPayload),
            get_pkt_hdr: sym!(b"nfq_get_msg_packet_hdr\0", FnNfqGetPacketHdr),
            set_verdict: sym!(b"nfq_set_verdict\0", FnNfqSetVerdict),
            _lib: lib,
        })
    }
}

// ── Interceptor ───────────────────────────────────────────────────────────────

/// NFQueue-backed [`PacketInterceptor`] for Linux.
///
/// Requires `libnetfilter_queue` installed and an iptables OUTPUT rule that
/// redirects the connection's source port to queue [`NFQUEUE_NUM`].
#[derive(Debug)]
pub(super) struct NfQueueInterceptor {
    lib: Arc<NfqLib>,
}

impl NfQueueInterceptor {
    /// Try to open the NFQueue library.  Returns `None` when the library is absent.
    pub(super) fn try_open() -> Option<Self> {
        let lib = NfqLib::try_load()?;
        debug!("libnetfilter_queue loaded — TCP disorder available via NFQueue");
        Some(Self { lib: Arc::new(lib) })
    }
}

impl PacketInterceptor for NfQueueInterceptor {
    fn backend_name(&self) -> &'static str {
        "NFQueue"
    }

    fn intercept_connection(
        self: Arc<Self>,
        local_addr: SocketAddr,
        delay_ms: u64,
    ) -> io::Result<TcpDisorderHandle> {
        let lib = Arc::clone(&self.lib);
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let local_port = local_addr.port();

        std::thread::spawn(move || {
            run_nfq_disorder_thread(lib, local_port, delay_ms, cancel_rx);
        });

        Ok(TcpDisorderHandle::new(cancel_tx, self))
    }
}

/// Blocking disorder thread using libnetfilter_queue.
///
/// Reads two packets from the queue (intercept two data segments), sends them
/// in reversed order with `delay_ms` between, then exits releasing the queue.
fn run_nfq_disorder_thread(
    lib: Arc<NfqLib>,
    _local_port: u16,
    delay_ms: u64,
    mut cancel_rx: oneshot::Receiver<()>,
) {
    // SAFETY: nfq_open returns a valid handle or NULL.
    let h = unsafe { (lib.open)() };
    if h.is_null() {
        warn!("NFQueue: nfq_open failed");
        return;
    }

    // Shared state passed through the C callback as a raw pointer.
    // We use a simple pair of slots for the two captured packets.
    struct Slots {
        pkt1: Option<(u32, Vec<u8>)>,
        pkt2: Option<(u32, Vec<u8>)>,
    }

    // Fat-pointer bundle passed to the C callback.
    // #[repr(C)] guarantees the field layout matches what cb expects when it
    // casts the void* back to *mut UserData.
    #[repr(C)]
    struct UserData {
        slots: Slots,
        lib_ptr: *const NfqLib,
    }

    let slots = Slots {
        pkt1: None,
        pkt2: None,
    };

    // C callback — called synchronously inside nfq_handle_packet.
    unsafe extern "C" fn cb(
        qh: *mut nfq_q_handle,
        _msg: *mut std::ffi::c_void,
        nfad: *mut nfq_data,
        user: *mut std::ffi::c_void,
    ) -> std::ffi::c_int {
        // SAFETY: user is a valid *mut UserData for the duration of the call.
        let user_data = &mut *(user as *mut UserData);
        let slots = &mut user_data.slots;
        let lib = &*user_data.lib_ptr;

        let hdr = (lib.get_pkt_hdr)(nfad);
        if hdr.is_null() {
            return -1;
        }
        let pkt_id = u32::from_be((*hdr).packet_id);

        let mut payload_ptr: *mut u8 = std::ptr::null_mut();
        let payload_len = (lib.get_payload)(nfad, &mut payload_ptr);
        if payload_len <= 0 || payload_ptr.is_null() {
            // Drop the packet — we can't store it.
            (lib.set_verdict)(qh, pkt_id, NF_DROP, 0, std::ptr::null());
            return 0;
        }

        let data = std::slice::from_raw_parts(payload_ptr, payload_len as usize).to_vec();

        if slots.pkt1.is_none() {
            slots.pkt1 = Some((pkt_id, data));
            // Drop (hold) the first packet.
            (lib.set_verdict)(qh, pkt_id, NF_DROP, 0, std::ptr::null());
        } else if slots.pkt2.is_none() {
            slots.pkt2 = Some((pkt_id, data));
            // Drop (hold) the second packet too — we will reinject both below.
            (lib.set_verdict)(qh, pkt_id, NF_DROP, 0, std::ptr::null());
        } else {
            // More than 2 segments — accept remainder unchanged.
            (lib.set_verdict)(qh, pkt_id, NF_ACCEPT, 0, std::ptr::null());
        }

        0
    }

    // SAFETY: lib_ptr points to data kept alive by lib Arc above.
    let lib_ptr: *const NfqLib = Arc::as_ptr(&lib);
    let mut user = UserData { slots, lib_ptr };

    // SAFETY: h is valid; cb has the correct signature; &mut user is valid for
    // the duration of the nfq_create_queue call and subsequent packet handling.
    let qh = unsafe {
        (lib.create_queue)(
            h,
            NFQUEUE_NUM,
            cb,
            &mut user as *mut UserData as *mut std::ffi::c_void,
        )
    };

    if qh.is_null() {
        warn!("NFQueue: nfq_create_queue failed (queue {NFQUEUE_NUM} — check iptables rule)");
        unsafe { (lib.close)(h) };
        return;
    }

    let fd = unsafe { (lib.fd)(h) };
    let mut buf = vec![0u8; 65_535];

    // Read packets until we have both segments or cancel is signalled.
    for _ in 0..64 {
        if cancel_rx.try_recv().is_ok() {
            break;
        }
        // Blocking read from the netlink socket.
        // SAFETY: fd is valid; buf is large enough.
        let rv = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if rv > 0 {
            unsafe { (lib.handle_packet)(h, buf.as_mut_ptr(), rv as i32) };
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }

        if user.slots.pkt1.is_some() && user.slots.pkt2.is_some() {
            break;
        }
    }

    // Reinject in reversed order.
    if let (Some((_, pkt2)), Some((_, pkt1))) = (user.slots.pkt2.take(), user.slots.pkt1.take()) {
        // Send segment 2 first.
        unsafe {
            (lib.set_verdict)(
                qh,
                0, // packet IDs already consumed by DROP verdict; use raw inject
                NF_ACCEPT,
                pkt2.len() as u32,
                pkt2.as_ptr(),
            );
        }

        std::thread::sleep(Duration::from_millis(delay_ms.clamp(10, 200)));

        // Send segment 1.
        unsafe {
            (lib.set_verdict)(qh, 0, NF_ACCEPT, pkt1.len() as u32, pkt1.as_ptr());
        }
    } else if let Some((_, pkt1)) = user.slots.pkt1.take() {
        // Only one segment captured — accept it.
        unsafe {
            (lib.set_verdict)(qh, 0, NF_ACCEPT, pkt1.len() as u32, pkt1.as_ptr());
        }
    }

    unsafe {
        (lib.destroy_queue)(qh);
        (lib.close)(h);
    }
}

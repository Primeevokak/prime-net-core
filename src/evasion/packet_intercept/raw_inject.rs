//! Raw packet injection via WinDivert.
//!
//! Provides [`RawInjector`] — a thin wrapper around a WinDivert handle opened
//! in send-only mode.  Used by:
//! - [`FakeProbeStrategy::BadTimestamp`] / `BadChecksum` / `BadSeq` — inject a
//!   TCP segment with corrupted fields that DPI processes but the server drops.
//! - [`SeqOverlap`] — inject a TCP segment with decremented sequence numbers.
//! - [`QuicBypass`] — inject fake QUIC Initial packets before the real one.
//!
//! All operations are best-effort: injection failures are logged and ignored.

use std::io;
use std::net::SocketAddr;
use std::sync::OnceLock;

use tracing::{debug, warn};

// ── Minimal IP + TCP + UDP header builders ──────────────────────────────────

/// Parameters for building a raw TCP packet.
pub struct TcpPacketParams<'a> {
    /// Source address (IP + port).
    pub src: SocketAddr,
    /// Destination address (IP + port).
    pub dst: SocketAddr,
    /// TCP sequence number.
    pub seq: u32,
    /// TCP acknowledgment number.
    pub ack: u32,
    /// TCP flags byte (SYN=0x02, ACK=0x10, PSH=0x08, etc.).
    pub flags: u8,
    /// IP TTL.
    pub ttl: u8,
    /// TCP payload.
    pub payload: &'a [u8],
    /// If true, add a TCP timestamp option with TSval=0 (PAWS rejection).
    pub corrupt_timestamp: bool,
    /// If true, set a deliberately wrong TCP checksum.
    pub corrupt_checksum: bool,
}

/// Build a raw IPv4 + TCP packet with custom seq/ack, flags, and optional
/// timestamp manipulation.
///
/// Returns the complete IP packet ready for WinDivert injection.
pub fn build_tcp_packet(p: &TcpPacketParams<'_>) -> Vec<u8> {
    let (src, dst) = (p.src, p.dst);
    let (seq, ack, flags, ttl) = (p.seq, p.ack, p.flags, p.ttl);
    let payload = p.payload;
    let (corrupt_timestamp, corrupt_checksum) = (p.corrupt_timestamp, p.corrupt_checksum);
    let src_ip = match src.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Vec::new(), // IPv6 not supported yet
    };
    let dst_ip = match dst.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Vec::new(),
    };

    // TCP header: 20 bytes base + 12 bytes timestamp option = 32 bytes
    let tcp_header_len = if corrupt_timestamp { 32 } else { 20 };
    let total_len = 20 + tcp_header_len + payload.len(); // IP header + TCP header + payload

    let mut pkt = vec![0u8; total_len];

    // ── IPv4 header (20 bytes) ──
    pkt[0] = 0x45; // version=4, IHL=5 (20 bytes)
    pkt[1] = 0x00; // DSCP/ECN
    let total_u16 = total_len as u16;
    pkt[2..4].copy_from_slice(&total_u16.to_be_bytes());
    // ID, flags, fragment offset = 0
    pkt[8] = ttl;
    pkt[9] = 6; // protocol = TCP
                // checksum at [10..12] — will be recalculated by WinDivert
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    // ── TCP header ──
    let tcp = &mut pkt[20..];
    tcp[0..2].copy_from_slice(&src.port().to_be_bytes()); // src port
    tcp[2..4].copy_from_slice(&dst.port().to_be_bytes()); // dst port
    tcp[4..8].copy_from_slice(&seq.to_be_bytes()); // sequence number
    tcp[8..12].copy_from_slice(&ack.to_be_bytes()); // ack number
    let data_offset = (tcp_header_len / 4) as u8;
    tcp[12] = data_offset << 4; // data offset
    tcp[13] = flags; // TCP flags (SYN=0x02, ACK=0x10, PSH=0x08)
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window size
                                                          // checksum at [16..18] — WinDivert will recalculate (unless we corrupt it)
                                                          // urgent pointer at [18..20] = 0

    if corrupt_timestamp {
        // TCP timestamp option: kind=8, len=10, TSval=0 (bad), TSecr=0
        tcp[20] = 0x01; // NOP
        tcp[21] = 0x01; // NOP
        tcp[22] = 0x08; // Timestamp kind
        tcp[23] = 0x0A; // Timestamp length
                        // TSval = 0 at [24..28] (already zeroed)
                        // TSecr = 0 at [28..32] (already zeroed)
    }

    // Payload
    pkt[20 + tcp_header_len..].copy_from_slice(payload);

    if corrupt_checksum {
        // Set a deliberately wrong TCP checksum so the server drops it
        // but DPI that doesn't validate checksums still processes it.
        pkt[20 + 16] = 0xDE;
        pkt[20 + 17] = 0xAD;
    }

    pkt
}

/// Build a raw IPv4 + UDP packet.
///
/// Returns the complete IP packet ready for WinDivert injection.
pub fn build_udp_packet(src: SocketAddr, dst: SocketAddr, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let src_ip = match src.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Vec::new(),
    };
    let dst_ip = match dst.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => return Vec::new(),
    };

    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut pkt = vec![0u8; total_len];

    // IPv4 header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = ttl;
    pkt[9] = 17; // protocol = UDP
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    // UDP header
    let udp = &mut pkt[20..];
    udp[0..2].copy_from_slice(&src.port().to_be_bytes());
    udp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // checksum at [6..8] = 0 (optional for IPv4 UDP)

    // Payload
    pkt[28..].copy_from_slice(payload);

    pkt
}

// ── WinDivert injector ──────────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use super::*;

    /// Opaque WinDivert handle.
    type WdHandle = *mut std::ffi::c_void;
    const WINDIVERT_LAYER_NETWORK: u32 = 0;
    /// WINDIVERT_FLAG_SNIFF = 1: don't drop the original packet.
    const WINDIVERT_FLAG_SNIFF: u64 = 1;

    /// Raw packet injector backed by WinDivert.
    ///
    /// Opens a single WinDivert handle in "sniff" mode (the `true` filter
    /// matches everything but `SNIFF` flag means captured packets are also
    /// delivered to the OS — we only use `Send`).  The handle is reused
    /// for all injections during the engine's lifetime.
    pub(super) struct Injector {
        handle: WdHandle,
        send: FnSend,
        calc_checksums: FnCalcChecksums,
    }

    // SAFETY: WinDivert handles are thread-safe for Send operations when
    // each call provides its own address buffer.
    unsafe impl Send for Injector {}
    unsafe impl Sync for Injector {}

    type FnOpen = unsafe extern "C" fn(*const i8, u32, i16, u64) -> WdHandle;
    type FnSend = unsafe extern "C" fn(WdHandle, *const u8, u32, *mut u32, *const [u8; 80]) -> bool;
    type FnCalcChecksums = unsafe extern "C" fn(*mut u8, u32, *mut [u8; 80], u64) -> bool;
    type FnClose = unsafe extern "C" fn(WdHandle) -> bool;

    impl Injector {
        /// Try to create an injector by loading WinDivert.
        pub fn try_new() -> Option<Self> {
            // SAFETY: loading WinDivert.dll; guarded by Option return.
            let lib = unsafe { libloading::Library::new("WinDivert.dll").ok()? };

            macro_rules! sym {
                ($name:expr, $ty:ty) => {
                    // SAFETY: symbol names match WinDivert 2.x public API.
                    **unsafe { lib.get::<libloading::Symbol<$ty>>($name).ok()? }
                };
            }

            let open: FnOpen = sym!(b"WinDivertOpen\0", FnOpen);
            let send: FnSend = sym!(b"WinDivertSend\0", FnSend);
            let calc_checksums: FnCalcChecksums =
                sym!(b"WinDivertHelperCalcChecksums\0", FnCalcChecksums);
            let _close: FnClose = sym!(b"WinDivertClose\0", FnClose);

            // Open a handle that matches everything but doesn't capture
            // (SNIFF mode).  We only use Send to inject packets.
            let filter = std::ffi::CString::new("true").ok()?;
            // SAFETY: valid NUL-terminated filter, known layer and flags.
            let handle = unsafe {
                (open)(
                    filter.as_ptr(),
                    WINDIVERT_LAYER_NETWORK,
                    -1, // priority: lowest
                    WINDIVERT_FLAG_SNIFF,
                )
            };

            if handle.is_null() || handle == usize::MAX as WdHandle {
                warn!("RawInjector: WinDivertOpen failed");
                // Keep the library alive — not dropping since we don't
                // store it.  But since open failed, just return None.
                std::mem::forget(lib);
                return None;
            }

            // Leak the library — it must live as long as the process.
            std::mem::forget(lib);

            debug!("RawInjector: WinDivert packet injector ready");
            Some(Self {
                handle,
                send,
                calc_checksums,
            })
        }

        /// Inject a raw IP packet into the network stack.
        ///
        /// The packet must be a valid IPv4 packet (header + payload).
        /// WinDivert recalculates checksums unless `skip_checksums` is true.
        pub fn inject(&self, mut pkt: Vec<u8>, skip_checksums: bool) -> io::Result<()> {
            let mut addr = [0u8; 80]; // WinDivert address
                                      // Set outbound direction: bit 0 of byte 2 (Network layer).
                                      // WinDivert 2.x: Outbound flag is at offset 8 bit 0 in the
                                      // Network sub-struct, but for simple injection setting the
                                      // direction flag in the Outbound field works.
            addr[2] |= 0x01; // Outbound = true (Network.Outbound at bit 0 of byte 2)

            if !skip_checksums {
                // SAFETY: pkt is a valid mutable buffer; addr is 80-byte zeroed.
                unsafe {
                    (self.calc_checksums)(pkt.as_mut_ptr(), pkt.len() as u32, &mut addr, 0);
                }
            }

            let mut sent: u32 = 0;
            // SAFETY: handle is a valid open WinDivert handle; pkt is a
            // valid IP packet with correct checksums.
            let ok = unsafe {
                (self.send)(
                    self.handle,
                    pkt.as_ptr(),
                    pkt.len() as u32,
                    &mut sent,
                    &addr,
                )
            };

            if !ok {
                return Err(io::Error::other("WinDivert: packet injection failed"));
            }
            Ok(())
        }
    }
}

/// Global singleton injector — initialized once on first use.
#[cfg(windows)]
static INJECTOR: OnceLock<Option<platform::Injector>> = OnceLock::new();

/// Inject a raw IPv4 packet into the outbound network path.
///
/// WinDivert recalculates IP/TCP/UDP checksums automatically.
/// Returns `Ok(())` on success or if no injector is available (best-effort).
/// The `skip_checksums` flag prevents checksum recalculation (for BadChecksum).
pub fn inject_raw_packet(pkt: Vec<u8>, skip_checksums: bool) -> io::Result<()> {
    #[cfg(windows)]
    {
        let injector = INJECTOR.get_or_init(platform::Injector::try_new);
        if let Some(inj) = injector.as_ref() {
            return inj.inject(pkt, skip_checksums);
        }
    }
    // Non-Windows or WinDivert unavailable — silently skip.
    let _ = (pkt, skip_checksums);
    Ok(())
}

/// Check whether the raw packet injector is available.
pub fn is_injector_available() -> bool {
    #[cfg(windows)]
    {
        let injector = INJECTOR.get_or_init(platform::Injector::try_new);
        injector.is_some()
    }
    #[cfg(not(windows))]
    false
}

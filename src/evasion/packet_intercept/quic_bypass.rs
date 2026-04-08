//! WinDivert-based QUIC DPI bypass for TUN mode.
//!
//! Intercepts outgoing UDP port 443 packets at the kernel level, detects QUIC
//! Initial packets, and injects fake QUIC Initials with whitelisted SNIs before
//! the real packet.  This confuses stateful DPI that tracks QUIC connections by
//! their first Initial packet's SNI.
//!
//! Inspired by zapret's QUIC fake injection approach.
//!
//! # Usage
//!
//! ```ignore
//! let handle = quic_bypass::start(8)?;
//! handle.stop();
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, info};

use crate::evasion::quic_initial::{
    build_fake_quic_initial, parse_quic_initial_header, random_whitelisted_sni,
};

/// Handle to a running QUIC bypass thread.
///
/// Dropping the handle stops the bypass thread.
pub struct QuicBypassHandle {
    stop_flag: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl QuicBypassHandle {
    /// Signal the bypass thread to stop and wait for it to exit.
    pub fn stop(mut self) {
        self.stop_flag.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for QuicBypassHandle {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Release);
        // Don't join in Drop — thread will exit on next recv timeout.
    }
}

/// Start the WinDivert QUIC bypass thread.
///
/// Intercepts outgoing UDP port 443 packets and injects `fake_count` fake QUIC
/// Initials before each real one.  Only available on Windows with WinDivert.
///
/// Returns `Err` if WinDivert cannot be loaded.
#[cfg(windows)]
pub fn start(fake_count: u8) -> std::io::Result<QuicBypassHandle> {
    use std::io;

    let lib = unsafe { libloading::Library::new("WinDivert.dll") }
        .map_err(|e| io::Error::other(format!("WinDivert not available for QUIC bypass: {e}")))?;

    type WdHandle = *mut std::ffi::c_void;
    type FnOpen = unsafe extern "C" fn(*const i8, u32, i16, u64) -> WdHandle;
    type FnClose = unsafe extern "C" fn(WdHandle) -> bool;
    type FnRecv = unsafe extern "C" fn(WdHandle, *mut u8, u32, *mut u32, *mut [u8; 80]) -> bool;
    type FnSend = unsafe extern "C" fn(WdHandle, *const u8, u32, *mut u32, *const [u8; 80]) -> bool;
    type FnCalcChecksums = unsafe extern "C" fn(*mut u8, u32, *mut [u8; 80], u64) -> bool;

    macro_rules! sym {
        ($lib:expr, $name:expr, $ty:ty) => {
            // SAFETY: symbol names match WinDivert 2.x API.
            **unsafe { $lib.get::<libloading::Symbol<$ty>>($name) }
                .map_err(|e| io::Error::other(format!("WinDivert symbol load failed: {e}")))?
        };
    }

    let open: FnOpen = sym!(lib, b"WinDivertOpen\0", FnOpen);
    let close: FnClose = sym!(lib, b"WinDivertClose\0", FnClose);
    let recv: FnRecv = sym!(lib, b"WinDivertRecv\0", FnRecv);
    let send: FnSend = sym!(lib, b"WinDivertSend\0", FnSend);
    let calc_checksums: FnCalcChecksums =
        sym!(lib, b"WinDivertHelperCalcChecksums\0", FnCalcChecksums);

    // Filter: outgoing UDP packets to port 443.
    let filter = std::ffi::CString::new("outbound and udp and udp.DstPort == 443")
        .map_err(|e| io::Error::other(format!("bad WinDivert filter: {e}")))?;

    // SAFETY: valid NUL-terminated filter; WINDIVERT_LAYER_NETWORK = 0;
    // priority = -2 (lower than TcpDisorder and RawInjector).
    let handle: WdHandle = unsafe { (open)(filter.as_ptr(), 0, -2, 0) };

    if handle.is_null() || handle == usize::MAX as WdHandle {
        return Err(io::Error::other(
            "WinDivert: failed to open QUIC bypass handle",
        ));
    }

    // Leak the library so it lives as long as the handle.
    std::mem::forget(lib);

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop_flag);

    info!("QUIC bypass: WinDivert intercept started (fake_count={fake_count})");

    // Bundle everything the bypass thread needs into a Send-safe wrapper.
    struct BypassCtx {
        handle: *mut std::ffi::c_void,
        close: FnClose,
        recv: FnRecv,
        send: FnSend,
        calc_checksums: FnCalcChecksums,
    }
    // SAFETY: WinDivert handles and function pointers are thread-safe.
    // The handle is exclusively used by the single bypass thread.
    unsafe impl Send for BypassCtx {}

    let ctx = BypassCtx {
        handle,
        close,
        recv,
        send,
        calc_checksums,
    };
    let thread = {
        // SAFETY: BypassCtx contains a WinDivert handle (*mut c_void) which
        // is thread-safe but not marked Send by Rust. We guarantee the handle
        // is used exclusively by the spawned thread.
        let closure: Box<dyn FnOnce() + Send> = unsafe {
            let closure = move || {
                run_quic_bypass_loop(
                    ctx.handle,
                    ctx.close,
                    ctx.recv,
                    ctx.send,
                    ctx.calc_checksums,
                    fake_count,
                    stop_clone,
                );
            };
            // Transmute to add Send bound — safe because BypassCtx is Send.
            std::mem::transmute::<Box<dyn FnOnce()>, Box<dyn FnOnce() + Send>>(Box::new(closure))
        };
        std::thread::Builder::new()
            .name("quic-bypass".to_owned())
            .spawn(closure)
    }
    .map_err(|e| io::Error::other(format!("failed to spawn QUIC bypass thread: {e}")))?;

    Ok(QuicBypassHandle {
        stop_flag,
        thread: Some(thread),
    })
}

/// Not available on non-Windows.
#[cfg(not(windows))]
pub fn start(_fake_count: u8) -> std::io::Result<QuicBypassHandle> {
    Err(std::io::Error::other(
        "QUIC bypass requires WinDivert (Windows only)",
    ))
}

/// Main loop: recv packets, detect QUIC Initials, inject fakes, re-inject real.
#[cfg(windows)]
fn run_quic_bypass_loop(
    handle: *mut std::ffi::c_void,
    close: unsafe extern "C" fn(*mut std::ffi::c_void) -> bool,
    recv: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        *mut u8,
        u32,
        *mut u32,
        *mut [u8; 80],
    ) -> bool,
    send: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        *const u8,
        u32,
        *mut u32,
        *const [u8; 80],
    ) -> bool,
    calc_checksums: unsafe extern "C" fn(*mut u8, u32, *mut [u8; 80], u64) -> bool,
    fake_count: u8,
    stop_flag: Arc<AtomicBool>,
) {
    const BUF_LEN: usize = 65_535;
    let mut buf = vec![0u8; BUF_LEN];

    // Flow tracking: (src_port, dst_ip:dst_port) → packet count.
    // After 2 packets per flow, stop injecting fakes (only Initial matters).
    let mut flow_counts: HashMap<(u16, u32, u16), u8> = HashMap::new();
    let mut last_cleanup = Instant::now();

    while !stop_flag.load(Ordering::Acquire) {
        let mut pkt_len: u32 = 0;
        let mut addr = [0u8; 80];

        // SAFETY: handle is valid; buf is large enough for max IP packet.
        let ok = unsafe {
            (recv)(
                handle,
                buf.as_mut_ptr(),
                BUF_LEN as u32,
                &mut pkt_len,
                &mut addr,
            )
        };

        if !ok || pkt_len == 0 {
            if stop_flag.load(Ordering::Acquire) {
                break;
            }
            continue;
        }

        let pkt_data = &buf[..pkt_len as usize];

        // Parse IPv4 header to find UDP payload.
        if pkt_data.len() < 28 {
            // Too short for IP + UDP header — re-inject as-is.
            // SAFETY: re-injecting captured packet unchanged.
            unsafe {
                (send)(
                    handle,
                    pkt_data.as_ptr(),
                    pkt_len,
                    std::ptr::null_mut(),
                    &addr,
                );
            }
            continue;
        }

        let ihl = ((pkt_data[0] & 0x0F) as usize) * 4;
        if pkt_data.len() < ihl + 8 {
            // SAFETY: re-inject unchanged.
            unsafe {
                (send)(
                    handle,
                    pkt_data.as_ptr(),
                    pkt_len,
                    std::ptr::null_mut(),
                    &addr,
                );
            }
            continue;
        }

        let src_port = u16::from_be_bytes([pkt_data[ihl], pkt_data[ihl + 1]]);
        let dst_ip = u32::from_be_bytes([pkt_data[16], pkt_data[17], pkt_data[18], pkt_data[19]]);
        let dst_port = u16::from_be_bytes([pkt_data[ihl + 2], pkt_data[ihl + 3]]);

        let udp_payload = &pkt_data[ihl + 8..];

        // Flow tracking — only inject fakes for first 2 packets per flow.
        let flow_key = (src_port, dst_ip, dst_port);
        let count = flow_counts.entry(flow_key).or_insert(0);
        *count = count.saturating_add(1);

        if *count <= 2 {
            // Check if this is a QUIC Initial.
            if let Some(hdr) = parse_quic_initial_header(udp_payload) {
                debug!(
                    src_port,
                    dst_port,
                    dcid_len = hdr.dcid.len(),
                    "QUIC bypass: Initial detected, injecting {fake_count} fakes"
                );

                // Build and inject fake QUIC Initials.
                for _ in 0..fake_count {
                    let sni = random_whitelisted_sni();
                    if let Ok(fake_quic) = build_fake_quic_initial(&hdr.dcid, sni) {
                        // Build a complete IP+UDP packet with the fake QUIC payload.
                        // Copy IP+UDP headers from the real packet, replace payload.
                        let fake_pkt = rebuild_udp_packet(pkt_data, ihl, &fake_quic);
                        if !fake_pkt.is_empty() {
                            let mut fake_addr = addr;
                            let mut fake_buf = fake_pkt;
                            // SAFETY: recalculate checksums for the modified packet.
                            unsafe {
                                (calc_checksums)(
                                    fake_buf.as_mut_ptr(),
                                    fake_buf.len() as u32,
                                    &mut fake_addr,
                                    0,
                                );
                                (send)(
                                    handle,
                                    fake_buf.as_ptr(),
                                    fake_buf.len() as u32,
                                    std::ptr::null_mut(),
                                    &fake_addr,
                                );
                            }
                        }
                    }
                }
            }
        }

        // Re-inject the real packet.
        // SAFETY: re-injecting the original captured packet.
        unsafe {
            (send)(
                handle,
                pkt_data.as_ptr(),
                pkt_len,
                std::ptr::null_mut(),
                &addr,
            );
        }

        // Periodic cleanup of old flow entries (every 30 seconds).
        if last_cleanup.elapsed().as_secs() > 30 {
            flow_counts.clear();
            last_cleanup = Instant::now();
        }
    }

    // SAFETY: closing the WinDivert handle.
    unsafe {
        (close)(handle);
    }
    info!("QUIC bypass: WinDivert intercept stopped");
}

/// Rebuild an IP+UDP packet with a different UDP payload.
///
/// Copies IP and UDP headers from `original`, replaces the UDP payload
/// with `new_payload`, and adjusts length fields.
#[cfg(windows)]
fn rebuild_udp_packet(original: &[u8], ihl: usize, new_payload: &[u8]) -> Vec<u8> {
    if original.len() < ihl + 8 {
        return Vec::new();
    }

    let new_udp_len = 8 + new_payload.len();
    let new_total = ihl + new_udp_len;

    let mut pkt = vec![0u8; new_total];

    // Copy IP header.
    pkt[..ihl].copy_from_slice(&original[..ihl]);

    // Update IP total length.
    pkt[2..4].copy_from_slice(&(new_total as u16).to_be_bytes());
    // Zero IP checksum (recalculated by WinDivert).
    pkt[10] = 0;
    pkt[11] = 0;

    // Copy UDP header (ports).
    pkt[ihl..ihl + 4].copy_from_slice(&original[ihl..ihl + 4]);
    // Update UDP length.
    pkt[ihl + 4..ihl + 6].copy_from_slice(&(new_udp_len as u16).to_be_bytes());
    // Zero UDP checksum (recalculated by WinDivert).
    pkt[ihl + 6] = 0;
    pkt[ihl + 7] = 0;

    // UDP payload.
    pkt[ihl + 8..].copy_from_slice(new_payload);

    pkt
}

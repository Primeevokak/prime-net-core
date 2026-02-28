use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;
use tokio::time::Sleep;

#[derive(Debug, Clone)]
pub struct FragmentConfig {
    /// Maximum chunk size for the first write (best-effort DPI bypass). Clamped to <= 64.
    pub first_write_max: usize,
    /// Optional deterministic chunk sizes for the first write (splits by explicit offsets/parts).
    ///
    /// If set and non-empty, it takes precedence over `first_write_max`.
    pub first_write_plan: Option<Vec<usize>>,
    /// Minimum chunk size for subsequent writes while fragmentation is enabled.
    pub fragment_size_min: usize,
    /// Maximum chunk size for subsequent writes while fragmentation is enabled.
    pub fragment_size_max: usize,
    /// Optional delay between chunks.
    pub sleep_ms: u64,
    /// Optional per-chunk jitter range (overrides `sleep_ms` when set).
    pub jitter_ms: Option<(u64, u64)>,
    /// If true, randomize chunk sizes for non-first writes in fragment_size_min..=fragment_size_max.
    pub randomize_fragment_size: bool,
    /// If true, attempt to split first TLS ClientHello exactly at SNI extension boundary.
    /// This has higher priority than `first_write_plan`.
    pub split_at_sni: bool,
}

impl Default for FragmentConfig {
    fn default() -> Self {
        Self {
            first_write_max: 128,
            first_write_plan: None,
            fragment_size_min: 4,
            fragment_size_max: 128,
            sleep_ms: 1,
            jitter_ms: None,
            randomize_fragment_size: false,
            split_at_sni: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FragmentHandle {
    state: Arc<State>,
}

impl FragmentHandle {
    /// Disables fragmentation for the associated IO.
    pub fn disable(&self) {
        self.state.enabled.store(false, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct State {
    enabled: AtomicBool,
}

#[derive(Debug)]
pub struct FragmentingIo<T> {
    inner: T,
    cfg: FragmentConfig,
    state: Arc<State>,
    first_write: bool,
    first_plan_idx: usize,
    first_plan_remaining: usize,
    sni_plan_initialized: bool,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl<T> FragmentingIo<T> {
    pub fn new(inner: T, mut cfg: FragmentConfig) -> (Self, FragmentHandle) {
        if cfg.fragment_size_max == 0 {
            cfg.fragment_size_max = 1;
        }
        if cfg.fragment_size_min == 0 {
            cfg.fragment_size_min = 1;
        }
        if cfg.fragment_size_min > cfg.fragment_size_max {
            cfg.fragment_size_min = cfg.fragment_size_max;
        }
        if cfg.first_write_max == 0 {
            cfg.first_write_max = 1;
        }
        cfg.first_write_max = cfg.first_write_max.min(64);
        if cfg.first_write_plan.as_ref().is_some_and(|p| p.is_empty()) {
            cfg.first_write_plan = None;
        }

        let state = Arc::new(State {
            enabled: AtomicBool::new(true),
        });
        let handle = FragmentHandle {
            state: state.clone(),
        };
        (
            Self {
                inner,
                cfg,
                state,
                first_write: true,
                first_plan_idx: 0,
                first_plan_remaining: 0,
                sni_plan_initialized: false,
                sleep: None,
            },
            handle,
        )
    }

    fn enabled(&self) -> bool {
        self.state.enabled.load(Ordering::Relaxed)
    }

    fn next_sleep_ms(&self) -> u64 {
        if let Some((min, max)) = self.cfg.jitter_ms {
            let lo = min.min(max);
            let hi = min.max(max);
            if hi == 0 {
                return 0;
            }
            return rand::thread_rng().gen_range(lo..=hi);
        }
        self.cfg.sleep_ms
    }

    fn next_write_limit(&mut self, buf: &[u8]) -> usize {
        let buf_len = buf.len();
        if self.first_write && self.cfg.split_at_sni && !self.sni_plan_initialized {
            self.sni_plan_initialized = true;
            if let Some((sni_off, sni_len)) = find_sni_info(buf) {
                let mut plan = Vec::new();
                if sni_off > 0 {
                    plan.push(sni_off);
                }

                // Агрессивный разрез внутри SNI (разрезаем на части по 2 байта и остаток)
                if sni_len > 4 {
                    plan.push(2);
                    plan.push(2);
                    plan.push(sni_len - 4);
                } else if sni_len > 0 {
                    plan.push(1);
                    if sni_len > 1 {
                        plan.push(sni_len - 1);
                    }
                }

                let consumed = sni_off + sni_len;
                if consumed < buf_len {
                    plan.push(buf_len - consumed);
                }

                if !plan.is_empty() {
                    self.cfg.first_write_plan = Some(plan);
                }
            }
        }

        if let Some(plan) = self.cfg.first_write_plan.as_deref() {
            // The plan is applied across multiple poll_write calls for the first write buffer.
            if self.first_plan_remaining == 0 {
                let next = plan.get(self.first_plan_idx).copied().unwrap_or(0);
                if next == 0 {
                    // Skip invalid entries.
                    self.first_plan_idx = self.first_plan_idx.saturating_add(1);
                } else {
                    self.first_plan_remaining = next;
                }
            }

            if self.first_plan_remaining > 0 {
                return self.first_plan_remaining.min(buf_len.max(1)).max(1);
            }
        }

        if self.first_write {
            return self.cfg.first_write_max.min(buf_len.max(1)).max(1);
        }

        if self.cfg.randomize_fragment_size {
            let min = self.cfg.fragment_size_min.max(1);
            let mut max = self.cfg.fragment_size_max.max(min);

            // Limit by current buffer size to avoid out-of-bounds
            let limit = buf_len.max(1);
            if min >= limit {
                return limit;
            }

            max = max.min(limit);
            if min >= max {
                return min;
            }
            return rand::thread_rng().gen_range(min..=max);
        }
        self.cfg.fragment_size_max.min(buf_len.max(1)).max(1)
    }
}

pub(crate) fn find_sni_info(client_hello: &[u8]) -> Option<(usize, usize)> {
    let b = client_hello;
    // Minimal TLS Record + Handshake + ClientHello size
    if b.len() < 42 {
        return None;
    }
    if b[0] != 0x16 {
        return None;
    }
    let record_len = read_u16(b, 3)? as usize;
    if record_len + 5 > b.len() {
        // Record is fragmented or incomplete in this buffer. 
        // We can't reliably find SNI without the full record.
        return None;
    }

    let mut pos = 5usize;
    if b[pos] != 0x01 { // Handshake Type: Client Hello
        return None;
    }
    let hs_len = read_u24(b, pos + 1)? as usize;
    pos += 4;
    if pos + hs_len > b.len() {
        return None;
    }

    // Skip Version (2) + Random (32)
    pos = pos.checked_add(34)?;

    // Session ID
    let sid_len = *b.get(pos)? as usize;
    pos = pos.checked_add(1 + sid_len)?;

    // Cipher Suites
    let cs_len = read_u16(b, pos)? as usize;
    pos = pos.checked_add(2 + cs_len)?;

    // Compression Methods
    let cm_len = *b.get(pos)? as usize;
    pos = pos.checked_add(1 + cm_len)?;

    if pos + 2 > b.len() {
        return None;
    }

    // Extensions
    let ext_total = read_u16(b, pos)? as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > b.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = read_u16(b, pos)?;
        let ext_len = read_u16(b, pos + 2)? as usize;
        pos += 4;
        
        if pos + ext_len > ext_end {
            break;
        }

        if ext_type == 0x0000 {
            // Found SNI extension.
            // Type(2) | Len(2) | ListLen(2) | NameType(1) | NameLen(2) | Name(N)
            return Some((pos - 4, 4 + ext_len));
        }
        pos += ext_len;
    }
    None
}

fn read_u16(buf: &[u8], pos: usize) -> Option<u16> {
    let b0 = *buf.get(pos)?;
    let b1 = *buf.get(pos + 1)?;
    Some(u16::from_be_bytes([b0, b1]))
}

fn read_u24(buf: &[u8], pos: usize) -> Option<u32> {
    let b0 = *buf.get(pos)? as u32;
    let b1 = *buf.get(pos + 1)? as u32;
    let b2 = *buf.get(pos + 2)? as u32;
    Some((b0 << 16) | (b1 << 8) | b2)
}

impl<T: AsyncRead + Unpin> AsyncRead for FragmentingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FragmentingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.enabled() {
            self.sleep = None; // Reset any pending sleep if disabled mid-operation
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        if let Some(s) = &mut self.sleep {
            match s.as_mut().poll(cx) {
                Poll::Ready(()) => self.sleep = None,
                Poll::Pending => return Poll::Pending,
            }
        }

        let max = self.next_write_limit(buf);
        let slice = &buf[..max.min(buf.len())];

        match Pin::new(&mut self.inner).poll_write(cx, slice) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    // Update the first-write plan accounting if used.
                    if let Some(plan_len) = self.cfg.first_write_plan.as_ref().map(|p| p.len()) {
                        if self.first_plan_remaining > 0 {
                            self.first_plan_remaining = self.first_plan_remaining.saturating_sub(n);
                            if self.first_plan_remaining == 0 {
                                self.first_plan_idx = self.first_plan_idx.saturating_add(1);
                                if self.first_plan_idx >= plan_len {
                                    // Plan is complete; fall back to normal fragmentation for remaining writes.
                                    self.cfg.first_write_plan = None;
                                }
                            }
                        }
                    }

                    // Only advance from first_write if we actually wrote something
                    if self.first_write && self.cfg.first_write_plan.is_none() {
                        self.first_write = false;
                    }

                    let sleep_ms = self.next_sleep_ms();
                    if sleep_ms > 0 && self.enabled() {
                        if tokio::runtime::Handle::try_current().is_ok() {
                            if let Some(sleep) = self.sleep.as_mut() {
                                sleep
                                    .as_mut()
                                    .reset(Instant::now() + Duration::from_millis(sleep_ms));
                            } else {
                                self.sleep = Some(Box::pin(tokio::time::sleep(
                                    Duration::from_millis(sleep_ms),
                                )));
                            }
                        }
                    }
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use tokio::io::AsyncWrite;

    fn build_client_hello(host: &str, include_padding_extension: bool) -> Vec<u8> {
        let host = host.as_bytes();
        let sni_name_len = host.len() as u16;
        let sni_list_len = 1 + 2 + sni_name_len;
        let sni_ext_len = 2 + sni_list_len;

        let mut exts = Vec::new();
        if include_padding_extension {
            exts.extend_from_slice(&0x0015u16.to_be_bytes());
            exts.extend_from_slice(&2u16.to_be_bytes());
            exts.extend_from_slice(&[0x00, 0x00]);
        }
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&sni_ext_len.to_be_bytes());
        exts.extend_from_slice(&sni_list_len.to_be_bytes());
        exts.push(0x00);
        exts.extend_from_slice(&sni_name_len.to_be_bytes());
        exts.extend_from_slice(host);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01);
        let hs_len = body.len() as u32;
        hs.extend_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn find_sni_offset_basic_client_hello() {
        let ch = build_client_hello("example.com", false);
        assert_eq!(find_sni_info(&ch).map(|(o, _)| o), Some(52));
    }

    #[test]
    fn find_sni_offset_with_padding_extension() {
        let ch = build_client_hello("example.com", true);
        assert_eq!(find_sni_info(&ch).map(|(o, _)| o), Some(58));
    }

    #[test]
    fn split_at_sni_gracefully_falls_back_when_parse_fails() {
        let cfg = FragmentConfig {
            split_at_sni: true,
            first_write_max: 7,
            ..FragmentConfig::default()
        };
        let (mut io, _handle) = FragmentingIo::new(tokio::io::sink(), cfg);
        let first = io.next_write_limit(b"not a tls client hello");
        assert_eq!(first, 7);
    }

    struct DummyWriter;

    impl AsyncWrite for DummyWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn noop_waker() -> Waker {
        // SAFETY: vtable functions never dereference the data pointer.
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        // SAFETY: vtable satisfies RawWaker contract for no-op behavior.
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    #[test]
    fn poll_write_without_tokio_runtime_does_not_panic() {
        let cfg = FragmentConfig {
            sleep_ms: 5,
            ..FragmentConfig::default()
        };
        let (mut io, _handle) = FragmentingIo::new(DummyWriter, cfg);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Pin::new(&mut io);
        let res = AsyncWrite::poll_write(pinned.as_mut(), &mut cx, b"hello");
        assert!(matches!(res, Poll::Ready(Ok(5))));
    }
}

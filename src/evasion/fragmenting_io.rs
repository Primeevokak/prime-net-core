use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

#[derive(Debug, Clone)]
pub struct FragmentConfig {
    /// Maximum chunk size for the first write (best-effort DPI bypass). Clamped to <= 64.
    pub first_write_max: usize,
    /// Optional deterministic chunk sizes for the first write (splits by explicit offsets/parts).
    ///
    /// If set and non-empty, it takes precedence over `first_write_max`.
    pub first_write_plan: Option<Vec<usize>>,
    /// Maximum chunk size for subsequent writes while fragmentation is enabled.
    pub fragment_size: usize,
    /// Optional delay between chunks.
    pub sleep_ms: u64,
    /// Optional per-chunk jitter range (overrides `sleep_ms` when set).
    pub jitter_ms: Option<(u64, u64)>,
    /// If true, randomize chunk sizes for non-first writes in 1..=fragment_size (best-effort).
    pub randomize_fragment_size: bool,
    /// If true, attempt to split first TLS ClientHello exactly at SNI extension boundary.
    /// This has higher priority than `first_write_plan`.
    pub split_at_sni: bool,
}

impl Default for FragmentConfig {
    fn default() -> Self {
        Self {
            first_write_max: 64,
            first_write_plan: None,
            fragment_size: 64,
            sleep_ms: 10,
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
        if cfg.fragment_size == 0 {
            cfg.fragment_size = 1;
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
            if let Some(sni_off) = find_sni_offset(buf) {
                let mut plan = Vec::new();
                if sni_off > 0 {
                    plan.push(sni_off);
                }
                if sni_off < buf_len {
                    plan.push(1);
                }
                if sni_off + 1 < buf_len {
                    plan.push(buf_len - (sni_off + 1));
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

        if self.cfg.randomize_fragment_size && self.cfg.fragment_size > 1 {
            let max = self.cfg.fragment_size.min(buf_len.max(1));
            return rand::thread_rng().gen_range(1..=max.max(1));
        }
        self.cfg.fragment_size.min(buf_len.max(1)).max(1)
    }
}

fn find_sni_offset(client_hello: &[u8]) -> Option<usize> {
    let b = client_hello;
    if b.len() < 5 + 4 + 2 + 32 + 1 {
        return None;
    }
    if b[0] != 0x16 || b[1] != 0x03 {
        return None;
    }

    let mut pos = 5 + 4 + 2 + 32;
    if pos >= b.len() {
        return None;
    }

    let session_id_len = *b.get(pos)? as usize;
    pos = pos.checked_add(1 + session_id_len)?;

    let cs_len = u16::from_be_bytes([*b.get(pos)?, *b.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2 + cs_len)?;

    let cm_len = *b.get(pos)? as usize;
    pos = pos.checked_add(1 + cm_len)?;

    let ext_total = u16::from_be_bytes([*b.get(pos)?, *b.get(pos + 1)?]) as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_total)?.min(b.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([b[pos], b[pos + 1]]);
        let ext_len = u16::from_be_bytes([b[pos + 2], b[pos + 3]]) as usize;
        if ext_type == 0x0000 {
            return Some(pos);
        }
        pos = pos.checked_add(4 + ext_len)?;
    }
    None
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

                    self.first_write = false;

                    let sleep_ms = self.next_sleep_ms();
                    if sleep_ms > 0 && self.enabled() {
                        self.sleep = Some(Box::pin(tokio::time::sleep(Duration::from_millis(
                            sleep_ms,
                        ))));
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

    fn is_write_vectored(&self) -> bool {
        // We intentionally degrade to non-vectored writes while fragmentation is enabled.
        false
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        // Keep behavior simple and deterministic: write from the first non-empty slice.
        for b in bufs {
            if !b.is_empty() {
                return self.poll_write(cx, b);
            }
        }
        Poll::Ready(Ok(0))
    }
}

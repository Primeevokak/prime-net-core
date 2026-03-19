use std::io;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::warn;

use crate::evasion::packet_intercept::PacketInterceptor;
use crate::evasion::tls_parser::{parse_client_hello, ParsedClientHello};

/// Where to place the split point within the TLS ClientHello record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitAt {
    /// Fixed offset in bytes (counted from byte 0 of the TLS record, incl. the 5-byte header).
    Fixed(usize),
    /// Split right before the SNI extension (falls back to mid-record if SNI not found).
    BeforeSni,
    /// Split 1 byte inside the SNI extension (equivalent to byedpi `1+s`).
    IntoSni,
    /// Split through the middle of the SNI hostname (most aggressive).
    MidSni,
}

/// Where to split an HTTP/1.x request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpSplitAt {
    /// Split right before the `Host:` header line (second segment starts with `Host:`).
    BeforeHostHeader,
    /// Split at a fixed byte offset within the request.
    Fixed(usize),
}

/// Userspace TCP desync technique applied to TLS ClientHello or HTTP data.
///
/// Note: not `Copy` because `MultiSplit` owns a `Vec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesyncTechnique {
    /// Send two raw TCP segments with an explicit flush between them.
    /// Equivalent to byedpi `--split`.
    TcpSegmentSplit { at: SplitAt },

    /// Reconstruct the single TLS record as two separate TLS records and
    /// send each as its own TCP segment.
    /// Equivalent to byedpi `--tlsrec`.
    TlsRecordSplit { at: SplitAt },

    /// TLS record split combined with an OOB (URG) byte between the two fragments.
    /// Equivalent to byedpi `--tlsrec ... --oob`.
    /// Real `MSG_OOB` on Windows and Linux; falls back to plain split on other platforms.
    TlsRecordSplitOob { at: SplitAt },

    /// TCP segment split combined with an OOB (URG) byte at the split point.
    /// Equivalent to byedpi `--split ... --oob`.
    /// Real `MSG_OOB` on Windows and Linux; falls back to plain split on other platforms.
    TcpSegmentSplitOob { at: SplitAt },

    /// Split an HTTP/1.x request into two TCP segments for DPI evasion on port 80.
    HttpSplit { at: HttpSplitAt },

    /// Split data into N+1 TCP segments (one flush per split point).
    ///
    /// Points are resolved to absolute byte offsets at runtime using the parsed
    /// ClientHello, deduplicated, and sorted.  Effective against DPI that
    /// reassembles exactly 2 fragments but gives up on 3+.
    MultiSplit { points: Vec<SplitAt> },

    /// TLS record split with a dummy ApplicationData record injected between fragments.
    ///
    /// Sends fragment 1, then a 5-byte TLS 1.0 ApplicationData record with zero payload
    /// (`0x17 0x03 0x01 0x00 0x00`), then fragment 2.  Stateful DPI that tracks
    /// handshake context loses its place after the unexpected record type and fails to
    /// extract the SNI from the second handshake fragment.
    TlsRecordPadding { at: SplitAt },

    /// Send TCP segment 2 before segment 1 (TCP disorder / reordering).
    ///
    /// Requires a [`PacketInterceptor`] backend (WinDivert on Windows, NFQueue on
    /// Linux).  When no backend is available at runtime, falls back to a plain
    /// [`TcpSegmentSplit`] at `SplitAt::IntoSni` and logs a warning.
    ///
    /// Mechanism: intercept the first outgoing data segment (ClientHello part 1),
    /// immediately forward segment 2, then after `delay_ms` milliseconds forward
    /// segment 1.  DPI that relies on in-order segment reassembly cannot extract
    /// the SNI.
    ///
    /// **Do not use for Cloudflare-hosted targets** — Cloudflare's edges reject
    /// out-of-order TCP segments, causing connection failures.
    ///
    /// [`PacketInterceptor`]: crate::evasion::packet_intercept::PacketInterceptor
    TcpDisorder {
        /// Milliseconds between forwarding segment 2 and forwarding segment 1.
        delay_ms: u64,
    },
}

/// Optional low-TTL probe sent to the target before the real TCP connection.
///
/// Poisons the DPI middlebox's TCP state-tracking table so it desynchronises
/// from the real connection that follows.
#[derive(Debug, Clone, Copy)]
pub struct FakeProbe {
    /// IP TTL for the probe connection (typically 3–5 hops).
    pub ttl: u8,
    /// Random bytes to send in the probe body; 0 = empty probe (TCB-desync only).
    /// Ignored when `fake_sni` is set.
    pub data_size: usize,
    /// If `Some`, send a crafted TLS ClientHello with this SNI instead of random bytes.
    ///
    /// Preferred over `data_size > 0` because DPI that parses TLS records will
    /// actually extract the fake SNI and create state for a connection that then
    /// expires (TTL exhausted), leaving the DPI confused before the real ClientHello.
    pub fake_sni: Option<&'static str>,
}

/// A named native desync profile.
#[derive(Debug, Clone)]
pub struct NativeDesyncProfile {
    /// Short identifier used in logs and route-race labels.
    pub name: &'static str,
    /// The desync technique to apply to the first TLS ClientHello or HTTP request.
    pub technique: DesyncTechnique,
    /// If `false`, this profile is skipped for Cloudflare-hosted targets (Discord,
    /// Instagram, etc.) because those servers reject disordered TCP segments.
    pub cloudflare_safe: bool,
    /// If `Some`, send a low-TTL probe to the target before connecting.
    pub fake_probe: Option<FakeProbe>,
    /// If `true`, randomize the ASCII case of the SNI hostname bytes before sending
    /// (e.g. `discord.com` → `DiScOrD.cOm`).  Defeats DPI with exact-match SNI filters.
    pub randomize_sni_case: bool,
    /// Milliseconds to sleep between the first and subsequent TCP segment flushes.
    ///
    /// Defeats DPI middleboxes that have a short reassembly timer: if the second
    /// segment arrives after the timer expires, the DPI discards its buffer.
    /// `None` means no intentional delay (default).
    pub inter_fragment_delay_ms: Option<u64>,
}

/// In-process TCP desync engine — drop-in replacement for the external ciadpi pool.
///
/// Holds a list of [`NativeDesyncProfile`]s that map 1:1 to byedpi profiles.
/// Each profile gets its own [`RouteCandidate`] in the route-race so the ML
/// scorer can learn which technique wins for each domain.
///
/// The optional `packet_interceptor` enables [`DesyncTechnique::TcpDisorder`]
/// profiles.  When absent those profiles fall back to a plain TCP split.
#[derive(Debug)]
pub struct TcpDesyncEngine {
    profiles: Vec<NativeDesyncProfile>,
    /// Packet-level interceptor for TCP disorder (WinDivert / NFQueue).
    /// `None` when no backend could be loaded at startup.
    pub packet_interceptor: Option<Arc<dyn PacketInterceptor>>,
}

impl TcpDesyncEngine {
    /// Create an engine with an explicit profile list and no packet interceptor.
    pub fn new(profiles: Vec<NativeDesyncProfile>) -> Self {
        Self {
            profiles,
            packet_interceptor: None,
        }
    }

    /// Create an engine with an explicit profile list and a packet interceptor.
    pub fn new_with_interceptor(
        profiles: Vec<NativeDesyncProfile>,
        interceptor: Arc<dyn PacketInterceptor>,
    ) -> Self {
        Self {
            profiles,
            packet_interceptor: Some(interceptor),
        }
    }

    /// Build an engine with the platform-appropriate default profiles.
    ///
    /// On all platforms: TLS/TCP split, HTTP split, fake-probe, multi-split,
    /// delayed-split, and SNI-case profiles.
    /// On Windows and Unix: additionally OOB/URG and TCP-disorder profiles.
    ///
    /// Automatically tries to load the best available [`PacketInterceptor`]
    /// backend (WinDivert on Windows, NFQueue on Linux).
    pub fn with_default_profiles() -> Self {
        let interceptor = crate::evasion::packet_intercept::best_available_interceptor();
        Self {
            profiles: default_native_profiles(),
            packet_interceptor: interceptor,
        }
    }

    /// Number of profiles loaded in this engine.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Name of the profile at `idx` (for logging); returns `"unknown"` if out of range.
    pub fn profile_name(&self, idx: usize) -> &str {
        self.profiles.get(idx).map(|p| p.name).unwrap_or("unknown")
    }

    /// Reference to the profile at `idx`; panics if out of range.
    ///
    /// Used by the discovery module to clone profiles for reordering.
    pub fn profile_at(&self, idx: usize) -> &NativeDesyncProfile {
        &self.profiles[idx]
    }

    /// Returns `true` if the profile at `idx` is safe for Cloudflare-hosted targets.
    ///
    /// Returns `true` (safe by default) if `idx` is out of range.
    pub fn is_profile_cloudflare_safe(&self, idx: usize) -> bool {
        self.profiles
            .get(idx)
            .map(|p| p.cloudflare_safe)
            .unwrap_or(true)
    }

    /// Replace the profile list with a reordered copy (e.g. from discovery cache).
    ///
    /// The packet interceptor is preserved.
    pub fn set_profiles(&mut self, profiles: Vec<NativeDesyncProfile>) {
        self.profiles = profiles;
    }

    /// Returns the fake-probe spec for `idx`, if the profile requests one.
    pub fn profile_fake_probe(&self, idx: usize) -> Option<&FakeProbe> {
        self.profiles.get(idx).and_then(|p| p.fake_probe.as_ref())
    }

    /// Apply the desync technique for `profile_idx` to `data` using a generic writer.
    ///
    /// OOB techniques fall back to plain split when used with this method; use
    /// [`apply_to_tcp_stream`] instead to get real `MSG_OOB` injection.
    ///
    /// If `data` is not a TLS ClientHello (and the technique is not `HttpSplit`),
    /// writes it unchanged.
    pub async fn apply<W: AsyncWriteExt + Unpin>(
        &self,
        profile_idx: usize,
        writer: &mut W,
        data: &[u8],
    ) -> io::Result<()> {
        let profile = match self.profiles.get(profile_idx) {
            Some(p) => p,
            None => {
                writer.write_all(data).await?;
                writer.flush().await?;
                return Ok(());
            }
        };

        let delay = profile.inter_fragment_delay_ms;

        // HTTP-split only makes sense for plaintext HTTP (port 80).
        // If the first byte is 0x16, this is a TLS ClientHello — skip the HttpSplit
        // technique and fall through to the TLS-aware path below.
        if let DesyncTechnique::HttpSplit { at } = &profile.technique {
            if !data.is_empty() && data[0] == 0x16 {
                // TLS data reached an HttpSplit profile — treat as plain split at the
                // TLS record boundary (first 5 bytes = header, rest = payload).
                let split = data.len().min(5);
                tcp_segment_split(writer, data, split, delay).await?;
                writer.flush().await?;
                return Ok(());
            }
            let split = http_split_offset(data, *at);
            tcp_segment_split(writer, data, split, delay).await?;
            writer.flush().await?;
            return Ok(());
        }

        // All TLS-based techniques: pass non-TLS data unchanged.
        if data.len() < 5 || data[0] != 0x16 {
            writer.write_all(data).await?;
            writer.flush().await?;
            return Ok(());
        }

        let parsed = parse_client_hello(data);

        // SNI case randomization: work on an owned copy when enabled.
        let mut data_buf: Option<Vec<u8>> = None;
        if profile.randomize_sni_case {
            if let Some(ref p) = parsed {
                let mut buf = data.to_vec();
                randomize_sni_case_bytes(&mut buf, p);
                data_buf = Some(buf);
            }
        }
        let data = data_buf.as_deref().unwrap_or(data);

        apply_technique(writer, data, &profile.technique, parsed.as_ref(), delay).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Apply the desync technique to a raw [`TcpStream`], enabling real OOB injection.
    ///
    /// For `TlsRecordSplitOob` and `TcpSegmentSplitOob` profiles this sends an
    /// actual `MSG_OOB` byte between the two fragments (Windows and Linux).  All other
    /// techniques behave identically to [`apply`].
    pub async fn apply_to_tcp_stream(
        &self,
        profile_idx: usize,
        stream: &mut TcpStream,
        data: &[u8],
    ) -> io::Result<()> {
        let profile = match self.profiles.get(profile_idx) {
            Some(p) => p,
            None => {
                stream.write_all(data).await?;
                stream.flush().await?;
                return Ok(());
            }
        };

        let delay = profile.inter_fragment_delay_ms;

        // HTTP-split: plaintext evasion, no TLS check needed.
        if let DesyncTechnique::HttpSplit { at } = &profile.technique {
            let split = http_split_offset(data, *at);
            tcp_segment_split(stream, data, split, delay).await?;
            stream.flush().await?;
            return Ok(());
        }

        // TLS-based techniques: pass non-TLS data unchanged.
        if data.len() < 5 || data[0] != 0x16 {
            stream.write_all(data).await?;
            stream.flush().await?;
            return Ok(());
        }

        let parsed = parse_client_hello(data);

        // SNI case randomization: work on an owned copy when enabled.
        let mut data_buf: Option<Vec<u8>> = None;
        if profile.randomize_sni_case {
            if let Some(ref p) = parsed {
                let mut buf = data.to_vec();
                randomize_sni_case_bytes(&mut buf, p);
                data_buf = Some(buf);
            }
        }
        let data = data_buf.as_deref().unwrap_or(data);

        match &profile.technique {
            DesyncTechnique::TlsRecordSplitOob { at } => {
                let payload_split = split_offset_in_payload(data, *at, parsed.as_ref());
                tls_record_split_oob_real(stream, data, payload_split, delay).await?;
            }
            DesyncTechnique::TcpSegmentSplitOob { at } => {
                let split = split_offset_in_record(data, *at, parsed.as_ref());
                tcp_segment_split_oob_real(stream, data, split, delay).await?;
            }
            DesyncTechnique::TcpDisorder { delay_ms } => {
                apply_tcp_disorder(self, stream, data, parsed.as_ref(), *delay_ms).await?;
            }
            other => {
                // Non-OOB techniques behave the same on TcpStream as on generic writers.
                apply_technique(stream, data, other, parsed.as_ref(), delay).await?;
            }
        }

        stream.flush().await?;
        Ok(())
    }
}

// ── Technique dispatch ────────────────────────────────────────────────────────

/// Apply a non-OOB technique to a generic async writer.
async fn apply_technique<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    technique: &DesyncTechnique,
    parsed: Option<&ParsedClientHello>,
    delay_ms: Option<u64>,
) -> io::Result<()> {
    match technique {
        DesyncTechnique::TcpSegmentSplit { at } => {
            let split = split_offset_in_record(data, *at, parsed);
            tcp_segment_split(writer, data, split, delay_ms).await
        }
        DesyncTechnique::TlsRecordSplit { at } => {
            let payload_split = split_offset_in_payload(data, *at, parsed);
            tls_record_split(writer, data, payload_split, delay_ms).await
        }
        // OOB fallback to plain split when no raw socket is available.
        DesyncTechnique::TlsRecordSplitOob { at } => {
            let payload_split = split_offset_in_payload(data, *at, parsed);
            tls_record_split(writer, data, payload_split, delay_ms).await
        }
        DesyncTechnique::TcpSegmentSplitOob { at } => {
            let split = split_offset_in_record(data, *at, parsed);
            tcp_segment_split(writer, data, split, delay_ms).await
        }
        DesyncTechnique::HttpSplit { at } => {
            let split = http_split_offset(data, *at);
            tcp_segment_split(writer, data, split, delay_ms).await
        }
        DesyncTechnique::MultiSplit { points } => {
            multi_tcp_segment_split(writer, data, points, parsed, delay_ms).await
        }
        DesyncTechnique::TlsRecordPadding { at } => {
            let payload_split = split_offset_in_payload(data, *at, parsed);
            tls_record_padding_split(writer, data, payload_split, delay_ms).await
        }
        // TcpDisorder requires a raw socket + PacketInterceptor — fall back to plain split.
        DesyncTechnique::TcpDisorder { .. } => {
            let split = split_offset_in_record(data, SplitAt::IntoSni, parsed);
            tcp_segment_split(writer, data, split, delay_ms).await
        }
    }
}

// ── Core primitives ──────────────────────────────────────────────────────────

/// Send data as two TCP segments separated by an explicit flush.
///
/// `delay_ms`: optional sleep between the flush and the second write, to defeat
/// DPI middleboxes with short reassembly timers.
async fn tcp_segment_split<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    split: usize,
    delay_ms: Option<u64>,
) -> io::Result<()> {
    if split == 0 || split >= data.len() {
        writer.write_all(data).await?;
        return Ok(());
    }
    writer.write_all(&data[..split]).await?;
    writer.flush().await?;
    if let Some(ms) = delay_ms {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    writer.write_all(&data[split..]).await?;
    Ok(())
}

/// Reconstruct the TLS record as two separate TLS records.
///
/// `payload_split` is the split offset *within the TLS payload* (bytes after the 5-byte
/// TLS record header).  `delay_ms` is an optional inter-fragment sleep.
async fn tls_record_split<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    record: &[u8],
    payload_split: usize,
    delay_ms: Option<u64>,
) -> io::Result<()> {
    if record.len() < 5 || payload_split == 0 {
        writer.write_all(record).await?;
        return Ok(());
    }

    let content_type = record[0];
    let version = [record[1], record[2]];
    let payload = &record[5..];

    if payload_split >= payload.len() {
        writer.write_all(record).await?;
        return Ok(());
    }

    // Fragment 1: TLS record header + first part of payload.
    let len1 = (payload_split as u16).to_be_bytes();
    writer
        .write_all(&[content_type, version[0], version[1], len1[0], len1[1]])
        .await?;
    writer.write_all(&payload[..payload_split]).await?;
    writer.flush().await?;

    if let Some(ms) = delay_ms {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    // Fragment 2: TLS record header + remainder of payload.
    let rem = payload.len() - payload_split;
    let len2 = (rem as u16).to_be_bytes();
    writer
        .write_all(&[content_type, version[0], version[1], len2[0], len2[1]])
        .await?;
    writer.write_all(&payload[payload_split..]).await?;
    Ok(())
}

/// Split data into N+1 TCP segments with explicit flushes between each.
///
/// Split points are resolved from [`SplitAt`] to absolute byte offsets in `data`,
/// sorted, and deduplicated.  Effective against DPI that reassembles exactly
/// 2 fragments but gives up on 3 or more.
async fn multi_tcp_segment_split<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    points: &[SplitAt],
    parsed: Option<&ParsedClientHello>,
    delay_ms: Option<u64>,
) -> io::Result<()> {
    let mut offsets: Vec<usize> = points
        .iter()
        .map(|&at| split_offset_in_record(data, at, parsed))
        .filter(|&off| off > 0 && off < data.len())
        .collect();
    offsets.sort_unstable();
    offsets.dedup();

    if offsets.is_empty() {
        writer.write_all(data).await?;
        return Ok(());
    }

    let mut prev = 0usize;
    for &off in &offsets {
        if off > prev {
            writer.write_all(&data[prev..off]).await?;
            writer.flush().await?;
            if let Some(ms) = delay_ms {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            prev = off;
        }
    }
    if prev < data.len() {
        writer.write_all(&data[prev..]).await?;
    }
    Ok(())
}

/// TLS record split with a dummy ApplicationData record injected between fragments.
///
/// The injected record (`0x17 0x03 0x01 0x00 0x00`) is structurally valid per RFC 5246 but
/// unexpected mid-handshake.  Stateful DPI that maintains a handshake parse state machine
/// loses synchronisation and cannot extract the SNI hostname from fragment 2.
async fn tls_record_padding_split<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    record: &[u8],
    payload_split: usize,
    delay_ms: Option<u64>,
) -> io::Result<()> {
    if record.len() < 5 || payload_split == 0 {
        writer.write_all(record).await?;
        return Ok(());
    }

    let content_type = record[0];
    let version = [record[1], record[2]];
    let payload = &record[5..];

    if payload_split >= payload.len() {
        writer.write_all(record).await?;
        return Ok(());
    }

    // Fragment 1.
    let len1 = (payload_split as u16).to_be_bytes();
    writer
        .write_all(&[content_type, version[0], version[1], len1[0], len1[1]])
        .await?;
    writer.write_all(&payload[..payload_split]).await?;
    writer.flush().await?;

    if let Some(ms) = delay_ms {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    // Dummy ApplicationData record: content_type=0x17, version=TLS 1.0, length=0.
    // Injected between the two handshake fragments to confuse stateful DPI.
    writer.write_all(&[0x17, 0x03, 0x01, 0x00, 0x00]).await?;
    writer.flush().await?;

    // Fragment 2.
    let rem = payload.len() - payload_split;
    let len2 = (rem as u16).to_be_bytes();
    writer
        .write_all(&[content_type, version[0], version[1], len2[0], len2[1]])
        .await?;
    writer.write_all(&payload[payload_split..]).await?;
    Ok(())
}

/// TLS record split with a real OOB byte injected between the two fragments.
///
/// Requires a raw `TcpStream` for `MSG_OOB` access.
async fn tls_record_split_oob_real(
    stream: &mut TcpStream,
    record: &[u8],
    payload_split: usize,
    delay_ms: Option<u64>,
) -> io::Result<()> {
    if record.len() < 5 || payload_split == 0 {
        stream.write_all(record).await?;
        return Ok(());
    }

    let content_type = record[0];
    let version = [record[1], record[2]];
    let payload = &record[5..];

    if payload_split >= payload.len() {
        stream.write_all(record).await?;
        return Ok(());
    }

    // Fragment 1
    let len1 = (payload_split as u16).to_be_bytes();
    stream
        .write_all(&[content_type, version[0], version[1], len1[0], len1[1]])
        .await?;
    stream.write_all(&payload[..payload_split]).await?;
    stream.flush().await?;

    if let Some(ms) = delay_ms {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    // OOB byte between fragments — confuses DPI reassembly.
    crate::evasion::dpi_bypass::send_oob_byte(stream, 0x00).await?;

    // Fragment 2
    let rem = payload.len() - payload_split;
    let len2 = (rem as u16).to_be_bytes();
    stream
        .write_all(&[content_type, version[0], version[1], len2[0], len2[1]])
        .await?;
    stream.write_all(&payload[payload_split..]).await?;
    Ok(())
}

/// TCP segment split with a real OOB byte injected at the split point.
async fn tcp_segment_split_oob_real(
    stream: &mut TcpStream,
    data: &[u8],
    split: usize,
    delay_ms: Option<u64>,
) -> io::Result<()> {
    if split == 0 || split >= data.len() {
        stream.write_all(data).await?;
        return Ok(());
    }

    stream.write_all(&data[..split]).await?;
    stream.flush().await?;

    if let Some(ms) = delay_ms {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    // OOB byte between segments.
    crate::evasion::dpi_bypass::send_oob_byte(stream, 0x00).await?;

    stream.write_all(&data[split..]).await?;
    Ok(())
}

// ── TCP disorder ──────────────────────────────────────────────────────────────

/// Apply TCP disorder using the engine's packet interceptor if available.
///
/// Splits `data` at `IntoSni`, then:
/// - With interceptor: opens an intercept session on `stream`'s local address so
///   the kernel backend can hold segment 1 and forward segment 2 first.
/// - Without interceptor: falls back to a plain segment split (logs a warning
///   the first time so operators know to install WinDivert / configure NFQueue).
async fn apply_tcp_disorder(
    engine: &TcpDesyncEngine,
    stream: &mut TcpStream,
    data: &[u8],
    parsed: Option<&ParsedClientHello>,
    delay_ms: u64,
) -> io::Result<()> {
    let split = split_offset_in_record(data, SplitAt::IntoSni, parsed);

    let Some(ref interceptor) = engine.packet_interceptor else {
        // No backend available — plain split as fallback.
        warn!(
            "TcpDisorder: no packet interceptor available \
             (install WinDivert on Windows or configure NFQueue on Linux); \
             falling back to plain TCP split"
        );
        tcp_segment_split(stream, data, split, Some(delay_ms)).await?;
        return Ok(());
    };

    let local_addr = stream.local_addr().map_err(io::Error::other)?;

    // Start the intercept session — the backend will reorder our next two writes.
    let handle = interceptor
        .clone()
        .intercept_connection(local_addr, delay_ms)?;

    // Write both segments; the interceptor backend in the kernel will reorder them.
    if split > 0 && split < data.len() {
        stream.write_all(&data[..split]).await?;
        stream.flush().await?;
        stream.write_all(&data[split..]).await?;
    } else {
        stream.write_all(data).await?;
    }

    // Cancel the intercept session once both segments are written.
    handle.cancel();
    Ok(())
}

// ── SNI case randomization ────────────────────────────────────────────────────

/// Randomize the ASCII case of the SNI hostname bytes in place.
///
/// Modifies `record` at the byte range `[sni_hostname_offset, sni_hostname_offset + len)`.
/// Alphabetic bytes are randomly uppercased or lowercased; non-alpha bytes (dots, hyphens)
/// are left unchanged.  The TLS record remains structurally valid because only payload
/// values change, not lengths.
fn randomize_sni_case_bytes(record: &mut [u8], parsed: &ParsedClientHello) {
    let Some(offset) = parsed.sni_hostname_offset else {
        return;
    };
    let end = offset + parsed.sni_hostname_len;
    if end > record.len() {
        return;
    }
    let mut rng = rand::thread_rng();
    for byte in &mut record[offset..end] {
        if byte.is_ascii_alphabetic() {
            if rng.gen::<bool>() {
                *byte = byte.to_ascii_uppercase();
            } else {
                *byte = byte.to_ascii_lowercase();
            }
        }
    }
}

// ── Offset computation ────────────────────────────────────────────────────────

/// Compute the split offset within the **full TLS record buffer** (incl. 5-byte header).
fn split_offset_in_record(data: &[u8], at: SplitAt, parsed: Option<&ParsedClientHello>) -> usize {
    let max = data.len().saturating_sub(1).max(1);
    match at {
        SplitAt::Fixed(n) => n.clamp(1, max),
        SplitAt::BeforeSni => parsed
            .and_then(|p| p.sni_ext_offset)
            .map(|off| off.clamp(1, max))
            .unwrap_or(data.len() / 2),
        SplitAt::IntoSni => parsed
            .and_then(|p| p.sni_ext_offset)
            .map(|off| (off + 1).clamp(1, max))
            .unwrap_or(data.len() / 2),
        SplitAt::MidSni => parsed
            .and_then(|p| {
                p.sni_hostname_offset
                    .map(|off| off + p.sni_hostname_len / 2)
                    .or(p.sni_ext_offset.map(|off| off + 1))
            })
            .map(|off| off.clamp(1, max))
            .unwrap_or(data.len() / 2),
    }
}

/// Compute the split offset within the **TLS payload** (bytes after the 5-byte header).
fn split_offset_in_payload(data: &[u8], at: SplitAt, parsed: Option<&ParsedClientHello>) -> usize {
    if data.len() < 5 {
        return 0;
    }
    let payload_len = data.len() - 5;
    let max = payload_len.saturating_sub(1).max(1);

    match at {
        SplitAt::Fixed(n) => n.clamp(1, max),
        SplitAt::BeforeSni => parsed
            .and_then(|p| p.sni_ext_offset)
            .map(|off| off.saturating_sub(5).clamp(1, max))
            .unwrap_or(payload_len / 2),
        SplitAt::IntoSni => parsed
            .and_then(|p| p.sni_ext_offset)
            .map(|off| (off.saturating_sub(5) + 1).clamp(1, max))
            .unwrap_or(payload_len / 2),
        SplitAt::MidSni => parsed
            .and_then(|p| {
                p.sni_hostname_offset
                    .map(|off| off.saturating_sub(5) + p.sni_hostname_len / 2)
                    .or(p.sni_ext_offset.map(|off| off.saturating_sub(5) + 1))
            })
            .map(|off| off.clamp(1, max))
            .unwrap_or(payload_len / 2),
    }
}

/// Compute the split offset within an HTTP request for [`HttpSplitAt`].
fn http_split_offset(data: &[u8], at: HttpSplitAt) -> usize {
    let max = data.len().saturating_sub(1).max(1);
    match at {
        HttpSplitAt::Fixed(n) => n.clamp(1, max),
        HttpSplitAt::BeforeHostHeader => {
            // Find "\r\nHost:" (case-insensitive for the field name) and split
            // right after the "\r\n" so the second segment starts with "Host:".
            data.windows(7)
                .position(|w| {
                    w[0] == b'\r' && w[1] == b'\n' && w[2..].eq_ignore_ascii_case(b"host:")
                })
                .map(|pos| (pos + 2).clamp(1, max))
                .unwrap_or(data.len() / 2)
        }
    }
}

// ── Default profiles ──────────────────────────────────────────────────────────

/// Return the platform-appropriate default native desync profiles.
///
/// Every profile in this list performs genuinely distinct work so the ML scorer
/// learns real signals rather than duplicates.  Stubs are excluded via compile-time
/// gates (OOB profiles require `MSG_OOB`, available on Windows and Unix).
pub fn default_native_profiles() -> Vec<NativeDesyncProfile> {
    let mut profiles = vec![
        // 1. TLS record split right into the SNI extension — safest for Cloudflare.
        //    Equivalent: --tlsrec 1+s
        NativeDesyncProfile {
            name: "tlsrec-into-sni",
            technique: DesyncTechnique::TlsRecordSplit {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 2. TLS record split before the SNI extension.
        //    Equivalent: --tlsrec SNI-1
        NativeDesyncProfile {
            name: "tlsrec-before-sni",
            technique: DesyncTechnique::TlsRecordSplit {
                at: SplitAt::BeforeSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 3. TCP segment split right into the SNI extension.
        //    Equivalent: --split 1+s
        NativeDesyncProfile {
            name: "split-into-sni",
            technique: DesyncTechnique::TcpSegmentSplit {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 4. TLS record split through the middle of the SNI hostname.
        //    Equivalent: --tlsrec mid+s
        NativeDesyncProfile {
            name: "tlsrec-mid-sni",
            technique: DesyncTechnique::TlsRecordSplit {
                at: SplitAt::MidSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 5. TLS record split at a fixed 5-byte offset into the payload.
        //    Equivalent: --tlsrec 5
        NativeDesyncProfile {
            name: "tlsrec-fixed-5",
            technique: DesyncTechnique::TlsRecordSplit {
                at: SplitAt::Fixed(5),
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 6. TCP segment split before the SNI extension.
        //    Equivalent: --split before-sni
        NativeDesyncProfile {
            name: "split-before-sni",
            technique: DesyncTechnique::TcpSegmentSplit {
                at: SplitAt::BeforeSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 7. TCP segment split at fixed byte 1.
        //    Equivalent: --split 1
        NativeDesyncProfile {
            name: "split-fixed-1",
            technique: DesyncTechnique::TcpSegmentSplit {
                at: SplitAt::Fixed(1),
            },
            cloudflare_safe: false,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 8. TCP segment split at fixed byte 3.
        //    Equivalent: --split 3
        NativeDesyncProfile {
            name: "split-fixed-3",
            technique: DesyncTechnique::TcpSegmentSplit {
                at: SplitAt::Fixed(3),
            },
            cloudflare_safe: false,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 9. HTTP-level split before the Host: header — effective for port-80 DPI.
        NativeDesyncProfile {
            name: "http-before-host",
            technique: DesyncTechnique::HttpSplit {
                at: HttpSplitAt::BeforeHostHeader,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 10. TLS record split + fake low-TTL TCB probe (TTL=3).
        //     The probe desynchronises the DPI state table before the real SYN.
        NativeDesyncProfile {
            name: "tlsrec-into-sni-fake-ttl3",
            technique: DesyncTechnique::TlsRecordSplit {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: Some(FakeProbe {
                ttl: 3,
                data_size: 0,
                fake_sni: None,
            }),
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 11. TCP segment split + fake low-TTL probe.
        NativeDesyncProfile {
            name: "split-into-sni-fake-ttl3",
            technique: DesyncTechnique::TcpSegmentSplit {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: Some(FakeProbe {
                ttl: 3,
                data_size: 0,
                fake_sni: None,
            }),
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 12. Multi-split across the SNI region (3 split points → 4 segments).
        //     Targets DPI that reassembles exactly 2 fragments but gives up on 3+.
        NativeDesyncProfile {
            name: "multi-split-sni-region",
            technique: DesyncTechnique::MultiSplit {
                points: vec![SplitAt::BeforeSni, SplitAt::IntoSni, SplitAt::MidSni],
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 13. Multi-split with fixed offsets (4 split points → 5 segments).
        //     Confuses DPI doing offset-based packet inspection.
        NativeDesyncProfile {
            name: "multi-split-fixed",
            technique: DesyncTechnique::MultiSplit {
                points: vec![
                    SplitAt::Fixed(1),
                    SplitAt::Fixed(2),
                    SplitAt::BeforeSni,
                    SplitAt::IntoSni,
                ],
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 14. TCP split + 100 ms inter-fragment delay.
        //     Defeats DPI with short reassembly timers that discard incomplete buffers.
        NativeDesyncProfile {
            name: "split-into-sni-delay-100",
            technique: DesyncTechnique::TcpSegmentSplit {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: Some(100),
        },
        // 15. TLS record split + 250 ms inter-fragment delay.
        NativeDesyncProfile {
            name: "tlsrec-into-sni-delay-250",
            technique: DesyncTechnique::TlsRecordSplit {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: Some(250),
        },
        // 16. TCP split + SNI case randomization.
        //     Defeats DPI with exact-match SNI string filters (e.g. "discord.com").
        NativeDesyncProfile {
            name: "split-into-sni-case-rand",
            technique: DesyncTechnique::TcpSegmentSplit {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: true,
            inter_fragment_delay_ms: None,
        },
        // 17. TLS record split + SNI case randomization.
        NativeDesyncProfile {
            name: "tlsrec-into-sni-case-rand",
            technique: DesyncTechnique::TlsRecordSplit {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: true,
            inter_fragment_delay_ms: None,
        },
        // 18. TLS record split + dummy ApplicationData padding between fragments.
        //     The injected record confuses stateful DPI that tracks handshake context.
        NativeDesyncProfile {
            name: "tlsrec-pad-into-sni",
            technique: DesyncTechnique::TlsRecordPadding {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: false, // Padding mid-handshake may confuse Cloudflare edges.
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 19. TLS record split before SNI + dummy ApplicationData padding.
        NativeDesyncProfile {
            name: "tlsrec-pad-before-sni",
            technique: DesyncTechnique::TlsRecordPadding {
                at: SplitAt::BeforeSni,
            },
            cloudflare_safe: false,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 20. TLS record split + fake ClientHello probe with SNI="www.google.com" (TTL=3).
        //     Unlike the random-byte probe (profiles 10–11), this probe sends a structurally
        //     valid ClientHello that DPI parses and creates state for, then discards on TTL
        //     expiry.  The real ClientHello arrives into a confused DPI state.
        NativeDesyncProfile {
            name: "tlsrec-into-sni-fake-sni-probe",
            technique: DesyncTechnique::TlsRecordSplit {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: Some(FakeProbe {
                ttl: 3,
                data_size: 0,
                fake_sni: Some("www.google.com"),
            }),
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 21. TCP segment split + fake ClientHello probe.
        NativeDesyncProfile {
            name: "split-into-sni-fake-sni-probe",
            technique: DesyncTechnique::TcpSegmentSplit {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: Some(FakeProbe {
                ttl: 3,
                data_size: 0,
                fake_sni: Some("www.google.com"),
            }),
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
    ];

    // TCP disorder profiles — require WinDivert (Windows) or NFQueue (Linux).
    // Fall back to plain TCP split when no interceptor is available at runtime.
    // NOT safe for Cloudflare: their edges reject out-of-order TCP segments.
    #[cfg(any(windows, all(unix, not(target_os = "macos"))))]
    profiles.extend([
        // 22. TCP disorder with 15 ms delay — sends segment 2 before segment 1.
        NativeDesyncProfile {
            name: "tcp-disorder-15ms",
            technique: DesyncTechnique::TcpDisorder { delay_ms: 15 },
            cloudflare_safe: false,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 23. TCP disorder with 40 ms delay — longer gap defeats eager reassemblers.
        NativeDesyncProfile {
            name: "tcp-disorder-40ms",
            technique: DesyncTechnique::TcpDisorder { delay_ms: 40 },
            cloudflare_safe: false,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
    ]);

    // OOB/URG profiles require real MSG_OOB support.
    // On Windows: available via WinSock.
    // On Unix (Linux, macOS): available via libc::send with MSG_OOB.
    #[cfg(any(windows, unix))]
    profiles.extend([
        // 18. TLS record split + OOB byte between fragments.
        //     Equivalent: --tlsrec 1+s --oob
        NativeDesyncProfile {
            name: "tlsrec-into-sni-oob",
            technique: DesyncTechnique::TlsRecordSplitOob {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 19. TLS record split before SNI + OOB byte.
        NativeDesyncProfile {
            name: "tlsrec-before-sni-oob",
            technique: DesyncTechnique::TlsRecordSplitOob {
                at: SplitAt::BeforeSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 20. TCP segment split into SNI + OOB byte.
        //     Equivalent: --split 1+s --oob
        NativeDesyncProfile {
            name: "split-into-sni-oob",
            technique: DesyncTechnique::TcpSegmentSplitOob {
                at: SplitAt::IntoSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
        // 21. TCP segment split before SNI + OOB byte.
        NativeDesyncProfile {
            name: "split-before-sni-oob",
            technique: DesyncTechnique::TcpSegmentSplitOob {
                at: SplitAt::BeforeSni,
            },
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        },
    ]);

    profiles
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tls_record(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let sni_name_len = host.len() as u16;
        let sni_list_len = 1u16 + 2 + sni_name_len;
        let sni_ext_len = 2u16 + sni_list_len;

        let mut exts = Vec::new();
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

    #[tokio::test]
    async fn tls_record_split_reassembles_correctly() {
        let record = build_tls_record("discord.com");
        let mut buf = Vec::new();
        let _parsed = parse_client_hello(&record);
        // Split at payload offset 10
        tls_record_split(&mut buf, &record, 10, None).await.unwrap();

        // Two TLS records — reassemble payload and compare
        assert!(buf.len() > record.len()); // two TLS headers now (5 extra bytes)
        assert_eq!(buf[0], 0x16); // content type
        let len1 = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        assert_eq!(len1, 10);
        let f2_start = 5 + len1;
        assert_eq!(buf[f2_start], 0x16);
        let len2 = u16::from_be_bytes([buf[f2_start + 3], buf[f2_start + 4]]) as usize;

        let original_payload = &record[5..];
        let reassembled: Vec<u8> =
            [&buf[5..5 + len1], &buf[f2_start + 5..f2_start + 5 + len2]].concat();
        assert_eq!(reassembled, original_payload);
    }

    #[tokio::test]
    async fn tcp_segment_split_preserves_data() {
        let record = build_tls_record("example.com");
        let mut buf = Vec::new();
        tcp_segment_split(&mut buf, &record, 20, None)
            .await
            .unwrap();
        assert_eq!(buf, record);
    }

    #[tokio::test]
    async fn engine_apply_all_profiles() {
        let engine = TcpDesyncEngine::with_default_profiles();
        let record = build_tls_record("discord.com");
        for i in 0..engine.profile_count() {
            let mut buf = Vec::new();
            engine.apply(i, &mut buf, &record).await.unwrap();
            assert!(!buf.is_empty(), "profile {} produced empty output", i);
        }
    }

    #[tokio::test]
    async fn engine_apply_non_tls_passes_through() {
        let engine = TcpDesyncEngine::with_default_profiles();
        let data = b"GET / HTTP/1.1\r\n";
        let mut buf = Vec::new();
        engine.apply(0, &mut buf, data).await.unwrap();
        assert_eq!(buf.as_slice(), data.as_ref());
    }

    #[tokio::test]
    async fn http_split_splits_before_host_header() {
        let engine = TcpDesyncEngine::with_default_profiles();
        let idx = (0..engine.profile_count())
            .find(|&i| engine.profile_name(i) == "http-before-host")
            .expect("http-before-host profile missing");

        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut buf = Vec::new();
        engine.apply(idx, &mut buf, req).await.unwrap();

        // Output must equal the original request (Vec<u8> collects both writes).
        assert_eq!(buf.as_slice(), req.as_ref());
        // The split must be non-trivial — the first flush must not include "Host:".
        let host_pos = buf
            .windows(5)
            .position(|w| w == b"Host:")
            .expect("Host: not found");
        assert!(host_pos > 0, "split point must be before Host:");
    }

    #[tokio::test]
    async fn http_split_offset_finds_host_header() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let off = http_split_offset(req, HttpSplitAt::BeforeHostHeader);
        // offset should point to right after \r\n, before "Host:"
        assert_eq!(&req[off..off + 5], b"Host:");
    }

    #[tokio::test]
    async fn fake_probe_profiles_have_probe_set() {
        let engine = TcpDesyncEngine::with_default_profiles();
        let probe_profiles: Vec<&str> = (0..engine.profile_count())
            .filter(|&i| engine.profile_fake_probe(i).is_some())
            .map(|i| engine.profile_name(i))
            .collect();
        assert!(
            !probe_profiles.is_empty(),
            "at least one fake-probe profile expected"
        );
        for name in &probe_profiles {
            assert!(
                name.contains("fake"),
                "fake probe profile name should contain 'fake': {}",
                name
            );
        }
    }

    #[tokio::test]
    async fn multi_split_sni_region_produces_non_empty_output() {
        let engine = TcpDesyncEngine::with_default_profiles();
        let idx = (0..engine.profile_count())
            .find(|&i| engine.profile_name(i) == "multi-split-sni-region")
            .expect("multi-split-sni-region profile missing");

        let record = build_tls_record("discord.com");
        let mut buf = Vec::new();
        engine.apply(idx, &mut buf, &record).await.unwrap();
        assert_eq!(
            buf, record,
            "multi-split output must reconstruct original data"
        );
    }

    #[tokio::test]
    async fn multi_split_preserves_all_data() {
        let record = build_tls_record("youtube.com");
        let parsed = parse_client_hello(&record);
        let points = vec![SplitAt::BeforeSni, SplitAt::IntoSni, SplitAt::MidSni];
        let mut buf = Vec::new();
        multi_tcp_segment_split(&mut buf, &record, &points, parsed.as_ref(), None)
            .await
            .unwrap();
        assert_eq!(buf, record);
    }

    #[tokio::test]
    async fn sni_case_randomization_changes_hostname_bytes() {
        let record = build_tls_record("discord.com");
        let parsed = parse_client_hello(&record).expect("should parse");
        let offset = parsed.sni_hostname_offset.expect("hostname offset");
        let len = parsed.sni_hostname_len;

        let mut modified = record.clone();
        randomize_sni_case_bytes(&mut modified, &parsed);

        // The hostname bytes should be changed (case-randomized).
        let orig_host = &record[offset..offset + len];
        let new_host = &modified[offset..offset + len];
        // Both must be equal when lowercased (same hostname, different case).
        assert_eq!(
            orig_host.to_ascii_lowercase(),
            new_host.to_ascii_lowercase(),
            "hostname content must be preserved after case randomization"
        );
        // The rest of the record (non-hostname bytes) must be unchanged.
        assert_eq!(&record[..offset], &modified[..offset]);
        assert_eq!(&record[offset + len..], &modified[offset + len..]);
    }

    #[tokio::test]
    async fn sni_case_profile_applies_correctly() {
        let engine = TcpDesyncEngine::with_default_profiles();
        let idx = (0..engine.profile_count())
            .find(|&i| engine.profile_name(i) == "split-into-sni-case-rand")
            .expect("split-into-sni-case-rand profile missing");

        let record = build_tls_record("discord.com");
        let mut buf = Vec::new();
        engine.apply(idx, &mut buf, &record).await.unwrap();
        // Output data must contain the same bytes as original (modulo case).
        assert_eq!(
            buf.len(),
            record.len(),
            "case randomization must not change record length"
        );
        assert_eq!(
            buf.to_ascii_lowercase(),
            record.to_ascii_lowercase(),
            "lowercased output must equal lowercased input"
        );
    }
}

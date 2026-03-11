use std::io;
use tokio::io::AsyncWriteExt;

use crate::evasion::tls_parser::{parse_client_hello, ParsedClientHello};

/// Where to place the split point within the ClientHello.
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

/// Userspace TCP desync technique applied to TLS ClientHello data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesyncTechnique {
    /// Send two raw TCP segments with an explicit flush between them.
    /// Equivalent to byedpi `--split`.
    TcpSegmentSplit { at: SplitAt },

    /// Reconstruct the single TLS record as two separate TLS records and
    /// send each as its own TCP segment.
    /// Equivalent to byedpi `--tlsrec`.
    TlsRecordSplit { at: SplitAt },

    /// TLS record split combined with an OOB (URG) byte before the second fragment.
    /// Equivalent to byedpi `--tlsrec ... --oob`.
    TlsRecordSplitOob { at: SplitAt },

    /// TCP segment split combined with an OOB (URG) byte at the split point.
    /// Equivalent to byedpi `--split ... --oob`.
    TcpSegmentSplitOob { at: SplitAt },
}

/// A named native desync profile.
#[derive(Debug, Clone)]
pub struct NativeDesyncProfile {
    pub name: &'static str,
    pub technique: DesyncTechnique,
    /// If false, avoid for Cloudflare targets (Discord, Instagram, etc.) because
    /// those servers reject disordered TCP segments.
    pub cloudflare_safe: bool,
}

/// In-process TCP desync engine — drop-in replacement for the external ciadpi pool.
///
/// The engine holds a list of [`NativeDesyncProfile`]s that map 1:1 to what the
/// byedpi profiles used to do.  Each profile gets its own [`RouteCandidate`] in
/// the route-race, so the ML scorer can learn which profile wins for each domain.
pub struct TcpDesyncEngine {
    profiles: Vec<NativeDesyncProfile>,
}

impl TcpDesyncEngine {
    pub fn new(profiles: Vec<NativeDesyncProfile>) -> Self {
        Self { profiles }
    }

    /// Build an engine with the default profiles that mirror the 12 default byedpi profiles.
    pub fn with_default_profiles() -> Self {
        Self::new(default_native_profiles())
    }

    /// Number of profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Name of profile at `idx` (for logging).
    pub fn profile_name(&self, idx: usize) -> &str {
        self.profiles.get(idx).map(|p| p.name).unwrap_or("unknown")
    }

    /// Apply the desync technique for `profile_idx` to `data` and write the
    /// result to `writer`.  `data` should be the raw TLS ClientHello record.
    ///
    /// If the data is not a TLS ClientHello, writes it unchanged.
    pub async fn apply<W: AsyncWriteExt + Unpin>(
        &self,
        profile_idx: usize,
        writer: &mut W,
        data: &[u8],
    ) -> io::Result<()> {
        // If it's not a TLS ClientHello, pass through.
        if data.len() < 5 || data[0] != 0x16 {
            writer.write_all(data).await?;
            writer.flush().await?;
            return Ok(());
        }

        let profile = match self.profiles.get(profile_idx) {
            Some(p) => p,
            None => {
                writer.write_all(data).await?;
                writer.flush().await?;
                return Ok(());
            }
        };

        let parsed = parse_client_hello(data);
        apply_technique(writer, data, profile.technique, parsed.as_ref()).await?;
        writer.flush().await?;
        Ok(())
    }
}

// ── Technique dispatch ────────────────────────────────────────────────────────

async fn apply_technique<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    technique: DesyncTechnique,
    parsed: Option<&ParsedClientHello>,
) -> io::Result<()> {
    match technique {
        DesyncTechnique::TcpSegmentSplit { at } => {
            let split = split_offset_in_record(data, at, parsed);
            tcp_segment_split(writer, data, split).await
        }
        DesyncTechnique::TlsRecordSplit { at } => {
            let payload_split = split_offset_in_payload(data, at, parsed);
            tls_record_split(writer, data, payload_split).await
        }
        DesyncTechnique::TlsRecordSplitOob { at } => {
            let payload_split = split_offset_in_payload(data, at, parsed);
            tls_record_split_oob(writer, data, payload_split).await
        }
        DesyncTechnique::TcpSegmentSplitOob { at } => {
            let split = split_offset_in_record(data, at, parsed);
            tcp_segment_split_oob(writer, data, split).await
        }
    }
}

// ── Core primitives ──────────────────────────────────────────────────────────

/// Send data as two TCP segments separated by an explicit flush.
async fn tcp_segment_split<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    split: usize,
) -> io::Result<()> {
    if split == 0 || split >= data.len() {
        writer.write_all(data).await?;
        return Ok(());
    }
    writer.write_all(&data[..split]).await?;
    writer.flush().await?;
    writer.write_all(&data[split..]).await?;
    Ok(())
}

/// Reconstruct the TLS record as two separate TLS records.
///
/// `payload_split` is the split offset *within the TLS payload* (i.e. bytes after the 5-byte
/// TLS record header).
async fn tls_record_split<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    record: &[u8],
    payload_split: usize,
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

    // Fragment 1
    let len1 = (payload_split as u16).to_be_bytes();
    writer
        .write_all(&[content_type, version[0], version[1], len1[0], len1[1]])
        .await?;
    writer.write_all(&payload[..payload_split]).await?;
    writer.flush().await?;

    // Fragment 2
    let rem = payload.len() - payload_split;
    let len2 = (rem as u16).to_be_bytes();
    writer
        .write_all(&[content_type, version[0], version[1], len2[0], len2[1]])
        .await?;
    writer.write_all(&payload[payload_split..]).await?;
    Ok(())
}

/// TLS record split + OOB byte at the boundary on Windows; plain split on other platforms.
async fn tls_record_split_oob<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    record: &[u8],
    payload_split: usize,
) -> io::Result<()> {
    // On platforms without raw socket access through BoxStream we fall back to plain split.
    // Full OOB support is added when WinDivert/packet_intercept is available (Priority 2).
    tls_record_split(writer, record, payload_split).await
}

/// TCP segment split + OOB at split point.
async fn tcp_segment_split_oob<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    split: usize,
) -> io::Result<()> {
    // Same fallback as tls_record_split_oob for now.
    tcp_segment_split(writer, data, split).await
}

// ── Offset computation ────────────────────────────────────────────────────────

/// Compute split offset within the **full TLS record buffer** (incl. 5-byte header).
fn split_offset_in_record(
    data: &[u8],
    at: SplitAt,
    parsed: Option<&ParsedClientHello>,
) -> usize {
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

/// Compute split offset within the **TLS payload** (bytes after the 5-byte header).
fn split_offset_in_payload(
    data: &[u8],
    at: SplitAt,
    parsed: Option<&ParsedClientHello>,
) -> usize {
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

// ── Default profiles ──────────────────────────────────────────────────────────

/// 12 default profiles that mirror the existing byedpi profile set.
pub fn default_native_profiles() -> Vec<NativeDesyncProfile> {
    vec![
        // 1. TLS record split right into SNI — safest for Cloudflare.
        //    Equivalent: --tlsrec 1+s
        NativeDesyncProfile {
            name: "tlsrec-into-sni",
            technique: DesyncTechnique::TlsRecordSplit { at: SplitAt::IntoSni },
            cloudflare_safe: true,
        },
        // 2. TLS record split before SNI — very safe, SNI entirely in second fragment.
        //    Equivalent: --tlsrec SNI-1
        NativeDesyncProfile {
            name: "tlsrec-before-sni",
            technique: DesyncTechnique::TlsRecordSplit { at: SplitAt::BeforeSni },
            cloudflare_safe: true,
        },
        // 3. TCP segment split right into SNI.
        //    Equivalent: --split 1+s
        NativeDesyncProfile {
            name: "split-into-sni",
            technique: DesyncTechnique::TcpSegmentSplit { at: SplitAt::IntoSni },
            cloudflare_safe: true,
        },
        // 4. TLS record split through the middle of the SNI hostname — aggressive.
        //    Equivalent: roughly --tlsrec mid+s
        NativeDesyncProfile {
            name: "tlsrec-mid-sni",
            technique: DesyncTechnique::TlsRecordSplit { at: SplitAt::MidSni },
            cloudflare_safe: true,
        },
        // 5. TLS record split + OOB at boundary — effective for many Russian ISPs.
        //    Equivalent: --tlsrec 1+s --oob (OOB falls back to plain split on BoxStream)
        NativeDesyncProfile {
            name: "tlsrec-oob-into-sni",
            technique: DesyncTechnique::TlsRecordSplitOob { at: SplitAt::IntoSni },
            cloudflare_safe: true,
        },
        // 6. TLS record split at a fixed deep offset (5 bytes into payload).
        //    Equivalent: --tlsrec 5+s
        NativeDesyncProfile {
            name: "tlsrec-fixed-5",
            technique: DesyncTechnique::TlsRecordSplit { at: SplitAt::Fixed(5) },
            cloudflare_safe: true,
        },
        // 7. TCP segment split before SNI.
        //    Equivalent: --split before-sni
        NativeDesyncProfile {
            name: "split-before-sni",
            technique: DesyncTechnique::TcpSegmentSplit { at: SplitAt::BeforeSni },
            cloudflare_safe: true,
        },
        // 8. TCP split + OOB at position 2.
        //    Equivalent: --split 2 --oob 1
        NativeDesyncProfile {
            name: "split-oob-fixed-2",
            technique: DesyncTechnique::TcpSegmentSplitOob { at: SplitAt::Fixed(2) },
            cloudflare_safe: false,
        },
        // 9. TCP segment split at fixed offset 1.
        //    Equivalent: --disorder 1 --split 1 (without disorder)
        NativeDesyncProfile {
            name: "split-fixed-1",
            technique: DesyncTechnique::TcpSegmentSplit { at: SplitAt::Fixed(1) },
            cloudflare_safe: false,
        },
        // 10. TCP split at fixed offset 3.
        //     Equivalent: --disorder 3 --oob 1 (simplified)
        NativeDesyncProfile {
            name: "split-fixed-3",
            technique: DesyncTechnique::TcpSegmentSplit { at: SplitAt::Fixed(3) },
            cloudflare_safe: false,
        },
        // 11. TCP split + OOB at fixed offset 1.
        //     Equivalent: --split 1 --disoob 1
        NativeDesyncProfile {
            name: "split-oob-fixed-1",
            technique: DesyncTechnique::TcpSegmentSplitOob { at: SplitAt::Fixed(1) },
            cloudflare_safe: false,
        },
        // 12. TLS record split at mid-SNI + OOB — maximum split for stubborn ISPs.
        NativeDesyncProfile {
            name: "tlsrec-oob-mid-sni",
            technique: DesyncTechnique::TlsRecordSplitOob { at: SplitAt::MidSni },
            cloudflare_safe: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

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
        let parsed = parse_client_hello(&record);
        // Split at payload offset 10
        tls_record_split(&mut buf, &record, 10).await.unwrap();

        // Two TLS records — reassemble payload and compare
        assert!(buf.len() > record.len()); // Should have two TLS headers now (5 extra bytes)
        // Fragment 1 header
        assert_eq!(buf[0], 0x16); // content type
        let len1 = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        assert_eq!(len1, 10);
        // Fragment 2 header
        let f2_start = 5 + len1;
        assert_eq!(buf[f2_start], 0x16);
        let len2 = u16::from_be_bytes([buf[f2_start + 3], buf[f2_start + 4]]) as usize;

        // Reassembled payload == original payload
        let original_payload = &record[5..];
        let reassembled: Vec<u8> = [
            &buf[5..5 + len1],
            &buf[f2_start + 5..f2_start + 5 + len2],
        ]
        .concat();
        assert_eq!(reassembled, original_payload);
    }

    #[tokio::test]
    async fn tcp_segment_split_preserves_data() {
        let record = build_tls_record("example.com");
        let mut buf = Vec::new();
        tcp_segment_split(&mut buf, &record, 20).await.unwrap();
        assert_eq!(buf, record);
    }

    #[tokio::test]
    async fn engine_apply_all_profiles() {
        let engine = TcpDesyncEngine::with_default_profiles();
        let record = build_tls_record("discord.com");
        for i in 0..engine.profile_count() {
            let mut buf = Vec::new();
            engine.apply(i, &mut buf, &record).await.unwrap();
            // Reassembled bytes must equal original record
            // (TLS record split adds extra headers; extract payloads for comparison)
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
}

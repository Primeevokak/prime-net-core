//! QUIC Initial packet desync for DPI evasion.
//!
//! Builds and sends a fake QUIC Initial packet with an alternative SNI
//! (e.g. `"www.google.com"`) at a low IP TTL before the real packet is forwarded.
//! DPI that extracts the SNI from QUIC Initial packets will record the fake SNI and
//! either pass the real packet through or lose tracking state when the fake's TTL
//! expires before reaching the server.
//!
//! # Protocol background
//!
//! QUIC Initial packets (RFC 9000 §17.2.2) carry a TLS ClientHello inside a
//! CRYPTO frame.  The packet is encrypted with keys derived from the Destination
//! Connection ID (DCID) using a well-known algorithm (RFC 9001 §5.2).  Because the
//! derivation uses a public salt and the plaintext DCID, any observer (including DPI)
//! can derive the same keys and decrypt the packet — which is how DPI reads the SNI.
//!
//! We exploit this by constructing a valid fake Initial with the same DCID
//! (so the derived keys match), but with a different SNI in the CRYPTO frame.
//!
//! # Key derivation (RFC 9001 §5.2)
//!
//! ```text
//! initial_secret       = HKDF-Extract(initial_salt, dcid)
//! client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
//! key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
//! iv  = HKDF-Expand-Label(client_initial_secret, "quic iv",  "", 12)
//! hp  = HKDF-Expand-Label(client_initial_secret, "quic hp",  "", 16)
//! ```

use std::net::SocketAddr;

use aes::Aes128;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use cipher::{generic_array::GenericArray, BlockEncrypt};
use hkdf::Hkdf;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use sha2::Sha256;
use tokio::net::UdpSocket;
use tracing::debug;

/// Whitelisted SNIs used in fake QUIC Initials.
///
/// DPI sees one of these popular domains and passes the connection through.
const WHITELISTED_SNIS: &[&str] = &[
    "www.google.com",
    "cloudflare.com",
    "facebook.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
];

/// Pick a random whitelisted SNI for fake QUIC Initial packets.
pub fn random_whitelisted_sni() -> &'static str {
    WHITELISTED_SNIS
        .choose(&mut thread_rng())
        .copied()
        .unwrap_or("www.google.com")
}

// ── QUIC v1 constants ─────────────────────────────────────────────────────────

/// QUIC v1 Initial salt (RFC 9001 §5.2).
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC v1 wire version number.
const QUIC_VERSION_1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// Long header flag byte for a QUIC v1 Initial packet with 1-byte packet number.
/// Bits: 1 (long) 1 (fixed) 00 (Initial) 00 (reserved) 00 (pn_len - 1 = 0).
const INITIAL_FIRST_BYTE: u8 = 0xC0;

// ── Public API ────────────────────────────────────────────────────────────────

/// Parsed fields from a QUIC Initial long header (unencrypted parts only).
#[derive(Debug)]
pub struct QuicInitialHeader {
    /// Destination Connection ID from the client's Initial packet.
    pub dcid: Vec<u8>,
    /// QUIC version (4 bytes).
    pub version: [u8; 4],
    /// Byte offset into the UDP payload where the encrypted packet payload starts.
    pub payload_start: usize,
}

/// Try to parse the DCID and version from a QUIC Initial long-header packet.
///
/// Returns `None` if the packet is not a QUIC v1 Initial or is truncated.
/// Does not decrypt or validate the payload.
pub fn parse_quic_initial_header(buf: &[u8]) -> Option<QuicInitialHeader> {
    if buf.len() < 7 {
        return None;
    }
    // First byte: must be a long header Initial (top two bits = 11, next two = 00).
    // We accept any packet-number-length encoding in the low 2 bits.
    if buf[0] & 0xF0 != 0xC0 {
        return None;
    }
    // Version field.
    let version = [buf[1], buf[2], buf[3], buf[4]];
    if version != QUIC_VERSION_1 {
        return None;
    }

    // DCID length + DCID.
    let dcid_len = buf[5] as usize;
    let mut pos = 6;
    if buf.len() < pos + dcid_len {
        return None;
    }
    let dcid = buf[pos..pos + dcid_len].to_vec();
    pos += dcid_len;

    // SCID.
    if buf.len() < pos + 1 {
        return None;
    }
    let scid_len = buf[pos] as usize;
    pos += 1 + scid_len;

    // Token (variable-length integer length + token bytes).
    if buf.len() < pos + 1 {
        return None;
    }
    let token_len = read_varint(buf, &mut pos)?;
    pos += token_len as usize;

    // Length field (variable-length integer) — skip it.
    if buf.len() < pos + 1 {
        return None;
    }
    let _ = read_varint(buf, &mut pos)?;

    // Payload starts at current pos (packet number + encrypted payload).
    Some(QuicInitialHeader {
        dcid,
        version,
        payload_start: pos,
    })
}

/// Send a fake QUIC Initial packet to `target` with TTL `ttl`.
///
/// The fake packet uses the same DCID as the real packet (so the derived
/// keys match what DPI expects) but carries a TLS ClientHello with `fake_sni`
/// in the CRYPTO frame.
///
/// Best-effort: errors are silently ignored so the real packet is unaffected.
pub async fn send_fake_quic_initial(target: SocketAddr, dcid: &[u8], fake_sni: &str, ttl: u8) {
    match build_fake_quic_initial(dcid, fake_sni) {
        Ok(pkt) => {
            if let Ok(sock) = bind_udp_for_target(target).await {
                let _ = sock.set_ttl(u32::from(ttl.max(1)));
                let _ = sock.send_to(&pkt, target).await;
                debug!(
                    target = %target,
                    fake_sni,
                    ttl,
                    len = pkt.len(),
                    "sent fake QUIC Initial"
                );
            }
        }
        Err(e) => {
            debug!("build_fake_quic_initial: {e}");
        }
    }
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Derived QUIC Initial secrets for the client direction.
struct QuicInitialKeys {
    /// AES-128-GCM key (16 bytes).
    key: [u8; 16],
    /// AES-128-GCM IV / nonce base (12 bytes).
    iv: [u8; 12],
    /// Header-protection key (16 bytes, AES-128-ECB).
    hp: [u8; 16],
}

fn derive_initial_keys(dcid: &[u8]) -> QuicInitialKeys {
    // HKDF-Extract(salt=initial_salt_v1, ikm=dcid) → initial_secret PRK.
    let (_, initial_hkdf) = Hkdf::<Sha256>::extract(Some(&INITIAL_SALT_V1), dcid);

    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    let mut client_secret = [0u8; 32];
    hkdf_expand_label(&initial_hkdf, b"client in", &[], &mut client_secret);

    // Rebuild HKDF from client_initial_secret as a new PRK.
    let client_hkdf = Hkdf::<Sha256>::from_prk(&client_secret)
        .unwrap_or_else(|_| unreachable!("client_initial_secret is always 32 bytes = HashLen"));

    // key, iv, hp derived from client_initial_secret.
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    hkdf_expand_label(&client_hkdf, b"quic key", &[], &mut key);
    hkdf_expand_label(&client_hkdf, b"quic iv", &[], &mut iv);
    hkdf_expand_label(&client_hkdf, b"quic hp", &[], &mut hp);

    QuicInitialKeys { key, iv, hp }
}

/// HKDF-Expand-Label as defined in TLS 1.3 / RFC 8446 §7.1.
///
/// `HkdfLabel = { uint16 length, "tls13 " + label, context }`.
/// Delegates to `hkdf::Hkdf::expand` for correct multi-block support.
fn hkdf_expand_label(hkdf: &Hkdf<Sha256>, label: &[u8], context: &[u8], out: &mut [u8]) {
    let full_label: Vec<u8> = [b"tls13 " as &[u8], label].concat();
    // HkdfLabel encoding: uint16(length) || uint8(label_len) || label_bytes
    //                     || uint8(context_len) || context_bytes
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf.expand(&info, out)
        .unwrap_or_else(|_| unreachable!("HKDF output length is always valid here"));
}

// ── Fake packet construction ──────────────────────────────────────────────────

/// Build a fully encrypted QUIC v1 Initial packet with `fake_sni` in the CRYPTO frame.
/// Build a fully encrypted QUIC v1 Initial packet with a fake SNI.
pub(crate) fn build_fake_quic_initial(dcid: &[u8], fake_sni: &str) -> Result<Vec<u8>, String> {
    let keys = derive_initial_keys(dcid);

    // Build the plaintext CRYPTO frame payload (TLS ClientHello).
    let tls_hello = build_fake_client_hello(fake_sni);
    let crypto_frame = build_crypto_frame(&tls_hello);

    // Pad so the total packet is >= 1200 bytes (QUIC anti-amplification minimum).
    // Header layout: 1(first) + 4(ver) + 1(dcid_len) + dcid.len() + 1(scid_len=0)
    //              + 1(token_len=0) + 2(length varint) + 1(pn) = 11 + dcid.len()
    // Total = header_len + plaintext_len + 16(tag) → plaintext >= 1200 - header - 16
    let header_len = 11 + dcid.len();
    let target_payload_plaintext_len = 1200usize.saturating_sub(header_len + 16);
    let padding_needed = target_payload_plaintext_len.saturating_sub(crypto_frame.len());
    let mut plaintext_payload = crypto_frame;
    if padding_needed > 0 {
        // QUIC PADDING frame is just 0x00 bytes.
        plaintext_payload.extend(std::iter::repeat_n(0x00, padding_needed));
    }

    // Packet number: 0, encoded as 1 byte (pn_len bits in first byte = 00).
    let packet_number: u32 = 0;
    let pn_bytes = [0x00u8]; // 1-byte packet number = 0

    // Compute encrypted payload length = pn_len(1) + plaintext(n) + AEAD_tag(16)
    let encrypted_payload_len = pn_bytes.len() + plaintext_payload.len() + 16;

    // Build the unprotected long header.
    let mut header = Vec::with_capacity(64);
    header.push(INITIAL_FIRST_BYTE); // first byte (will be HP-protected)
    header.extend_from_slice(&QUIC_VERSION_1);
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(0x00); // SCID length = 0
    header.push(0x00); // Token length = 0 (1-byte varint)
                       // Length field: varint encoding of encrypted_payload_len.
                       // Use 2-byte form (0x4000 | len) which covers up to 16383 bytes.
    let len_varint = 0x4000u16 | encrypted_payload_len as u16;
    header.extend_from_slice(&len_varint.to_be_bytes());
    // Packet number (1 byte, unprotected at this stage).
    header.extend_from_slice(&pn_bytes);

    // AEAD nonce = iv XOR left-padded packet_number.
    let mut nonce_bytes = keys.iv;
    let pn_u64 = u64::from(packet_number);
    for (i, b) in pn_u64.to_be_bytes().iter().enumerate() {
        nonce_bytes[4 + i] ^= b; // nonce is 12 bytes; pn occupies the last 8
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AAD = the unprotected header bytes (everything before the packet number
    // is part of AAD; the pn itself is not part of AAD per RFC 9001 §5.3).
    // AAD = all header bytes up to but not including the packet number field.
    let aad = &header[..header.len() - pn_bytes.len()];

    // Encrypt: AES-128-GCM(key, nonce, plaintext, aad) → ciphertext || tag.
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
    let mut ciphertext = plaintext_payload;
    cipher
        .encrypt_in_place(nonce, aad, &mut ciphertext)
        .map_err(|e| format!("AEAD encrypt failed: {e}"))?;

    // Assemble pre-HP packet: header (incl. pn) || ciphertext.
    let mut packet = header;
    packet.extend_from_slice(&ciphertext);

    // Apply header protection (RFC 9001 §5.4.1).
    // HP sample = first 16 bytes of ciphertext (after the packet number).
    let pn_offset = packet.len() - ciphertext.len() - pn_bytes.len();
    let sample_start = pn_offset + 4; // sample starts 4 bytes after pn_offset
    if packet.len() < sample_start + 16 {
        return Err(format!(
            "packet too short for HP sample: {} bytes",
            packet.len()
        ));
    }
    // SAFETY: we checked `packet.len() >= sample_start + 16` above.
    let sample: [u8; 16] = packet[sample_start..sample_start + 16]
        .try_into()
        .unwrap_or_else(|_| unreachable!("slice is exactly 16 bytes"));

    // HP mask = AES-128-ECB(hp_key, sample).
    let hp_cipher = Aes128::new(GenericArray::from_slice(&keys.hp));
    let mut mask_block = GenericArray::from(sample);
    hp_cipher.encrypt_block(&mut mask_block);
    let mask = mask_block.as_slice();

    // Protect first byte: XOR with mask[0] & 0x0F (low 4 bits only for long header).
    packet[0] ^= mask[0] & 0x0F;
    // Protect packet number bytes: XOR each with mask[1..].
    for (i, pn_byte) in pn_bytes.iter().enumerate() {
        let _ = pn_byte; // pn_bytes value already embedded; we XOR in-place
        packet[pn_offset + i] ^= mask[1 + i];
    }

    Ok(packet)
}

/// Build a QUIC CRYPTO frame wrapping `tls_data`.
///
/// Frame type: 0x06 (CRYPTO), offset: 0 (varint), length: len(tls_data) (varint),
/// data: tls_data.
fn build_crypto_frame(tls_data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + 1 + 2 + tls_data.len());
    frame.push(0x06); // CRYPTO frame type
    frame.push(0x00); // offset = 0 (1-byte varint)
                      // length as 2-byte varint (0x4000 | len) for values up to 16383.
    let len = tls_data.len() as u16;
    frame.extend_from_slice(&(0x4000u16 | len).to_be_bytes());
    frame.extend_from_slice(tls_data);
    frame
}

/// Build a minimal but structurally valid TLS 1.3 ClientHello for `sni`.
fn build_fake_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len();

    // SNI extension data: list_len(2) + type(1) + name_len(2) + name
    let sni_list_len = 3 + sni_len;
    let sni_ext_data_len = 2 + sni_list_len;
    let sni_ext_wire = 4 + sni_ext_data_len;

    // Supported versions extension for TLS 1.3.
    let sv_ext_wire: usize = 4 + 3; // type(2)+len(2)+list_len(1)+version(2)

    let ext_total = sni_ext_wire + sv_ext_wire;

    // ClientHello body.
    let ch_body_len = 2 + 32 + 1 + 2 + 4 + 1 + 1 + 2 + ext_total;
    let hs_msg_len = 4 + ch_body_len;

    let mut buf = Vec::with_capacity(5 + hs_msg_len);

    // TLS record header.
    buf.extend_from_slice(&[0x16, 0x03, 0x01]);
    buf.extend_from_slice(&(hs_msg_len as u16).to_be_bytes());

    // Handshake header.
    buf.push(0x01); // ClientHello
    buf.extend_from_slice(&[
        (ch_body_len >> 16) as u8,
        (ch_body_len >> 8) as u8,
        ch_body_len as u8,
    ]);

    buf.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    let mut random = [0u8; 32];
    thread_rng().fill(&mut random);
    buf.extend_from_slice(&random); // random (randomized per fake)
    buf.push(0x00); // session_id_len
    buf.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // cipher_suites
    buf.extend_from_slice(&[0x01, 0x00]); // compression_methods
    buf.extend_from_slice(&(ext_total as u16).to_be_bytes()); // extensions_len

    // SNI extension.
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    buf.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&(sni_len as u16).to_be_bytes());
    buf.extend_from_slice(sni_bytes);

    // Supported versions extension (TLS 1.3).
    buf.extend_from_slice(&[0x00, 0x2b]); // supported_versions
    buf.extend_from_slice(&[0x00, 0x03]); // ext data len
    buf.push(0x02); // list len
    buf.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

    buf
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read a QUIC variable-length integer at `buf[*pos]`, advance `*pos`, return value.
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos >= buf.len() {
        return None;
    }
    let first = buf[*pos];
    let prefix = first >> 6;
    let byte_count = 1usize << prefix;
    if *pos + byte_count > buf.len() {
        return None;
    }
    let mut value = u64::from(first & 0x3F);
    for i in 1..byte_count {
        value = (value << 8) | u64::from(buf[*pos + i]);
    }
    *pos += byte_count;
    Some(value)
}

/// Bind a UDP socket appropriate for sending to `target` (IPv4 or IPv6).
/// Bind a UDP socket suitable for sending to `target` (IPv4 or IPv6).
pub(crate) async fn bind_udp_for_target(target: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind_addr = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    UdpSocket::bind(bind_addr).await
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod quic_initial_tests {
    use super::*;

    /// The well-known DCID used in RFC 9001 Appendix A (test vector).
    const RFC_TEST_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    #[test]
    fn key_derivation_matches_rfc9001_appendix_a() {
        // RFC 9001 Appendix A.1 — client Initial keys for DCID 0x8394c8f03e515708.
        let keys = derive_initial_keys(&RFC_TEST_DCID);

        // Expected values from RFC 9001 Appendix A.1.
        let expected_key: [u8; 16] = [
            0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1,
            0xa2, 0x2d,
        ];
        let expected_iv: [u8; 12] = [
            0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
        ];
        // hp = 9f50449e04a0e810283a1e9933adedd2 (RFC 9001 Appendix A.1, verified)
        let expected_hp: [u8; 16] = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
            0xed, 0xd2,
        ];

        assert_eq!(keys.key, expected_key, "key mismatch");
        assert_eq!(keys.iv, expected_iv, "iv mismatch");
        assert_eq!(keys.hp, expected_hp, "hp mismatch");
    }

    #[test]
    fn parse_quic_initial_header_detects_v1() {
        // Minimal long-header Initial: first_byte=0xC0, ver=0x00000001,
        // dcid_len=8, dcid=RFC_TEST_DCID, scid_len=0, token_len=0,
        // payload_len=0, pn=0.
        let mut pkt = vec![
            0xC0, 0x00, 0x00, 0x00, 0x01, // first byte + version
            0x08, // dcid_len
        ];
        pkt.extend_from_slice(&RFC_TEST_DCID);
        pkt.extend_from_slice(&[
            0x00, // scid_len
            0x00, // token_len (varint 0)
            0x40, 0x01, // payload_len varint (1)
            0x00, // pn
        ]);

        let hdr = parse_quic_initial_header(&pkt).expect("should parse");
        assert_eq!(hdr.dcid, RFC_TEST_DCID);
        assert_eq!(hdr.version, QUIC_VERSION_1);
    }

    #[test]
    fn parse_quic_initial_header_rejects_non_quic() {
        // TLS record is not a QUIC Initial.
        let tls_record = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02, 0x03];
        assert!(parse_quic_initial_header(&tls_record).is_none());
    }

    #[test]
    fn build_fake_quic_initial_produces_correct_structure() {
        let pkt = build_fake_quic_initial(&RFC_TEST_DCID, "www.google.com")
            .expect("build should succeed");

        // Packet must be at least 1200 bytes (QUIC minimum Initial size for anti-amplification).
        assert!(
            pkt.len() >= 1200,
            "fake Initial should be >= 1200 bytes, got {}",
            pkt.len()
        );
        // First byte must have the long-header bit set (bit 7) after HP.
        // (The fixed bit (bit 6) is also set; only bits 0-3 change due to HP.)
        assert_eq!(pkt[0] & 0xC0, 0xC0, "long header bits must survive HP");
        // Version field is unprotected and should be QUIC v1.
        assert_eq!(&pkt[1..5], &QUIC_VERSION_1);
    }

    #[test]
    fn fake_client_hello_contains_sni() {
        let sni = "fake.example.com";
        let hello = build_fake_client_hello(sni);
        // SNI bytes must appear somewhere in the record.
        assert!(
            hello.windows(sni.len()).any(|w| w == sni.as_bytes()),
            "SNI not found in fake ClientHello"
        );
        // Must start with TLS record type 0x16.
        assert_eq!(hello[0], 0x16);
    }
}

/// Full parsed TLS 1.3/1.2 ClientHello.
/// All byte offsets are relative to the start of the TLS record buffer (index 0 = 0x16 content-type byte).
#[derive(Debug, Clone)]
pub struct ParsedClientHello {
    /// Offset of the SNI extension entry (type + len + data) within the TLS record buffer.
    pub sni_ext_offset: Option<usize>,
    /// Total byte length of the SNI extension entry (4-byte header + data).
    pub sni_ext_len: usize,
    /// Offset of the SNI hostname bytes within the TLS record buffer.
    pub sni_hostname_offset: Option<usize>,
    /// Length of the hostname string.
    pub sni_hostname_len: usize,
    /// Parsed SNI hostname (owned, for convenience).
    pub sni_hostname: Option<String>,
    /// Whether any ALPN extension is present.
    pub has_alpn: bool,
    /// Whether an ECH (Encrypted Client Hello) extension is present.
    pub has_ech: bool,
}

const EXT_SNI: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_ECH: u16 = 0xfe0d; // 65037

/// Parse a TLS ClientHello from a raw TLS record buffer.
/// Returns `None` if the buffer does not look like a valid TLS ClientHello.
pub fn parse_client_hello(record: &[u8]) -> Option<ParsedClientHello> {
    let b = record;

    // Minimum viable ClientHello size
    if b.len() < 42 {
        return None;
    }

    // TLS Record header: ContentType(1) + Version(2) + Length(2)
    if b[0] != 0x16 {
        return None;
    }
    let record_payload_len = read_u16(b, 3)? as usize;
    if record_payload_len + 5 > b.len() {
        return None;
    }

    // Handshake header: HandshakeType(1) + Length(3)
    let mut pos = 5usize;
    if *b.get(pos)? != 0x01 {
        // Not a ClientHello
        return None;
    }
    let hs_len = read_u24(b, pos + 1)? as usize;
    pos += 4; // Skip HandshakeType + 3-byte length
    if pos + hs_len > b.len() {
        return None;
    }

    // ClientHello body: Version(2) + Random(32) = 34 bytes
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

    let mut sni_ext_offset: Option<usize> = None;
    let mut sni_ext_len = 0usize;
    let mut sni_hostname_offset: Option<usize> = None;
    let mut sni_hostname_len = 0usize;
    let mut sni_hostname: Option<String> = None;
    let mut has_alpn = false;
    let mut has_ech = false;

    while pos + 4 <= ext_end {
        let ext_type = read_u16(b, pos)?;
        let ext_data_len = read_u16(b, pos + 2)? as usize;
        let ext_start = pos;
        pos += 4; // Skip ext_type(2) + ext_len(2)

        if pos + ext_data_len > ext_end {
            break;
        }

        match ext_type {
            EXT_SNI => {
                // SNI extension data:
                // ServerNameList length (2) | NameType (1) | NameLength (2) | Name (N)
                sni_ext_offset = Some(ext_start);
                sni_ext_len = 4 + ext_data_len;

                let sni_data = &b[pos..pos + ext_data_len];
                if sni_data.len() >= 5 && sni_data[2] == 0x00 {
                    let name_len = read_u16(sni_data, 3)? as usize;
                    if 5 + name_len <= sni_data.len() {
                        let hostname_start_in_record = pos + 5;
                        sni_hostname_offset = Some(hostname_start_in_record);
                        sni_hostname_len = name_len;
                        sni_hostname = std::str::from_utf8(&sni_data[5..5 + name_len])
                            .ok()
                            .map(|s| s.to_owned());
                    }
                }
            }
            EXT_ALPN => {
                has_alpn = true;
            }
            EXT_ECH => {
                has_ech = true;
            }
            _ => {}
        }

        pos += ext_data_len;
    }

    Some(ParsedClientHello {
        sni_ext_offset,
        sni_ext_len,
        sni_hostname_offset,
        sni_hostname_len,
        sni_hostname,
        has_alpn,
        has_ech,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello_with_sni(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let sni_name_len = host.len() as u16;
        let sni_list_len = 1u16 + 2 + sni_name_len;
        let sni_ext_len = 2u16 + sni_list_len;

        let mut exts = Vec::new();
        exts.extend_from_slice(&EXT_SNI.to_be_bytes());
        exts.extend_from_slice(&sni_ext_len.to_be_bytes());
        exts.extend_from_slice(&sni_list_len.to_be_bytes());
        exts.push(0x00); // NameType = host_name
        exts.extend_from_slice(&sni_name_len.to_be_bytes());
        exts.extend_from_slice(host);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // Version
        body.extend_from_slice(&[0u8; 32]); // Random
        body.push(0x00); // Session ID len
        body.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites len
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x01); // Compression methods len
        body.push(0x00); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01); // HandshakeType = ClientHello
        let hs_len = body.len() as u32;
        hs.extend_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // ContentType = Handshake
        record.extend_from_slice(&[0x03, 0x01]); // Legacy version TLS 1.0
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn parse_basic_client_hello() {
        let ch = build_client_hello_with_sni("example.com");
        let parsed = parse_client_hello(&ch).expect("should parse");
        assert!(parsed.sni_ext_offset.is_some());
        assert_eq!(parsed.sni_hostname.as_deref(), Some("example.com"));
        assert_eq!(parsed.sni_hostname_len, "example.com".len());
        assert!(!parsed.has_alpn);
        assert!(!parsed.has_ech);
    }

    #[test]
    fn sni_hostname_offset_points_to_correct_bytes() {
        let host = "discord.com";
        let ch = build_client_hello_with_sni(host);
        let parsed = parse_client_hello(&ch).expect("should parse");
        let offset = parsed.sni_hostname_offset.expect("hostname offset");
        assert_eq!(&ch[offset..offset + host.len()], host.as_bytes());
    }

    #[test]
    fn parse_non_tls_returns_none() {
        let data = b"GET / HTTP/1.1\r\n";
        assert!(parse_client_hello(data).is_none());
    }

    #[test]
    fn parse_too_short_returns_none() {
        assert!(parse_client_hello(&[0x16, 0x03, 0x01]).is_none());
    }
}

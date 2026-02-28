pub use super::user_agent::{BrowserType, TlsFingerprintRandomizer};

use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

/// Generates a fake TLS ClientHello record with a randomized SNI from a curated list.
///
/// This is used as a probe to confuse DPI or to verify route health.
pub fn generate_fake_client_hello() -> Vec<u8> {
    let domains = [
        "www.google.com",
        "www.microsoft.com",
        "en.wikipedia.org",
        "www.apple.com",
        "www.amazon.com",
        "www.bing.com",
        "www.cloudflare.com",
        "www.reddit.com",
        "www.github.com",
    ];
    let domain = domains
        .choose(&mut thread_rng())
        .unwrap_or(&"www.google.com");
    build_client_hello_for_domain(domain)
}

/// Constructs a minimal TLS 1.2+ ClientHello record with the specified SNI.
pub fn build_client_hello_for_domain(domain: &str) -> Vec<u8> {
    const SUPPORTED_VERSIONS_EXT: [u8; 9] = [0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03];
    const ALPN_EXT: [u8; 16] = [
        0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f,
        0x31,
    ];
    const ALPN_EXT_TAIL: [u8; 2] = [0x2e, 0x31];

    let host = domain.as_bytes();
    let sni_name_len = host.len() as u16;
    let sni_list_len = 1 + 2 + sni_name_len;
    let sni_ext_len = 2 + sni_list_len;

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // Legacy Version (TLS 1.2)

    // Random (32 bytes)
    let mut random = [0u8; 32];
    rand::thread_rng().fill(&mut random);
    body.extend_from_slice(&random);

    // Cipher Suites: Add more common ones to look like a real browser
    let cipher_suites = [
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ];
    body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_suites);

    body.push(0x01); // Compression Methods Length
    body.push(0x00); // null compression

    // Extensions
    let mut exts_data = Vec::new();

    // SNI Extension
    exts_data.extend_from_slice(&0x0000u16.to_be_bytes());
    exts_data.extend_from_slice(&sni_ext_len.to_be_bytes());
    exts_data.extend_from_slice(&sni_list_len.to_be_bytes());
    exts_data.push(0x00);
    exts_data.extend_from_slice(&sni_name_len.to_be_bytes());
    exts_data.extend_from_slice(host);

    // Supported Versions
    exts_data.extend_from_slice(&SUPPORTED_VERSIONS_EXT);

    // ALPN (h2, http/1.1)
    exts_data.extend_from_slice(&ALPN_EXT);
    exts_data.extend_from_slice(&ALPN_EXT_TAIL);

    // GREASE Extensions (random types, empty body)
    // Chrome usually adds two GREASE extensions.
    let grease_type1 = 0x0a0au16 + (rand::thread_rng().gen_range(0..10) * 0x1010);
    let mut grease_type2 = 0x0a0au16 + (rand::thread_rng().gen_range(0..10) * 0x1010);
    while grease_type2 == grease_type1 {
        grease_type2 = 0x0a0au16 + (rand::thread_rng().gen_range(0..10) * 0x1010);
    }

    exts_data.extend_from_slice(&grease_type1.to_be_bytes());
    exts_data.extend_from_slice(&0u16.to_be_bytes());

    exts_data.extend_from_slice(&grease_type2.to_be_bytes());
    exts_data.extend_from_slice(&0u16.to_be_bytes());

    body.extend_from_slice(&(exts_data.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts_data);

    let mut hs = Vec::new();
    hs.push(0x01); // Handshake Type: ClientHello
    let hs_len = body.len() as u32;
    hs.extend_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
    hs.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16); // Content Type: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // Legacy Record Layer Version (TLS 1.0)
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

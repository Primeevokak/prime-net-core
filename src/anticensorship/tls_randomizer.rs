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
    let domain = domains.choose(&mut thread_rng()).unwrap_or(&"www.google.com");
    build_client_hello_for_domain(domain)
}

/// Constructs a minimal TLS 1.2+ ClientHello record with the specified SNI.
#[allow(clippy::expect_used)]
pub fn build_client_hello_for_domain(domain: &str) -> Vec<u8> {
    let host = domain.as_bytes();
    let sni_name_len = host.len() as u16;
    let sni_list_len = 1 + 2 + sni_name_len;
    let sni_ext_len = 2 + sni_list_len;

    // Supported Versions (TLS 1.2, 1.3)
    let supported_versions_ext = hex::decode("002b00050403040303").expect("valid hex");

    let mut exts = Vec::new();
    // SNI Extension
    exts.extend_from_slice(&0x0000u16.to_be_bytes());
    exts.extend_from_slice(&sni_ext_len.to_be_bytes());
    exts.extend_from_slice(&sni_list_len.to_be_bytes());
    exts.push(0x00);
    exts.extend_from_slice(&sni_name_len.to_be_bytes());
    exts.extend_from_slice(host);
    // Supported Versions Extension
    exts.extend_from_slice(&supported_versions_ext);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // Legacy Version (TLS 1.2)
    
    // Random (32 bytes)
    let mut random = [0u8; 32];
    rand::thread_rng().fill(&mut random);
    body.extend_from_slice(&random);

    body.push(0x00); // Session ID Length
    body.extend_from_slice(&2u16.to_be_bytes()); // Cipher Suites Length
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.push(0x01); // Compression Methods Length
    body.push(0x00); // null compression

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

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

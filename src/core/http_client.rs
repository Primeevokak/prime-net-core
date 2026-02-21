use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use reqwest::header::HOST;
use reqwest::header::RANGE;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_util::io::StreamReader;
use url::Url;

use rand::seq::SliceRandom;
use rand::thread_rng;
use rustls::SupportedProtocolVersion;

use crate::anticensorship::{
    CdnProvider, DomainFrontingProxy, FrontConfig, PrimeReqwestDnsResolver, ResolverChain,
    TlsFingerprintRandomizer,
};
use crate::config::{
    DomainFrontingRule, EchMode, EngineConfig, EvasionStrategy, FrontingProvider,
    TrackerBlockAction,
};
use crate::core::chunk_manager::{ChunkManager, DownloadStrategy, ProgressHook};
use crate::core::connection_pool::ConnectionPoolConfig;
use crate::core::{DownloadOutcome, RequestData, ResponseData, ResponseStream};
use crate::error::{EngineError, Result};
use crate::evasion::{FragmentConfig, FragmentingIo};
use crate::privacy::dnt::apply_signals;
use crate::privacy::record_blocked_domain;
use crate::privacy::referer_policy::{apply_referer_policy, RefererDecision};
use crate::privacy::tracker_blocker::TrackerBlocker;
use crate::telemetry::connection_tracker::{
    global_connection_tracker, ConnectionStatus, ConnectionTracker, DnsInfo, DownloadInfo, TlsInfo,
};
use crate::tls::{Ja3Fingerprint, TlsVersion};
use crate::websocket::{WebSocketClient, WsConfig};

mod http3;

trait AsyncIo: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncIo for T {}

#[derive(Debug)]
/// Primary HTTP client used by the engine.
///
/// This wraps an underlying `reqwest::Client` and applies engine configuration such as:
/// TLS (including optional ECH), anti-censorship DNS, domain fronting, and adaptive chunked downloads.
pub struct PrimeHttpClient {
    client_plain: reqwest::Client,
    client_ech_grease: Option<reqwest::Client>,
    client_ech_real_cache: parking_lot::Mutex<std::collections::HashMap<String, reqwest::Client>>,
    config: EngineConfig,
    chunk_manager: ChunkManager,
    resolver_chain: std::sync::Arc<ResolverChain>,
    dns_resolver: std::sync::Arc<PrimeReqwestDnsResolver>,
    fronting: DomainFrontingProxy,
    fronting_v2: FrontingV2,
    h2_reset_limiter: Option<std::sync::Arc<tokio::sync::Semaphore>>,
    tls_randomizer: TlsFingerprintRandomizer,
    connection_tracker: Option<ConnectionTracker>,
    tracker_blocker: Option<TrackerBlocker>,
}

#[derive(Debug, Clone)]
struct FrontingRuleV2 {
    candidates: Vec<String>,
    real_host: String,
}

#[derive(Debug)]
struct FrontingCacheEntry {
    front_domain: String,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct FrontingV2 {
    rules: HashMap<String, FrontingRuleV2>,
    cache: parking_lot::Mutex<HashMap<String, FrontingCacheEntry>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivacyInterception {
    None,
    Empty200,
}

fn build_fronting_maps(rules: &[DomainFrontingRule]) -> (DomainFrontingProxy, FrontingV2) {
    let mut v1 = DomainFrontingProxy::new();
    let mut v2 = FrontingV2 {
        rules: HashMap::new(),
        cache: parking_lot::Mutex::new(HashMap::new()),
    };

    for rule in rules {
        let target = rule.target_host.to_ascii_lowercase();

        let candidates: Vec<String> = if !rule.front_domains.is_empty() {
            rule.front_domains
                .iter()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        } else if !rule.front_domain.trim().is_empty() {
            vec![rule.front_domain.trim().to_owned()]
        } else {
            Vec::new()
        };

        if candidates.is_empty() {
            continue;
        }

        // v1 proxy map uses the first candidate for compatibility (used by WebSocketClient today).
        let first = candidates[0].clone();
        v1.upsert_mapping(
            target.clone(),
            FrontConfig {
                front_domain: first.clone(),
                real_host: rule.real_host.clone(),
                sni_domain: rule.sni_domain.clone().unwrap_or_else(|| first.clone()),
                provider: map_fronting_provider(&rule.provider),
            },
        );

        v2.rules.insert(
            target,
            FrontingRuleV2 {
                candidates,
                real_host: rule.real_host.clone(),
            },
        );
    }

    (v1, v2)
}

include!("http_client_parts/request_pipeline.rs");
include!("http_client_parts/transport_tls_fragmentation.rs");
include!("http_client_parts/download_and_privacy.rs");
include!("http_client_parts/chunked_download.rs");
fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    fn val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = val(bytes[i * 2])?;
        let lo = val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn extract_sha256_from_text(s: &str) -> Option<String> {
    // Common formats:
    // - "<hex>  filename"
    // - "SHA256 (filename) = <hex>"
    // We look for the first 64-hex token/substr.
    for token in s.split_whitespace() {
        if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(token.to_ascii_lowercase());
        }
    }

    let bytes = s.as_bytes();
    if bytes.len() < 64 {
        return None;
    }
    for i in 0..=(bytes.len() - 64) {
        let sub = &bytes[i..i + 64];
        if sub.iter().all(|b| b.is_ascii_hexdigit()) {
            return Some(String::from_utf8_lossy(sub).to_ascii_lowercase());
        }
    }
    None
}

fn should_fallback_from_ech(err: &EngineError) -> bool {
    match err {
        EngineError::Http(e) => e.is_connect() || e.is_timeout(),
        _ => false,
    }
}

fn build_reqwest_client(
    cfg: &EngineConfig,
    pool: &ConnectionPoolConfig,
    dns_resolver: std::sync::Arc<PrimeReqwestDnsResolver>,
    tls: rustls::ClientConfig,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(cfg.download.connect_timeout_secs))
        .timeout(Duration::from_secs(cfg.download.request_timeout_secs))
        .tcp_keepalive(Duration::from_secs(30))
        .http2_adaptive_window(true)
        .http2_keep_alive_timeout(Duration::from_secs(30));

    // Use an explicit rustls ClientConfig so that tls.alpn_protocols and ECH settings are applied.
    // (Reqwest's high-level builder API doesn't expose ALPN, and ECH requires rustls config.)
    builder = builder.use_preconfigured_tls(tls);
    builder = pool.apply(builder);
    // Keep behavior deterministic across environments/CI: only use proxy when explicitly configured.
    builder = builder.no_proxy();
    if let Some(proxy_cfg) = &cfg.proxy {
        builder = builder.proxy(proxy_cfg.as_reqwest_proxy()?);
    }
    builder = builder.dns_resolver(dns_resolver);

    Ok(builder.build()?)
}

#[cfg(feature = "observability")]
fn record_http_metrics(started: Instant, ok: bool) {
    let elapsed = started.elapsed().as_secs_f64();
    if ok {
        crate::observability::prometheus::HTTP_REQUESTS_OK.inc();
        crate::observability::prometheus::HTTP_REQUEST_DURATION_OK.observe(elapsed);
    } else {
        crate::observability::prometheus::HTTP_REQUESTS_ERROR.inc();
        crate::observability::prometheus::HTTP_REQUEST_DURATION_ERROR.observe(elapsed);
    }
}

fn build_headers(headers: &[(String, String)]) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.insert(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_str(value)?,
        );
    }
    Ok(map)
}

fn collect_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| Some((k.to_string(), v.to_str().ok()?.to_owned())))
        .collect()
}

fn parse_total_length_from_content_range(headers: &HeaderMap) -> Option<u64> {
    // Content-Range: bytes 0-0/12345
    let v = headers.get(reqwest::header::CONTENT_RANGE)?.to_str().ok()?;
    let (_unit_and_range, total) = v.split_once('/')?;
    if total.trim() == "*" {
        return None;
    }
    total.trim().parse::<u64>().ok()
}

fn retry_delay(attempt: usize) -> Duration {
    // 200ms, 400ms, 800ms ... with a small jitter (best-effort).
    let base_ms: u64 = 200;
    let max_shift = 6usize;
    let exp = (attempt.min(max_shift)) as u32;
    let backoff = base_ms.saturating_mul(1_u64 << exp);
    let jitter = rand::random::<u64>() % 100;
    Duration::from_millis(backoff.saturating_add(jitter))
}

fn is_tcp_connection_reset(err: &EngineError) -> bool {
    use std::error::Error as _;
    use std::io;

    let mut cur: Option<&(dyn std::error::Error + 'static)> = match err {
        EngineError::Http(e) => e.source(),
        _ => None,
    };

    while let Some(e) = cur {
        if let Some(ioe) = e.downcast_ref::<io::Error>() {
            if ioe.kind() == io::ErrorKind::ConnectionReset
                || ioe.kind() == io::ErrorKind::ConnectionAborted
            {
                return true;
            }
        }
        cur = e.source();
    }

    // Best-effort fallback for wrappers that don't expose `io::Error` directly.
    let s = err.to_string().to_ascii_lowercase();
    s.contains("connection reset") || s.contains("connection was reset") || s.contains("econnreset")
}

fn map_fronting_provider(provider: &FrontingProvider) -> CdnProvider {
    match provider {
        FrontingProvider::Cloudflare => CdnProvider::Cloudflare,
        FrontingProvider::Fastly => CdnProvider::Fastly,
        FrontingProvider::GoogleCdn => CdnProvider::GoogleCdn,
        FrontingProvider::AzureCdn => CdnProvider::AzureCdn,
    }
}

fn build_rustls_ech_config(
    ech_config_list: &[u8],
) -> std::result::Result<rustls::client::EchConfig, rustls::Error> {
    let suites = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
    rustls::client::EchConfig::new(
        rustls::pki_types::EchConfigListBytes::from(ech_config_list),
        suites,
    )
}

fn build_ech_grease_mode() -> Result<rustls::client::EchMode> {
    let suite = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
        .first()
        .ok_or_else(|| EngineError::Internal("no HPKE suites available for ECH".to_owned()))?;
    let (placeholder_pub, _placeholder_priv) = suite.generate_key_pair().map_err(|e| {
        EngineError::Internal(format!("ECH placeholder key generation failed: {e}"))
    })?;
    let grease = rustls::client::EchGreaseConfig::new(*suite, placeholder_pub);
    Ok(rustls::client::EchMode::Grease(grease))
}

fn default_crypto_provider_arc() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

fn base_crypto_provider() -> rustls::crypto::CryptoProvider {
    // Clone the process default if installed, otherwise use aws-lc-rs defaults.
    // We keep this separate from `default_crypto_provider_arc()` to allow per-client tuning
    // (JA3-adjacent) without mutating the global default provider.
    rustls::crypto::CryptoProvider::get_default()
        .map(|arc| (**arc).clone())
        .unwrap_or_else(rustls::crypto::aws_lc_rs::default_provider)
}

fn select_crypto_provider(cfg: &EngineConfig) -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    match cfg.tls.ja3_fingerprint {
        Ja3Fingerprint::RustlsDefault => default_crypto_provider_arc(),
        other => std::sync::Arc::new(apply_ja3_profile(base_crypto_provider(), other)),
    }
}

fn apply_ja3_profile(
    mut provider: rustls::crypto::CryptoProvider,
    profile: Ja3Fingerprint,
) -> rustls::crypto::CryptoProvider {
    match profile {
        Ja3Fingerprint::RustlsDefault => {}
        Ja3Fingerprint::Chrome120 => {
            // Chrome generally prefers AES_128 first (then AES_256, then CHACHA20).
            reorder_cipher_suites(
                &mut provider.cipher_suites,
                &[
                    rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                ],
            );
            // Keep X25519 first for compatibility; keep PQ-hybrid (if present) last.
            reorder_kx_groups(
                &mut provider.kx_groups,
                &[
                    rustls::NamedGroup::X25519,
                    rustls::NamedGroup::secp256r1,
                    rustls::NamedGroup::secp384r1,
                    rustls::NamedGroup::X25519MLKEM768,
                ],
            );
        }
        Ja3Fingerprint::Firefox121 => {
            // Firefox tends to prefer CHACHA20 earlier when available on non-AES-NI machines,
            // but from our side we can only apply a fixed preference ordering.
            reorder_cipher_suites(
                &mut provider.cipher_suites,
                &[
                    rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                    rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                ],
            );
            reorder_kx_groups(
                &mut provider.kx_groups,
                &[
                    rustls::NamedGroup::X25519,
                    rustls::NamedGroup::secp256r1,
                    rustls::NamedGroup::secp384r1,
                    rustls::NamedGroup::X25519MLKEM768,
                ],
            );
        }
        Ja3Fingerprint::Random => {
            let mut rng = thread_rng();

            // Best-effort: keep a sane first ciphersuite if present, then randomize the rest.
            if let Some(pos) = provider
                .cipher_suites
                .iter()
                .position(|s| s.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
            {
                provider.cipher_suites.swap(0, pos);
            }
            if provider.cipher_suites.len() > 1 {
                provider.cipher_suites[1..].shuffle(&mut rng);
            }

            // Keep X25519 first if present, randomize the remainder.
            if let Some(pos) = provider
                .kx_groups
                .iter()
                .position(|g| g.name() == rustls::NamedGroup::X25519)
            {
                provider.kx_groups.swap(0, pos);
            }
            if provider.kx_groups.len() > 1 {
                provider.kx_groups[1..].shuffle(&mut rng);
            }
        }
    }
    provider
}

fn reorder_cipher_suites(
    suites: &mut Vec<rustls::SupportedCipherSuite>,
    preferred: &[rustls::CipherSuite],
) {
    let mut out: Vec<rustls::SupportedCipherSuite> = Vec::with_capacity(suites.len());

    for id in preferred {
        for s in suites.iter().copied() {
            if s.suite() == *id && !out.contains(&s) {
                out.push(s);
            }
        }
    }

    for s in suites.iter().copied() {
        if !out.contains(&s) {
            out.push(s);
        }
    }

    *suites = out;
}

fn reorder_kx_groups(
    groups: &mut Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    preferred: &[rustls::NamedGroup],
) {
    let mut out: Vec<&'static dyn rustls::crypto::SupportedKxGroup> =
        Vec::with_capacity(groups.len());
    let mut seen: Vec<rustls::NamedGroup> = Vec::new();

    for id in preferred {
        for g in groups.iter().copied() {
            if g.name() == *id && !seen.contains(id) {
                out.push(g);
                seen.push(*id);
            }
        }
    }

    for g in groups.iter().copied() {
        let id = g.name();
        if !seen.contains(&id) {
            out.push(g);
            seen.push(id);
        }
    }

    *groups = out;
}

fn build_rustls_client_config(
    cfg: &EngineConfig,
    ech_mode: Option<rustls::client::EchMode>,
) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let versions = select_rustls_versions_plain(cfg)?;

    let provider = select_crypto_provider(cfg);

    // NOTE: rustls' `with_ech()` typestate transition does not allow calling
    // `with_protocol_versions()` after it. Internally, `with_ech()` forces TLS 1.3.
    let builder = if let Some(mode) = ech_mode {
        validate_ech_tls_constraints(cfg)?;
        rustls::ClientConfig::builder_with_provider(provider)
            .with_ech(mode)
            .map_err(|e| EngineError::Internal(format!("failed to enable ECH: {e}")))?
    } else {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .map_err(|_| EngineError::Config("invalid TLS protocol versions".to_owned()))?
    };

    let mut tls = builder.with_root_certificates(roots).with_no_client_auth();

    // ALPN protocols (drives HTTP/2 negotiation).
    let mut alpn = Vec::new();
    for p in &cfg.tls.alpn_protocols {
        let p = p.trim();
        if !p.is_empty() {
            alpn.push(p.as_bytes().to_vec());
        }
    }
    if alpn.is_empty() {
        alpn.push(b"h2".to_vec());
        alpn.push(b"http/1.1".to_vec());
    }
    if cfg.tls.ja3_fingerprint == Ja3Fingerprint::Random && alpn.len() > 1 {
        alpn.shuffle(&mut thread_rng());
    }
    tls.alpn_protocols = alpn;
    tls.enable_sni = true;

    Ok(tls)
}

fn validate_ech_tls_constraints(cfg: &EngineConfig) -> Result<()> {
    let min = cfg.tls.min_version;
    let max = cfg.tls.max_version;
    let min_r = tls_rank(min);
    let max_r = tls_rank(max);

    if !(min_r <= tls_rank(TlsVersion::Tls1_3) && max_r >= tls_rank(TlsVersion::Tls1_3)) {
        return Err(EngineError::Config(
            "anticensorship.ech_mode requires TLS 1.3 to be allowed by tls.min_version/tls.max_version".to_owned(),
        ));
    }
    Ok(())
}

fn select_rustls_versions_plain(
    cfg: &EngineConfig,
) -> Result<Vec<&'static SupportedProtocolVersion>> {
    let min = cfg.tls.min_version;
    let max = cfg.tls.max_version;
    let min_r = tls_rank(min);
    let max_r = tls_rank(max);

    // Only TLS 1.2 and 1.3 are supported by the current rustls backend wiring.
    let mut versions: Vec<&'static SupportedProtocolVersion> = Vec::new();
    if min_r <= tls_rank(TlsVersion::Tls1_3) && max_r >= tls_rank(TlsVersion::Tls1_3) {
        versions.push(&rustls::version::TLS13);
    }
    if min_r <= tls_rank(TlsVersion::Tls1_2) && max_r >= tls_rank(TlsVersion::Tls1_2) {
        versions.push(&rustls::version::TLS12);
    }

    if versions.is_empty() {
        return Err(EngineError::Config(
            "no supported TLS versions selected (only TLS 1.2 and 1.3 are supported)".to_owned(),
        ));
    }

    Ok(versions)
}

fn tls_rank(v: TlsVersion) -> u8 {
    match v {
        TlsVersion::Tls1_0 => 10,
        TlsVersion::Tls1_1 => 11,
        TlsVersion::Tls1_2 => 12,
        TlsVersion::Tls1_3 => 13,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn read_u8(buf: &[u8], pos: &mut usize) -> Option<u8> {
        let v = *buf.get(*pos)?;
        *pos += 1;
        Some(v)
    }

    fn read_u16(buf: &[u8], pos: &mut usize) -> Option<u16> {
        let b0 = *buf.get(*pos)? as u16;
        let b1 = *buf.get(*pos + 1)? as u16;
        *pos += 2;
        Some((b0 << 8) | b1)
    }

    fn read_u24(buf: &[u8], pos: &mut usize) -> Option<usize> {
        let b0 = *buf.get(*pos)? as usize;
        let b1 = *buf.get(*pos + 1)? as usize;
        let b2 = *buf.get(*pos + 2)? as usize;
        *pos += 3;
        Some((b0 << 16) | (b1 << 8) | b2)
    }

    fn capture_client_hello(cfg: rustls::ClientConfig) -> Vec<u8> {
        let server_name =
            rustls::pki_types::ServerName::try_from("example.com").expect("valid server name");
        let mut conn = rustls::ClientConnection::new(Arc::new(cfg), server_name)
            .expect("client connection should build");
        let mut out = Vec::new();
        conn.write_tls(&mut out).expect("write_tls should work");
        out
    }

    fn supported_versions_from_client_hello(tls_stream: &[u8]) -> Option<Vec<u16>> {
        // Reassemble handshake fragments from TLS records.
        let mut pos = 0usize;
        let mut handshake = Vec::new();
        while pos + 5 <= tls_stream.len() {
            let ct = tls_stream[pos];
            let _legacy_ver = u16::from_be_bytes([tls_stream[pos + 1], tls_stream[pos + 2]]);
            let len = u16::from_be_bytes([tls_stream[pos + 3], tls_stream[pos + 4]]) as usize;
            pos += 5;
            let frag = tls_stream.get(pos..pos + len)?;
            pos += len;
            if ct == 22 {
                handshake.extend_from_slice(frag);
            }
        }

        // First handshake message should be ClientHello (type 1).
        let mut hp = 0usize;
        let hs_type = read_u8(&handshake, &mut hp)?;
        if hs_type != 1 {
            return None;
        }
        let hs_len = read_u24(&handshake, &mut hp)?;
        let ch = handshake.get(hp..hp + hs_len)?;

        // Parse ClientHello enough to reach extensions.
        let mut cp = 0usize;
        let _legacy_client_ver = read_u16(ch, &mut cp)?;
        cp += 32; // random
        let sid_len = read_u8(ch, &mut cp)? as usize;
        cp += sid_len;
        let cs_len = read_u16(ch, &mut cp)? as usize;
        cp += cs_len;
        let comp_len = read_u8(ch, &mut cp)? as usize;
        cp += comp_len;
        let ext_len = read_u16(ch, &mut cp)? as usize;
        let exts = ch.get(cp..cp + ext_len)?;

        // Walk extensions.
        let mut ep = 0usize;
        while ep + 4 <= exts.len() {
            let ty = u16::from_be_bytes([exts[ep], exts[ep + 1]]);
            let elen = u16::from_be_bytes([exts[ep + 2], exts[ep + 3]]) as usize;
            ep += 4;
            let data = exts.get(ep..ep + elen)?;
            ep += elen;

            // supported_versions (RFC 8446) = 0x002b
            if ty == 0x002b {
                let mut dp = 0usize;
                let list_len = read_u8(data, &mut dp)? as usize;
                let list = data.get(dp..dp + list_len)?;
                let mut out = Vec::new();
                for chunk in list.chunks_exact(2) {
                    out.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                }
                return Some(out);
            }
        }
        None
    }

    fn cipher_suites_from_client_hello(tls_stream: &[u8]) -> Option<Vec<u16>> {
        // Reassemble handshake fragments from TLS records.
        let mut pos = 0usize;
        let mut handshake = Vec::new();
        while pos + 5 <= tls_stream.len() {
            let ct = tls_stream[pos];
            let len = u16::from_be_bytes([tls_stream[pos + 3], tls_stream[pos + 4]]) as usize;
            pos += 5;
            let frag = tls_stream.get(pos..pos + len)?;
            pos += len;
            if ct == 22 {
                handshake.extend_from_slice(frag);
            }
        }

        // First handshake message should be ClientHello (type 1).
        let mut hp = 0usize;
        let hs_type = read_u8(&handshake, &mut hp)?;
        if hs_type != 1 {
            return None;
        }
        let hs_len = read_u24(&handshake, &mut hp)?;
        let ch = handshake.get(hp..hp + hs_len)?;

        let mut cp = 0usize;
        let _legacy_client_ver = read_u16(ch, &mut cp)?;
        cp += 32; // random
        let sid_len = read_u8(ch, &mut cp)? as usize;
        cp += sid_len;
        let cs_len = read_u16(ch, &mut cp)? as usize;
        let cs = ch.get(cp..cp + cs_len)?;

        let mut out = Vec::new();
        for chunk in cs.chunks_exact(2) {
            out.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        Some(out)
    }

    #[test]
    fn ech_forces_tls13_only_in_client_hello() {
        let mut cfg = EngineConfig::default();
        cfg.tls.min_version = TlsVersion::Tls1_2;
        cfg.tls.max_version = TlsVersion::Tls1_3;
        cfg.anticensorship.ech_mode = Some(EchMode::Grease);

        let client_cfg =
            build_rustls_client_config(&cfg, Some(build_ech_grease_mode().expect("grease mode")))
                .expect("client config should build");
        let ch = capture_client_hello(client_cfg);
        let versions =
            supported_versions_from_client_hello(&ch).expect("supported_versions present");
        assert_eq!(versions, vec![0x0304]); // TLS 1.3 only
    }

    #[test]
    fn non_ech_offers_tls12_and_tls13_in_client_hello() {
        let mut cfg = EngineConfig::default();
        cfg.tls.min_version = TlsVersion::Tls1_2;
        cfg.tls.max_version = TlsVersion::Tls1_3;
        cfg.anticensorship.ech_enabled = false;

        let client_cfg =
            build_rustls_client_config(&cfg, None).expect("client config should build");
        let ch = capture_client_hello(client_cfg);
        let versions =
            supported_versions_from_client_hello(&ch).expect("supported_versions present");
        assert!(versions.contains(&0x0304)); // TLS 1.3
        assert!(versions.contains(&0x0303)); // TLS 1.2
    }

    #[test]
    fn ech_requires_tls13_to_be_allowed_by_config() {
        let mut cfg = EngineConfig::default();
        cfg.tls.min_version = TlsVersion::Tls1_2;
        cfg.tls.max_version = TlsVersion::Tls1_2;
        cfg.anticensorship.ech_mode = Some(EchMode::Grease);

        let err =
            build_rustls_client_config(&cfg, Some(build_ech_grease_mode().expect("grease mode")))
                .expect_err("must reject ECH when TLS1.3 is not allowed");
        match err {
            EngineError::Config(msg) => assert!(msg.contains("requires TLS 1.3")),
            other => panic!("expected config error, got: {other:?}"),
        }
    }

    #[test]
    fn chrome_profile_reorders_cipher_suites_best_effort() {
        let mut cfg = EngineConfig::default();
        cfg.tls.ja3_fingerprint = Ja3Fingerprint::Chrome120;
        let client_cfg =
            build_rustls_client_config(&cfg, None).expect("client config should build");
        let ch = capture_client_hello(client_cfg);
        let suites = cipher_suites_from_client_hello(&ch).expect("cipher suites present");

        // Ensure common TLS 1.3 suites appear in the intended order: 0x1301 < 0x1302 < 0x1303.
        let i1 = suites
            .iter()
            .position(|v| *v == 0x1301)
            .expect("TLS_AES_128_GCM_SHA256");
        let i2 = suites
            .iter()
            .position(|v| *v == 0x1302)
            .expect("TLS_AES_256_GCM_SHA384");
        let i3 = suites
            .iter()
            .position(|v| *v == 0x1303)
            .expect("TLS_CHACHA20_POLY1305_SHA256");
        assert!(i1 < i2 && i2 < i3);
    }

    #[test]
    fn firefox_profile_reorders_cipher_suites_best_effort() {
        let mut cfg = EngineConfig::default();
        cfg.tls.ja3_fingerprint = Ja3Fingerprint::Firefox121;
        let client_cfg =
            build_rustls_client_config(&cfg, None).expect("client config should build");
        let ch = capture_client_hello(client_cfg);
        let suites = cipher_suites_from_client_hello(&ch).expect("cipher suites present");

        // Intended order: 0x1301 < 0x1303 < 0x1302.
        let i1 = suites
            .iter()
            .position(|v| *v == 0x1301)
            .expect("TLS_AES_128_GCM_SHA256");
        let i2 = suites
            .iter()
            .position(|v| *v == 0x1302)
            .expect("TLS_AES_256_GCM_SHA384");
        let i3 = suites
            .iter()
            .position(|v| *v == 0x1303)
            .expect("TLS_CHACHA20_POLY1305_SHA256");
        assert!(i1 < i3 && i3 < i2);
    }
}

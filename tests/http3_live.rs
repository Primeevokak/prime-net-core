use prime_net_engine_core::config::DnsResolverKind;
use prime_net_engine_core::{EngineConfig, PrimeHttpClient, RequestData};

// Run manually:
// - set env PRIME_NET_ENGINE_LIVE_TESTS=1
// - cargo test --test http3_live -- --nocapture
#[tokio::test]
#[ignore]
async fn http3_live_smoke() {
    if std::env::var("PRIME_NET_ENGINE_LIVE_TESTS").ok().as_deref() != Some("1") {
        return;
    }

    let mut cfg = EngineConfig::default();
    cfg.anticensorship.doh_enabled = false;
    cfg.anticensorship.dot_enabled = false;
    cfg.anticensorship.doq_enabled = false;
    cfg.anticensorship.system_dns_enabled = true;
    cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::System];
    cfg.transport.prefer_http3 = true;
    cfg.transport.http3_only = true;
    cfg.transport.http3_connect_timeout_ms = 10_000;
    cfg.transport.http3_idle_timeout_ms = 30_000;

    let client = PrimeHttpClient::new(cfg).expect("client build");

    // A QUIC-capable endpoint. Expect redirects or 200 depending on deployment.
    let url = "https://cloudflare-quic.com/".to_owned();
    let resp = client
        .fetch(RequestData::get(url), None)
        .await
        .expect("http3 live fetch");

    assert!(
        resp.status_code >= 200 && resp.status_code < 400,
        "status={}",
        resp.status_code
    );
    assert!(!resp.body.is_empty(), "empty body");
}

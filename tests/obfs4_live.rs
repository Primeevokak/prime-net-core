use prime_net_engine_core::config::{
    Obfs4PtConfig, PluggableTransportConfig, PluggableTransportKind,
};
use prime_net_engine_core::{EngineConfig, PrimeEngine, RequestData};

#[tokio::test]
#[ignore]
async fn obfs4_live_smoke() {
    if std::env::var("PRIME_NET_ENGINE_LIVE_TESTS").ok().as_deref() != Some("1") {
        return;
    }

    let server = std::env::var("OBFS4_SERVER").expect("set OBFS4_SERVER=host:port");
    let cert = std::env::var("OBFS4_CERT").expect("set OBFS4_CERT=... (from bridge line cert=...)");
    let fingerprint = std::env::var("OBFS4_FINGERPRINT").ok();
    let iat_mode = std::env::var("OBFS4_IAT_MODE")
        .ok()
        .and_then(|v| v.parse::<u8>().ok());

    let tor_bin = std::env::var("TOR_BIN").unwrap_or_else(|_| "tor".to_owned());
    let obfs4proxy_bin =
        std::env::var("OBFS4PROXY_BIN").unwrap_or_else(|_| "obfs4proxy".to_owned());

    let cfg = EngineConfig {
        pt: Some(PluggableTransportConfig {
            kind: PluggableTransportKind::Obfs4,
            local_socks5_bind: "127.0.0.1:0".to_owned(),
            silent_drop: true,
            trojan: None,
            shadowsocks: None,
            obfs4: Some(Obfs4PtConfig {
                server,
                fingerprint,
                cert,
                iat_mode,
                tor_bin,
                tor_args: Vec::new(),
                obfs4proxy_bin,
                obfs4proxy_args: Vec::new(),
            }),
            snowflake: None,
        }),
        ..EngineConfig::default()
    };

    let eng = PrimeEngine::new(cfg).await.expect("engine init");
    let client = eng.client();

    let resp = client
        .fetch(RequestData::get("https://example.com/"), None)
        .await
        .expect("fetch");
    assert_eq!(resp.status_code, 200);
    assert!(!resp.body.is_empty());
}

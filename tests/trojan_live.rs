use prime_net_engine_core::config::{
    PluggableTransportConfig, PluggableTransportKind, TrojanPtConfig,
};
use prime_net_engine_core::{EngineConfig, PrimeEngine, RequestData};

#[tokio::test]
#[ignore]
async fn trojan_live_smoke() {
    if std::env::var("PRIME_NET_ENGINE_LIVE_TESTS").ok().as_deref() != Some("1") {
        return;
    }

    let server = std::env::var("TROJAN_SERVER").expect("set TROJAN_SERVER=host:port");
    let password = std::env::var("TROJAN_PASSWORD").expect("set TROJAN_PASSWORD=...");
    let sni = std::env::var("TROJAN_SNI").ok();

    let cfg = EngineConfig {
        pt: Some(PluggableTransportConfig {
            kind: PluggableTransportKind::Trojan,
            local_socks5_bind: "127.0.0.1:0".to_owned(),
            silent_drop: true,
            trojan: Some(TrojanPtConfig {
                server,
                password,
                sni,
                alpn_protocols: vec!["http/1.1".to_owned()],
                insecure_skip_verify: false,
            }),
            shadowsocks: None,
            obfs4: None,
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

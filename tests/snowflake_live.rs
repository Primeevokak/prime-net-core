use prime_net_engine_core::config::{
    PluggableTransportConfig, PluggableTransportKind, SnowflakePtConfig,
};
use prime_net_engine_core::{EngineConfig, PrimeEngine, RequestData};

#[tokio::test]
#[ignore]
async fn snowflake_live_smoke() {
    if std::env::var("PRIME_NET_ENGINE_LIVE_TESTS").ok().as_deref() != Some("1") {
        return;
    }

    let tor_bin = std::env::var("TOR_BIN").unwrap_or_else(|_| "tor".to_owned());
    let snowflake_bin =
        std::env::var("SNOWFLAKE_BIN").unwrap_or_else(|_| "snowflake-client".to_owned());

    let broker = std::env::var("SNOWFLAKE_BROKER").ok();
    let front = std::env::var("SNOWFLAKE_FRONT").ok();
    let amp_cache = std::env::var("SNOWFLAKE_AMP_CACHE").ok();
    let stun_servers = std::env::var("SNOWFLAKE_STUN")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let cfg = EngineConfig {
        pt: Some(PluggableTransportConfig {
            kind: PluggableTransportKind::Snowflake,
            local_socks5_bind: "127.0.0.1:0".to_owned(),
            silent_drop: true,
            trojan: None,
            shadowsocks: None,
            obfs4: None,
            snowflake: Some(SnowflakePtConfig {
                tor_bin,
                tor_args: Vec::new(),
                snowflake_bin,
                broker,
                front,
                amp_cache,
                stun_servers,
                bridge: None,
                snowflake_args: Vec::new(),
            }),
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

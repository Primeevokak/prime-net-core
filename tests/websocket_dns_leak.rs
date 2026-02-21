use prime_net_engine_core::websocket::{WebSocketClient, WsConfig};

#[test]
fn websocket_requires_resolver_chain_to_prevent_dns_leak() {
    let err = WebSocketClient::try_new(WsConfig::default(), None)
        .expect_err("must reject missing ResolverChain");
    let msg = err.to_string().to_ascii_lowercase();
    assert!(msg.contains("resolverchain") || msg.contains("resolver chain"));
    assert!(msg.contains("dns leak") || msg.contains("dns"));
}

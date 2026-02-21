use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use prime_net_engine_core::config::DnsResolverKind;
use prime_net_engine_core::{EngineConfig, PrimeHttpClient, RequestData};

#[tokio::test]
#[cfg_attr(windows, ignore = "flaky on Windows: local QUIC loopback timeout")]
async fn http3_local_server_smoke() {
    // Build a local QUIC + HTTP/3 server.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen");
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let priv_key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13 only")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_key.into())
        .expect("rustls server config");
    server_crypto.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec(), b"h3-30".to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .expect("quic server crypto"),
    ));

    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let endpoint = quinn::Endpoint::server(server_config, bind).expect("quinn server endpoint");
    let addr = endpoint.local_addr().expect("local addr");

    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => {
                    break;
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    tokio::spawn(async move {
                        let conn = match incoming.await {
                            Ok(c) => c,
                            Err(_) => return,
                        };
                        let conn = h3_quinn::Connection::new(conn);
                        let mut h3_conn = match h3::server::Connection::new(conn).await {
                            Ok(c) => c,
                            Err(_) => return,
                        };

                        while let Ok(Some(resolver)) = h3_conn.accept().await {
                            tokio::spawn(async move {
                                let (req, mut stream) = match resolver.resolve_request().await {
                                    Ok(v) => v,
                                    Err(_) => return,
                                };
                                let path = req.uri().path();
                                let body = if path == "/ok" { "ok" } else { "not found" };
                                let status = if path == "/ok" {
                                    http::StatusCode::OK
                                } else {
                                    http::StatusCode::NOT_FOUND
                                };

                                let response = http::Response::builder().status(status).body(()).unwrap();
                                let _ = stream.send_response(response).await;
                                let _ = stream.send_data(Bytes::from(body)).await;
                                let _ = stream.finish().await;
                            });
                        }
                    });
                }
            }
        }
    });

    // Client: force system DNS only (avoid external DNS in tests), enable HTTP/3, skip cert verify (self-signed).
    let mut cfg = EngineConfig::default();
    cfg.anticensorship.doh_enabled = false;
    cfg.anticensorship.dot_enabled = false;
    cfg.anticensorship.doq_enabled = false;
    cfg.anticensorship.system_dns_enabled = true;
    cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::System];
    cfg.transport.prefer_http3 = true;
    cfg.transport.http3_only = true;
    cfg.transport.http3_connect_timeout_ms = 5_000;
    cfg.transport.http3_idle_timeout_ms = 5_000;
    cfg.transport.http3_insecure_skip_verify = true;

    let client = PrimeHttpClient::new(cfg).expect("client build");
    let url = format!("https://127.0.0.1:{}/ok", addr.port());
    let resp = client
        .fetch(RequestData::get(url), None)
        .await
        .expect("http3 fetch");

    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.body, b"ok");

    // Stop server.
    let _ = stop_tx.send(());
    let _ = server.await;
}

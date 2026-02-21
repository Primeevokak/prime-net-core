use prime_net_engine_core::{EngineConfig, PrimeHttpClient, RequestData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn basic_fetch_works() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("read local addr");

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept socket");
        let mut buf = [0_u8; 2048];
        let _ = socket.read(&mut buf).await.expect("read request");

        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nworld";
        socket.write_all(response).await.expect("write response");
    });

    let mut cfg = EngineConfig::default();
    cfg.download.adaptive_enabled = false; // avoid HEAD probing in this unit test
    let client = PrimeHttpClient::new(cfg).expect("client should build");
    let response = client
        .fetch(RequestData::get(format!("http://{addr}/hello")), None)
        .await
        .expect("request should succeed");

    assert_eq!(response.status_code, 200);
    assert_eq!(response.body, b"world");

    server.await.expect("server task should finish");
}

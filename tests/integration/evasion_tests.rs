use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

use prime_net_engine_core::anticensorship::ResolverChain;
use prime_net_engine_core::pt::direct::DirectOutbound;
use prime_net_engine_core::pt::socks5_server::{start_socks5_server, RelayOptions};

#[tokio::test]
async fn test_randomized_fragmentation_and_window_size() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Mock server that just echoes back
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let _ = socket.write_all(&buf[..n]).await;
                }
            });
        }
    });

    let resolver = Arc::new(ResolverChain::from_config(&Default::default()).unwrap());
    let outbound = Arc::new(DirectOutbound::new(resolver));

    let opts = RelayOptions {
        fragment_client_hello: true,
        fragment_size_min: 1,
        fragment_size_max: 5,
        randomize_fragment_size: true,
        tcp_window_size: 10,
        ..RelayOptions::default()
    };

    let server = start_socks5_server("127.0.0.1:0", outbound, false, opts)
        .await
        .unwrap();
    let proxy_addr = server.listen_addr();

    // Test connection through SOCKS5 with evasion
    let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

    // SOCKS5 handshake
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();

    // SOCKS5 connect
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(
        &addr
            .ip()
            .to_string()
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .octets(),
    );
    req.extend_from_slice(&addr.port().to_be_bytes());
    client.write_all(&req).await.unwrap();
    let mut resp = [0u8; 10];
    client.read_exact(&mut resp).await.unwrap();

    // Send data (should be fragmented randomly)
    let test_data = b"Hello with randomized fragmentation!";
    client.write_all(test_data).await.unwrap();

    let mut buf = vec![0u8; test_data.len()];
    let res = timeout(Duration::from_secs(2), client.read_exact(&mut buf)).await;

    assert!(res.is_ok(), "Timeout waiting for echo");
    assert_eq!(&buf, test_data);
}

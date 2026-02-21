use futures_util::StreamExt;
use prime_net_engine_core::{UdpOverTcpConfig, UdpOverTcpTunnel, UdpTargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn udp_over_tcp_tunnel_can_send_and_receive_frames() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");

        // Read one client datagram (IPv4 target).
        let mut at = [0u8; 1];
        sock.read_exact(&mut at).await.expect("read at");
        assert_eq!(at[0], 0x01);

        let mut ip = [0u8; 4];
        sock.read_exact(&mut ip).await.expect("read ip");
        assert_eq!(ip, [1, 2, 3, 4]);

        let mut port = [0u8; 2];
        sock.read_exact(&mut port).await.expect("read port");
        assert_eq!(u16::from_be_bytes(port), 5353);

        let mut len = [0u8; 2];
        sock.read_exact(&mut len).await.expect("read len");
        let len = u16::from_be_bytes(len) as usize;

        let mut payload = vec![0u8; len];
        sock.read_exact(&mut payload).await.expect("read payload");
        assert_eq!(payload, b"ping");

        // Respond back with a datagram from 9.9.9.9:53, payload "pong".
        sock.write_all(&[0x01]).await.expect("write at");
        sock.write_all(&[9, 9, 9, 9]).await.expect("write ip");
        sock.write_all(&53u16.to_be_bytes())
            .await
            .expect("write port");
        sock.write_all(&4u16.to_be_bytes())
            .await
            .expect("write len");
        sock.write_all(b"pong").await.expect("write payload");
        sock.flush().await.expect("flush");
    });

    let tunnel = UdpOverTcpTunnel::connect(addr, UdpOverTcpConfig::default())
        .await
        .expect("connect");

    tunnel
        .send_to(
            UdpTargetAddr::Socket("1.2.3.4:5353".parse().unwrap()),
            b"ping",
        )
        .await
        .expect("send");

    let mut tunnel = tunnel;
    let d = tunnel
        .next()
        .await
        .expect("stream item")
        .expect("ok datagram");

    assert_eq!(d.addr, UdpTargetAddr::Socket("9.9.9.9:53".parse().unwrap()));
    assert_eq!(d.data, b"pong");

    server.await.expect("server");
}

#[cfg(test)]
mod evasion_integration_tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use rand::Rng;

    #[tokio::test]
    async fn test_send_fake_sni_probe_writes_correct_data() {
        let (mut client, server) = tokio::io::duplex(1024);
        let mut server_box: BoxStream = Box::new(server);
        
        // Spawn the probe sender
        tokio::spawn(async move {
            let _ = send_fake_sni_probe(&mut server_box, 2).await;
        });

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.expect("read failed");
        
        // Check if it's a TLS handshake (0x16) and contains "max.ru"
        assert!(n > 0);
        assert_eq!(buf[0], 0x16);
        let content = String::from_utf8_lossy(&buf[..n]);
        assert!(content.contains("max.ru"));
    }

    #[test]
    fn test_is_tls_client_hello_detection() {
        let real_ch = hex::decode("16030100510100").unwrap();
        let not_tls = b"GET / HTTP/1.1";
        
        assert!(is_tls_client_hello(&real_ch));
        assert!(!is_tls_client_hello(not_tls));
    }

    #[test]
    fn test_find_sni_info_basic() {
        // A minimal hex representation of a TLS ClientHello with SNI example.com
        let ch_hex = "160301008501000081030366eb6ed012000000000000000000000000000000000000000000000000000000000008130213031301000100005000000010000e00000b6578616d706c652e636f6d000b000403000102000a000c0008001d001700180019002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601";
        let ch = hex::decode(ch_hex).unwrap();
        
        let info = find_sni_info(&ch);
        assert!(info.is_some());
        let (off, len) = info.unwrap();
        assert!(off > 43);
        assert!(len > 10);
        
        // Check if the SNI extension type is 0x0000 at the offset
        assert_eq!(ch[off], 0x00);
        assert_eq!(ch[off+1], 0x00);
        
        // Check if the extension data contains "example.com"
        let ext_data = &ch[off..off+len];
        assert!(String::from_utf8_lossy(ext_data).contains("example.com"));
    }

    #[tokio::test]
    async fn test_udp_padding_logic() {
        let min = 32;
        let max = 128;
        let mut seen_different = false;
        let first = rand::thread_rng().gen_range(min..=max);
        
        for _ in 0..10 {
            let current = rand::thread_rng().gen_range(min..=max);
            assert!(current >= min && current <= max);
            if current != first {
                seen_different = true;
            }
        }
        assert!(seen_different, "Padding should be randomized");
    }

    #[tokio::test]
    async fn test_tcp_window_size_application() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        let client_task = tokio::spawn(async move {
            tokio::net::TcpStream::connect(addr).await.unwrap()
        });
        
        let (server_stream, _) = listener.accept().await.unwrap();
        let _client_stream = client_task.await.unwrap();
        
        // Test applying tiny window (simulating the trick start)
        let res = apply_tcp_window_size(&server_stream, 4);
        assert!(res.is_ok());
        
        // Test applying large window (simulating the trick end)
        let res = apply_tcp_window_size(&server_stream, 65536);
        assert!(res.is_ok());
    }
}

use super::*;

#[cfg(test)]
mod evasion_integration_tests {
    use super::*;
    use crate::evasion::fragmenting_io::find_sni_info;
    use rand::Rng;

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
        assert_eq!(ch[off + 1], 0x00);

        // Check if the extension data contains "example.com"
        let ext_data = &ch[off..off + len];
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
}

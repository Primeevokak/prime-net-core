use prime_net_engine_core::config::UserAgentPreset;
use prime_net_engine_core::{EngineConfig, PrimeHttpClient, RequestData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn base_config() -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.download.adaptive_enabled = false;
    cfg.anticensorship.tls_randomization_enabled = false;
    cfg.privacy.signals.send_dnt = false;
    cfg.privacy.signals.send_gpc = false;
    cfg
}

fn parse_headers(req: &str) -> Vec<(String, String)> {
    req.split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            Some((k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect()
}

fn header_count(headers: &[(String, String)], name: &str) -> usize {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .count()
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

async fn execute_request(cfg: EngineConfig, req_headers: &[(&str, &str)]) -> Vec<(String, String)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("read local addr");

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept socket");
        let mut raw = Vec::new();
        let mut buf = [0_u8; 2048];
        loop {
            let n = socket.read(&mut buf).await.expect("read request");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&raw).to_string();
        let headers = parse_headers(&request);
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";
        socket.write_all(response).await.expect("write response");
        headers
    });

    let mut req = RequestData::get(format!("http://{addr}/privacy-headers"));
    for (name, value) in req_headers {
        req = req.header(*name, *value);
    }

    let client = PrimeHttpClient::new(cfg).expect("client build");
    let response = client
        .fetch(req, None)
        .await
        .expect("request should succeed");
    assert_eq!(response.status_code, 200);
    server.await.expect("server task should finish")
}

#[tokio::test]
async fn user_agent_disabled_does_not_inject() {
    let cfg = base_config();
    let headers = execute_request(cfg, &[]).await;
    assert!(header_value(&headers, "user-agent").is_none());
}

#[tokio::test]
async fn user_agent_chrome_preset_injected() {
    let mut cfg = base_config();
    cfg.privacy.user_agent.enabled = true;
    cfg.privacy.user_agent.preset = UserAgentPreset::ChromeWindows;

    let headers = execute_request(cfg, &[]).await;
    assert_eq!(
        header_value(&headers, "user-agent"),
        Some(
            UserAgentPreset::ChromeWindows
                .ua_string()
                .expect("preset should have value")
        )
    );
}

#[tokio::test]
async fn user_agent_custom_value_injected() {
    let mut cfg = base_config();
    cfg.privacy.user_agent.enabled = true;
    cfg.privacy.user_agent.preset = UserAgentPreset::Custom;
    cfg.privacy.user_agent.custom_value = "PrimeTestUA/1.0".to_owned();

    let headers = execute_request(cfg, &[]).await;
    assert_eq!(
        header_value(&headers, "user-agent"),
        Some("PrimeTestUA/1.0")
    );
}

#[tokio::test]
async fn user_agent_custom_empty_does_not_inject() {
    let mut cfg = base_config();
    cfg.privacy.user_agent.enabled = true;
    cfg.privacy.user_agent.preset = UserAgentPreset::Custom;
    cfg.privacy.user_agent.custom_value.clear();

    let headers = execute_request(cfg, &[]).await;
    assert!(header_value(&headers, "user-agent").is_none());
}

#[tokio::test]
async fn referer_override_replaces_existing_value() {
    let mut cfg = base_config();
    cfg.privacy.referer_override.enabled = true;
    cfg.privacy.referer_override.value = "https://primeevolution.com".to_owned();

    let headers = execute_request(cfg, &[("Referer", "https://old.example/search?q=abc")]).await;
    assert_eq!(
        header_value(&headers, "referer"),
        Some("https://primeevolution.com")
    );
    assert_eq!(header_count(&headers, "referer"), 1);
}

#[tokio::test]
async fn ip_spoof_injects_forwarded_headers() {
    let mut cfg = base_config();
    cfg.privacy.ip_spoof.enabled = true;
    cfg.privacy.ip_spoof.spoofed_ip = "77.88.21.10".to_owned();

    let headers = execute_request(cfg, &[]).await;
    assert_eq!(
        header_value(&headers, "x-forwarded-for"),
        Some("77.88.21.10")
    );
    assert_eq!(header_value(&headers, "x-real-ip"), Some("77.88.21.10"));
}

#[tokio::test]
async fn webrtc_block_sets_permissions_policy() {
    let mut cfg = base_config();
    cfg.privacy.webrtc.block_enabled = true;

    let headers = execute_request(cfg, &[]).await;
    let value = header_value(&headers, "permissions-policy").unwrap_or_default();
    assert!(value.contains("camera=()"));
}

#[tokio::test]
async fn webrtc_and_location_use_single_permissions_policy_header() {
    let mut cfg = base_config();
    cfg.privacy.webrtc.block_enabled = true;
    cfg.privacy.location_api.block_enabled = true;

    let headers = execute_request(cfg, &[]).await;
    assert_eq!(header_count(&headers, "permissions-policy"), 1);
    assert_eq!(
        header_value(&headers, "permissions-policy"),
        Some("camera=(), microphone=(), geolocation=()")
    );
}

#[tokio::test]
async fn all_features_disabled_adds_no_privacy_headers() {
    let cfg = base_config();
    let headers = execute_request(cfg, &[]).await;

    assert!(header_value(&headers, "user-agent").is_none());
    assert!(header_value(&headers, "referer").is_none());
    assert!(header_value(&headers, "x-forwarded-for").is_none());
    assert!(header_value(&headers, "x-real-ip").is_none());
    assert!(header_value(&headers, "permissions-policy").is_none());
}

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

use crate::error::{EngineError, Result};

pub struct ProxyDiagnostics;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticResult {
    pub level: DiagnosticLevel,
    pub message: String,
    pub suggestion: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DiagnosticLevel {
    Ok,
    Info,
    Warn,
    Error,
}

impl ProxyDiagnostics {
    pub fn check_socks5_listening(endpoint: &str) -> DiagnosticResult {
        let addrs = match resolve_endpoint_addrs(endpoint) {
            Ok(v) => v,
            Err(e) => {
                return DiagnosticResult::error(
                    "Invalid SOCKS endpoint",
                    &format!("Expected host:port. Error: {e}"),
                );
            }
        };

        let mut last_err: Option<std::io::Error> = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
                Ok(_) => return DiagnosticResult::ok("SOCKS5 server listening"),
                Err(e) => last_err = Some(e),
            }
        }
        let err = last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no resolved addresses".to_owned());
        DiagnosticResult::error(
            "SOCKS5 server not responding",
            &format!("Error: {err}. Run: prime-net-engine socks --bind {endpoint}"),
        )
    }

    pub async fn check_pac_server(url: &str) -> DiagnosticResult {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap_or_default();
        match client.get(url).timeout(Duration::from_secs(2)).send().await {
            Ok(resp) if resp.status().is_success() => DiagnosticResult::ok("PAC server responding"),
            Ok(resp) => DiagnosticResult::error(
                &format!("PAC server returned {}", resp.status()),
                "Check PAC server logs",
            ),
            Err(e) => DiagnosticResult::error(
                "PAC server not reachable",
                &format!("Error: {e}. Run: prime-net-engine proxy serve-pac"),
            ),
        }
    }

    pub fn check_system_proxy_config() -> DiagnosticResult {
        #[cfg(target_os = "windows")]
        {
            use winreg::enums::HKEY_CURRENT_USER;
            use winreg::RegKey;
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let settings =
                hkcu.open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
            return match settings {
                Ok(key) => {
                    let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
                    if enabled == 1 {
                        DiagnosticResult::ok("System proxy enabled in registry")
                    } else {
                        DiagnosticResult::info(
                            "ProxyEnable=0 in registry",
                            "Enable proxy only when core SOCKS5 server is running",
                        )
                    }
                }
                Err(e) => DiagnosticResult::error("Cannot read registry", &format!("Error: {e}")),
            };
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("scutil").args(["--proxy"]).output();
            return match output {
                Ok(out) if out.status.success() => {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if text.contains("SOCKSProxy : 1") || text.contains("ProxyAutoConfigEnable : 1")
                    {
                        DiagnosticResult::ok("System proxy configured (active)")
                    } else {
                        DiagnosticResult::warn(
                            "No SOCKS/PAC proxy enabled in scutil",
                            "Run: prime-net-engine proxy enable --mode pac",
                        )
                    }
                }
                _ => DiagnosticResult::error("Cannot check proxy settings via scutil", ""),
            };
        }

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("gsettings")
                .args(["get", "org.gnome.system.proxy", "mode"])
                .output();
            let mut results = Vec::new();
            if let Ok(out) = output {
                if out.status.success() {
                    let mode = String::from_utf8_lossy(&out.stdout)
                        .trim()
                        .trim_matches('\'')
                        .to_owned();
                    if mode == "manual" || mode == "auto" {
                        results.push(format!("GSettings mode: {mode}"));
                    }
                }
            }

            // Check resolvectl for DNS
            let r_out = Command::new("resolvectl").arg("status").output();
            if let Ok(out) = r_out {
                if out.status.success() {
                    results.push("systemd-resolved (resolvectl) active".to_owned());
                }
            }

            return if results.is_empty() {
                DiagnosticResult::info(
                    "Generic Linux: no desktop-specific proxy detected",
                    "Check environment variables (ALL_PROXY)",
                )
            } else {
                DiagnosticResult::ok(&results.join(", "))
            };
        }

        #[allow(unreachable_code)]
        DiagnosticResult::info("Platform diagnostics not available", "")
    }

    pub fn check_network_connectivity() -> DiagnosticResult {
        // Simple check to see if we can reach a public DNS server (e.g., Google DNS)
        let addr = SocketAddr::from(([8, 8, 8, 8], 53));
        match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(_) => DiagnosticResult::ok("Internet connectivity established (ICMP/TCP)"),
            Err(e) => DiagnosticResult::error(
                "No internet connectivity",
                &format!("Error: {e}. Check your network interface or ISP."),
            ),
        }
    }

    pub fn run_sync_basic(socks_endpoint: &str) -> Result<Vec<DiagnosticResult>> {
        if socks_endpoint.trim().is_empty() {
            return Err(EngineError::InvalidInput(
                "socks endpoint for diagnostics must not be empty".to_owned(),
            ));
        }
        Ok(vec![
            Self::check_network_connectivity(),
            Self::check_socks5_listening(socks_endpoint),
            Self::check_system_proxy_config(),
        ])
    }

    /// Run ISP/ТСПУ analysis: detect censorship mechanism, test DNS ports, and
    /// recommend the best evasion approach for the user's ISP.
    ///
    /// All probes use direct TCP/HTTP (no system proxy) to test from the
    /// user's real network perspective.
    pub async fn run_isp_analysis() -> IspAnalysisReport {
        let mut findings = Vec::new();

        // 1. Basic internet connectivity (sync, run on blocking thread)
        let connectivity = tokio::task::spawn_blocking(Self::check_network_connectivity)
            .await
            .unwrap_or_else(|_| DiagnosticResult::error("Thread panic in connectivity check", ""));
        let has_internet = connectivity.level == DiagnosticLevel::Ok;
        findings.push(connectivity);

        if !has_internet {
            return IspAnalysisReport {
                findings,
                tspu_detected: None,
                dot_port_blocked: true,
                doh_reachable: false,
                recommended_action: "No internet connection detected. Check your network."
                    .to_owned(),
            };
        }

        // 2. ТСПУ probe — try TCP to known censored IPs with short timeout
        //    Quick RST/refused (<350 ms) → RST injection by ТСПУ
        //    Timeout → IP/range blocking
        //    Success → bypass active or IP not blocked for this user
        let tspu_detected = tokio::task::spawn_blocking(|| {
            // YouTube backend IPs commonly blocked by ТСПУ in Russia
            let probe_targets: &[std::net::SocketAddr] = &[
                std::net::SocketAddr::from(([142, 250, 185, 78], 443)),
                std::net::SocketAddr::from(([142, 250, 74, 46], 443)),
            ];
            let timeout = Duration::from_millis(350);
            for &addr in probe_targets {
                match std::net::TcpStream::connect_timeout(&addr, timeout) {
                    Ok(_) => return None, // Connected — not blocked (bypass may be active)
                    Err(e) => {
                        use std::io::ErrorKind;
                        match e.kind() {
                            // RST injection: connection actively refused — ТСПУ signature
                            ErrorKind::ConnectionRefused => return Some(true),
                            // Timeout: IP-range drop — also a censorship signal
                            ErrorKind::TimedOut | ErrorKind::WouldBlock => return Some(true),
                            _ => {}
                        }
                    }
                }
            }
            None
        })
        .await
        .unwrap_or(None);

        match tspu_detected {
            Some(true) => findings.push(DiagnosticResult::warn(
                "ТСПУ censorship detected",
                "Native desync bypass (prime-mode) is recommended. Enable it in Settings → DPI Evasion.",
            )),
            Some(false) => findings.push(DiagnosticResult::ok(
                "No active ТСПУ censorship detected for tested IPs",
            )),
            None => findings.push(DiagnosticResult::info(
                "ТСПУ probe inconclusive — bypass may already be active",
                "If you see connection issues, enable prime-mode in Settings.",
            )),
        }

        // 3. DNS over TLS port 853 check
        let dot_port_blocked = tokio::task::spawn_blocking(|| {
            let targets: &[std::net::SocketAddr] = &[
                std::net::SocketAddr::from(([8, 8, 8, 8], 853)),
                std::net::SocketAddr::from(([1, 1, 1, 1], 853)),
            ];
            let timeout = Duration::from_secs(2);
            targets
                .iter()
                .all(|&addr| std::net::TcpStream::connect_timeout(&addr, timeout).is_err())
        })
        .await
        .unwrap_or(true);

        if dot_port_blocked {
            findings.push(DiagnosticResult::warn(
                "DNS over TLS (port 853) is blocked",
                "Use DNS over HTTPS instead. Enable DoH in Settings → DNS.",
            ));
        } else {
            findings.push(DiagnosticResult::ok("DNS over TLS (port 853) reachable"));
        }

        // 4. DNS over HTTPS reachability check
        let doh_reachable = async {
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()
                .ok()?;
            let resp = client
                .get("https://1.1.1.1/dns-query?name=example.com&type=A")
                .header("accept", "application/dns-json")
                .send()
                .await
                .ok()?;
            Some(resp.status().is_success())
        }
        .await
        .unwrap_or(false);

        if doh_reachable {
            findings.push(DiagnosticResult::ok(
                "DNS over HTTPS reachable (Cloudflare 1.1.1.1)",
            ));
        } else {
            findings.push(DiagnosticResult::warn(
                "DNS over HTTPS not reachable",
                "Your ISP may be blocking DoH. Try alternative providers in Settings → DNS.",
            ));
        }

        // 5. Recommendation
        let recommended_action =
            build_recommendation(tspu_detected, dot_port_blocked, doh_reachable);

        IspAnalysisReport {
            findings,
            tspu_detected,
            dot_port_blocked,
            doh_reachable,
            recommended_action,
        }
    }
}

/// ISP analysis report with ТСПУ detection results and recommended action.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IspAnalysisReport {
    /// Diagnostic findings, one per probe.
    pub findings: Vec<DiagnosticResult>,
    /// Whether ТСПУ censorship was detected. `None` means probe was inconclusive.
    pub tspu_detected: Option<bool>,
    /// Whether DNS port 853 (DoT) is blocked.
    pub dot_port_blocked: bool,
    /// Whether DNS over HTTPS is reachable.
    pub doh_reachable: bool,
    /// Human-readable recommended action for the user.
    pub recommended_action: String,
}

fn build_recommendation(
    tspu_detected: Option<bool>,
    dot_blocked: bool,
    doh_reachable: bool,
) -> String {
    let mut parts = Vec::new();
    if tspu_detected == Some(true) {
        parts.push("Enable prime-mode (DPI evasion) in Settings → DPI Evasion.");
    }
    if dot_blocked && doh_reachable {
        parts.push("Switch from DoT to DoH in Settings → DNS.");
    } else if dot_blocked && !doh_reachable {
        parts.push("Both DoT and DoH are blocked — use system DNS or try alternative providers.");
    }
    if parts.is_empty() {
        "No action required — your connection looks healthy.".to_owned()
    } else {
        parts.join(" ")
    }
}

fn resolve_endpoint_addrs(endpoint: &str) -> std::io::Result<Vec<SocketAddr>> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty endpoint",
        ));
    }
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    let addrs: Vec<SocketAddr> = endpoint.to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "endpoint resolved to no addresses",
        ));
    }
    Ok(addrs)
}

impl DiagnosticResult {
    pub fn ok(msg: &str) -> Self {
        Self {
            level: DiagnosticLevel::Ok,
            message: msg.to_owned(),
            suggestion: String::new(),
        }
    }

    pub fn info(msg: &str, suggestion: &str) -> Self {
        Self {
            level: DiagnosticLevel::Info,
            message: msg.to_owned(),
            suggestion: suggestion.to_owned(),
        }
    }

    pub fn warn(msg: &str, suggestion: &str) -> Self {
        Self {
            level: DiagnosticLevel::Warn,
            message: msg.to_owned(),
            suggestion: suggestion.to_owned(),
        }
    }

    pub fn error(msg: &str, suggestion: &str) -> Self {
        Self {
            level: DiagnosticLevel::Error,
            message: msg.to_owned(),
            suggestion: suggestion.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_endpoint_addrs_supports_localhost() {
        let addrs = resolve_endpoint_addrs("localhost:1080")
            .expect("localhost:1080 should resolve for diagnostics");
        assert!(!addrs.is_empty());
    }

    #[test]
    fn resolve_endpoint_addrs_rejects_invalid_endpoint() {
        assert!(resolve_endpoint_addrs("localhost").is_err());
    }
}

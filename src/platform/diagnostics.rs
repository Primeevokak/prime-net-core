use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

use crate::error::{EngineError, Result};

pub struct ProxyDiagnostics;

#[derive(Debug, Clone)]
pub struct DiagnosticResult {
    pub level: DiagnosticLevel,
    pub message: String,
    pub suggestion: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        let client = reqwest::Client::new();
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
        let addr = "8.8.8.8:53".parse::<SocketAddr>().unwrap();
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

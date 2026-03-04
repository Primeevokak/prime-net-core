use std::net::SocketAddr;
use std::time::Duration;

use crate::blocklist::{expand_tilde, BlocklistCache};
use crate::config::EngineConfig;
use crate::platform::diagnostics::{DiagnosticLevel, ProxyDiagnostics};

pub struct HealthChecker {
    config: EngineConfig,
}

impl HealthChecker {
    pub fn new(config: EngineConfig) -> Self {
        Self { config }
    }

    pub async fn run_all_checks(&self) -> Vec<HealthCheckResult> {
        vec![
            self.check_socks5_port().await,
            self.check_pac_server().await,
            self.check_system_proxy(),
            self.check_blocklist_freshness(),
        ]
    }

    async fn check_socks5_port(&self) -> HealthCheckResult {
        let endpoint = self.config.system_proxy.socks_endpoint.clone();
        let resolve =
            tokio::time::timeout(Duration::from_secs(1), tokio::net::lookup_host(&endpoint)).await;
        let mut addrs: std::vec::IntoIter<SocketAddr> = match resolve {
            Ok(Ok(v)) => v.collect::<Vec<_>>().into_iter(),
            Ok(Err(_)) | Err(_) => {
                return HealthCheckResult::error(
                    "Invalid SOCKS5 endpoint in config",
                    "Set system_proxy.socks_endpoint to host:port",
                );
            }
        };
        let Some(addr) = addrs.next() else {
            return HealthCheckResult::error(
                "Invalid SOCKS5 endpoint in config",
                "Set system_proxy.socks_endpoint to host:port",
            );
        };

        match tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr))
            .await
        {
            Ok(Ok(_)) => HealthCheckResult::ok("SOCKS5 server running"),
            Ok(Err(e)) => HealthCheckResult::warn("SOCKS5 not responding", &e.to_string()),
            Err(_) => HealthCheckResult::warn("SOCKS5 check timed out", ""),
        }
    }

    async fn check_pac_server(&self) -> HealthCheckResult {
        let url = format!(
            "http://127.0.0.1:{}/proxy.pac",
            self.config.system_proxy.pac_port
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build();
        let Ok(client) = client else {
            return HealthCheckResult::info("PAC check unavailable", "");
        };
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                HealthCheckResult::ok("PAC server responding")
            }
            _ => HealthCheckResult::warn(
                "PAC server not running",
                "Run: prime-net-engine proxy serve-pac",
            ),
        }
    }

    fn check_system_proxy(&self) -> HealthCheckResult {
        let diagnostics = ProxyDiagnostics::check_system_proxy_config();
        match diagnostics.level {
            DiagnosticLevel::Ok => HealthCheckResult::ok(&diagnostics.message),
            DiagnosticLevel::Info => {
                HealthCheckResult::info(&diagnostics.message, &diagnostics.suggestion)
            }
            DiagnosticLevel::Warn => {
                HealthCheckResult::warn(&diagnostics.message, &diagnostics.suggestion)
            }
            DiagnosticLevel::Error => {
                HealthCheckResult::error(&diagnostics.message, &diagnostics.suggestion)
            }
        }
    }

    fn check_blocklist_freshness(&self) -> HealthCheckResult {
        let path = expand_tilde(&self.config.blocklist.cache_path);
        let cache = BlocklistCache::status(&path);
        let Ok(cache) = cache else {
            return HealthCheckResult::warn(
                "Blocklist cache is unreadable",
                "Run: prime-net-engine blocklist update",
            );
        };

        let Some(cache) = cache else {
            return HealthCheckResult::warn(
                "Blocklist not downloaded",
                "Run: prime-net-engine blocklist update",
            );
        };

        let age_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH + Duration::from_secs(cache.updated_at_unix))
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if age_secs > 7 * 24 * 3600 {
            HealthCheckResult::warn(
                &format!("Blocklist outdated ({} days old)", age_secs / 86_400),
                "Run: prime-net-engine blocklist update",
            )
        } else {
            HealthCheckResult::ok(&format!("Blocklist fresh ({} hours old)", age_secs / 3600))
        }
    }
}

pub struct HealthCheckResult {
    pub level: HealthLevel,
    pub message: String,
    pub suggestion: String,
}

pub enum HealthLevel {
    Ok,
    Info,
    Warn,
    Error,
}

impl HealthCheckResult {
    pub fn ok(msg: &str) -> Self {
        Self {
            level: HealthLevel::Ok,
            message: msg.to_owned(),
            suggestion: String::new(),
        }
    }

    pub fn info(msg: &str, suggestion: &str) -> Self {
        Self {
            level: HealthLevel::Info,
            message: msg.to_owned(),
            suggestion: suggestion.to_owned(),
        }
    }

    pub fn warn(msg: &str, suggestion: &str) -> Self {
        Self {
            level: HealthLevel::Warn,
            message: msg.to_owned(),
            suggestion: suggestion.to_owned(),
        }
    }

    pub fn error(msg: &str, suggestion: &str) -> Self {
        Self {
            level: HealthLevel::Error,
            message: msg.to_owned(),
            suggestion: suggestion.to_owned(),
        }
    }
}

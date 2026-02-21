use std::process::Command;

use crate::error::{EngineError, Result};
use crate::platform::{ProxyManager, ProxyMode, ProxyStatus};

pub struct MacOSProxyManager;

#[derive(Debug, Clone)]
pub enum MacOSProxyMode {
    Manual(String),
    Pac(String),
}

impl MacOSProxyManager {
    pub fn list_network_services() -> Result<Vec<String>> {
        let out = Command::new("networksetup")
            .arg("-listallnetworkservices")
            .output()?;
        if !out.status.success() {
            return Err(EngineError::Internal(
                String::from_utf8_lossy(&out.stderr).to_string(),
            ));
        }
        let mut items = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("An asterisk") || line.starts_with('*') {
                continue;
            }
            items.push(line.to_owned());
        }
        if items.is_empty() {
            return Err(EngineError::Internal(
                "no active macOS network services found".to_owned(),
            ));
        }
        Ok(items)
    }

    fn services() -> Result<Vec<String>> {
        Self::list_network_services()
    }

    fn run_ok(args: &[&str]) -> Result<()> {
        let out = Command::new("networksetup").args(args).output()?;
        if out.status.success() {
            return Ok(());
        }
        Err(EngineError::Internal(
            String::from_utf8_lossy(&out.stderr).to_string(),
        ))
    }

    pub fn get_primary_service() -> Result<String> {
        let out = Command::new("route").args(["get", "default"]).output()?;
        if !out.status.success() {
            return Self::services()?
                .into_iter()
                .next()
                .ok_or_else(|| EngineError::Internal("no network services found".to_owned()));
        }
        let body = String::from_utf8_lossy(&out.stdout);
        let interface = body.lines().find_map(|line| {
            line.split_once("interface:")
                .map(|(_, v)| v.trim().to_owned())
        });
        let Some(interface) = interface else {
            return Self::services()?
                .into_iter()
                .next()
                .ok_or_else(|| EngineError::Internal("no network services found".to_owned()));
        };

        for service in Self::services()? {
            let info = Command::new("networksetup")
                .args(["-getinfo", &service])
                .output()?;
            if info.status.success() {
                let text = String::from_utf8_lossy(&info.stdout);
                if text.contains(&interface) {
                    return Ok(service);
                }
            }
        }

        Self::services()?
            .into_iter()
            .next()
            .ok_or_else(|| EngineError::Internal("no network services found".to_owned()))
    }

    fn enable_for_service(&self, service: &str, endpoint: &str) -> Result<()> {
        let (host, port) = parse_endpoint(endpoint)?;
        Self::run_ok(&["-setsocksfirewallproxy", service, host, port])?;
        Self::run_ok(&["-setsocksfirewallproxystate", service, "on"])?;
        Self::run_ok(&["-setautoproxystate", service, "off"])?;
        Ok(())
    }

    pub fn set_proxy_mode(&self, service: &str, mode: MacOSProxyMode) -> Result<()> {
        match mode {
            MacOSProxyMode::Manual(endpoint) => self.enable_for_service(service, &endpoint),
            MacOSProxyMode::Pac(url) => {
                Self::run_ok(&["-setautoproxyurl", service, &url])?;
                Self::run_ok(&["-setautoproxystate", service, "on"])?;
                Self::run_ok(&["-setsocksfirewallproxystate", service, "off"])?;
                Ok(())
            }
        }
    }

    pub fn enable_all_services(&self, endpoint: &str) -> Result<()> {
        for service in Self::services()? {
            self.set_proxy_mode(&service, MacOSProxyMode::Manual(endpoint.to_owned()))?;
        }
        Ok(())
    }
}

impl ProxyManager for MacOSProxyManager {
    fn enable(&self, socks_endpoint: &str) -> Result<()> {
        self.enable_all_services(socks_endpoint)
    }

    fn enable_pac(&self, pac_url: &str) -> Result<()> {
        for service in Self::services()? {
            self.set_proxy_mode(&service, MacOSProxyMode::Pac(pac_url.to_owned()))?;
        }
        Ok(())
    }

    fn disable(&self) -> Result<()> {
        for service in Self::services()? {
            Self::run_ok(&["-setsocksfirewallproxystate", &service, "off"])?;
            Self::run_ok(&["-setautoproxystate", &service, "off"])?;
        }
        Ok(())
    }

    fn status(&self) -> Result<ProxyStatus> {
        let service = Self::get_primary_service()?;
        let out = Command::new("networksetup")
            .args(["-getsocksfirewallproxy", &service])
            .output()?;
        let body = String::from_utf8_lossy(&out.stdout);
        let enabled = body.lines().any(|l| l.contains("Enabled: Yes"));
        let server = body
            .lines()
            .find_map(|l| l.strip_prefix("Server: "))
            .map(|s| s.trim().to_owned());
        let port = body
            .lines()
            .find_map(|l| l.strip_prefix("Port: "))
            .map(|s| s.trim().to_owned());

        let socks_endpoint = match (server, port) {
            (Some(h), Some(p)) => Some(format!("{h}:{p}")),
            _ => None,
        };

        let pac_out = Command::new("networksetup")
            .args(["-getautoproxyurl", &service])
            .output()?;
        let pac_body = String::from_utf8_lossy(&pac_out.stdout);
        let pac_enabled = pac_body.lines().any(|l| l.contains("Enabled: Yes"));
        let pac_url = pac_body
            .lines()
            .find_map(|l| l.strip_prefix("URL: "))
            .map(|s| s.trim().to_owned());

        Ok(ProxyStatus {
            enabled: enabled || pac_enabled,
            mode: if pac_enabled {
                ProxyMode::Pac
            } else if enabled {
                ProxyMode::All
            } else {
                ProxyMode::Off
            },
            socks_endpoint,
            pac_url,
        })
    }
}

fn parse_endpoint(endpoint: &str) -> Result<(&str, &str)> {
    let e = endpoint.trim();
    if let Some(stripped) = e.strip_prefix('[') {
        if let Some((host, rest)) = stripped.split_once("]:") {
            if !host.is_empty() && !rest.is_empty() {
                return Ok((host, rest));
            }
        }
    }
    if let Some((host, port)) = e.rsplit_once(':') {
        let host = host.trim();
        let port = port.trim();
        if !host.is_empty() && !port.is_empty() {
            return Ok((host, port));
        }
    }
    Err(EngineError::InvalidInput(
        "invalid socks endpoint (expected host:port)".to_owned(),
    ))
}

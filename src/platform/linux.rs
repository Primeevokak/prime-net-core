use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::error::{EngineError, Result};
use crate::platform::{ProxyManager, ProxyMode, ProxyStatus};

pub struct LinuxProxyManager;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopEnvironment {
    Gnome,
    Kde,
    Xfce,
    Mate,
    Cinnamon,
    Unknown,
}

impl LinuxProxyManager {
    fn run_ok(program: &str, args: &[&str]) -> bool {
        Command::new(program)
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn write_env_file(socks_endpoint: &str) -> Result<()> {
        let path = Self::env_file();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = format!("ALL_PROXY=socks5://{socks_endpoint}\n");
        fs::write(path, content)?;
        Ok(())
    }

    fn env_file() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
            return home
                .join(".config")
                .join("prime-net-engine")
                .join("proxy.env");
        }
        PathBuf::from("proxy.env")
    }

    fn run_out(program: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(program).args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    fn trim_single_quotes(input: &str) -> String {
        let trimmed = input.trim();
        trimmed.trim_matches('\'').to_owned()
    }

    fn gsettings_get(schema: &str, key: &str) -> Option<String> {
        Self::run_out("gsettings", &["get", schema, key])
            .map(|v| Self::trim_single_quotes(&v))
            .and_then(|v| if v.is_empty() { None } else { Some(v) })
    }

    fn env_socks_endpoint() -> Option<String> {
        if let Ok(value) = std::env::var("ALL_PROXY") {
            return Some(value.trim_start_matches("socks5://").to_owned());
        }
        let raw = fs::read_to_string(Self::env_file()).ok()?;
        for line in raw.lines() {
            if let Some(value) = line.strip_prefix("ALL_PROXY=") {
                return Some(
                    value
                        .trim()
                        .trim_matches('"')
                        .trim_start_matches("socks5://")
                        .to_owned(),
                );
            }
        }
        None
    }

    fn parse_endpoint(endpoint: &str) -> (String, String) {
        let e = endpoint.trim();
        if let Some(stripped) = e.strip_prefix('[') {
            if let Some((host, rest)) = stripped.split_once("]:") {
                return (host.to_owned(), rest.to_owned());
            }
        }
        let mut parts = e.rsplitn(2, ':');
        let port = parts.next().unwrap_or("1080").to_owned();
        let host = parts.next().unwrap_or("127.0.0.1").to_owned();
        (host, port)
    }

    pub fn detect_de() -> DesktopEnvironment {
        if let Ok(value) = std::env::var("XDG_CURRENT_DESKTOP") {
            let v = value.to_ascii_lowercase();
            if v.contains("gnome") {
                return DesktopEnvironment::Gnome;
            }
            if v.contains("kde") {
                return DesktopEnvironment::Kde;
            }
            if v.contains("xfce") {
                return DesktopEnvironment::Xfce;
            }
            if v.contains("mate") {
                return DesktopEnvironment::Mate;
            }
            if v.contains("cinnamon") {
                return DesktopEnvironment::Cinnamon;
            }
        }
        if Self::is_process_running("gnome-shell") {
            return DesktopEnvironment::Gnome;
        }
        if Self::is_process_running("kwin") {
            return DesktopEnvironment::Kde;
        }
        DesktopEnvironment::Unknown
    }

    fn is_process_running(name: &str) -> bool {
        Command::new("pgrep")
            .arg(name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn configure_gnome(endpoint: &str) -> bool {
        let (host, port) = Self::parse_endpoint(endpoint);
        let mode_ok = Self::run_ok(
            "gsettings",
            &["set", "org.gnome.system.proxy", "mode", "manual"],
        );
        let host_ok = Self::run_ok(
            "gsettings",
            &[
                "set",
                "org.gnome.system.proxy.socks",
                "host",
                &format!("'{host}'"),
            ],
        );
        let port_ok = Self::run_ok(
            "gsettings",
            &["set", "org.gnome.system.proxy.socks", "port", &port],
        );
        mode_ok && host_ok && port_ok
    }

    fn configure_kde(endpoint: &str) -> bool {
        let (host, port) = Self::parse_endpoint(endpoint);
        let first = Self::run_ok(
            "kwriteconfig5",
            &[
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "ProxyType",
                "1",
            ],
        );
        let second = Self::run_ok(
            "kwriteconfig5",
            &[
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "socksProxy",
                &format!("{host}:{port}"),
            ],
        );
        first && second
    }

    fn configure_xfce(_endpoint: &str) -> bool {
        true
    }

    fn configure_mate(endpoint: &str) -> bool {
        Self::configure_gnome(endpoint)
    }

    fn configure_env_vars(endpoint: &str) -> Result<()> {
        let path = Self::env_file();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut lines = Vec::new();
        lines.push(format!("ALL_PROXY=socks5://{endpoint}"));
        lines.push(format!("all_proxy=socks5://{endpoint}"));
        lines.push(format!("HTTP_PROXY=socks5://{endpoint}"));
        lines.push(format!("HTTPS_PROXY=socks5://{endpoint}"));
        fs::write(path, lines.join("\n") + "\n")?;
        Ok(())
    }

    pub fn configure_networkmanager(&self, pac_url: &str) -> Result<()> {
        let conn_name = Self::get_active_nm_connection()?;
        let status = Command::new("nmcli")
            .args([
                "connection",
                "modify",
                &conn_name,
                "proxy.method",
                "auto",
                "proxy.pac-url",
                pac_url,
            ])
            .status()?;
        if !status.success() {
            return Err(EngineError::Internal(
                "failed to apply NetworkManager PAC settings".to_owned(),
            ));
        }
        Ok(())
    }

    fn get_active_nm_connection() -> Result<String> {
        let output = Command::new("nmcli")
            .args(["-t", "-f", "NAME", "connection", "show", "--active"])
            .output()?;
        if !output.status.success() {
            return Err(EngineError::Internal(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .map(|s| s.to_owned())
            .ok_or_else(|| EngineError::Internal("no active NetworkManager connection".to_owned()))
    }

    pub fn set_system_dns(&self, dns_server: &str) -> Result<()> {
        // Try resolvectl (systemd-resolved)
        if Self::run_ok("resolvectl", &["status"]) {
            if let Ok(iface) = Self::get_default_interface() {
                let _ = Command::new("resolvectl").args(["dns", &iface, dns_server]).status();
                let _ = Command::new("resolvectl").args(["domain", &iface, "~."]).status();
                let _ = Command::new("resolvectl").arg("flush-caches").status();
            }
        }

        // Also try NetworkManager as a backup
        if let Ok(conn) = Self::get_active_nm_connection() {
            let _ = Command::new("nmcli")
                .args(["connection", "modify", &conn, "ipv4.dns", dns_server, "ipv4.ignore-auto-dns", "yes"])
                .status();
            let _ = Command::new("nmcli").args(["connection", "up", &conn]).status();
        }

        Ok(())
    }

    pub fn reset_system_dns(&self) -> Result<()> {
        if Self::run_ok("resolvectl", &["status"]) {
            if let Ok(iface) = Self::get_default_interface() {
                let _ = Command::new("resolvectl").args(["revert", &iface]).status();
            }
        }
        if let Ok(conn) = Self::get_active_nm_connection() {
            let _ = Command::new("nmcli")
                .args(["connection", "modify", &conn, "-ipv4.dns", "ipv4.ignore-auto-dns", "no"])
                .status();
            let _ = Command::new("nmcli").args(["connection", "up", &conn]).status();
        }
        Ok(())
    }

    fn get_default_interface() -> Result<String> {
        let out = Command::new("ip").args(["route", "show", "default"]).output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.split_whitespace()
            .nth(4)
            .map(|s| s.to_owned())
            .ok_or_else(|| EngineError::Internal("could not find default network interface".to_owned()))
    }
}

impl ProxyManager for LinuxProxyManager {
    fn enable(&self, socks_endpoint: &str) -> Result<()> {
        let applied = match Self::detect_de() {
            DesktopEnvironment::Gnome | DesktopEnvironment::Cinnamon => {
                Self::configure_gnome(socks_endpoint)
            }
            DesktopEnvironment::Kde => Self::configure_kde(socks_endpoint),
            DesktopEnvironment::Xfce => Self::configure_xfce(socks_endpoint),
            DesktopEnvironment::Mate => Self::configure_mate(socks_endpoint),
            DesktopEnvironment::Unknown => false,
        };
        if !applied {
            Self::configure_env_vars(socks_endpoint)?;
        } else {
            Self::write_env_file(socks_endpoint)?;
        }
        Ok(())
    }

    fn enable_pac(&self, pac_url: &str) -> Result<()> {
        let gnome_ok = Self::run_ok(
            "gsettings",
            &["set", "org.gnome.system.proxy", "mode", "auto"],
        ) && Self::run_ok(
            "gsettings",
            &["set", "org.gnome.system.proxy", "autoconfig-url", pac_url],
        );
        if !gnome_ok {
            let _ = self.configure_networkmanager(pac_url);
        }
        Ok(())
    }

    fn disable(&self) -> Result<()> {
        let _ = Self::run_ok(
            "gsettings",
            &["set", "org.gnome.system.proxy", "mode", "none"],
        );
        let path = Self::env_file();
        if path.exists() {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }

    fn set_dns(&self, dns_server: &str) -> Result<()> {
        self.set_system_dns(dns_server)
    }

    fn reset_dns(&self) -> Result<()> {
        self.reset_system_dns()
    }

    fn status(&self) -> Result<ProxyStatus> {
        let pac_mode = matches!(
            Self::gsettings_get("org.gnome.system.proxy", "mode").as_deref(),
            Some("auto")
        );
        let pac_url = if pac_mode {
            Self::gsettings_get("org.gnome.system.proxy", "autoconfig-url")
        } else {
            None
        };
        let socks_endpoint = Self::env_socks_endpoint();
        let gnome_manual = matches!(
            Self::gsettings_get("org.gnome.system.proxy", "mode").as_deref(),
            Some("manual")
        );
        let enabled = pac_url.is_some() || socks_endpoint.is_some() || gnome_manual;
        Ok(ProxyStatus {
            enabled,
            mode: if pac_url.is_some() {
                ProxyMode::Pac
            } else if socks_endpoint.is_some() || gnome_manual {
                ProxyMode::All
            } else {
                ProxyMode::Off
            },
            socks_endpoint,
            pac_url,
        })
    }
}

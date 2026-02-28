use crate::error::Result;

pub mod diagnostics;
pub mod ttl;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyMode {
    Off,
    All,
    Pac,
}

#[derive(Debug, Clone)]
pub struct ProxyStatus {
    pub enabled: bool,
    pub mode: ProxyMode,
    pub socks_endpoint: Option<String>,
    pub pac_url: Option<String>,
}

pub trait ProxyManager: Send + Sync {
    fn enable(&self, socks_endpoint: &str) -> Result<()>;
    fn enable_pac(&self, pac_url: &str) -> Result<()>;
    fn disable(&self) -> Result<()>;
    fn status(&self) -> Result<ProxyStatus>;

    /// Sets the system DNS server (e.g. to 127.0.0.1) to prevent leaks.
    fn set_dns(&self, _dns_server: &str) -> Result<()> {
        Ok(())
    }

    /// Resets system DNS to automatic/default settings.
    fn reset_dns(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub fn system_proxy_manager() -> Box<dyn ProxyManager> {
    Box::new(windows::WindowsProxyManager)
}

pub fn resolve_process_id_by_connection(
    local: std::net::SocketAddr,
    remote: std::net::SocketAddr,
) -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        windows::get_process_id_by_connection(local, remote)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (local, remote);
        None
    }
}

pub fn resolve_process_name_by_pid(pid: u32) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        windows::get_process_name_by_pid(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "macos")]
pub fn system_proxy_manager() -> Box<dyn ProxyManager> {
    Box::new(macos::MacOSProxyManager)
}

#[cfg(target_os = "linux")]
pub fn system_proxy_manager() -> Box<dyn ProxyManager> {
    Box::new(linux::LinuxProxyManager)
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub fn system_proxy_manager() -> Box<dyn ProxyManager> {
    Box::new(UnsupportedProxyManager)
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
struct UnsupportedProxyManager;

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
impl ProxyManager for UnsupportedProxyManager {
    fn enable(&self, _socks_endpoint: &str) -> Result<()> {
        Err(crate::error::EngineError::Internal(
            "system proxy is not supported on this platform".to_owned(),
        ))
    }

    fn enable_pac(&self, _pac_url: &str) -> Result<()> {
        Err(crate::error::EngineError::Internal(
            "system proxy is not supported on this platform".to_owned(),
        ))
    }

    fn disable(&self) -> Result<()> {
        Err(crate::error::EngineError::Internal(
            "system proxy is not supported on this platform".to_owned(),
        ))
    }

    fn status(&self) -> Result<ProxyStatus> {
        Err(crate::error::EngineError::Internal(
            "system proxy is not supported on this platform".to_owned(),
        ))
    }
}

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;

use crate::error::{EngineError, Result};
use crate::platform::{ProxyManager, ProxyMode, ProxyStatus};

const INTERNET_SETTINGS: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WindowsProxyBackup {
    proxy_enable: u32,
    proxy_server: Option<String>,
    auto_config_url: Option<String>,
    proxy_override: Option<String>,
}

pub struct WindowsProxyManager;

impl WindowsProxyManager {
    const DEFAULT_PROXY_BYPASS: &'static str =
        "localhost;127.*;10.*;192.168.*;172.16.*;*.local;<local>";

    fn backup_path() -> PathBuf {
        if let Some(dir) = dirs::config_dir() {
            return dir
                .join("prime-net-engine")
                .join("proxy-backup-windows.json");
        }
        PathBuf::from("proxy-backup-windows.json")
    }

    fn save_backup(backup: &WindowsProxyBackup) -> Result<()> {
        let path = Self::backup_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(backup)
            .map_err(|e| EngineError::Internal(format!("backup encode failed: {e}")))?;
        fs::write(path, data)?;
        Ok(())
    }

    fn clear_backup() -> Result<()> {
        let path = Self::backup_path();
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(EngineError::Io(e)),
        }
    }

    fn load_backup() -> Result<Option<WindowsProxyBackup>> {
        let path = Self::backup_path();
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(path)?;
        let parsed: WindowsProxyBackup = serde_json::from_slice(&raw)
            .map_err(|e| EngineError::Internal(format!("backup decode failed: {e}")))?;
        Ok(Some(parsed))
    }

    fn save_backup_if_missing(&self) -> Result<()> {
        if Self::load_backup()?.is_none() {
            let backup = self.backup_current_settings()?;
            Self::save_backup(&backup)?;
        }
        Ok(())
    }

    fn open_settings_read() -> Result<RegKey> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        hkcu.open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ)
            .map_err(EngineError::Io)
    }

    fn open_settings_write() -> Result<RegKey> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        hkcu.open_subkey_with_flags(INTERNET_SETTINGS, KEY_SET_VALUE | KEY_READ)
            .map_err(EngineError::Io)
    }

    fn broadcast_settings_change() {
        let mut param = "Internet Settings\0".encode_utf16().collect::<Vec<u16>>();
        if param.is_empty() || *param.last().unwrap_or(&0) != 0 {
            param.push(0);
        }
        unsafe {
            let _ = SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                param.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                2000,
                std::ptr::null_mut(),
            );
        }
    }

    pub fn requires_elevation(&self) -> bool {
        Command::new("net")
            .args(["session"])
            .status()
            .map(|s| !s.success())
            .unwrap_or(true)
    }

    pub fn request_elevation(&self) -> Result<()> {
        if self.requires_elevation() {
            return Err(EngineError::Internal(
                "administrator privileges may be required for some proxy operations".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn refresh_internet_settings(&self) -> Result<()> {
        unsafe {
            let ok_changed = InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            ) != 0;
            let ok_refresh = InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null_mut(),
                0,
            ) != 0;
            if !ok_changed || !ok_refresh {
                return Err(EngineError::Internal(
                    "failed to refresh internet settings".to_owned(),
                ));
            }
        }
        Self::broadcast_settings_change();
        Ok(())
    }

    pub fn get_active_adapters(&self) -> Result<Vec<String>> {
        let out = Command::new("netsh")
            .args(["interface", "show", "interface"])
            .output()?;
        if !out.status.success() {
            return Err(EngineError::Internal(
                String::from_utf8_lossy(&out.stderr).to_string(),
            ));
        }
        let mut adapters = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("Admin State")
                || trimmed.starts_with("---")
            {
                continue;
            }
            let cols = trimmed.split_whitespace().collect::<Vec<_>>();
            if cols.len() < 4 {
                continue;
            }
            let state = cols[1].to_ascii_lowercase();
            if state != "connected" {
                continue;
            }
            let name = cols[3..].join(" ");
            if !name.is_empty() {
                adapters.push(name);
            }
        }
        Ok(adapters)
    }

    pub fn enable_per_adapter(&self, adapter: &str, endpoint: &str) -> Result<()> {
        let _ = self.request_elevation();
        let proxy_value = Self::composite_proxy_server(endpoint);
        let settings = format!(
            "{{\"Proxy\":\"{proxy_value}\",\"ProxyBypass\":\"{}\"}}",
            Self::DEFAULT_PROXY_BYPASS
        );
        let out = Command::new("netsh")
            .args([
                "winhttp",
                "set",
                "advproxy",
                "setting-scope=user",
                &format!("settings={settings}"),
            ])
            .output()?;
        if !out.status.success() {
            return Err(EngineError::Internal(format!(
                "failed to set adapter proxy for {adapter}: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    pub fn set_proxy_bypass(&self, bypass: &str) -> Result<()> {
        let key_w = Self::open_settings_write()?;
        let value = if bypass.trim().is_empty() {
            Self::DEFAULT_PROXY_BYPASS
        } else {
            bypass
        };
        key_w.set_value("ProxyOverride", &value)?;
        Ok(())
    }

    fn backup_current_settings(&self) -> Result<WindowsProxyBackup> {
        let key_r = Self::open_settings_read()?;
        Ok(WindowsProxyBackup {
            proxy_enable: key_r.get_value("ProxyEnable").unwrap_or(0_u32),
            proxy_server: key_r.get_value("ProxyServer").ok(),
            auto_config_url: key_r.get_value("AutoConfigURL").ok(),
            proxy_override: key_r.get_value("ProxyOverride").ok(),
        })
    }

    fn restore_from_backup(&self, backup: &WindowsProxyBackup) -> Result<()> {
        let key_w = Self::open_settings_write()?;
        key_w.set_value("ProxyEnable", &backup.proxy_enable)?;
        match &backup.proxy_server {
            Some(v) => key_w.set_value("ProxyServer", v)?,
            None => {
                let _ = key_w.delete_value("ProxyServer");
            }
        }
        match &backup.auto_config_url {
            Some(v) => key_w.set_value("AutoConfigURL", v)?,
            None => {
                let _ = key_w.delete_value("AutoConfigURL");
            }
        }
        match &backup.proxy_override {
            Some(v) => key_w.set_value("ProxyOverride", v)?,
            None => {
                let _ = key_w.delete_value("ProxyOverride");
            }
        }
        self.refresh_internet_settings()?;
        Ok(())
    }

    fn extract_socks_endpoint(proxy_server: &str) -> Option<String> {
        let raw = proxy_server.trim();
        if raw.is_empty() {
            return None;
        }
        if !raw.contains('=') {
            return Some(raw.to_owned());
        }

        for part in raw.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((scheme, value)) = part.split_once('=') {
                let scheme = scheme.trim().to_ascii_lowercase();
                let value = value.trim();
                if (scheme == "socks" || scheme == "socks5") && !value.is_empty() {
                    return Some(value.to_owned());
                }
                if (scheme == "http" || scheme == "https") && !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
        }
        None
    }

    fn include_socks_proxy_entry() -> bool {
        std::env::var("PRIME_WINDOWS_PROXY_INCLUDE_SOCKS")
            .map(|v| {
                !matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "off"
                )
            })
            .unwrap_or(false)
    }

    fn composite_proxy_server(endpoint: &str) -> String {
        // On Windows many apps downgrade SOCKS to v4 (IP-literal requests), which harms
        // anti-censorship effectiveness. Prefer HTTP/HTTPS CONNECT by default.
        if Self::include_socks_proxy_entry() {
            return format!("http={endpoint};https={endpoint};socks={endpoint}");
        }
        format!("http={endpoint};https={endpoint}")
    }
}

pub fn get_process_id_by_connection(
    local: std::net::SocketAddr,
    remote: std::net::SocketAddr,
) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let mut dw_size = 0;
    let family = if local.is_ipv4() {
        AF_INET as u32
    } else {
        AF_INET6 as u32
    };

    // Initial call to get required size
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut dw_size,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }

    let mut buffer = vec![0u8; dw_size as usize];
    let ret = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut dw_size,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if ret != 0 {
        return None;
    }

    if local.is_ipv4() {
        let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let num_entries = unsafe { (*table).dwNumEntries };
        let entries =
            unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), num_entries as usize) };

        for entry in entries {
            let entry_local_addr = std::net::Ipv4Addr::from(u32::from_be(entry.dwLocalAddr));
            let entry_local_port = u16::from_be(entry.dwLocalPort as u16);
            let entry_remote_addr = std::net::Ipv4Addr::from(u32::from_be(entry.dwRemoteAddr));
            let entry_remote_port = u16::from_be(entry.dwRemotePort as u16);

            if let (std::net::SocketAddr::V4(l), std::net::SocketAddr::V4(r)) = (local, remote) {
                if entry_local_addr == *l.ip()
                    && entry_local_port == l.port()
                    && entry_remote_addr == *r.ip()
                    && entry_remote_port == r.port()
                {
                    return Some(entry.dwOwningPid);
                }
            }
        }
    } else {
        let table = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
        let num_entries = unsafe { (*table).dwNumEntries };
        let entries =
            unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), num_entries as usize) };

        for entry in entries {
            let entry_local_addr = std::net::Ipv6Addr::from(entry.ucLocalAddr);
            let entry_local_port = u16::from_be(entry.dwLocalPort as u16);
            let entry_remote_addr = std::net::Ipv6Addr::from(entry.ucRemoteAddr);
            let entry_remote_port = u16::from_be(entry.dwRemotePort as u16);

            if let (std::net::SocketAddr::V6(l), std::net::SocketAddr::V6(r)) = (local, remote) {
                if entry_local_addr == *l.ip()
                    && entry_local_port == l.port()
                    && entry_remote_addr == *r.ip()
                    && entry_remote_port == r.port()
                {
                    return Some(entry.dwOwningPid);
                }
            }
        }
    }

    None
}

pub fn get_process_name_by_pid(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle: HANDLE = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut buffer = [0u16; 1024];
    let mut size = buffer.len() as u32;
    let res = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut size)
    };

    unsafe { CloseHandle(handle) };

    if res == 0 {
        return None;
    }

    let path = String::from_utf16_lossy(&buffer[..size as usize]);
    std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
}

#[repr(C)]
#[allow(non_snake_case)]
struct MIB_TCPROW_OWNER_PID {
    dwState: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
    dwOwningPid: u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct MIB_TCPTABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_TCPROW_OWNER_PID; 1],
}

#[repr(C)]
#[allow(non_snake_case)]
struct MIB_TCP6ROW_OWNER_PID {
    ucLocalAddr: [u8; 16],
    dwLocalScopeId: u32,
    dwLocalPort: u32,
    ucRemoteAddr: [u8; 16],
    dwRemoteScopeId: u32,
    dwRemotePort: u32,
    dwState: u32,
    dwOwningPid: u32,
}

#[repr(C)]
#[allow(non_snake_case)]
struct MIB_TCP6TABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_TCP6ROW_OWNER_PID; 1],
}

impl ProxyManager for WindowsProxyManager {
    fn enable(&self, socks_endpoint: &str) -> Result<()> {
        self.save_backup_if_missing()?;

        let key_w = Self::open_settings_write()?;
        key_w.set_value("ProxyEnable", &1_u32)?;
        key_w.set_value("ProxyServer", &Self::composite_proxy_server(socks_endpoint))?;
        let _ = key_w.delete_value("AutoConfigURL");
        self.set_proxy_bypass("")?;

        if let Ok(adapters) = self.get_active_adapters() {
            for adapter in adapters {
                let _ = self.enable_per_adapter(&adapter, socks_endpoint);
            }
        }

        self.refresh_internet_settings()?;
        Ok(())
    }

    fn enable_pac(&self, pac_url: &str) -> Result<()> {
        self.save_backup_if_missing()?;

        let key_w = Self::open_settings_write()?;
        key_w.set_value("ProxyEnable", &0_u32)?;
        key_w.set_value("AutoConfigURL", &pac_url)?;
        self.set_proxy_bypass("")?;

        self.refresh_internet_settings()?;
        Ok(())
    }

    fn disable(&self) -> Result<()> {
        if let Some(b) = Self::load_backup()? {
            self.restore_from_backup(&b)?;
            Self::clear_backup()?;
        } else {
            let key_w = Self::open_settings_write()?;
            key_w.set_value("ProxyEnable", &0_u32)?;
            let _ = key_w.delete_value("ProxyServer");
            let _ = key_w.delete_value("AutoConfigURL");
            let _ = key_w.delete_value("ProxyOverride");
            self.refresh_internet_settings()?;
        }
        Ok(())
    }

    fn status(&self) -> Result<ProxyStatus> {
        let key = Self::open_settings_read()?;
        let enabled = key.get_value("ProxyEnable").unwrap_or(0_u32) != 0;
        let server: Option<String> = key.get_value("ProxyServer").ok();
        let pac: Option<String> = key.get_value("AutoConfigURL").ok();
        let socks_endpoint = server.as_deref().and_then(Self::extract_socks_endpoint);
        let mode = if pac.as_deref().is_some() {
            ProxyMode::Pac
        } else if enabled {
            ProxyMode::All
        } else {
            ProxyMode::Off
        };

        Ok(ProxyStatus {
            enabled: enabled || pac.is_some(),
            mode,
            socks_endpoint,
            pac_url: pac,
        })
    }
}

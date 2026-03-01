use std::fs;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{EngineError, Result};
use crate::tls::TlsConfig;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EngineConfig {
    pub download: DownloadConfig,
    pub anticensorship: AntiCensorshipConfig,
    pub evasion: EvasionConfig,
    #[serde(default)]
    pub privacy: PrivacyConfig,
    pub proxy: Option<ProxyConfig>,
    #[serde(default)]
    pub system_proxy: SystemProxyConfig,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
    #[serde(default)]
    pub updater: UpdaterConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// Optional pluggable transport (PT) stack. When enabled, the engine will typically expose a local
    /// SOCKS5 endpoint and route HTTP/DNS through it.
    #[serde(default)]
    pub pt: Option<PluggableTransportConfig>,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Best-effort: prefer HTTP/3 (QUIC) for `https://` requests when supported by the build.
    #[serde(default)]
    pub prefer_http3: bool,
    /// If true, do not fall back to TCP transports when HTTP/3 was selected.
    #[serde(default)]
    pub http3_only: bool,
    /// HTTP/3 connect timeout in milliseconds.
    #[serde(default = "default_http3_connect_timeout_ms")]
    pub http3_connect_timeout_ms: u64,
    /// HTTP/3 idle timeout in milliseconds.
    #[serde(default = "default_http3_idle_timeout_ms")]
    pub http3_idle_timeout_ms: u64,
    /// Optional keep-alive interval in milliseconds (sends QUIC keep-alives).
    #[serde(default)]
    pub http3_keep_alive_interval_ms: Option<u64>,
    /// DANGEROUS: accept invalid certificates for HTTP/3 (intended for testing).
    #[serde(default)]
    pub http3_insecure_skip_verify: bool,
}

fn default_http3_connect_timeout_ms() -> u64 {
    10_000
}

fn default_http3_idle_timeout_ms() -> u64 {
    30_000
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            prefer_http3: false,
            http3_only: false,
            http3_connect_timeout_ms: default_http3_connect_timeout_ms(),
            http3_idle_timeout_ms: default_http3_idle_timeout_ms(),
            http3_keep_alive_interval_ms: None,
            http3_insecure_skip_verify: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivacyConfig {
    #[serde(default)]
    pub tracker_blocker: TrackerBlockerConfig,
    #[serde(default)]
    pub referer: RefererConfig,
    #[serde(default)]
    pub signals: PrivacySignalsConfig,
    #[serde(default)]
    pub user_agent: UserAgentConfig,
    #[serde(default)]
    pub referer_override: RefererOverrideConfig,
    #[serde(default)]
    pub ip_spoof: IpSpoofConfig,
    #[serde(default)]
    pub webrtc: WebRtcConfig,
    #[serde(default)]
    pub location_api: LocationApiConfig,
}

/// User-Agent spoofing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UserAgentConfig {
    /// Master on/off switch.
    pub enabled: bool,
    /// Active preset.
    pub preset: UserAgentPreset,
    /// Custom User-Agent string used when `preset == Custom`.
    pub custom_value: String,
}

/// User-Agent preset selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserAgentPreset {
    /// Chrome on Windows 10 preset.
    ChromeWindows,
    /// Firefox on Linux preset.
    FirefoxLinux,
    /// Safari on macOS preset.
    SafariMacOs,
    /// Custom User-Agent string from config.
    #[default]
    Custom,
}

impl UserAgentPreset {
    /// Returns a hardcoded User-Agent string for built-in presets.
    ///
    /// Returns `None` for `Custom`.
    pub fn ua_string(&self) -> Option<&'static str> {
        match self {
            Self::ChromeWindows => Some(concat!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ",
                "AppleWebKit/537.36 (KHTML, like Gecko) ",
                "Chrome/124.0.0.0 Safari/537.36"
            )),
            Self::FirefoxLinux => Some(concat!(
                "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) ",
                "Gecko/20100101 Firefox/125.0"
            )),
            Self::SafariMacOs => Some(concat!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) ",
                "AppleWebKit/605.1.15 (KHTML, like Gecko) ",
                "Version/17.4.1 Safari/605.1.15"
            )),
            Self::Custom => None,
        }
    }
}

impl Default for UserAgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            preset: UserAgentPreset::Custom,
            custom_value: String::new(),
        }
    }
}

/// Referer override configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RefererOverrideConfig {
    /// Master on/off switch.
    pub enabled: bool,
    /// Referer value that will be injected into every outgoing request.
    pub value: String,
}

impl Default for RefererOverrideConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            value: "https://primeevolution.com".to_owned(),
        }
    }
}

/// X-Forwarded-For / X-Real-IP spoofing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IpSpoofConfig {
    /// Master on/off switch.
    pub enabled: bool,
    /// Spoofed IP value used for `X-Forwarded-For` and `X-Real-IP`.
    pub spoofed_ip: String,
}

impl Default for IpSpoofConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            spoofed_ip: "77.88.21.10".to_owned(),
        }
    }
}

/// Best-effort WebRTC leak protection configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct WebRtcConfig {
    /// Enables WebRTC-related header signal injection.
    pub block_enabled: bool,
}

/// Location API suppression configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LocationApiConfig {
    /// Enables geolocation header signal injection.
    pub block_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerBlockerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tracker_lists")]
    pub lists: Vec<String>,
    #[serde(default)]
    pub custom_lists: Vec<String>,
    #[serde(default)]
    pub mode: TrackerBlockerMode,
    #[serde(default)]
    pub on_block: TrackerBlockAction,
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Default for TrackerBlockerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lists: default_tracker_lists(),
            custom_lists: Vec::new(),
            mode: TrackerBlockerMode::default(),
            on_block: TrackerBlockAction::default(),
            allowlist: Vec::new(),
        }
    }
}

fn default_tracker_lists() -> Vec<String> {
    vec!["easyprivacy".to_owned(), "easylist".to_owned()]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrackerBlockerMode {
    #[default]
    Block,
    LogOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrackerBlockAction {
    #[default]
    Error,
    Empty200,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefererConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: RefererMode,
    #[serde(default = "default_strip_from_search_engines")]
    pub strip_from_search_engines: bool,
    #[serde(default)]
    pub search_engine_domains: Vec<String>,
}

impl Default for RefererConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: RefererMode::default(),
            strip_from_search_engines: default_strip_from_search_engines(),
            search_engine_domains: Vec::new(),
        }
    }
}

fn default_strip_from_search_engines() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RefererMode {
    Strip,
    #[default]
    OriginOnly,
    PassThrough,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacySignalsConfig {
    #[serde(default = "default_send_dnt")]
    pub send_dnt: bool,
    #[serde(default = "default_send_gpc")]
    pub send_gpc: bool,
}

impl Default for PrivacySignalsConfig {
    fn default() -> Self {
        Self {
            send_dnt: default_send_dnt(),
            send_gpc: default_send_gpc(),
        }
    }
}

fn default_send_dnt() -> bool {
    true
}

fn default_send_gpc() -> bool {
    true
}


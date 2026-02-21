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

impl EngineConfig {
    pub fn builder() -> EngineConfigBuilder {
        EngineConfigBuilder::new()
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        let ext = path
            .extension()
            .and_then(|v| v.to_str())
            .unwrap_or_default();
        let mut config: EngineConfig = match ext {
            "toml" => toml::from_str(&content).map_err(|e| EngineError::Config(e.to_string()))?,
            "json" => {
                serde_json::from_str(&content).map_err(|e| EngineError::Config(e.to_string()))?
            }
            "yaml" | "yml" => {
                serde_yaml::from_str(&content).map_err(|e| EngineError::Config(e.to_string()))?
            }
            _ => toml::from_str(&content)
                .or_else(|_| serde_json::from_str(&content))
                .or_else(|_| serde_yaml::from_str(&content))
                .map_err(|e| EngineError::Config(e.to_string()))?,
        };
        let _ = config.apply_compat_repairs();
        config.validate()?;
        Ok(config)
    }

    /// Applies compatibility repairs for legacy or partially-migrated configs.
    ///
    /// Returns textual notes describing each applied repair.
    pub fn apply_compat_repairs(&mut self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.anticensorship.domain_fronting_enabled
            && self.anticensorship.domain_fronting_rules.is_empty()
        {
            self.anticensorship.domain_fronting_enabled = false;
            notes.push(
                "anticensorship.domain_fronting_enabled disabled because domain_fronting_rules is empty"
                    .to_owned(),
            );
        }

        let old_chain = self.anticensorship.dns_fallback_chain.clone();
        self.anticensorship
            .dns_fallback_chain
            .retain(|kind| match kind {
                DnsResolverKind::Doh => self.anticensorship.doh_enabled,
                DnsResolverKind::Dot => self.anticensorship.dot_enabled,
                DnsResolverKind::Doq => self.anticensorship.doq_enabled,
                DnsResolverKind::System => self.anticensorship.system_dns_enabled,
            });
        if self.anticensorship.dns_fallback_chain.is_empty() {
            if self.anticensorship.doh_enabled {
                self.anticensorship
                    .dns_fallback_chain
                    .push(DnsResolverKind::Doh);
            } else if self.anticensorship.system_dns_enabled {
                self.anticensorship
                    .dns_fallback_chain
                    .push(DnsResolverKind::System);
            } else if self.anticensorship.dot_enabled {
                self.anticensorship
                    .dns_fallback_chain
                    .push(DnsResolverKind::Dot);
            } else if self.anticensorship.doq_enabled {
                self.anticensorship
                    .dns_fallback_chain
                    .push(DnsResolverKind::Doq);
            }
        }
        if self.anticensorship.dns_fallback_chain != old_chain {
            notes.push(
                "anticensorship.dns_fallback_chain repaired to match enabled resolvers".to_owned(),
            );
        }

        let old_doh = self.anticensorship.doh_providers.clone();
        self.anticensorship
            .doh_providers
            .retain(|p| !p.trim().eq_ignore_ascii_case("cloudflare"));
        if self.anticensorship.doh_providers.is_empty() {
            self.anticensorship.doh_providers = vec![
                "adguard".to_owned(),
                "google".to_owned(),
                "quad9".to_owned(),
            ];
        }
        if self.anticensorship.doh_providers != old_doh {
            notes.push(
                "anticensorship.doh_providers repaired: cloudflare removed, adguard/google/quad9 prioritized"
                    .to_owned(),
            );
        }

        let old_dot = self.anticensorship.dot_servers.clone();
        self.anticensorship.dot_servers.retain(|s| {
            let v = s.trim();
            v != "1.1.1.1:853" && v != "1.0.0.1:853"
        });
        if self.anticensorship.dot_enabled && self.anticensorship.dot_servers.is_empty() {
            self.anticensorship.dot_servers = vec![
                "94.140.14.14:853".to_owned(),
                "94.140.15.15:853".to_owned(),
                "8.8.8.8:853".to_owned(),
                "8.8.4.4:853".to_owned(),
            ];
            self.anticensorship.dot_sni = "dns.adguard-dns.com".to_owned();
        }
        if self.anticensorship.dot_servers != old_dot {
            notes.push(
                "anticensorship.dot_servers repaired: cloudflare endpoints removed".to_owned(),
            );
        }

        let old_doq = self.anticensorship.doq_servers.clone();
        self.anticensorship.doq_servers.retain(|s| {
            let v = s.trim();
            v != "1.1.1.1:784" && v != "1.0.0.1:784"
        });
        if self.anticensorship.doq_enabled && self.anticensorship.doq_servers.is_empty() {
            self.anticensorship.doq_servers =
                vec!["94.140.14.14:784".to_owned(), "94.140.15.15:784".to_owned()];
            self.anticensorship.doq_sni = "dns.adguard-dns.com".to_owned();
        }
        if self.anticensorship.doq_servers != old_doq {
            notes.push(
                "anticensorship.doq_servers repaired: cloudflare endpoints removed".to_owned(),
            );
        }
        notes
    }

    pub fn validate(&self) -> Result<()> {
        self.tls.validate()?;
        if self.anticensorship.effective_ech_mode().is_some() {
            let min = self.tls.min_version;
            let max = self.tls.max_version;
            let min_r = tls_version_rank(min);
            let max_r = tls_version_rank(max);
            if !(min_r <= tls_version_rank(crate::tls::TlsVersion::Tls1_3)
                && max_r >= tls_version_rank(crate::tls::TlsVersion::Tls1_3))
            {
                return Err(EngineError::Config(
                    "anticensorship.ech_mode requires TLS 1.3 to be allowed by tls.min_version/tls.max_version"
                        .to_owned(),
                ));
            }
        }
        if self.download.initial_concurrency == 0 {
            return Err(EngineError::Config(
                "download.initial_concurrency must be > 0".to_owned(),
            ));
        }
        if self.download.max_concurrency == 0 {
            return Err(EngineError::Config(
                "download.max_concurrency must be > 0".to_owned(),
            ));
        }
        if self.download.initial_concurrency > self.download.max_concurrency {
            return Err(EngineError::Config(
                "download.initial_concurrency cannot exceed max_concurrency".to_owned(),
            ));
        }
        if self.download.chunk_size_mb == 0 {
            return Err(EngineError::Config(
                "download.chunk_size_mb must be > 0".to_owned(),
            ));
        }
        if self.download.request_timeout_secs == 0 || self.download.connect_timeout_secs == 0 {
            return Err(EngineError::Config(
                "request/connect timeout values must be > 0".to_owned(),
            ));
        }
        if self.transport.http3_connect_timeout_ms == 0 {
            return Err(EngineError::Config(
                "transport.http3_connect_timeout_ms must be > 0".to_owned(),
            ));
        }
        if self.transport.http3_only && !self.transport.prefer_http3 {
            return Err(EngineError::Config(
                "transport.http3_only=true requires transport.prefer_http3=true".to_owned(),
            ));
        }
        if self.transport.http3_idle_timeout_ms == 0 {
            return Err(EngineError::Config(
                "transport.http3_idle_timeout_ms must be > 0".to_owned(),
            ));
        }
        if let Some(v) = self.transport.http3_keep_alive_interval_ms {
            if v == 0 {
                return Err(EngineError::Config(
                    "transport.http3_keep_alive_interval_ms must be > 0 when set".to_owned(),
                ));
            }
        }
        if let Some(pt) = &self.pt {
            if self.proxy.is_some() {
                return Err(EngineError::Config(
                    "pt is enabled but proxy is also set; use only one (pt will provide a local socks5 endpoint)"
                        .to_owned(),
                ));
            }
            if pt.local_socks5_bind.trim().is_empty() {
                return Err(EngineError::Config(
                    "pt.local_socks5_bind must not be empty".to_owned(),
                ));
            }
            match pt.kind {
                PluggableTransportKind::Trojan => {
                    let t = pt.trojan.as_ref().ok_or_else(|| {
                        EngineError::Config("pt.kind=trojan requires [pt].trojan".to_owned())
                    })?;
                    if t.server.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.trojan.server must not be empty".to_owned(),
                        ));
                    }
                    if t.password.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.trojan.password must not be empty".to_owned(),
                        ));
                    }
                }
                PluggableTransportKind::Shadowsocks => {
                    let s = pt.shadowsocks.as_ref().ok_or_else(|| {
                        EngineError::Config(
                            "pt.kind=shadowsocks requires [pt].shadowsocks".to_owned(),
                        )
                    })?;
                    if s.server.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.shadowsocks.server must not be empty".to_owned(),
                        ));
                    }
                    if s.password.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.shadowsocks.password must not be empty".to_owned(),
                        ));
                    }
                    if s.method.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.shadowsocks.method must not be empty".to_owned(),
                        ));
                    }
                }
                PluggableTransportKind::Obfs4 => {
                    let o = pt.obfs4.as_ref().ok_or_else(|| {
                        EngineError::Config("pt.kind=obfs4 requires [pt].obfs4".to_owned())
                    })?;
                    if o.server.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.obfs4.server must not be empty".to_owned(),
                        ));
                    }
                    if o.cert.trim().is_empty() {
                        return Err(EngineError::Config(
                            "pt.obfs4.cert must not be empty".to_owned(),
                        ));
                    }
                }
                PluggableTransportKind::Snowflake => {
                    let s = pt.snowflake.as_ref().ok_or_else(|| {
                        EngineError::Config("pt.kind=snowflake requires [pt].snowflake".to_owned())
                    })?;
                    if let Some(bridge) = s.bridge.as_deref() {
                        if bridge.trim().is_empty() {
                            return Err(EngineError::Config(
                                "pt.snowflake.bridge must not be empty when set".to_owned(),
                            ));
                        }
                    }
                }
            }
        }
        if let Some(v) = self.evasion.tls_record_max_fragment_size {
            // TLS maximum fragment length is capped at 2^14 (16384) bytes (RFC 8446/5246 record limits).
            if v == 0 || v > 16_384 {
                return Err(EngineError::Config(
                    "evasion.tls_record_max_fragment_size must be in 1..=16384".to_owned(),
                ));
            }
        }
        if !self.evasion.client_hello_split_offsets.is_empty() {
            let mut prev = 0usize;
            for &off in &self.evasion.client_hello_split_offsets {
                if off == 0 {
                    return Err(EngineError::Config(
                        "evasion.client_hello_split_offsets must not contain 0".to_owned(),
                    ));
                }
                if off <= prev {
                    return Err(EngineError::Config(
                        "evasion.client_hello_split_offsets must be strictly increasing".to_owned(),
                    ));
                }
                prev = off;
            }
        }
        if self.evasion.fragment_budget_bytes == 0 {
            return Err(EngineError::Config(
                "evasion.fragment_budget_bytes must be > 0".to_owned(),
            ));
        }
        if self.evasion.classifier_entry_ttl_secs == 0 {
            return Err(EngineError::Config(
                "evasion.classifier_entry_ttl_secs must be > 0".to_owned(),
            ));
        }
        if self.evasion.classifier_cache_path.trim().is_empty() {
            return Err(EngineError::Config(
                "evasion.classifier_cache_path must not be empty".to_owned(),
            ));
        }
        if self.evasion.traffic_shaping_enabled
            && self.evasion.timing_jitter_ms_min > self.evasion.timing_jitter_ms_max
        {
            return Err(EngineError::Config(
                "evasion.timing_jitter_ms_min must be <= evasion.timing_jitter_ms_max".to_owned(),
            ));
        }
        if let Some(v) = self.download.http2_max_concurrent_reset_streams {
            if v == 0 {
                return Err(EngineError::Config(
                    "download.http2_max_concurrent_reset_streams must be > 0".to_owned(),
                ));
            }
        }
        if let Some(v) = self.download.verify_hash.as_deref() {
            let v = v.trim();
            if v.is_empty() {
                return Err(EngineError::Config(
                    "download.verify_hash must not be empty when provided".to_owned(),
                ));
            }
            if v.eq_ignore_ascii_case("auto") {
                // Expected digest comes from "<file>.sha256" at runtime.
            } else if let Some(hex) = v.strip_prefix("sha256:") {
                let hex = hex.trim();
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(EngineError::Config(
                        "download.verify_hash must be 'auto' or 'sha256:<64 hex>'".to_owned(),
                    ));
                }
            } else {
                return Err(EngineError::Config(
                    "download.verify_hash must be 'auto' or 'sha256:<64 hex>'".to_owned(),
                ));
            }
        }
        if self.anticensorship.domain_fronting_enabled
            && self.anticensorship.domain_fronting_rules.is_empty()
        {
            return Err(EngineError::Config(
                "anticensorship.domain_fronting_rules must be provided when domain_fronting_enabled=true"
                    .to_owned(),
            ));
        }
        for rule in &self.anticensorship.domain_fronting_rules {
            if rule.target_host.trim().is_empty() {
                return Err(EngineError::Config(
                    "anticensorship.domain_fronting_rules[*].target_host is empty".to_owned(),
                ));
            }
            let has_v2 = rule.front_domains.iter().any(|d| !d.trim().is_empty());
            let has_v1 = !rule.front_domain.trim().is_empty();
            if !(has_v1 || has_v2) {
                return Err(EngineError::Config(
                    "anticensorship.domain_fronting_rules[*] must have front_domain or front_domains".to_owned(),
                ));
            }
            if rule.front_domains.iter().any(|d| d.trim().is_empty()) {
                return Err(EngineError::Config(
                    "anticensorship.domain_fronting_rules[*].front_domains contains empty domain"
                        .to_owned(),
                ));
            }
            if rule.real_host.trim().is_empty() {
                return Err(EngineError::Config(
                    "anticensorship.domain_fronting_rules[*].real_host is empty".to_owned(),
                ));
            }
        }

        if self.anticensorship.dns_fallback_chain.is_empty() {
            return Err(EngineError::Config(
                "anticensorship.dns_fallback_chain must not be empty".to_owned(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for kind in &self.anticensorship.dns_fallback_chain {
            if !seen.insert(kind) {
                return Err(EngineError::Config(
                    "anticensorship.dns_fallback_chain contains duplicate entries".to_owned(),
                ));
            }
        }
        if !self.anticensorship.doh_enabled
            && self
                .anticensorship
                .dns_fallback_chain
                .contains(&DnsResolverKind::Doh)
        {
            return Err(EngineError::Config(
                "anticensorship.dns_fallback_chain includes doh but doh_enabled=false".to_owned(),
            ));
        }
        if !self.anticensorship.dot_enabled
            && self
                .anticensorship
                .dns_fallback_chain
                .contains(&DnsResolverKind::Dot)
        {
            return Err(EngineError::Config(
                "anticensorship.dns_fallback_chain includes dot but dot_enabled=false".to_owned(),
            ));
        }
        if self.anticensorship.dot_enabled && self.anticensorship.dot_servers.is_empty() {
            return Err(EngineError::Config(
                "anticensorship.dot_servers must not be empty when dot_enabled=true".to_owned(),
            ));
        }
        if !self.anticensorship.doq_enabled
            && self
                .anticensorship
                .dns_fallback_chain
                .contains(&DnsResolverKind::Doq)
        {
            return Err(EngineError::Config(
                "anticensorship.dns_fallback_chain includes doq but doq_enabled=false".to_owned(),
            ));
        }
        if self.anticensorship.doq_enabled && self.anticensorship.doq_servers.is_empty() {
            return Err(EngineError::Config(
                "anticensorship.doq_servers must not be empty when doq_enabled=true".to_owned(),
            ));
        }
        if !self.anticensorship.system_dns_enabled
            && self
                .anticensorship
                .dns_fallback_chain
                .contains(&DnsResolverKind::System)
        {
            return Err(EngineError::Config(
                "anticensorship.dns_fallback_chain includes system but system_dns_enabled=false"
                    .to_owned(),
            ));
        }
        if self.blocklist.update_interval_hours == 0 {
            return Err(EngineError::Config(
                "blocklist.update_interval_hours must be > 0".to_owned(),
            ));
        }
        if self.system_proxy.pac_port == 0 {
            return Err(EngineError::Config(
                "system_proxy.pac_port must be in 1..=65535".to_owned(),
            ));
        }
        if !is_host_port_endpoint(&self.system_proxy.socks_endpoint) {
            return Err(EngineError::Config(
                "system_proxy.socks_endpoint must be 'host:port' (IPv6: '[::1]:port')".to_owned(),
            ));
        }
        if self.updater.check_interval_hours == 0 {
            return Err(EngineError::Config(
                "updater.check_interval_hours must be > 0".to_owned(),
            ));
        }
        if !is_valid_repo_slug(&self.updater.repo) {
            return Err(EngineError::Config(
                "updater.repo must be 'owner/name'".to_owned(),
            ));
        }
        for domain in &self.privacy.referer.search_engine_domains {
            if normalize_domain(domain).is_none() {
                return Err(EngineError::Config(
                    "privacy.referer.search_engine_domains must contain valid domains".to_owned(),
                ));
            }
        }
        for domain in &self.privacy.tracker_blocker.allowlist {
            if normalize_domain(domain).is_none() {
                return Err(EngineError::Config(
                    "privacy.tracker_blocker.allowlist must contain valid domains".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn tls_version_rank(v: crate::tls::TlsVersion) -> u8 {
    match v {
        crate::tls::TlsVersion::Tls1_0 => 10,
        crate::tls::TlsVersion::Tls1_1 => 11,
        crate::tls::TlsVersion::Tls1_2 => 12,
        crate::tls::TlsVersion::Tls1_3 => 13,
    }
}

fn is_host_port_endpoint(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return false;
    }

    if let Some(rest) = v.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return false;
        };
        if host.trim().is_empty() {
            return false;
        }
        let Some(port) = tail.strip_prefix(':') else {
            return false;
        };
        return port.trim().parse::<u16>().map(|p| p > 0).unwrap_or(false);
    }

    let Some((host, port)) = v.rsplit_once(':') else {
        return false;
    };
    if host.trim().is_empty() {
        return false;
    }
    port.trim().parse::<u16>().map(|p| p > 0).unwrap_or(false)
}

fn is_valid_repo_slug(value: &str) -> bool {
    let mut parts = value.trim().split('/');
    let Some(owner) = parts.next() else {
        return false;
    };
    let Some(name) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    if owner.is_empty() || name.is_empty() {
        return false;
    }
    let valid = |seg: &str| {
        seg.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    valid(owner) && valid(name)
}

fn normalize_domain(value: &str) -> Option<String> {
    let v = value.trim().trim_start_matches("*.").trim_end_matches('.');
    if v.is_empty() || !v.contains('.') {
        return None;
    }
    if v.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    {
        Some(v.to_ascii_lowercase())
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadConfig {
    pub initial_concurrency: usize,
    pub max_concurrency: usize,
    pub chunk_size_mb: usize,
    pub max_retries: usize,
    pub adaptive_enabled: bool,
    pub adaptive_threshold_mbps: f64,
    pub request_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub max_idle_per_host: usize,
    pub pool_idle_timeout_secs: u64,
    /// Best-effort protection for problematic servers during high-concurrency HTTP/2 downloads.
    ///
    /// Reqwest does not currently expose hyper's `http2_max_concurrent_reset_streams` knob. In this build,
    /// the value is used to limit internal probe operations that may cause stream resets.
    #[serde(default)]
    pub http2_max_concurrent_reset_streams: Option<usize>,
    /// Optional integrity verification for downloads.
    ///
    /// Supported values:
    /// - "sha256:<64-hex>" to verify against an explicit digest
    /// - "auto" to read expected digest from a sibling "<file>.sha256" file
    #[serde(default)]
    pub verify_hash: Option<String>,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            initial_concurrency: 4,
            max_concurrency: 16,
            chunk_size_mb: 4,
            max_retries: 2,
            adaptive_enabled: true,
            adaptive_threshold_mbps: 25.0,
            request_timeout_secs: 30,
            connect_timeout_secs: 10,
            max_idle_per_host: 16,
            pool_idle_timeout_secs: 30,
            http2_max_concurrent_reset_streams: None,
            verify_hash: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiCensorshipConfig {
    pub doh_enabled: bool,
    pub doh_providers: Vec<String>,
    pub doh_cache_ttl_secs: u64,
    #[serde(default)]
    pub bootstrap_ips: Vec<IpAddr>,
    #[serde(default)]
    pub dnssec_enabled: bool,
    #[serde(default = "default_dns_cache_size")]
    pub dns_cache_size: usize,
    #[serde(default = "default_dns_timeout_secs")]
    pub dns_query_timeout_secs: u64,
    #[serde(default = "default_dns_attempts")]
    pub dns_attempts: usize,
    #[serde(default)]
    pub dot_enabled: bool,
    #[serde(default)]
    pub dot_servers: Vec<String>,
    #[serde(default = "default_dot_sni")]
    pub dot_sni: String,
    #[serde(default)]
    pub doq_enabled: bool,
    #[serde(default)]
    pub doq_servers: Vec<String>,
    #[serde(default = "default_doq_sni")]
    pub doq_sni: String,
    #[serde(default)]
    pub dns_fallback_chain: Vec<DnsResolverKind>,
    #[serde(default)]
    pub system_dns_enabled: bool,
    /// Preferred ECH behavior.
    ///
    /// If set, it enables ECH and overrides legacy `ech_enabled`.
    #[serde(default)]
    pub ech_mode: Option<EchMode>,
    /// Legacy switch for enabling ECH GREASE (placeholder). Prefer `ech_mode`.
    #[serde(default)]
    pub ech_enabled: bool,
    pub domain_fronting_enabled: bool,
    #[serde(default)]
    pub domain_fronting_rules: Vec<DomainFrontingRule>,
    /// Cache TTL for dynamic fronting probe results.
    #[serde(default = "default_fronting_probe_ttl_secs")]
    pub fronting_probe_ttl_secs: u64,
    /// Timeout for the dynamic fronting availability probe (HEAD request).
    #[serde(default = "default_fronting_probe_timeout_secs")]
    pub fronting_probe_timeout_secs: u64,
    pub tls_randomization_enabled: bool,
}

impl Default for AntiCensorshipConfig {
    fn default() -> Self {
        Self {
            doh_enabled: true,
            doh_providers: vec![
                "adguard".to_owned(),
                "google".to_owned(),
                "quad9".to_owned(),
            ],
            doh_cache_ttl_secs: 300,
            bootstrap_ips: Vec::new(),
            dnssec_enabled: true,
            dns_cache_size: default_dns_cache_size(),
            dns_query_timeout_secs: default_dns_timeout_secs(),
            dns_attempts: default_dns_attempts(),
            dot_enabled: false,
            dot_servers: vec![
                "94.140.14.14:853".to_owned(),
                "94.140.15.15:853".to_owned(),
                "8.8.8.8:853".to_owned(),
                "8.8.4.4:853".to_owned(),
            ],
            dot_sni: default_dot_sni(),
            doq_enabled: false,
            doq_servers: vec!["94.140.14.14:784".to_owned(), "94.140.15.15:784".to_owned()],
            doq_sni: default_doq_sni(),
            dns_fallback_chain: vec![DnsResolverKind::Doh, DnsResolverKind::System],
            system_dns_enabled: true,
            ech_mode: None,
            ech_enabled: false,
            domain_fronting_enabled: false,
            domain_fronting_rules: Vec::new(),
            fronting_probe_ttl_secs: default_fronting_probe_ttl_secs(),
            fronting_probe_timeout_secs: default_fronting_probe_timeout_secs(),
            tls_randomization_enabled: true,
        }
    }
}

fn default_fronting_probe_ttl_secs() -> u64 {
    600
}

fn default_fronting_probe_timeout_secs() -> u64 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EchMode {
    Grease,
    Real,
    Auto,
}

impl AntiCensorshipConfig {
    /// Returns the effective ECH behavior.
    ///
    /// - If `ech_mode` is set, it enables ECH and selects the specified mode.
    /// - Else if legacy `ech_enabled=true`, it enables ECH GREASE.
    pub fn effective_ech_mode(&self) -> Option<EchMode> {
        if let Some(m) = &self.ech_mode {
            return Some(m.clone());
        }
        if self.ech_enabled {
            return Some(EchMode::Grease);
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum DnsResolverKind {
    Doh,
    Dot,
    Doq,
    System,
}

fn default_dns_cache_size() -> usize {
    4096
}

fn default_dns_timeout_secs() -> u64 {
    5
}

fn default_dns_attempts() -> usize {
    2
}

fn default_dot_sni() -> String {
    "dns.adguard-dns.com".to_owned()
}

fn default_doq_sni() -> String {
    "dns.adguard-dns.com".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFrontingRule {
    pub target_host: String,
    /// Legacy single front domain (v1).
    #[serde(default)]
    pub front_domain: String,
    /// Dynamic front domain candidates (v2). If set and non-empty, it takes precedence over `front_domain`.
    #[serde(default)]
    pub front_domains: Vec<String>,
    pub real_host: String,
    pub sni_domain: Option<String>,
    #[serde(default)]
    pub provider: FrontingProvider,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FrontingProvider {
    #[default]
    Cloudflare,
    Fastly,
    GoogleCdn,
    AzureCdn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    /// Main offline DPI bypass profile for direct SOCKS relay ("prime-mode").
    #[serde(default = "default_prime_mode")]
    pub prime_mode: bool,
    #[serde(default)]
    pub strategy: Option<EvasionStrategy>,
    #[serde(default = "default_fragment_size")]
    pub fragment_size: usize,
    #[serde(default = "default_fragment_sleep_ms")]
    pub fragment_sleep_ms: u64,
    /// Optional TLS maximum fragment size (in bytes) applied only for the fragment path.
    ///
    /// This influences TLS record sizing (best-effort; depends on peer support for MFL).
    #[serde(default)]
    pub tls_record_max_fragment_size: Option<usize>,
    /// Max retries for the "TCP RST circuit breaker" fallback (enable fragment on the fly).
    #[serde(default = "default_rst_retry_max")]
    pub rst_retry_max: usize,
    pub traffic_shaping_enabled: bool,
    pub timing_jitter_ms_min: u64,
    pub timing_jitter_ms_max: u64,
    /// Optional explicit split offsets for TLS ClientHello segmentation (best-effort).
    ///
    /// Offsets are byte positions within the first TLS write buffer. The engine will attempt to split
    /// the first outgoing TLS bytes into 3+ parts at these offsets when `strategy="desync"`.
    #[serde(default)]
    pub client_hello_split_offsets: Vec<usize>,
    /// If true, the relay attempts SNI-aware split for the first TLS ClientHello write.
    #[serde(default = "default_split_at_sni")]
    pub split_at_sni: bool,
    /// Windows-oriented first-packet TTL tweak (0 disables).
    #[serde(default)]
    pub first_packet_ttl: u8,
    /// Max number of early outbound bytes eligible for fragmentation in SOCKS relay.
    #[serde(default = "default_fragment_budget_bytes")]
    pub fragment_budget_bytes: usize,
    /// Packet-level bypass backend switch (env can override).
    #[serde(default = "default_packet_bypass_enabled")]
    pub packet_bypass_enabled: bool,
    /// Persist per-destination relay classifier state across restarts.
    #[serde(default = "default_classifier_persist_enabled")]
    pub classifier_persist_enabled: bool,
    /// Path to relay classifier state JSON cache.
    #[serde(default = "default_classifier_cache_path")]
    pub classifier_cache_path: String,
    /// TTL for persisted classifier entries (seconds).
    #[serde(default = "default_classifier_entry_ttl_secs")]
    pub classifier_entry_ttl_secs: u64,
    /// Enables strategy racing v1 for first-time destinations in prime-mode.
    #[serde(default = "default_strategy_race_enabled")]
    pub strategy_race_enabled: bool,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            strategy: None,
            fragment_size: default_fragment_size(),
            fragment_sleep_ms: default_fragment_sleep_ms(),
            tls_record_max_fragment_size: None,
            rst_retry_max: default_rst_retry_max(),
            traffic_shaping_enabled: false,
            timing_jitter_ms_min: 5,
            timing_jitter_ms_max: 35,
            client_hello_split_offsets: vec![1, 5, 40],
            split_at_sni: true,
            first_packet_ttl: 0,
            fragment_budget_bytes: default_fragment_budget_bytes(),
            packet_bypass_enabled: default_packet_bypass_enabled(),
            classifier_persist_enabled: default_classifier_persist_enabled(),
            classifier_cache_path: default_classifier_cache_path(),
            classifier_entry_ttl_secs: default_classifier_entry_ttl_secs(),
            strategy_race_enabled: default_strategy_race_enabled(),
            prime_mode: default_prime_mode(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EvasionStrategy {
    Fragment,
    Desync,
    Auto,
}

fn default_fragment_size() -> usize {
    64
}

fn default_fragment_sleep_ms() -> u64 {
    10
}

fn default_rst_retry_max() -> usize {
    2
}

fn default_split_at_sni() -> bool {
    true
}

fn default_fragment_budget_bytes() -> usize {
    16 * 1024
}

fn default_packet_bypass_enabled() -> bool {
    true
}

fn default_classifier_persist_enabled() -> bool {
    true
}

fn default_classifier_entry_ttl_secs() -> u64 {
    7 * 24 * 60 * 60
}

fn default_classifier_cache_path() -> String {
    if let Some(dir) = dirs::cache_dir() {
        return dir
            .join("prime-net-engine")
            .join("relay-classifier.json")
            .to_string_lossy()
            .to_string();
    }
    "~/.cache/prime-net-engine/relay-classifier.json".to_owned()
}

fn default_strategy_race_enabled() -> bool {
    true
}

fn default_prime_mode() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub address: String,
}

impl ProxyConfig {
    pub fn as_reqwest_proxy(&self) -> Result<reqwest::Proxy> {
        if self.address.trim().is_empty() {
            return Err(EngineError::Config("proxy.address is empty".to_owned()));
        }
        let scheme_prefix = match self.kind {
            ProxyKind::Http => "http://",
            ProxyKind::Https => "https://",
            ProxyKind::Socks5 => "socks5h://",
        };
        let normalized = if self.address.contains("://") {
            self.address.clone()
        } else {
            format!("{scheme_prefix}{}", self.address)
        };
        reqwest::Proxy::all(&normalized).map_err(|e| EngineError::Config(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Http,
    Https,
    Socks5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluggableTransportConfig {
    pub kind: PluggableTransportKind,
    /// Where the embedded local SOCKS5 server should listen, e.g. "127.0.0.1:0".
    ///
    /// Use port 0 to request an ephemeral port.
    #[serde(default = "default_pt_local_socks5_bind")]
    pub local_socks5_bind: String,
    /// If true, invalid/unknown handshakes are handled with a silent drop (best-effort).
    #[serde(default)]
    pub silent_drop: bool,
    /// Trojan client settings (required when kind="trojan").
    #[serde(default)]
    pub trojan: Option<TrojanPtConfig>,
    /// Shadowsocks client settings (TCP-only client).
    #[serde(default)]
    pub shadowsocks: Option<ShadowsocksPtConfig>,
    /// Obfs4 client settings (reserved; not implemented in this build).
    #[serde(default)]
    pub obfs4: Option<Obfs4PtConfig>,
    /// Snowflake client settings (reserved; not implemented in this build).
    #[serde(default)]
    pub snowflake: Option<SnowflakePtConfig>,
}

fn default_pt_local_socks5_bind() -> String {
    "127.0.0.1:0".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PluggableTransportKind {
    Trojan,
    Shadowsocks,
    Obfs4,
    Snowflake,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrojanPtConfig {
    /// Trojan server address, "host:port" (port usually 443).
    pub server: String,
    /// Trojan password (will be SHA-224 hashed per protocol).
    pub password: String,
    /// Optional SNI override for TLS (defaults to server host when it is a domain).
    #[serde(default)]
    pub sni: Option<String>,
    /// Optional ALPN list for Trojan TLS. Defaults to ["http/1.1"] to resemble HTTPS.
    #[serde(default = "default_trojan_alpn")]
    pub alpn_protocols: Vec<String>,
    /// DANGEROUS: accept invalid certificates (intended for testing).
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

fn default_trojan_alpn() -> Vec<String> {
    vec!["http/1.1".to_owned()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksPtConfig {
    pub server: String,
    pub password: String,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obfs4PtConfig {
    pub server: String,
    /// Optional bridge identity fingerprint (40 hex chars) used by Tor bridge lines.
    #[serde(default)]
    pub fingerprint: Option<String>,
    pub cert: String,
    pub iat_mode: Option<u8>,
    /// Tor binary (must be available on PATH if not overridden).
    #[serde(default = "default_tor_bin")]
    pub tor_bin: String,
    /// Extra args passed to `tor` CLI (advanced).
    #[serde(default)]
    pub tor_args: Vec<String>,
    /// obfs4proxy binary (must be available on PATH if not overridden).
    #[serde(default = "default_obfs4proxy_bin")]
    pub obfs4proxy_bin: String,
    /// Extra args passed to `obfs4proxy` (advanced).
    #[serde(default)]
    pub obfs4proxy_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemProxyConfig {
    #[serde(default)]
    pub auto_configure: bool,
    #[serde(default)]
    pub mode: SystemProxyMode,
    #[serde(default = "default_system_proxy_pac_port")]
    pub pac_port: u16,
    #[serde(default = "default_system_proxy_socks_endpoint")]
    pub socks_endpoint: String,
}

impl Default for SystemProxyConfig {
    fn default() -> Self {
        Self {
            auto_configure: false,
            mode: SystemProxyMode::Off,
            pac_port: default_system_proxy_pac_port(),
            socks_endpoint: default_system_proxy_socks_endpoint(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SystemProxyMode {
    #[default]
    Off,
    All,
    Pac,
    Custom,
}

fn default_system_proxy_pac_port() -> u16 {
    8888
}

fn default_system_proxy_socks_endpoint() -> String {
    "127.0.0.1:1080".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistConfig {
    #[serde(default = "default_blocklist_enabled")]
    pub enabled: bool,
    #[serde(default = "default_blocklist_source")]
    pub source: String,
    #[serde(default = "default_blocklist_auto_update")]
    pub auto_update: bool,
    #[serde(default = "default_blocklist_update_interval_hours")]
    pub update_interval_hours: u64,
    #[serde(default = "default_blocklist_cache_path")]
    pub cache_path: String,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            enabled: default_blocklist_enabled(),
            source: default_blocklist_source(),
            auto_update: default_blocklist_auto_update(),
            update_interval_hours: default_blocklist_update_interval_hours(),
            cache_path: default_blocklist_cache_path(),
        }
    }
}

fn default_blocklist_enabled() -> bool {
    true
}

fn default_blocklist_source() -> String {
    "https://github.com/zapret-info/z-i/raw/master/dump.csv".to_owned()
}

fn default_blocklist_auto_update() -> bool {
    true
}

fn default_blocklist_update_interval_hours() -> u64 {
    24
}

fn default_blocklist_cache_path() -> String {
    if let Some(dir) = dirs::cache_dir() {
        return dir
            .join("prime-net-engine")
            .join("blocklist.json")
            .to_string_lossy()
            .to_string();
    }
    "~/.cache/prime-net-engine/blocklist.json".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdaterConfig {
    #[serde(default = "default_updater_enabled")]
    pub enabled: bool,
    #[serde(default = "default_updater_auto_check")]
    pub auto_check: bool,
    #[serde(default = "default_updater_interval_hours")]
    pub check_interval_hours: u64,
    #[serde(default = "default_updater_repo")]
    pub repo: String,
    #[serde(default)]
    pub channel: UpdateChannel,
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self {
            enabled: default_updater_enabled(),
            auto_check: default_updater_auto_check(),
            check_interval_hours: default_updater_interval_hours(),
            repo: default_updater_repo(),
            channel: UpdateChannel::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    #[default]
    Stable,
    Beta,
    Nightly,
}

fn default_updater_enabled() -> bool {
    true
}

fn default_updater_auto_check() -> bool {
    true
}

fn default_updater_interval_hours() -> u64 {
    24
}

fn default_updater_repo() -> String {
    "your-username/prime-net-engine".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub crash_reports: bool,
    #[serde(default = "default_telemetry_endpoint")]
    pub endpoint: String,
    #[serde(default)]
    pub include_config: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            crash_reports: false,
            endpoint: default_telemetry_endpoint(),
            include_config: false,
        }
    }
}

fn default_telemetry_endpoint() -> String {
    "https://crashes.example.com".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnowflakePtConfig {
    /// Tor binary (must be available on PATH if not overridden).
    #[serde(default = "default_tor_bin")]
    pub tor_bin: String,
    /// Extra args passed to `tor` CLI (advanced).
    #[serde(default)]
    pub tor_args: Vec<String>,
    /// snowflake-client binary (must be available on PATH if not overridden).
    #[serde(default = "default_snowflake_bin")]
    pub snowflake_bin: String,
    /// Broker URL (optional; snowflake-client default may apply).
    #[serde(default)]
    pub broker: Option<String>,
    /// Domain fronting front domain (optional; for broker fetch).
    #[serde(default)]
    pub front: Option<String>,
    /// AMP cache URL (optional).
    #[serde(default)]
    pub amp_cache: Option<String>,
    /// STUN servers (optional). Passed as repeated `-stun <server>` args to snowflake-client.
    #[serde(default)]
    pub stun_servers: Vec<String>,
    /// Optional bridge placeholder. If not set, a safe dummy address is used.
    #[serde(default)]
    pub bridge: Option<String>,
    /// Extra args passed to snowflake-client (advanced).
    #[serde(default)]
    pub snowflake_args: Vec<String>,
}

fn default_tor_bin() -> String {
    "tor".to_owned()
}

fn default_obfs4proxy_bin() -> String {
    "obfs4proxy".to_owned()
}

fn default_snowflake_bin() -> String {
    "snowflake-client".to_owned()
}

pub fn default_snowflake_pt_config(bind: impl Into<String>) -> PluggableTransportConfig {
    PluggableTransportConfig {
        kind: PluggableTransportKind::Snowflake,
        local_socks5_bind: bind.into(),
        silent_drop: false,
        trojan: None,
        shadowsocks: None,
        obfs4: None,
        snowflake: Some(SnowflakePtConfig {
            tor_bin: default_tor_bin(),
            tor_args: Vec::new(),
            snowflake_bin: default_snowflake_bin(),
            broker: None,
            front: None,
            amp_cache: None,
            stun_servers: Vec::new(),
            bridge: None,
            snowflake_args: Vec::new(),
        }),
    }
}

pub struct EngineConfigBuilder {
    config: EngineConfig,
}

impl EngineConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: EngineConfig::default(),
        }
    }

    pub fn download(mut self, cfg: DownloadConfig) -> Self {
        self.config.download = cfg;
        self
    }

    pub fn anticensorship(mut self, cfg: AntiCensorshipConfig) -> Self {
        self.config.anticensorship = cfg;
        self
    }

    pub fn evasion(mut self, cfg: EvasionConfig) -> Self {
        self.config.evasion = cfg;
        self
    }

    pub fn privacy(mut self, cfg: PrivacyConfig) -> Self {
        self.config.privacy = cfg;
        self
    }

    pub fn proxy(mut self, cfg: ProxyConfig) -> Self {
        self.config.proxy = Some(cfg);
        self
    }

    pub fn pt(mut self, cfg: PluggableTransportConfig) -> Self {
        self.config.pt = Some(cfg);
        self
    }

    pub fn transport(mut self, cfg: TransportConfig) -> Self {
        self.config.transport = cfg;
        self
    }

    pub fn tls(mut self, cfg: TlsConfig) -> Self {
        self.config.tls = cfg;
        self
    }

    pub fn build(self) -> Result<EngineConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for EngineConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(EngineConfig::default().validate().is_ok());
    }

    #[test]
    fn invalid_concurrency_fails_validation() {
        let mut cfg = EngineConfig::default();
        cfg.download.initial_concurrency = 8;
        cfg.download.max_concurrency = 2;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn fronting_enabled_requires_rules() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.domain_fronting_enabled = true;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn fronting_rule_must_have_required_fields() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.domain_fronting_enabled = true;
        cfg.anticensorship.domain_fronting_rules = vec![DomainFrontingRule {
            target_host: "".to_owned(),
            front_domain: "front.example".to_owned(),
            front_domains: Vec::new(),
            real_host: "real.example".to_owned(),
            sni_domain: None,
            provider: FrontingProvider::Cloudflare,
        }];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn dns_chain_must_not_have_duplicates() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::Doh, DnsResolverKind::Doh];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn dns_chain_cannot_include_disabled_doh() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.doh_enabled = false;
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::Doh, DnsResolverKind::System];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn dns_chain_cannot_include_disabled_system() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.system_dns_enabled = false;
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::System];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn compat_repair_disables_empty_fronting() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.domain_fronting_enabled = true;
        cfg.anticensorship.domain_fronting_rules.clear();
        let notes = cfg.apply_compat_repairs();
        assert!(!cfg.anticensorship.domain_fronting_enabled);
        assert_eq!(notes.len(), 1);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn compat_repair_removes_disabled_dns_resolvers_from_chain() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.system_dns_enabled = false;
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::Doh, DnsResolverKind::System];
        let notes = cfg.apply_compat_repairs();
        assert_eq!(
            cfg.anticensorship.dns_fallback_chain,
            vec![DnsResolverKind::Doh]
        );
        assert!(!notes.is_empty());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn invalid_system_proxy_socks_endpoint_fails_validation() {
        let mut cfg = EngineConfig::default();
        cfg.system_proxy.socks_endpoint = "localhost".to_owned();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_system_proxy_pac_port_fails_validation() {
        let mut cfg = EngineConfig::default();
        cfg.system_proxy.pac_port = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn updater_repo_must_be_owner_name() {
        let mut cfg = EngineConfig::default();
        cfg.updater.repo = "invalid/repo/slug".to_owned();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_privacy_search_domain_fails_validation() {
        let mut cfg = EngineConfig::default();
        cfg.privacy.referer.search_engine_domains = vec!["https://google.com".to_owned()];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_privacy_allowlist_domain_fails_validation() {
        let mut cfg = EngineConfig::default();
        cfg.privacy.tracker_blocker.allowlist = vec!["exa mple.com".to_owned()];
        assert!(cfg.validate().is_err());
    }
}

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{EngineError, Result};
use crate::adblock::AdblockConfig;
use crate::privacy::cname_uncloaking::CnameUncloakingConfig;
use crate::privacy::cookie_policy::CookiePolicyConfig;
use crate::privacy::header_normalizer::HeaderNormalizerConfig;
use crate::privacy::https_upgrade::HttpsUpgradeConfig;
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
    #[serde(default)]
    pub pt: Option<PluggableTransportConfig>,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub mtproto_ws: MtprotoWsConfig,
    /// Ad-blocking engine configuration (EasyList/AdGuard filter syntax).
    #[serde(default)]
    pub adblock: AdblockConfig,
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
    #[serde(default = "default_max_response_body_mb")]
    pub max_response_body_mb: usize,
    #[serde(default)]
    pub http2_max_concurrent_reset_streams: Option<usize>,
    #[serde(default)]
    pub verify_hash: Option<String>,
}

fn default_max_response_body_mb() -> usize { 100 }

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
            max_response_body_mb: 100,
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
    #[serde(default = "default_dns_parallel_racing")]
    pub dns_parallel_racing: bool,
    #[serde(default)]
    pub ech_mode: Option<EchMode>,
    #[serde(default)]
    pub ech_enabled: bool,
    pub domain_fronting_enabled: bool,
    #[serde(default)]
    pub domain_fronting_rules: Vec<DomainFrontingRule>,
    #[serde(default = "default_fronting_probe_ttl_secs")]
    pub fronting_probe_ttl_secs: u64,
    #[serde(default = "default_fronting_probe_timeout_secs")]
    pub fronting_probe_timeout_secs: u64,
    pub tls_randomization_enabled: bool,
}

impl AntiCensorshipConfig {
    pub fn effective_ech_mode(&self) -> Option<EchMode> {
        self.ech_mode
            .clone()
            .or(if self.ech_enabled { Some(EchMode::Grease) } else { None })
    }
}

impl Default for AntiCensorshipConfig {
    fn default() -> Self {
        let bootstrap = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        ];
        Self {
            doh_enabled: true,
            doh_providers: vec!["adguard".to_owned(), "google".to_owned(), "quad9".to_owned()],
            doh_cache_ttl_secs: 300,
            bootstrap_ips: bootstrap,
            dnssec_enabled: true,
            dns_cache_size: 4096,
            dns_query_timeout_secs: 5,
            dns_attempts: 2,
            dot_enabled: false,
            dot_servers: vec!["94.140.14.14:853".to_owned()],
            dot_sni: String::new(), // auto-detected per server IP via dot_sni_for_ip()
            doq_enabled: false,
            doq_servers: vec!["94.140.14.14:784".to_owned()],
            doq_sni: "dns.adguard-dns.com".to_owned(),
            dns_fallback_chain: vec![DnsResolverKind::Doh],
            system_dns_enabled: false,
            dns_parallel_racing: true,
            ech_mode: None,
            ech_enabled: false,
            domain_fronting_enabled: false,
            domain_fronting_rules: Vec::new(),
            fronting_probe_ttl_secs: 600,
            fronting_probe_timeout_secs: 5,
            tls_randomization_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFrontingRule {
    pub target_host: String,
    #[serde(default)]
    pub front_domain: String,
    #[serde(default)]
    pub front_domains: Vec<String>,
    pub real_host: String,
    pub sni_domain: Option<String>,
    #[serde(default)]
    pub provider: FrontingProvider,
}

/// Serializable representation of a split-point for native desync profiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SplitAtConfig {
    /// Fixed byte offset from the start of the data.
    Fixed(usize),
    /// Split right before the SNI extension.
    BeforeSni,
    /// Split 1 byte into the SNI extension.
    IntoSni,
    /// Split through the middle of the SNI hostname.
    MidSni,
}

/// Serializable representation of an HTTP split-point.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpSplitAtConfig {
    /// Split right before the `Host:` header line.
    BeforeHostHeader,
    /// Split at a fixed byte offset.
    Fixed(usize),
}

/// Serializable representation of a desync technique for user-defined profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NativeTechniqueConfig {
    /// Send two TLS records instead of one, split at `split_at`.
    TlsRecordSplit { split_at: SplitAtConfig },
    /// Send two TCP segments, split at `split_at`.
    TcpSegmentSplit { split_at: SplitAtConfig },
    /// TLS record split combined with an OOB (URG) byte.
    TlsRecordSplitOob { split_at: SplitAtConfig },
    /// TCP segment split combined with an OOB (URG) byte.
    TcpSegmentSplitOob { split_at: SplitAtConfig },
    /// Split an HTTP/1.x request at `http_split_at`.
    HttpSplit { http_split_at: HttpSplitAtConfig },
    /// Split into N+1 TCP segments at multiple `points`.
    MultiSplit { points: Vec<SplitAtConfig> },
    /// TLS record split with a dummy ApplicationData record injected between fragments.
    TlsRecordPadding { split_at: SplitAtConfig },
    /// Send TCP segment 2 before segment 1 (requires WinDivert/NFQueue).
    TcpDisorder { delay_ms: u64 },
    /// Inject fake ClientHello with decremented TCP seq (zapret seqovl).
    SeqOverlap { overlap_size: usize },
    /// Chain of multiple techniques applied sequentially to one connection.
    Chain { steps: Vec<ChainStepConfig> },
}

/// A single step in a multi-technique desync chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChainStepConfig {
    /// Apply a TLS record split.
    TlsRecordSplit { split_at: SplitAtConfig },
    /// Apply a TCP segment split.
    TcpSegmentSplit { split_at: SplitAtConfig },
    /// Send an OOB (URG) byte at the split point.
    OobByte,
    /// Insert a dummy TLS ApplicationData record.
    TlsPadding,
    /// Wait N milliseconds between segments.
    Delay { ms: u64 },
}

/// Configuration for a low-TTL fake probe sent before the real TCP connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeProbeConfig {
    /// IP TTL for the probe connection (typically 3–5 hops).
    pub ttl: u8,
    /// Random bytes to send in the probe body; 0 = empty probe (TCB-desync only).
    #[serde(default)]
    pub data_size: usize,
    /// If set, send a crafted TLS ClientHello with this SNI instead of random bytes.
    #[serde(default)]
    pub fake_sni: Option<String>,
    /// How to prevent the probe from reaching the server.
    ///
    /// `None` = use TTL only.  Alternatives: `bad_timestamp`, `bad_checksum`, `bad_seq`.
    #[serde(default)]
    pub fooling: Option<crate::evasion::tcp_desync::FakeProbeStrategy>,
}

/// User-defined native desync profile loaded from config.
///
/// Appended to (or replacing) the built-in profile set at engine startup.
/// Use this to experiment with custom DPI evasion parameters for your ISP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeProfileConfig {
    /// Unique name shown in logs and ML route stats.
    pub name: String,
    /// The DPI evasion technique to apply to the first outbound data segment.
    pub technique: NativeTechniqueConfig,
    /// Whether this profile is safe for Cloudflare-hosted targets.
    ///
    /// Profiles that send out-of-order TCP segments must set this to `false`
    /// as Cloudflare edges reject disordered segments.
    #[serde(default = "default_true")]
    pub cloudflare_safe: bool,
    /// Optional low-TTL probe sent before the real connection to desync DPI.
    #[serde(default)]
    pub fake_probe: Option<FakeProbeConfig>,
    /// Randomize ASCII case of the SNI hostname bytes (e.g. `DiScOrD.cOm`).
    #[serde(default)]
    pub randomize_sni_case: bool,
    /// Milliseconds to wait between TCP segment flushes.
    ///
    /// Defeats DPI with short reassembly timers that discard incomplete buffers.
    #[serde(default)]
    pub inter_fragment_delay_ms: Option<u64>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    #[serde(default = "default_prime_mode")]
    pub prime_mode: bool,
    #[serde(default)]
    pub strategy: Option<EvasionStrategy>,
    #[serde(default = "default_fragment_size_min")]
    pub fragment_size_min: usize,
    #[serde(default = "default_fragment_size_max")]
    pub fragment_size_max: usize,
    #[serde(default = "default_randomize_fragment_size")]
    pub randomize_fragment_size: bool,
    #[serde(default = "default_fragment_sleep_ms")]
    pub fragment_sleep_ms: u64,
    #[serde(default)]
    pub tcp_window_size: u32,
    #[serde(default)]
    pub fake_packets_count: u8,
    #[serde(default = "default_fake_ttl")]
    pub fake_packets_ttl: u8,
    #[serde(default = "default_fake_data_size")]
    pub fake_packets_data_size: usize,
    #[serde(default)]
    pub tls_record_max_fragment_size: Option<usize>,
    #[serde(default = "default_rst_retry_max")]
    pub rst_retry_max: usize,
    #[serde(default)]
    pub traffic_shaping_enabled: bool,
    #[serde(default = "default_timing_jitter_ms_min")]
    pub timing_jitter_ms_min: u64,
    #[serde(default = "default_timing_jitter_ms_max")]
    pub timing_jitter_ms_max: u64,
    #[serde(default = "default_client_hello_split_offsets")]
    pub client_hello_split_offsets: Vec<usize>,
    #[serde(default = "default_split_at_sni")]
    pub split_at_sni: bool,
    #[serde(default)]
    pub first_packet_ttl: u8,
    #[serde(default = "default_fragment_budget_bytes")]
    pub fragment_budget_bytes: usize,
    #[serde(default = "default_packet_bypass_enabled")]
    pub packet_bypass_enabled: bool,
    #[serde(default = "default_classifier_persist_enabled")]
    pub classifier_persist_enabled: bool,
    #[serde(default = "default_classifier_cache_path")]
    pub classifier_cache_path: String,
    #[serde(default = "default_classifier_entry_ttl_secs")]
    pub classifier_entry_ttl_secs: u64,
    #[serde(default = "default_strategy_race_enabled")]
    pub strategy_race_enabled: bool,
    /// Домены, для которых принудительно включать фрагментацию ClientHello и stage=2
    /// с первого соединения, не дожидаясь обучения классификатора.
    /// Поддерживает суффиксное совпадение: "sndcdn.com" матчит "cdn1.sndcdn.com".
    #[serde(default = "default_aggressive_fragment_domains")]
    pub aggressive_fragment_domains: Vec<String>,
    /// TTL для preferred_stage в секундах.
    /// После истечения stage не восстанавливается при старте и прунится из памяти.
    /// Default: 172800 (48 часов).
    #[serde(default = "default_stage_cache_ttl_secs")]
    pub stage_cache_ttl_secs: u64,
    /// TTL для winner-записи при загрузке из диска (секунды).
    /// Default: 86400 (24 часа) — текущее поведение, теперь конфигурируемое.
    #[serde(default = "default_winner_cache_ttl_secs")]
    pub winner_cache_ttl_secs: u64,
    /// Таймаут ожидания первого UDP-ответа при QUIC-соединении на порт 443 (мс).
    /// При истечении домен помечается как "QUIC silent drop" на 1800 секунд.
    /// При следующем подключении UDP блокируется → приложение переходит на TCP.
    /// 0 = отключено. Default: 3000 (3 секунды).
    #[serde(default = "default_quic_probe_timeout_ms")]
    pub quic_probe_timeout_ms: u64,
    /// Number of fake QUIC Initial packets to inject before the real one.
    ///
    /// Higher values improve bypass reliability against stateful DPI.
    /// Inspired by zapret's `--dpi-desync-repeats` (6-11).
    /// Default: 8.
    #[serde(default = "default_quic_fake_repeat_count")]
    pub quic_fake_repeat_count: u8,
    /// Trailing zero-byte padding added to outgoing QUIC (UDP port 443) packets.
    ///
    /// Defeats DPI that fingerprints by packet size.  QUIC ignores trailing
    /// bytes after the protected payload.  0 = disabled (default).
    #[serde(default)]
    pub quic_udp_padding_bytes: u16,
    /// Additional native desync profiles defined in user config.
    ///
    /// These are appended to the built-in profile list. Set
    /// `disable_default_native_profiles: true` to use only these.
    #[serde(default)]
    pub native_profiles: Vec<NativeProfileConfig>,
    /// When `true`, skip the built-in profile set and use only `native_profiles`.
    ///
    /// Useful for ISP-specific fine-tuning where built-ins are known to be ineffective.
    #[serde(default)]
    pub disable_default_native_profiles: bool,
    /// When `true`, engage a kill switch that redirects the system proxy to a dead port
    /// if the SOCKS5 listener becomes unreachable, preventing traffic leaks.
    #[serde(default)]
    pub kill_switch_enabled: bool,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            prime_mode: true,
            strategy: None,
            fragment_size_min: 16,
            fragment_size_max: 128,
            randomize_fragment_size: true,
            fragment_sleep_ms: 1,
            tcp_window_size: 0,
            fake_packets_count: 0,
            fake_packets_ttl: 2,
            fake_packets_data_size: 16,
            tls_record_max_fragment_size: None,
            rst_retry_max: 2,
            traffic_shaping_enabled: false,
            timing_jitter_ms_min: 5,
            timing_jitter_ms_max: 35,
            client_hello_split_offsets: vec![1, 5, 40],
            split_at_sni: true,
            first_packet_ttl: 0,
            fragment_budget_bytes: 16384,
            packet_bypass_enabled: true,
            classifier_persist_enabled: true,
            classifier_cache_path: default_classifier_cache_path(),
            classifier_entry_ttl_secs: 604800,
            strategy_race_enabled: true,
            aggressive_fragment_domains: default_aggressive_fragment_domains(),
            stage_cache_ttl_secs: default_stage_cache_ttl_secs(),
            winner_cache_ttl_secs: default_winner_cache_ttl_secs(),
            quic_probe_timeout_ms: default_quic_probe_timeout_ms(),
            quic_fake_repeat_count: default_quic_fake_repeat_count(),
            quic_udp_padding_bytes: 0,
            native_profiles: Vec::new(),
            disable_default_native_profiles: false,
            kill_switch_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default = "default_censored_groups")]
    pub censored_groups: std::collections::HashMap<String, Vec<String>>,
    #[serde(default = "default_ml_routing_enabled")]
    pub ml_routing_enabled: bool,
    /// Explicit domain → route arm overrides that skip ML entirely.
    ///
    /// Keys are domain suffixes (e.g. `"discord.com"`); subdomains match automatically.
    /// Values are route identifiers:
    /// - `"direct"` — always use direct TCP, no evasion.
    /// - `"bypass:N"` — always use bypass pool entry N (1-based index).
    /// - `"native:profile_name"` — always use the named native desync profile
    ///   (e.g. `"native:tlsrec-into-sni-oob"`).  Also accepts `"native:N"` (1-based index).
    ///
    /// Example:
    /// ```toml
    /// [routing.domain_profiles]
    /// "discord.com" = "native:tlsrec-into-sni-oob"
    /// "youtube.com" = "native:tlsrec-into-sni-fake-ttl3"
    /// "rutracker.org" = "bypass:1"
    /// ```
    #[serde(default)]
    pub domain_profiles: std::collections::HashMap<String, String>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            censored_groups: default_censored_groups(),
            ml_routing_enabled: true,
            domain_profiles: std::collections::HashMap::new(),
        }
    }
}

fn default_censored_groups() -> std::collections::HashMap<String, Vec<String>> {
    let mut map = std::collections::HashMap::new();
    map.insert("youtube".to_owned(), vec!["youtube".to_owned(), "ytimg".to_owned()]);
    map
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PrivacyConfig {
    /// DNT / GPC signal injection settings.
    pub signals: PrivacySignalsConfig,
    /// User-Agent header override settings.
    pub user_agent: UserAgentConfig,
    /// Referer header stripping / normalization settings.
    pub referer: RefererConfig,
    /// Domain-level tracker blocking settings.
    pub tracker_blocker: TrackerBlockerConfig,
    /// IP spoofing header injection settings.
    pub ip_spoof: IpSpoofConfig,
    /// Referer header override settings.
    pub referer_override: RefererOverrideConfig,
    /// WebRTC leak prevention settings.
    pub webrtc: WebRtcConfig,
    /// Geolocation API blocking settings.
    pub location_api: LocationApiConfig,
    /// HTTP header normalization to reduce fingerprinting surface.
    pub header_normalizer: HeaderNormalizerConfig,
    /// Third-party cookie blocking at the proxy level.
    pub cookie_policy: CookiePolicyConfig,
    /// Automatic HTTP-to-HTTPS upgrade settings.
    pub https_upgrade: HttpsUpgradeConfig,
    /// CNAME-based first-party tracker detection settings.
    pub cname_uncloaking: CnameUncloakingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivacySignalsConfig { pub send_dnt: bool, pub send_gpc: bool }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAgentConfig {
    pub enabled: bool,
    pub preset: UserAgentPreset,
    pub custom_value: String,
}

impl Default for UserAgentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            preset: UserAgentPreset::ChromeWindows,
            custom_value: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UserAgentPreset { ChromeWindows, FirefoxWindows, FirefoxLinux, SafariMacOs, Custom }

impl UserAgentPreset {
    pub fn ua_string(&self) -> Option<&'static str> {
        match self {
            Self::ChromeWindows => Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            Self::FirefoxWindows => Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"),
            Self::FirefoxLinux => Some("Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"),
            Self::SafariMacOs => Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"),
            Self::Custom => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefererConfig {
    pub enabled: bool,
    pub policy: RefererPolicy,
    pub mode: RefererMode,
    pub strip_from_search_engines: bool,
    pub search_engine_domains: Vec<String>,
}
impl Default for RefererConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            policy: RefererPolicy::Origin,
            mode: RefererMode::Strip,
            strip_from_search_engines: true,
            search_engine_domains: vec!["google.com".to_owned()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RefererPolicy { NoReferer, Origin, SameOrigin, StrictOrigin }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RefererMode { Strip, OriginOnly, PassThrough }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TrackerBlockerConfig {
    pub enabled: bool,
    pub mode: TrackerBlockerMode,
    pub on_block: TrackerBlockAction,
    pub allowlist: Vec<String>,
    pub custom_lists: Vec<String>,
    pub lists: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum TrackerBlockerMode { Lax, #[default] Standard, Strict, LogOnly, Block }
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum TrackerBlockAction { #[default] Error, Empty200 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpSpoofConfig { pub enabled: bool, pub spoofed_ip: String }
impl Default for IpSpoofConfig { fn default() -> Self { Self { enabled: false, spoofed_ip: "127.0.0.1".to_owned() } } }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefererOverrideConfig { pub enabled: bool, pub value: String }
impl Default for RefererOverrideConfig { fn default() -> Self { Self { enabled: false, value: "https://google.com".to_owned() } } }
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebRtcConfig { pub block_enabled: bool }
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocationApiConfig { pub block_enabled: bool }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig { pub kind: ProxyKind, pub address: String }
impl ProxyConfig {
    pub fn as_reqwest_proxy(&self) -> Result<reqwest::Proxy> {
        let prefix = match self.kind { ProxyKind::Http => "http://", ProxyKind::Https => "https://", ProxyKind::Socks5 => "socks5h://" };
        let addr = if self.address.contains("://") { self.address.clone() } else { format!("{prefix}{}", self.address) };
        reqwest::Proxy::all(addr).map_err(|e| EngineError::Config(e.to_string()))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyKind { Http, Https, Socks5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluggableTransportConfig {
    pub kind: PluggableTransportKind,
    pub local_socks5_bind: String,
    pub silent_drop: bool,
    pub trojan: Option<TrojanPtConfig>,
    pub shadowsocks: Option<ShadowsocksPtConfig>,
    pub obfs4: Option<Obfs4PtConfig>,
    pub snowflake: Option<SnowflakePtConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PluggableTransportKind { Trojan, Shadowsocks, Obfs4, Snowflake }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrojanPtConfig {
    pub server: String,
    pub password: String,
    pub sni: Option<String>,
    pub alpn_protocols: Vec<String>,
    pub insecure_skip_verify: bool,
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
    pub fingerprint: Option<String>,
    pub cert: String,
    pub iat_mode: Option<u8>,
    pub tor_bin: String,
    pub tor_args: Vec<String>,
    pub obfs4proxy_bin: String,
    pub obfs4proxy_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnowflakePtConfig {
    pub tor_bin: String,
    pub tor_args: Vec<String>,
    pub snowflake_bin: String,
    pub broker: Option<String>,
    pub front: Option<String>,
    pub amp_cache: Option<String>,
    pub stun_servers: Vec<String>,
    pub bridge: Option<String>,
    pub snowflake_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemProxyConfig {
    pub auto_configure: bool,
    pub mode: SystemProxyMode,
    pub pac_port: u16,
    pub socks_endpoint: String,
}

impl Default for SystemProxyConfig {
    fn default() -> Self {
        Self {
            auto_configure: false,
            mode: SystemProxyMode::Off,
            pac_port: 8888,
            socks_endpoint: "127.0.0.1:1080".to_owned(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum SystemProxyMode { #[default] Off, All, Pac, Custom }

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
pub enum UpdateChannel { #[default] Stable, Beta, Nightly }

/// Crash reporting telemetry. `include_config` has been removed — the engine never sends
/// the raw config to prevent accidental PT password leakage. Only a SHA-256 hash of the
/// config is included in crash reports via `CrashReport::config_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelemetryConfig { pub crash_reports: bool, pub endpoint: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub http3_connect_timeout_ms: u64,
    pub http3_request_timeout_ms: u64,
    pub http3_only: bool,
    pub prefer_http3: bool,
    pub http3_idle_timeout_ms: u64,
    pub http3_keep_alive_interval_ms: Option<u64>,
    pub http3_insecure_skip_verify: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            http3_connect_timeout_ms: 5000,
            http3_request_timeout_ms: 30000,
            http3_only: false,
            prefer_http3: true,
            http3_idle_timeout_ms: 10000,
            http3_keep_alive_interval_ms: Some(5000),
            http3_insecure_skip_verify: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EchMode { Grease, Real, Auto }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DnsResolverKind { Doh, Dot, Doq, System }
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum FrontingProvider { #[default] Cloudflare, Fastly, GoogleCdn, AzureCdn }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvasionStrategy { Fragment, Desync, Auto }

/// Configuration for the built-in MTProto-over-WebSocket proxy for Telegram.
///
/// When enabled, the engine listens on `listen_addr` and accepts plain MTProto
/// obfuscated connections from Telegram Desktop.  Traffic is tunnelled to
/// `kws{N}.web.telegram.org` (or the CF proxy domain) over WSS, bypassing
/// ISP-level IP blocks on Telegram's native address ranges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtprotoWsConfig {
    /// Enable the built-in MTProto WebSocket proxy for Telegram.
    pub enabled: bool,
    /// Local listen address for Telegram Desktop connections.
    pub listen_addr: String,
    /// Proxy secret — 16 random bytes as lowercase hex (32 chars).
    ///
    /// Generate with `openssl rand -hex 16`.  An empty string causes the engine
    /// to auto-generate a random secret on first start (not persisted).
    pub secret_hex: String,
    /// Use Cloudflare proxy domain to avoid Telegram IP blocks (recommended).
    pub cf_proxy_enabled: bool,
    /// Cloudflare proxy domain — must have `kws{N}.{domain}` DNS records pointing
    /// to Telegram DCs via CF.
    pub cf_proxy_domain: String,
}

impl Default for MtprotoWsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "127.0.0.1:1443".to_owned(),
            secret_hex: String::new(),
            cf_proxy_enabled: true,
            cf_proxy_domain: "pclead.co.uk".to_owned(),
        }
    }
}

// Helpers
fn default_prime_mode() -> bool { true }
fn default_classifier_cache_path() -> String {
    if let Some(dir) = dirs::cache_dir() {
        let path = dir.join("prime-net-engine").join("relay-classifier.json");
        if let Ok(s) = path.into_os_string().into_string() {
            return s;
        }
    }
    "relay-classifier.json".to_owned()
}
fn default_client_hello_split_offsets() -> Vec<usize> { vec![1, 5, 40] }
fn default_classifier_entry_ttl_secs() -> u64 { 604800 }
fn default_ml_routing_enabled() -> bool { true }
fn default_fragment_size_min() -> usize { 16 }
fn default_fragment_size_max() -> usize { 128 }
fn default_randomize_fragment_size() -> bool { true }
fn default_fragment_sleep_ms() -> u64 { 1 }
fn default_fake_ttl() -> u8 { 2 }
fn default_fake_data_size() -> usize { 16 }
fn default_rst_retry_max() -> usize { 2 }
fn default_timing_jitter_ms_min() -> u64 { 5 }
fn default_timing_jitter_ms_max() -> u64 { 35 }
fn default_split_at_sni() -> bool { true }
fn default_fragment_budget_bytes() -> usize { 16 * 1024 }
fn default_packet_bypass_enabled() -> bool { true }
fn default_strategy_race_enabled() -> bool { true }
fn default_dns_cache_size() -> usize { 4096 }
fn default_dns_timeout_secs() -> u64 { 5 }
fn default_dns_attempts() -> usize { 2 }
fn default_dns_parallel_racing() -> bool { true }
fn default_dot_sni() -> String { String::new() }
fn default_doq_sni() -> String { "dns.adguard-dns.com".to_owned() }
fn default_fronting_probe_ttl_secs() -> u64 { 600 }
fn default_fronting_probe_timeout_secs() -> u64 { 5 }
fn default_classifier_persist_enabled() -> bool { true }
fn default_updater_enabled() -> bool { true }
fn default_updater_auto_check() -> bool { true }
fn default_updater_interval_hours() -> u64 { 24 }
fn default_updater_repo() -> String { "prime-net/engine".to_owned() }
fn default_blocklist_enabled() -> bool { true }
fn default_blocklist_auto_update() -> bool { true }
fn default_blocklist_update_interval_hours() -> u64 { 24 }
fn default_blocklist_source() -> String { "https://antifilter.download/list/domains.lst".to_owned() }
fn default_blocklist_cache_path() -> String {
    if let Some(dir) = dirs::cache_dir() {
        let path = dir.join("prime-net-engine").join("blocklist.json");
        if let Ok(s) = path.into_os_string().into_string() {
            return s;
        }
    }
    "blocklist.json".to_owned()
}
fn default_aggressive_fragment_domains() -> Vec<String> {
    vec!["soundcloud.com".to_owned(), "sndcdn.com".to_owned()]
}
fn default_stage_cache_ttl_secs() -> u64 { 172800 }
fn default_winner_cache_ttl_secs() -> u64 { 86400 }
fn default_quic_probe_timeout_ms() -> u64 { 3000 }
fn default_quic_fake_repeat_count() -> u8 { 8 }

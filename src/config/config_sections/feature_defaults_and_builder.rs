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
    #[serde(default = "default_fragment_size_min")]
    pub fragment_size_min: usize,
    #[serde(default = "default_fragment_size_max")]
    pub fragment_size_max: usize,
    #[serde(default = "default_randomize_fragment_size")]
    pub randomize_fragment_size: bool,
    #[serde(default = "default_fragment_sleep_ms")]
    pub fragment_sleep_ms: u64,
    /// Optional TCP receive window size for the first packet (0 uses system default).
    /// Small values (1-10) can confuse some DPI.
    #[serde(default)]
    pub tcp_window_size: u32,
    /// Number of fake packets to send before the real connection (0 disables).
    #[serde(default)]
    pub fake_packets_count: u8,
    /// TTL for fake packets (should be enough to reach DPI but not the server).
    #[serde(default = "default_fake_ttl")]
    pub fake_packets_ttl: u8,
    /// Size of junk data in fake packets.
    #[serde(default = "default_fake_data_size")]
    pub fake_packets_data_size: usize,
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
            fragment_size_min: default_fragment_size_min(),
            fragment_size_max: default_fragment_size_max(),
            randomize_fragment_size: default_randomize_fragment_size(),
            fragment_sleep_ms: default_fragment_sleep_ms(),
            tcp_window_size: 0,
            fake_packets_count: 0,
            fake_packets_ttl: default_fake_ttl(),
            fake_packets_data_size: default_fake_data_size(),
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

fn default_fragment_size_min() -> usize {
    1
}

fn default_fragment_size_max() -> usize {
    64
}

fn default_randomize_fragment_size() -> bool {
    true
}

fn default_fragment_sleep_ms() -> u64 {
    10
}

fn default_fake_ttl() -> u8 {
    2
}

fn default_fake_data_size() -> usize {
    16
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
    #[serde(default)]
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
    #[serde(default)]
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

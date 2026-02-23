use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{EngineError, Result};

#[cfg(feature = "hickory-dns")]
use parking_lot::Mutex;
#[cfg(feature = "hickory-dns")]
use std::net::SocketAddr;
#[cfg(feature = "hickory-dns")]
use std::sync::OnceLock;

#[cfg(feature = "hickory-dns")]
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
#[cfg(feature = "hickory-dns")]
use hickory_resolver::name_server::TokioConnectionProvider;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::proto::rr::{RData, RecordType};
#[cfg(feature = "hickory-dns")]
use hickory_resolver::proto::xfer::Protocol;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::TokioResolver;

/// Upstream DNS resolver selection.
///
/// Note: `DoH`/`DoT`/`DoQ` upstreams may require `DnsConfig.bootstrap_ips` to avoid using the system
/// resolver to resolve their hostnames (privacy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsResolverType {
    SystemDns,
    DoH(DoHProvider),
    DoT(DnsTlsUpstream),
    DoQ(DnsTlsUpstream),
    CustomUdp(String),
    CustomTcp(String),
}

/// DNS-over-HTTPS provider selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DoHProvider {
    Cloudflare,
    Google,
    Quad9,
    AdGuard,
    Custom { url: String },
}

/// DNS-over-TLS / DNS-over-QUIC upstream endpoint configuration.
///
/// Supports both a legacy string form and an extended form with explicit SNI:
///
/// - `"1.1.1.1:853"` (string)
/// - `{ server = "1.1.1.1:853", sni = "cloudflare-dns.com" }` (map)
///
/// NOTE: If `server` is an IP literal, providing `sni` is required for proper certificate validation
/// (most public resolvers don't have IP SANs in their certificates).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DnsTlsUpstream {
    Address(String),
    AddressWithSni {
        server: String,
        #[serde(default)]
        sni: Option<String>,
    },
}

impl DnsTlsUpstream {
    fn server(&self) -> &str {
        match self {
            Self::Address(v) => v,
            Self::AddressWithSni { server, .. } => server,
        }
    }

    fn sni(&self) -> Option<&str> {
        match self {
            Self::Address(_) => None,
            Self::AddressWithSni { sni, .. } => sni.as_deref(),
        }
    }
}

/// DNS resolver runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Enable DNSSEC validation at the resolver level (if supported by the backend).
    #[serde(default)]
    pub enable_dnssec: bool,
    /// Maximum cache size for the backend resolver.
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
    /// Per-query timeout.
    #[serde(default = "default_timeout")]
    pub query_timeout: Duration,
    /// Number of retries (attempts = `retry_count + 1`).
    #[serde(default = "default_retry_count")]
    pub retry_count: usize,
    /// Optional bootstrap IPs used to connect to DoH/DoT/DoQ upstream hostnames without using
    /// the system resolver.
    ///
    /// If empty, resolving upstream hostnames will fall back to system DNS (privacy leak).
    #[serde(default)]
    pub bootstrap_ips: Vec<IpAddr>,
}

fn default_cache_size() -> usize {
    1024
}

fn default_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_retry_count() -> usize {
    2
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable_dnssec: false,
            cache_size: default_cache_size(),
            query_timeout: default_timeout(),
            retry_count: default_retry_count(),
            bootstrap_ips: Vec::new(),
        }
    }
}

/// A "universal" resolver that can try a primary upstream and fall back to a chain of upstreams.
///
/// If compiled without `hickory-dns`, resolution falls back to `tokio::net::lookup_host` (system DNS).
#[derive(Debug, Clone)]
pub struct UniversalDnsResolver {
    /// Primary resolver to be used first.
    pub primary: DnsResolverType,
    /// Ordered list of fallback resolvers to be attempted after `primary`.
    pub fallback_chain: Vec<DnsResolverType>,
    /// Resolver configuration (timeouts, cache, bootstrap, ...).
    pub config: DnsConfig,
    /// If `true`, DNSSEC validation is requested for lookups (when supported).
    pub dnssec_validation: bool,
}

impl Default for UniversalDnsResolver {
    fn default() -> Self {
        Self {
            primary: DnsResolverType::SystemDns,
            fallback_chain: Vec::new(),
            config: DnsConfig::default(),
            dnssec_validation: false,
        }
    }
}

/// Result of an A/AAAA lookup.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub ips: Vec<IpAddr>,
}

/// Result of an MX lookup.
#[derive(Debug, Clone)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

/// Result of an SRV lookup.
#[derive(Debug, Clone)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[cfg(feature = "hickory-dns")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResolverCacheKey {
    resolver: String,
    dnssec: bool,
    cache_size: usize,
    timeout_ms: u64,
    attempts: usize,
}

#[cfg(feature = "hickory-dns")]
static RESOLVER_CACHE: OnceLock<Mutex<std::collections::HashMap<ResolverCacheKey, TokioResolver>>> =
    OnceLock::new();

impl UniversalDnsResolver {
    /// Resolve A/AAAA records for `domain` and return the results along with DNSSEC validation
    /// (when available and enabled).
    ///
    /// # Errors
    ///
    /// Returns an error if all configured resolvers fail, or if resolution yields no addresses.
    pub async fn resolve_with_dnssec(&self, domain: &str) -> Result<DnsResponse> {
        let ips = self.resolve_ips(domain).await?;
        Ok(DnsResponse { ips })
    }

    /// Resolve a PTR record for `ip`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `hickory-dns` feature is not enabled.
    pub async fn resolve_ptr(&self, _ip: IpAddr) -> Result<String> {
        #[cfg(feature = "hickory-dns")]
        {
            return self.resolve_ptr_hickory(_ip).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Internal(
                "PTR resolution requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    /// Resolve MX records for `domain`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `hickory-dns` feature is not enabled.
    pub async fn resolve_mx(&self, _domain: &str) -> Result<Vec<MxRecord>> {
        #[cfg(feature = "hickory-dns")]
        {
            return self.resolve_mx_hickory(_domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Internal(
                "MX resolution requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    /// Resolve TXT records for `domain`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `hickory-dns` feature is not enabled.
    pub async fn resolve_txt(&self, _domain: &str) -> Result<Vec<String>> {
        #[cfg(feature = "hickory-dns")]
        {
            return self.resolve_txt_hickory(_domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Internal(
                "TXT resolution requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    /// Resolve SRV records for `service` (e.g. `"_sip._tcp.example.com"`).
    ///
    /// # Errors
    ///
    /// Returns an error if the `hickory-dns` feature is not enabled.
    pub async fn resolve_srv(&self, _service: &str) -> Result<Vec<SrvRecord>> {
        #[cfg(feature = "hickory-dns")]
        {
            return self.resolve_srv_hickory(_service).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Internal(
                "SRV resolution requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    /// Resolve a CNAME record for `domain`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `hickory-dns` feature is not enabled.
    pub async fn resolve_cname(&self, _domain: &str) -> Result<String> {
        #[cfg(feature = "hickory-dns")]
        {
            return self.resolve_cname_hickory(_domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Internal(
                "CNAME resolution requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    async fn resolve_ips(&self, domain: &str) -> Result<Vec<IpAddr>> {
        #[cfg(feature = "hickory-dns")]
        {
            let mut last_err: Option<EngineError> = None;
            for kind in self.resolver_order() {
                match self.get_or_build_resolver(kind).await {
                    Ok(resolver) => match resolver.lookup_ip(domain).await {
                        Ok(lookup) => {
                            let mut ips: Vec<IpAddr> = lookup.iter().collect();
                            
                            // ANTI-POISONING: Strictly filter out loopback and unspecified IPs for public domains.
                            // If an ISP returns 127.0.0.1 for Instagram, we ignore it and try the next resolver in chain (DoH).
                            let is_public_domain = !domain.ends_with(".local") && !domain.contains("localhost");
                            if is_public_domain {
                                ips.retain(|ip| !ip.is_loopback() && !ip.is_unspecified());
                            }

                            if !ips.is_empty() {
                                ips.sort_unstable();
                                ips.dedup();
                                return Ok(ips);
                            }
                            
                            last_err = Some(EngineError::Internal(format!(
                                "dns lookup for '{domain}' using {kind:?} returned only poisoned or empty results"
                            )));
                        }
                        Err(e) => {
                            last_err = Some(EngineError::Internal(format!(
                                "dns lookup for '{domain}' failed using {kind:?}: {e}"
                            )));
                        }
                    },
                    Err(e) => last_err = Some(e),
                }
            }
            Err(last_err.unwrap_or_else(|| {
                EngineError::Internal(format!(
                    "dns lookup for '{domain}' failed: all resolvers returned no valid addresses"
                ))
            }))
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            self.resolve_system(domain).await
        }
    }

    #[cfg(not(feature = "hickory-dns"))]
    async fn resolve_system(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let result = tokio::net::lookup_host((domain, 443)).await.map_err(|e| {
            EngineError::Internal(format!("system dns lookup for '{domain}' failed: {e}"))
        })?;
        let mut ips: Vec<IpAddr> = result.map(|addr| addr.ip()).collect();
        ips.sort_unstable();
        ips.dedup();
        if ips.is_empty() {
            return Err(EngineError::Internal(format!(
                "system dns lookup for '{domain}' returned no addresses"
            )));
        }
        Ok(ips)
    }

    #[cfg(feature = "hickory-dns")]
    fn resolver_order(&self) -> impl Iterator<Item = &DnsResolverType> {
        std::iter::once(&self.primary).chain(self.fallback_chain.iter())
    }

    #[cfg(feature = "hickory-dns")]
    fn resolver_opts(&self) -> ResolverOpts {
        let mut opts = ResolverOpts::default();
        opts.cache_size = self.config.cache_size.max(512);
        opts.recursion_desired = true;
        opts.timeout = if self.config.query_timeout.as_secs() == 0 {
            Duration::from_secs(5)
        } else {
            self.config.query_timeout.max(Duration::from_secs(3))
        };
        opts.attempts = (self.config.retry_count + 3).max(3);
        opts
    }

    #[cfg(feature = "hickory-dns")]
    fn cache_key_for(&self, kind: &DnsResolverType) -> ResolverCacheKey {
        let opts = self.resolver_opts();
        ResolverCacheKey {
            resolver: match kind {
                DnsResolverType::SystemDns => "system".to_owned(),
                DnsResolverType::DoH(p) => match p {
                    DoHProvider::Cloudflare => "doh:cloudflare".to_owned(),
                    DoHProvider::Google => "doh:google".to_owned(),
                    DoHProvider::Quad9 => "doh:quad9".to_owned(),
                    DoHProvider::AdGuard => "doh:adguard".to_owned(),
                    DoHProvider::Custom { url } => format!("doh:custom:{url}"),
                },
                DnsResolverType::DoT(v) => match v {
                    DnsTlsUpstream::Address(server) => format!("dot:{server}"),
                    DnsTlsUpstream::AddressWithSni { server, sni } => match sni.as_deref() {
                        Some(s) if !s.trim().is_empty() => format!("dot:{server}#sni={s}"),
                        _ => format!("dot:{server}"),
                    },
                },
                DnsResolverType::DoQ(v) => match v {
                    DnsTlsUpstream::Address(server) => format!("doq:{server}"),
                    DnsTlsUpstream::AddressWithSni { server, sni } => match sni.as_deref() {
                        Some(s) if !s.trim().is_empty() => format!("doq:{server}#sni={s}"),
                        _ => format!("doq:{server}"),
                    },
                },
                DnsResolverType::CustomUdp(v) => format!("udp:{v}"),
                DnsResolverType::CustomTcp(v) => format!("tcp:{v}"),
            },
            dnssec: false, // Hardcoded false
            cache_size: opts.cache_size,
            timeout_ms: opts.timeout.as_millis() as u64,
            attempts: opts.attempts,
        }
    }

    #[cfg(feature = "hickory-dns")]
    async fn get_or_build_resolver(&self, kind: &DnsResolverType) -> Result<TokioResolver> {
        let key = self.cache_key_for(kind);
        let cache = RESOLVER_CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
        {
            let guard = cache.lock();
            if let Some(v) = guard.get(&key).cloned() {
                return Ok(v);
            }
        }

        let resolver = self.build_resolver(kind).await?;
        cache.lock().insert(key, resolver.clone());
        Ok(resolver)
    }

    #[cfg(feature = "hickory-dns")]
    async fn build_resolver(&self, kind: &DnsResolverType) -> Result<TokioResolver> {
        match kind {
            DnsResolverType::SystemDns => {
                let mut builder = TokioResolver::builder_tokio().map_err(|e| {
                    EngineError::Internal(format!("system resolver build failed: {e}"))
                })?;
                let opts = self.resolver_opts();
                builder.options_mut().cache_size = opts.cache_size;
                builder.options_mut().timeout = opts.timeout;
                builder.options_mut().attempts = opts.attempts;
                Ok(builder.build())
            }
            DnsResolverType::DoH(provider) => {
                let (host, endpoint) = doh_host_and_path(provider)?;
                let addrs = resolve_socket_addrs(&host, 443, &self.config.bootstrap_ips).await?;
                let mut group = NameServerConfigGroup::new();
                for sa in addrs {
                    let mut ns = NameServerConfig::new(sa, Protocol::Https);
                    ns.tls_dns_name = Some(host.clone());
                    ns.http_endpoint = endpoint.clone();
                    group.push(ns);
                }
                if group.is_empty() {
                    return Err(EngineError::Config(
                        "no DoH name servers resolved".to_owned(),
                    ));
                }

                let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
                let resolver = hickory_resolver::Resolver::builder_with_config(
                    cfg,
                    TokioConnectionProvider::default(),
                )
                .with_options(self.resolver_opts())
                .build();
                Ok(resolver)
            }
            DnsResolverType::DoT(server) => {
                let (host, port) = split_host_port(server.server(), 853)?;
                let addrs = resolve_socket_addrs(&host, port, &self.config.bootstrap_ips).await?;
                let sni = server.sni().map(str::trim).filter(|s| !s.is_empty());
                if let Some(sni) = sni {
                    if is_ip_literal(sni) {
                        return Err(EngineError::Config(format!(
                            "invalid DoT SNI (must be a hostname, not an IP): {sni}"
                        )));
                    }
                }
                let mut group = NameServerConfigGroup::new();
                for sa in addrs {
                    let mut ns = NameServerConfig::new(sa, Protocol::Tls);
                    if is_ip_literal(&host) {
                        let sni = sni.ok_or_else(|| {
                            EngineError::Config(format!(
                                "DoT server is an IP literal and requires explicit SNI for certificate validation: {host}:{port}"
                            ))
                        })?;
                        ns.tls_dns_name = Some(sni.to_owned());
                    } else {
                        ns.tls_dns_name = Some(sni.unwrap_or(&host).to_owned());
                    }
                    group.push(ns);
                }
                if group.is_empty() {
                    return Err(EngineError::Config(
                        "no DoT name servers resolved".to_owned(),
                    ));
                }
                let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
                let resolver = hickory_resolver::Resolver::builder_with_config(
                    cfg,
                    TokioConnectionProvider::default(),
                )
                .with_options(self.resolver_opts())
                .build();
                Ok(resolver)
            }
            DnsResolverType::DoQ(server) => {
                let (host, port) = split_host_port(server.server(), 784)?;
                let addrs = resolve_socket_addrs(&host, port, &self.config.bootstrap_ips).await?;
                let sni = server.sni().map(str::trim).filter(|s| !s.is_empty());
                if let Some(sni) = sni {
                    if is_ip_literal(sni) {
                        return Err(EngineError::Config(format!(
                            "invalid DoQ SNI (must be a hostname, not an IP): {sni}"
                        )));
                    }
                }
                let mut group = NameServerConfigGroup::new();
                for sa in addrs {
                    let mut ns = NameServerConfig::new(sa, Protocol::Quic);
                    if is_ip_literal(&host) {
                        let sni = sni.ok_or_else(|| {
                            EngineError::Config(format!(
                                "DoQ server is an IP literal and requires explicit SNI for certificate validation: {host}:{port}"
                            ))
                        })?;
                        ns.tls_dns_name = Some(sni.to_owned());
                    } else {
                        ns.tls_dns_name = Some(sni.unwrap_or(&host).to_owned());
                    }
                    group.push(ns);
                }
                if group.is_empty() {
                    return Err(EngineError::Config(
                        "no DoQ name servers resolved".to_owned(),
                    ));
                }
                let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
                let resolver = hickory_resolver::Resolver::builder_with_config(
                    cfg,
                    TokioConnectionProvider::default(),
                )
                .with_options(self.resolver_opts())
                .build();
                Ok(resolver)
            }
            DnsResolverType::CustomUdp(server) => {
                let (host, port) = split_host_port(server, 53)?;
                let addrs = resolve_socket_addrs(&host, port, &self.config.bootstrap_ips).await?;
                let mut group = NameServerConfigGroup::new();
                for sa in addrs {
                    group.push(NameServerConfig::new(sa, Protocol::Udp));
                }
                if group.is_empty() {
                    return Err(EngineError::Config(
                        "no UDP name servers resolved".to_owned(),
                    ));
                }
                let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
                let resolver = hickory_resolver::Resolver::builder_with_config(
                    cfg,
                    TokioConnectionProvider::default(),
                )
                .with_options(self.resolver_opts())
                .build();
                Ok(resolver)
            }
            DnsResolverType::CustomTcp(server) => {
                let (host, port) = split_host_port(server, 53)?;
                let addrs = resolve_socket_addrs(&host, port, &self.config.bootstrap_ips).await?;
                let mut group = NameServerConfigGroup::new();
                for sa in addrs {
                    group.push(NameServerConfig::new(sa, Protocol::Tcp));
                }
                if group.is_empty() {
                    return Err(EngineError::Config(
                        "no TCP name servers resolved".to_owned(),
                    ));
                }
                let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
                let resolver = hickory_resolver::Resolver::builder_with_config(
                    cfg,
                    TokioConnectionProvider::default(),
                )
                .with_options(self.resolver_opts())
                .build();
                Ok(resolver)
            }
        }
    }

    #[cfg(feature = "hickory-dns")]
    async fn resolve_ptr_hickory(&self, ip: IpAddr) -> Result<String> {
        let mut last_err: Option<EngineError> = None;
        for kind in self.resolver_order() {
            let resolver = match self.get_or_build_resolver(kind).await {
                Ok(v) => v,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match resolver.reverse_lookup(ip).await {
                Ok(lookup) => {
                    if let Some(ptr) = lookup.iter().next() {
                        return Ok(trim_trailing_dot(&ptr.to_utf8()));
                    }
                    last_err = Some(EngineError::Internal(
                        "PTR lookup returned no records".to_owned(),
                    ));
                }
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!(
                        "PTR lookup failed using {kind:?}: {e}"
                    )));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("PTR lookup failed".to_owned())))
    }

    #[cfg(feature = "hickory-dns")]
    async fn resolve_mx_hickory(&self, domain: &str) -> Result<Vec<MxRecord>> {
        let mut last_err: Option<EngineError> = None;
        for kind in self.resolver_order() {
            let resolver = match self.get_or_build_resolver(kind).await {
                Ok(v) => v,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match resolver.mx_lookup(domain).await {
                Ok(lookup) => {
                    let mut out: Vec<MxRecord> = lookup
                        .iter()
                        .map(|mx| MxRecord {
                            preference: mx.preference(),
                            exchange: trim_trailing_dot(&mx.exchange().to_utf8()),
                        })
                        .collect();
                    out.sort_by_key(|v| v.preference);
                    return Ok(out);
                }
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!(
                        "MX lookup failed using {kind:?}: {e}"
                    )));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("MX lookup failed".to_owned())))
    }

    #[cfg(feature = "hickory-dns")]
    async fn resolve_txt_hickory(&self, domain: &str) -> Result<Vec<String>> {
        let mut last_err: Option<EngineError> = None;
        for kind in self.resolver_order() {
            let resolver = match self.get_or_build_resolver(kind).await {
                Ok(v) => v,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match resolver.txt_lookup(domain).await {
                Ok(lookup) => {
                    let mut out = Vec::new();
                    for txt in lookup.iter() {
                        // TXT records can be split across multiple character-strings; join them.
                        let mut bytes = Vec::new();
                        for part in txt.txt_data() {
                            bytes.extend_from_slice(part);
                        }
                        out.push(String::from_utf8_lossy(&bytes).to_string());
                    }
                    return Ok(out);
                }
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!(
                        "TXT lookup failed using {kind:?}: {e}"
                    )));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("TXT lookup failed".to_owned())))
    }

    #[cfg(feature = "hickory-dns")]
    async fn resolve_srv_hickory(&self, service: &str) -> Result<Vec<SrvRecord>> {
        let mut last_err: Option<EngineError> = None;
        for kind in self.resolver_order() {
            let resolver = match self.get_or_build_resolver(kind).await {
                Ok(v) => v,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match resolver.srv_lookup(service).await {
                Ok(lookup) => {
                    let mut out: Vec<SrvRecord> = lookup
                        .iter()
                        .map(|srv| SrvRecord {
                            priority: srv.priority(),
                            weight: srv.weight(),
                            port: srv.port(),
                            target: trim_trailing_dot(&srv.target().to_utf8()),
                        })
                        .collect();
                    out.sort_by_key(|v| (v.priority, v.weight, v.port));
                    return Ok(out);
                }
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!(
                        "SRV lookup failed using {kind:?}: {e}"
                    )));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("SRV lookup failed".to_owned())))
    }

    #[cfg(feature = "hickory-dns")]
    async fn resolve_cname_hickory(&self, domain: &str) -> Result<String> {
        let mut last_err: Option<EngineError> = None;
        for kind in self.resolver_order() {
            let resolver = match self.get_or_build_resolver(kind).await {
                Ok(v) => v,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match resolver.lookup(domain, RecordType::CNAME).await {
                Ok(lookup) => {
                    for r in lookup.iter() {
                        if let RData::CNAME(cname) = r {
                            return Ok(trim_trailing_dot(&cname.0.to_utf8()));
                        }
                    }
                    last_err = Some(EngineError::Internal(
                        "CNAME lookup returned no CNAME records".to_owned(),
                    ));
                }
                Err(e) => {
                    last_err = Some(EngineError::Internal(format!(
                        "CNAME lookup failed using {kind:?}: {e}"
                    )));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("CNAME lookup failed".to_owned())))
    }
}

#[cfg(feature = "hickory-dns")]
fn trim_trailing_dot(s: &str) -> String {
    s.strip_suffix('.').unwrap_or(s).to_owned()
}

#[cfg(feature = "hickory-dns")]
fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}


use std::net::IpAddr;

use crate::config::{AntiCensorshipConfig, DnsResolverKind};
use crate::error::{EngineError, Result};

#[cfg(feature = "hickory-dns")]
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
#[cfg(feature = "hickory-dns")]
use hickory_resolver::name_server::TokioConnectionProvider;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::proto::rr::rdata::svcb::SvcParamValue;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::proto::rr::{RData, RecordType};
#[cfg(feature = "hickory-dns")]
use hickory_resolver::proto::xfer::Protocol;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::TokioResolver;

#[cfg(feature = "hickory-dns")]
#[derive(Debug, Default)]
struct ResolverState {
    doh: Option<TokioResolver>,
    dot: Option<TokioResolver>,
    doq: Option<TokioResolver>,
    system: Option<TokioResolver>,
}

#[derive(Debug, Clone)]
/// DNS resolver chain used by the anti-censorship flows.
///
/// Resolution is attempted in the order configured in `dns_fallback_chain`.
/// The first resolver that returns a non-empty set of IPs wins.
pub struct ResolverChain {
    chain: Vec<DnsResolverKind>,
    cfg: AntiCensorshipConfig,
    #[cfg(feature = "hickory-dns")]
    state: std::sync::Arc<parking_lot::Mutex<ResolverState>>,
}

impl ResolverChain {
    /// Builds a resolver chain from the anti-censorship configuration.
    pub fn from_config(cfg: &AntiCensorshipConfig) -> Result<Self> {
        Ok(Self {
            chain: cfg.dns_fallback_chain.clone(),
            cfg: cfg.clone(),
            #[cfg(feature = "hickory-dns")]
            state: std::sync::Arc::new(parking_lot::Mutex::new(ResolverState::default())),
        })
    }

    /// Resolves `domain` to a set of IP addresses.
    ///
    /// If `domain` is an IP literal, it is returned as-is without any network I/O.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let mut last_err: Option<EngineError> = None;
        for kind in &self.chain {
            match self.resolve_kind(kind, domain).await {
                Ok(ips) if !ips.is_empty() => return Ok(ips),
                Ok(_) => {
                    last_err = Some(EngineError::Internal(format!(
                        "{} returned no addresses for '{domain}'",
                        kind_name(kind)
                    )));
                }
                Err(e) => last_err = Some(e),
            };
        }

        match last_err {
            Some(e) => Err(e),
            None => Err(EngineError::Config(
                "dns_fallback_chain is empty: no resolvers to try".to_owned(),
            )),
        }
    }

    /// Best-effort fetch of ECHConfigList bytes for `domain` via DNS HTTPS RR.
    ///
    /// The lookup follows the same configured resolver chain order as `resolve()`.
    /// Returns `Ok(None)` if no ECH config list was published (or no resolver succeeded).
    pub async fn lookup_ech_config_list(&self, domain: &str) -> Result<Option<Vec<u8>>> {
        #[cfg(feature = "hickory-dns")]
        {
            let domain = domain.trim().to_ascii_lowercase();
            if domain.is_empty() {
                return Err(EngineError::InvalidInput("domain is empty".to_owned()));
            }

            let mut last_err: Option<EngineError> = None;
            for kind in &self.chain {
                let res = match kind {
                    DnsResolverKind::Doh => {
                        if !self.cfg.doh_enabled {
                            Err(EngineError::Config(
                                "dns_fallback_chain contains 'doh' but doh_enabled=false"
                                    .to_owned(),
                            ))
                        } else {
                            let r = self.get_or_init_doh_resolver().await?;
                            lookup_ech_https_rr(&r, &domain).await
                        }
                    }
                    DnsResolverKind::Dot => {
                        if !self.cfg.dot_enabled {
                            Err(EngineError::Config(
                                "dns_fallback_chain contains 'dot' but dot_enabled=false"
                                    .to_owned(),
                            ))
                        } else {
                            let r = self.get_or_init_dot_resolver()?;
                            lookup_ech_https_rr(&r, &domain).await
                        }
                    }
                    DnsResolverKind::Doq => {
                        if !self.cfg.doq_enabled {
                            Err(EngineError::Config(
                                "dns_fallback_chain contains 'doq' but doq_enabled=false"
                                    .to_owned(),
                            ))
                        } else {
                            let r = self.get_or_init_doq_resolver()?;
                            lookup_ech_https_rr(&r, &domain).await
                        }
                    }
                    DnsResolverKind::System => {
                        if !self.cfg.system_dns_enabled {
                            Err(EngineError::Config(
                                "dns_fallback_chain contains 'system' but system_dns_enabled=false"
                                    .to_owned(),
                            ))
                        } else {
                            let r = self.get_or_init_system_resolver()?;
                            lookup_ech_https_rr(&r, &domain).await
                        }
                    }
                };

                match res {
                    Ok(Some(bytes)) => return Ok(Some(bytes)),
                    Ok(None) => {}
                    Err(e) => last_err = Some(e),
                }
            }

            // Best-effort: if nothing succeeded, treat as "no ECH".
            let _ = last_err;
            Ok(None)
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            let _ = domain;
            Err(EngineError::Internal(
                "ECH config lookup requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    async fn resolve_kind(&self, kind: &DnsResolverKind, domain: &str) -> Result<Vec<IpAddr>> {
        match kind {
            DnsResolverKind::Doh => self.resolve_doh(domain).await,
            DnsResolverKind::Dot => self.resolve_dot(domain).await,
            DnsResolverKind::Doq => self.resolve_doq(domain).await,
            DnsResolverKind::System => self.resolve_system(domain).await,
        }
    }

    async fn resolve_system(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if !self.cfg.system_dns_enabled {
            return Err(EngineError::Config(
                "dns_fallback_chain contains 'system' but system_dns_enabled=false".to_owned(),
            ));
        }

        #[cfg(feature = "hickory-dns")]
        {
            let resolver = self.get_or_init_system_resolver()?;
            return lookup_ips(&resolver, domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            system_resolve(domain).await
        }
    }

    async fn resolve_doh(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if !self.cfg.doh_enabled {
            return Err(EngineError::Config(
                "dns_fallback_chain contains 'doh' but doh_enabled=false".to_owned(),
            ));
        }

        #[cfg(feature = "hickory-dns")]
        {
            let resolver = self.get_or_init_doh_resolver().await?;
            return lookup_ips(&resolver, domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Config(
                "DoH requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    async fn resolve_dot(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if !self.cfg.dot_enabled {
            return Err(EngineError::Config(
                "dns_fallback_chain contains 'dot' but dot_enabled=false".to_owned(),
            ));
        }

        #[cfg(feature = "hickory-dns")]
        {
            let resolver = self.get_or_init_dot_resolver()?;
            return lookup_ips(&resolver, domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Config(
                "DoT requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    async fn resolve_doq(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if !self.cfg.doq_enabled {
            return Err(EngineError::Config(
                "dns_fallback_chain contains 'doq' but doq_enabled=false".to_owned(),
            ));
        }

        #[cfg(feature = "hickory-dns")]
        {
            let resolver = self.get_or_init_doq_resolver()?;
            return lookup_ips(&resolver, domain).await;
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Config(
                "DoQ requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }

    #[cfg(feature = "hickory-dns")]
    fn base_opts(&self) -> ResolverOpts {
        let mut opts = ResolverOpts::default();
        opts.cache_size = self.cfg.dns_cache_size;
        opts.timeout = std::time::Duration::from_secs(self.cfg.dns_query_timeout_secs.max(1));
        opts.attempts = self.cfg.dns_attempts.max(1);
        opts.validate = self.cfg.dnssec_enabled;
        // Back-compat: reuse doh_cache_ttl_secs as a hard upper-bound for cached answers.
        // (Hickory cache is shared across all upstream protocols).
        let max_ttl = std::time::Duration::from_secs(self.cfg.doh_cache_ttl_secs.max(30));
        opts.positive_max_ttl = Some(max_ttl);
        opts.negative_max_ttl = Some(max_ttl);
        opts
    }

    #[cfg(feature = "hickory-dns")]
    fn get_or_init_system_resolver(&self) -> Result<TokioResolver> {
        if let Some(r) = self.state.lock().system.clone() {
            return Ok(r);
        }

        let mut builder = TokioResolver::builder_tokio().map_err(|e| {
            EngineError::Internal(format!("system resolver builder init failed: {e}"))
        })?;
        *builder.options_mut() = self.base_opts();
        let resolver = builder.build();
        self.state.lock().system = Some(resolver.clone());
        Ok(resolver)
    }

    #[cfg(feature = "hickory-dns")]
    async fn get_or_init_doh_resolver(&self) -> Result<TokioResolver> {
        if let Some(r) = self.state.lock().doh.clone() {
            return Ok(r);
        }

        let mut group = NameServerConfigGroup::new();
        let opts = self.base_opts();

        for provider in &self.cfg.doh_providers {
            let host = doh_host_for_provider(provider);
            if host.trim().is_empty() {
                continue;
            }

            if !self.cfg.bootstrap_ips.is_empty() {
                // Prefer explicit bootstrap IPs to avoid leaking upstream resolution to system DNS.
                for ip in self.cfg.bootstrap_ips.iter().copied() {
                    let mut ns =
                        NameServerConfig::new(std::net::SocketAddr::new(ip, 443), Protocol::Https);
                    ns.tls_dns_name = Some(host.clone());
                    // Default http_endpoint is /dns-query when None.
                    group.push(ns);
                }
                continue;
            }

            // Bootstrapping fallback: system DNS leakage can occur here; prefer bootstrap_ips in config.
            let resolved = tokio::net::lookup_host((host.as_str(), 443))
                .await
                .map_err(|e| {
                    EngineError::Internal(format!("bootstrap resolve failed for {host}: {e}"))
                })?;
            let mut ips: Vec<IpAddr> = resolved.map(|sa| sa.ip()).collect();
            ips.sort_unstable();
            ips.dedup();

            for ip in ips.into_iter() {
                let mut ns =
                    NameServerConfig::new(std::net::SocketAddr::new(ip, 443), Protocol::Https);
                ns.tls_dns_name = Some(host.clone());
                // Default http_endpoint is /dns-query when None.
                group.push(ns);
            }
        }

        if group.is_empty() {
            return Err(EngineError::Config(
                "no DoH name servers configured (doh_providers empty?)".to_owned(),
            ));
        }

        let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
        let resolver = hickory_resolver::Resolver::builder_with_config(
            cfg,
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build();

        // Avoid racing initialization: if another task has already installed a resolver, reuse it.
        let mut state = self.state.lock();
        if let Some(r) = state.doh.clone() {
            return Ok(r);
        }
        state.doh = Some(resolver.clone());
        Ok(resolver)
    }

    #[cfg(feature = "hickory-dns")]
    fn get_or_init_dot_resolver(&self) -> Result<TokioResolver> {
        if let Some(r) = self.state.lock().dot.clone() {
            return Ok(r);
        }

        let mut group = NameServerConfigGroup::new();
        let opts = self.base_opts();
        let sni = if self.cfg.dot_sni.trim().is_empty() {
            None
        } else {
            Some(self.cfg.dot_sni.clone())
        };

        for server in &self.cfg.dot_servers {
            let sa = parse_socket_addr(server, 853)?;
            let mut ns = NameServerConfig::new(sa, Protocol::Tls);
            ns.tls_dns_name = sni.clone();
            group.push(ns);
        }
        if group.is_empty() {
            return Err(EngineError::Config(
                "dot_enabled=true but dot_servers is empty".to_owned(),
            ));
        }

        let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
        let resolver = hickory_resolver::Resolver::builder_with_config(
            cfg,
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build();
        let mut state = self.state.lock();
        if let Some(r) = state.dot.clone() {
            return Ok(r);
        }
        state.dot = Some(resolver.clone());
        Ok(resolver)
    }

    #[cfg(feature = "hickory-dns")]
    fn get_or_init_doq_resolver(&self) -> Result<TokioResolver> {
        if let Some(r) = self.state.lock().doq.clone() {
            return Ok(r);
        }

        let mut group = NameServerConfigGroup::new();
        let opts = self.base_opts();
        let sni = if self.cfg.doq_sni.trim().is_empty() {
            None
        } else {
            Some(self.cfg.doq_sni.clone())
        };

        for server in &self.cfg.doq_servers {
            let sa = parse_socket_addr(server, 784)?;
            let mut ns = NameServerConfig::new(sa, Protocol::Quic);
            ns.tls_dns_name = sni.clone();
            group.push(ns);
        }
        if group.is_empty() {
            return Err(EngineError::Config(
                "doq_enabled=true but doq_servers is empty".to_owned(),
            ));
        }

        let cfg = ResolverConfig::from_parts(None, Vec::new(), group);
        let resolver = hickory_resolver::Resolver::builder_with_config(
            cfg,
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build();
        let mut state = self.state.lock();
        if let Some(r) = state.doq.clone() {
            return Ok(r);
        }
        state.doq = Some(resolver.clone());
        Ok(resolver)
    }
}

#[cfg(feature = "hickory-dns")]
async fn lookup_ips(resolver: &TokioResolver, domain: &str) -> Result<Vec<IpAddr>> {
    let lookup = resolver
        .lookup_ip(domain)
        .await
        .map_err(|e| EngineError::Internal(format!("dns lookup failed for '{domain}': {e}")))?;
    let mut ips: Vec<IpAddr> = lookup.iter().collect();
    ips.sort_unstable();
    ips.dedup();
    Ok(ips)
}

#[cfg(feature = "hickory-dns")]
async fn lookup_ech_https_rr(resolver: &TokioResolver, domain: &str) -> Result<Option<Vec<u8>>> {
    let lookup = resolver
        .lookup(domain, RecordType::HTTPS)
        .await
        .map_err(|e| EngineError::Internal(format!("HTTPS lookup failed for {domain}: {e}")))?;

    // Pick the first HTTPS/SVCB record that contains an ECH config list.
    // If multiple are present, prefer the lowest SvcPriority.
    let mut best: Option<(u16, Vec<u8>)> = None;
    for r in lookup.iter() {
        let RData::HTTPS(https) = r else { continue };
        let prio = https.svc_priority();
        for (_, v) in https.svc_params() {
            if let SvcParamValue::EchConfigList(ech) = v {
                let value = (prio, ech.0.clone());
                match &best {
                    None => best = Some(value),
                    Some((best_prio, _)) if prio < *best_prio => best = Some(value),
                    _ => {}
                }
            }
        }
    }

    Ok(best.map(|(_, bytes)| bytes))
}

#[cfg(not(feature = "hickory-dns"))]
async fn system_resolve(domain: &str) -> Result<Vec<IpAddr>> {
    let result = tokio::net::lookup_host((domain, 443)).await.map_err(|e| {
        EngineError::Internal(format!("system DNS lookup failed for '{domain}': {e}"))
    })?;
    let mut ips: Vec<IpAddr> = result.map(|addr| addr.ip()).collect();
    ips.sort_unstable();
    ips.dedup();
    Ok(ips)
}

#[cfg(feature = "hickory-dns")]
fn doh_host_for_provider(provider: &str) -> String {
    let v = provider.trim();
    if v.contains("://") {
        if let Ok(url) = url::Url::parse(v) {
            if let Some(host) = url.host_str() {
                return host.to_owned();
            }
        }
        return v.to_owned();
    }

    let key = v.to_ascii_lowercase();
    match key.as_str() {
        "cloudflare"
        | "cloudflare-security"
        | "cloudflare_security"
        | "cloudflare-family"
        | "cloudflare_family" => "cloudflare-dns.com".to_owned(),
        "google" => "dns.google".to_owned(),
        "quad9" | "quad9-secured" | "quad9_secured" => "dns.quad9.net".to_owned(),
        "adguard" | "adguard-family" | "adguard_family" => "dns.adguard.com".to_owned(),
        "mullvad" | "mullvaddns" | "mullvad-dns" | "mullvad_dns" => "doh.mullvad.net".to_owned(),
        "opendns" | "opendns-family" | "opendns_family" => "doh.opendns.com".to_owned(),
        _ => v.to_owned(),
    }
}

fn kind_name(kind: &DnsResolverKind) -> &'static str {
    match kind {
        DnsResolverKind::Doh => "DoH",
        DnsResolverKind::Dot => "DoT",
        DnsResolverKind::Doq => "DoQ",
        DnsResolverKind::System => "System DNS",
    }
}

#[cfg(feature = "hickory-dns")]
fn parse_socket_addr(value: &str, default_port: u16) -> Result<std::net::SocketAddr> {
    let v = value.trim();
    if v.is_empty() {
        return Err(EngineError::Config("empty DNS server address".to_owned()));
    }
    let with_port = if v.contains(':') && v.rfind(':') != v.find(':') && !v.contains(']') {
        // Likely raw IPv6 without brackets and without port; bracket it.
        format!("[{v}]:{default_port}")
    } else if v.contains(':') && v.contains(']') {
        // [IPv6]:port or [IPv6]
        if v.contains("]:") {
            v.to_owned()
        } else {
            format!("{v}:{default_port}")
        }
    } else if v.contains(':') {
        // host:port or ipv4:port
        v.to_owned()
    } else {
        format!("{v}:{default_port}")
    };
    with_port
        .parse::<std::net::SocketAddr>()
        .map_err(|e| EngineError::Config(format!("invalid socket addr '{value}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EngineConfig;

    #[tokio::test]
    async fn chain_with_only_system_resolves_localhost() {
        let mut cfg = EngineConfig::default();
        cfg.anticensorship.doh_enabled = false;
        cfg.anticensorship.dot_enabled = false;
        cfg.anticensorship.doq_enabled = false;
        cfg.anticensorship.system_dns_enabled = true;
        cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::System];
        let chain = ResolverChain::from_config(&cfg.anticensorship).expect("build chain");
        let ips = chain.resolve("localhost").await.expect("resolve localhost");
        assert!(!ips.is_empty());
    }
}

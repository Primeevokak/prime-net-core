use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::Deserialize;
use url::Url;

use crate::error::{EngineError, Result};

#[derive(Debug, Clone)]
pub enum DoHProvider {
    Cloudflare,
    CloudflareSecurity,
    CloudflareFamily,
    Google,
    Quad9,
    Quad9Secured,
    AdGuard,
    AdGuardFamily,
    OpenDns,
    OpenDnsFamily,
    MullvadDns,
    ControlD,
    Custom(String),
}

impl DoHProvider {
    pub fn from_name(name: &str) -> Self {
        let name = name.trim();
        let lower = name.to_lowercase();
        match lower.as_str() {
            "cloudflare" => Self::Cloudflare,
            "cloudflare-security" | "cloudflare_security" => Self::CloudflareSecurity,
            "cloudflare-family" | "cloudflare_family" => Self::CloudflareFamily,
            "google" => Self::Google,
            "quad9" => Self::Quad9,
            "quad9-secured" | "quad9_secured" => Self::Quad9Secured,
            "adguard" => Self::AdGuard,
            "adguard-family" | "adguard_family" => Self::AdGuardFamily,
            "opendns" => Self::OpenDns,
            "opendns-family" | "opendns_family" => Self::OpenDnsFamily,
            "mullvad" | "mullvaddns" | "mullvad-dns" | "mullvad_dns" => Self::MullvadDns,
            "controld" | "control-d" | "control_d" => Self::ControlD,
            _ => {
                // Convention: "nextdns:<config_id>".
                if let Some(rest) = lower.strip_prefix("nextdns:") {
                    return Self::Custom(format!("https://dns.nextdns.io/{rest}"));
                }
                Self::Custom(name.to_owned())
            }
        }
    }

    /// Returns the provider DoH endpoint URL.
    ///
    /// This is used by the engine DoH implementation and by the CLI config checker.
    pub fn endpoint_url(&self) -> String {
        match self {
            DoHProvider::Cloudflare => "https://cloudflare-dns.com/dns-query".to_owned(),
            DoHProvider::CloudflareSecurity => {
                "https://security.cloudflare-dns.com/dns-query".to_owned()
            }
            DoHProvider::CloudflareFamily => {
                "https://family.cloudflare-dns.com/dns-query".to_owned()
            }
            DoHProvider::Google => "https://dns.google/resolve".to_owned(),
            DoHProvider::Quad9 => "https://dns.quad9.net/dns-query".to_owned(),
            DoHProvider::Quad9Secured => "https://dns9.quad9.net/dns-query".to_owned(),
            DoHProvider::AdGuard => "https://dns.adguard.com/dns-query".to_owned(),
            DoHProvider::AdGuardFamily => "https://dns-family.adguard.com/dns-query".to_owned(),
            DoHProvider::OpenDns => "https://doh.opendns.com/dns-query".to_owned(),
            DoHProvider::OpenDnsFamily => {
                "https://doh.familyshield.opendns.com/dns-query".to_owned()
            }
            DoHProvider::MullvadDns => "https://doh.mullvad.net/dns-query".to_owned(),
            DoHProvider::ControlD => "https://freedns.controld.com/p0".to_owned(),
            DoHProvider::Custom(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DoHResolver {
    providers: Vec<DoHProvider>,
    cache: std::sync::Arc<RwLock<HashMap<String, CachedDnsEntry>>>,
    client: reqwest::Client,
    default_ttl: Duration,
}

#[derive(Debug, Clone)]
struct CachedDnsEntry {
    expires_at: Instant,
    ips: Vec<IpAddr>,
}

impl DoHResolver {
    pub fn new(
        provider_names: Vec<String>,
        ttl_secs: u64,
        bootstrap_ips: Vec<IpAddr>,
    ) -> Result<Self> {
        let providers: Vec<DoHProvider> = if provider_names.is_empty() {
            vec![
                DoHProvider::AdGuard,
                DoHProvider::Google,
                DoHProvider::Quad9,
            ]
        } else {
            provider_names
                .iter()
                .map(|v| DoHProvider::from_name(v))
                .collect()
        };

        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .no_proxy();
        if !bootstrap_ips.is_empty() {
            // Only apply bootstrap IPs if we have a single provider.
            // Applying the same IP list to multiple distinct providers would be incorrect
            // (e.g. resolving google.com and cloudflare.com to the same IP).
            if providers.len() == 1 {
                if let Some(provider) = providers.first() {
                    if let Ok(url) = Url::parse(&provider.endpoint_url()) {
                        if let Some(host) = url.host_str() {
                            let addrs: Vec<std::net::SocketAddr> = bootstrap_ips
                                .iter()
                                .copied()
                                .map(|ip| std::net::SocketAddr::new(ip, 443))
                                .collect();
                            builder = builder.resolve_to_addrs(host, &addrs);
                        }
                    }
                }
            } else {
                // If we could log here, we should warn that bootstrap_ips are ignored for multi-provider setup.
                // For now, we just skip applying them to avoid breakage.
            }
        }
        let client = builder.build()?;

        Ok(Self {
            providers,
            cache: std::sync::Arc::new(RwLock::new(HashMap::new())),
            client,
            default_ttl: Duration::from_secs(ttl_secs.max(30)),
        })
    }

    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let (ips, needs_refresh) = {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(domain) {
                let now = Instant::now();
                if entry.expires_at > now {
                    // Pre-fetching: if 30% or less of TTL remains, refresh in background
                    let ttl_remaining = entry.expires_at.duration_since(now);
                    let needs_refresh = ttl_remaining < self.default_ttl / 3;
                    (Some(entry.ips.clone()), needs_refresh)
                } else {
                    (None, true)
                }
            } else {
                (None, true)
            }
        };

        if let Some(ips) = ips {
            if needs_refresh {
                let self_clone = self.clone();
                let domain_clone = domain.to_owned();
                tokio::spawn(async move {
                    let _ = self_clone.refresh_cache(&domain_clone).await;
                });
            }
            return Ok(ips);
        }

        self.refresh_cache(domain).await
    }

    async fn refresh_cache(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let mut last_err = None;
        for provider in &self.providers {
            match self.query_doh_provider(provider, domain, false).await {
                Ok(answer) => {
                    if !answer.ips.is_empty() {
                        self.cache.write().insert(
                            domain.to_owned(),
                            CachedDnsEntry {
                                expires_at: Instant::now() + answer.ttl,
                                ips: answer.ips.clone(),
                            },
                        );
                        return Ok(answer.ips);
                    }
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| EngineError::Internal("DoH refresh failed: no results".to_owned())))
    }

    pub async fn resolve_with_dnssec(&self, domain: &str) -> Result<(Vec<IpAddr>, bool)> {
        let mut last_err = None;
        for provider in &self.providers {
            match self.query_doh_provider(provider, domain, true).await {
                Ok(answer) => {
                    if !answer.ips.is_empty() {
                        return Ok((answer.ips, answer.ad));
                    }
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| EngineError::Internal("DoH DNSSEC resolve failed".to_owned())))
    }

    async fn query_doh_provider(
        &self,
        provider: &DoHProvider,
        domain: &str,
        dnssec_ok: bool,
    ) -> Result<DoHResolved> {
        let endpoint = provider.endpoint_url();

        let (a_res, aaaa_res) = tokio::join!(
            self.query_record(&endpoint, domain, "A", dnssec_ok),
            self.query_record(&endpoint, domain, "AAAA", dnssec_ok)
        );

        let a = a_res?;
        let aaaa = aaaa_res?;

        let mut addresses = Vec::new();
        addresses.extend(a.ips);
        addresses.extend(aaaa.ips);
        addresses.sort_unstable();
        addresses.dedup();

        // Respect record TTL when present, but never exceed our default TTL.
        let ttl = a.ttl.min(aaaa.ttl).min(self.default_ttl);
        Ok(DoHResolved {
            ips: addresses,
            ttl,
            ad: a.ad || aaaa.ad,
        })
    }

    async fn query_record(
        &self,
        endpoint: &str,
        domain: &str,
        record_type: &str,
        dnssec_ok: bool,
    ) -> Result<DoHResolved> {
        let request = if endpoint.contains("/resolve") {
            self.client.get(endpoint).query(&[
                ("name", domain),
                ("type", record_type),
                ("do", if dnssec_ok { "1" } else { "0" }),
            ])
        } else {
            self.client
                .get(endpoint)
                .query(&[
                    ("name", domain),
                    ("type", record_type),
                    ("do", if dnssec_ok { "1" } else { "0" }),
                ])
                .header("accept", "application/dns-json")
        };

        let answer = request.send().await?;
        if !answer.status().is_success() {
            return Ok(DoHResolved::empty(self.default_ttl));
        }
        let parsed: DoHAnswer = answer.json().await?;
        if parsed.status != 0 {
            return Ok(DoHResolved::empty(self.default_ttl));
        }

        let mut ips = Vec::new();
        let mut ttl = self.default_ttl;
        if let Some(records) = parsed.answer {
            for record in records {
                if let Ok(ip) = IpAddr::from_str(&record.data) {
                    ips.push(ip);
                }
                if let Some(rec_ttl) = record.ttl {
                    ttl = ttl.min(Duration::from_secs(rec_ttl as u64));
                }
            }
        }
        Ok(DoHResolved {
            ips,
            ttl,
            ad: parsed.ad.unwrap_or(false),
        })
    }

    async fn system_resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let result = tokio::net::lookup_host((domain, 443))
            .await
            .map_err(|e| EngineError::Internal(e.to_string()))?;
        let mut ips: Vec<IpAddr> = result.map(|addr| addr.ip()).collect();
        ips.sort_unstable();
        ips.dedup();
        if ips.is_empty() {
            return Err(EngineError::Internal(
                "DNS resolve produced no addresses".to_owned(),
            ));
        }
        Ok(ips)
    }
}

#[derive(Debug, Deserialize)]
struct DoHAnswer {
    #[serde(rename = "Status")]
    status: i32,
    #[serde(rename = "AD")]
    ad: Option<bool>,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DoHRecord>>,
}

#[derive(Debug, Deserialize)]
struct DoHRecord {
    #[serde(rename = "TTL")]
    ttl: Option<u32>,
    data: String,
}

#[derive(Debug, Clone)]
struct DoHResolved {
    ips: Vec<IpAddr>,
    ttl: Duration,
    ad: bool,
}

impl DoHResolved {
    fn empty(default_ttl: Duration) -> Self {
        Self {
            ips: Vec::new(),
            ttl: default_ttl,
            ad: false,
        }
    }
}

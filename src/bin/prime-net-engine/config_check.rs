use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use prime_net_engine_core::anticensorship::DoHProvider;
use prime_net_engine_core::anticensorship::ResolverChain;
use prime_net_engine_core::config::DomainFrontingRule;
use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::EngineConfig;
use reqwest::header::{HeaderValue, HOST};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone)]
pub struct ConfigCheckOpts {
    pub offline: bool,
    pub probe_domain: String,
}

#[derive(Debug, Clone)]
pub struct ConfigCheckReport {
    pub doh_results: Vec<(String, bool, String)>,
    pub fronting_results: Vec<(String, bool, String)>,
}

pub async fn run_config_check(
    cfg: &EngineConfig,
    opts: &ConfigCheckOpts,
) -> Result<ConfigCheckReport> {
    cfg.validate()?;

    if opts.offline {
        return Ok(ConfigCheckReport {
            doh_results: Vec::new(),
            fronting_results: Vec::new(),
        });
    }

    let mut report = ConfigCheckReport {
        doh_results: Vec::new(),
        fronting_results: Vec::new(),
    };

    if cfg.anticensorship.doh_enabled {
        #[cfg(not(feature = "hickory-dns"))]
        {
            return Err(EngineError::Config(
                "anticensorship.doh_enabled=true requires building with Cargo feature 'hickory-dns'".to_owned(),
            ));
        }

        // The main engine DoH path is implemented via Hickory (feature-gated). The CLI checker
        // verifies reachability of configured DoH endpoints directly.
        for provider in &cfg.anticensorship.doh_providers {
            let r = probe_doh_provider(
                provider,
                &opts.probe_domain,
                cfg.anticensorship.bootstrap_ips.clone(),
            )
            .await;
            match r {
                Ok(()) => report
                    .doh_results
                    .push((provider.clone(), true, "ok".to_owned())),
                Err(e) => report
                    .doh_results
                    .push((provider.clone(), false, e.to_string())),
            }
        }
    }

    if cfg.anticensorship.domain_fronting_enabled {
        let resolver = ResolverChain::from_config(&cfg.anticensorship)?;
        for rule in &cfg.anticensorship.domain_fronting_rules {
            probe_fronting_rule(&resolver, cfg, rule, &mut report).await;
        }
    }

    Ok(report)
}

async fn probe_fronting_rule(
    resolver: &ResolverChain,
    cfg: &EngineConfig,
    rule: &DomainFrontingRule,
    report: &mut ConfigCheckReport,
) {
    let candidates: Vec<String> = if !rule.front_domains.is_empty() {
        rule.front_domains
            .iter()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect()
    } else if !rule.front_domain.trim().is_empty() {
        vec![rule.front_domain.trim().to_owned()]
    } else {
        Vec::new()
    };

    for front in candidates {
        let label = format!(
            "fronting: target_host={} front_domain={} real_host={}",
            rule.target_host, front, rule.real_host
        );
        let res = probe_front_domain(resolver, cfg, &front, &rule.real_host).await;
        match res {
            Ok(()) => report.fronting_results.push((label, true, "ok".to_owned())),
            Err(e) => report.fronting_results.push((label, false, e.to_string())),
        }
    }
}

async fn probe_front_domain(
    resolver: &ResolverChain,
    cfg: &EngineConfig,
    front_domain: &str,
    real_host: &str,
) -> Result<()> {
    let ips = resolver.resolve(front_domain).await?;
    if ips.is_empty() {
        return Err(EngineError::Internal(format!(
            "resolver returned no IPs for front domain '{front_domain}'"
        )));
    }

    let Ok(host_header) = HeaderValue::from_str(real_host) else {
        return Err(EngineError::InvalidInput(
            "invalid real_host for Host header".to_owned(),
        ));
    };

    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(
            cfg.download.connect_timeout_secs.max(1),
        ))
        .timeout(Duration::from_secs(
            cfg.anticensorship.fronting_probe_timeout_secs.max(1),
        ));

    let addrs: Vec<SocketAddr> = ips
        .iter()
        .copied()
        .map(|ip| SocketAddr::new(ip, 443))
        .collect();
    builder = builder.resolve_to_addrs(front_domain, &addrs);
    let client = builder.build().map_err(EngineError::Http)?;

    let url = format!("https://{front_domain}/");
    let resp = client.head(url).header(HOST, host_header).send().await?;
    if resp.status().as_u16() >= 500 {
        return Err(EngineError::Internal(format!(
            "fronting probe got status {}",
            resp.status()
        )));
    }
    Ok(())
}

async fn probe_doh_provider(
    provider_name: &str,
    domain: &str,
    bootstrap_ips: Vec<IpAddr>,
) -> Result<()> {
    let provider = DoHProvider::from_name(provider_name);
    let endpoint = provider.endpoint_url();
    let url = Url::parse(&endpoint).map_err(EngineError::Url)?;
    let host = url
        .host_str()
        .ok_or_else(|| EngineError::InvalidInput("DoH endpoint missing host".to_owned()))?
        .to_owned();

    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(8));
    if !bootstrap_ips.is_empty() {
        let addrs: Vec<SocketAddr> = bootstrap_ips
            .iter()
            .copied()
            .map(|ip| SocketAddr::new(ip, 443))
            .collect();
        builder = builder.resolve_to_addrs(&host, &addrs);
    }
    let client = builder.build().map_err(EngineError::Http)?;

    let mut req = client.get(&endpoint);
    // Google uses /resolve, others use /dns-query with application/dns-json.
    req = req.query(&[("name", domain), ("type", "A"), ("do", "0")]);
    if !endpoint.contains("/resolve") {
        req = req.header("accept", "application/dns-json");
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Err(EngineError::Internal(format!(
            "DoH endpoint returned HTTP {}",
            resp.status()
        )));
    }

    let parsed: DoHJsonAnswer = resp.json().await?;
    if parsed.status != 0 {
        return Err(EngineError::Internal(format!(
            "DoH JSON Status={} (non-zero)",
            parsed.status
        )));
    }

    let ips = parsed
        .answer
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| r.data.parse::<IpAddr>().ok())
        .collect::<Vec<_>>();

    if ips.is_empty() {
        return Err(EngineError::Internal(
            "DoH probe returned no A records".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct DoHJsonAnswer {
    #[serde(rename = "Status")]
    status: i32,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DoHJsonRecord>>,
}

#[derive(Debug, Deserialize)]
struct DoHJsonRecord {
    #[serde(rename = "data")]
    data: String,
}

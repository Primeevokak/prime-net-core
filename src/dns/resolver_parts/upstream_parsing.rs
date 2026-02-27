#[cfg(feature = "hickory-dns")]
fn split_host_port(value: &str, default_port: u16) -> Result<(String, u16)> {
    let v = value.trim();
    if v.is_empty() {
        return Err(EngineError::Config("empty DNS server address".to_owned()));
    }

    // Bracketed IPv6: [::1]:853
    if let Some(rest) = v.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err(EngineError::Config(format!(
                "invalid DNS server address '{}': missing closing ']'",
                v
            )));
        };
        let host = host.trim();
        if host.is_empty() {
            return Err(EngineError::Config(format!(
                "invalid DNS server address '{}': host is empty",
                v
            )));
        }
        let port = if tail.is_empty() {
            default_port
        } else {
            let raw = tail.strip_prefix(':').ok_or_else(|| {
                EngineError::Config(format!(
                    "invalid DNS server address '{}': unexpected trailing characters",
                    v
                ))
            })?;
            let raw = raw.trim();
            if raw.is_empty() {
                return Err(EngineError::Config(format!(
                    "invalid DNS server address '{}': port is empty",
                    v
                )));
            }
            raw.parse::<u16>().map_err(|_| {
                EngineError::Config(format!("invalid DNS server address '{}': invalid port", v))
            })?
        };
        return Ok((host.to_owned(), port));
    }

    // If it's a pure IP, use default port.
    if v.parse::<IpAddr>().is_ok() {
        return Ok((v.to_owned(), default_port));
    }

    // host:port or host
    if let Some((h, p)) = v.rsplit_once(':') {
        let host = h.trim();
        if host.is_empty() {
            return Err(EngineError::Config(format!(
                "invalid DNS server address '{}': host is empty",
                v
            )));
        }
        let raw = p.trim();
        if raw.is_empty() {
            return Err(EngineError::Config(format!(
                "invalid DNS server address '{}': port is empty",
                v
            )));
        }
        let port = raw.parse::<u16>().map_err(|_| {
            EngineError::Config(format!("invalid DNS server address '{}': invalid port", v))
        })?;
        return Ok((host.to_owned(), port));
    }

    Ok((v.to_owned(), default_port))
}

#[cfg(feature = "hickory-dns")]
async fn resolve_socket_addrs(
    host: &str,
    port: u16,
    bootstrap_ips: &[IpAddr],
    allow_system_fallback: bool,
) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    // Prefer explicit bootstrap IPs to avoid leaking upstream resolver hostnames to the system DNS.
    // If none are provided, fall back to system DNS (warn loudly).
    let mut addrs: Vec<SocketAddr> = if !bootstrap_ips.is_empty() {
        bootstrap_ips
            .iter()
            .copied()
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    } else {
        if !allow_system_fallback {
            return Err(EngineError::Config(format!(
                "bootstrap DNS is required to resolve upstream '{host}:{port}' without system DNS leak; set dns.bootstrap_ips or use an IP literal"
            )));
        }
        tracing::warn!(
            host = host,
            port = port,
            "resolving DNS upstream via system resolver (privacy leak); set dns.bootstrap_ips or use an IP literal"
        );
        let resolved = tokio::net::lookup_host((host, port)).await.map_err(|e| {
            EngineError::Internal(format!("failed to resolve nameserver {host}:{port}: {e}"))
        })?;
        resolved.collect()
    };
    addrs.sort_unstable_by(|a, b| a.ip().cmp(&b.ip()).then_with(|| a.port().cmp(&b.port())));
    addrs.dedup();
    Ok(addrs)
}

#[cfg(feature = "hickory-dns")]
fn doh_host_and_path(provider: &DoHProvider) -> Result<(String, Option<String>)> {
    let url = match provider {
        DoHProvider::Cloudflare => "https://cloudflare-dns.com/dns-query".to_owned(),
        DoHProvider::Google => "https://dns.google/dns-query".to_owned(),
        DoHProvider::Quad9 => "https://dns.quad9.net/dns-query".to_owned(),
        DoHProvider::AdGuard => "https://dns.adguard.com/dns-query".to_owned(),
        DoHProvider::Custom { url } => url.clone(),
    };

    let parsed = url::Url::parse(&url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| EngineError::Config(format!("invalid DoH url (no host): {url}")))?
        .to_owned();
    let path = parsed.path().trim();
    let endpoint = if path.is_empty() || path == "/" {
        None
    } else {
        Some(path.to_owned())
    };
    Ok((host, endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "hickory-dns")]
    #[tokio::test]
    async fn dot_ip_literal_requires_explicit_sni() {
        let r = UniversalDnsResolver {
            primary: DnsResolverType::DoT(DnsTlsUpstream::Address("1.1.1.1:853".to_owned())),
            fallback_chain: Vec::new(),
            config: DnsConfig::default(),
            dnssec_validation: false,
        };

        let err = r
            .build_resolver(&r.primary)
            .await
            .expect_err("IP literal DoT must require explicit SNI");
        match err {
            EngineError::Config(msg) => assert!(msg.contains("requires explicit SNI")),
            other => panic!("expected config error, got: {other:?}"),
        }
    }

    #[cfg(feature = "hickory-dns")]
    #[tokio::test]
    async fn dot_ip_literal_with_sni_is_accepted() {
        let r = UniversalDnsResolver {
            primary: DnsResolverType::DoT(DnsTlsUpstream::AddressWithSni {
                server: "1.1.1.1:853".to_owned(),
                sni: Some("cloudflare-dns.com".to_owned()),
            }),
            fallback_chain: Vec::new(),
            config: DnsConfig::default(),
            dnssec_validation: false,
        };

        r.build_resolver(&r.primary)
            .await
            .expect("DoT with explicit SNI should build");
    }

    #[cfg(feature = "hickory-dns")]
    #[tokio::test]
    async fn bootstrap_ips_are_used_without_system_dns() {
        let bootstrap = [IpAddr::from([1, 2, 3, 4])];
        let addrs = resolve_socket_addrs("does-not-exist.invalid", 853, &bootstrap, false)
            .await
            .expect("bootstrap should bypass system DNS resolution");
        assert_eq!(addrs, vec![SocketAddr::new(bootstrap[0], 853)]);
    }

    #[cfg(feature = "hickory-dns")]
    #[tokio::test]
    async fn encrypted_upstream_without_bootstrap_is_rejected() {
        let err = resolve_socket_addrs("dns.google", 443, &[], false)
            .await
            .expect_err("DoH/DoT/DoQ upstream without bootstrap must fail closed");
        assert!(format!("{err}").contains("bootstrap DNS is required"));
    }

    #[cfg(feature = "hickory-dns")]
    #[test]
    fn split_host_port_rejects_invalid_port_instead_of_using_default() {
        let err = split_host_port("dns.google:not-a-port", 853)
            .expect_err("invalid port must not silently fallback to default");
        assert!(format!("{err}").contains("invalid port"));
    }

    #[cfg(feature = "hickory-dns")]
    #[test]
    fn split_host_port_rejects_empty_host() {
        let err = split_host_port(":853", 853).expect_err("empty host must fail");
        assert!(format!("{err}").contains("host is empty"));
    }

    #[cfg(feature = "hickory-dns")]
    #[test]
    fn split_host_port_rejects_unexpected_trailing_after_brackets() {
        let err = split_host_port("[::1]extra", 853)
            .expect_err("unexpected trailing chars after bracketed host must fail");
        assert!(format!("{err}").contains("unexpected trailing characters"));
    }
}

use std::collections::HashMap;

use url::Url;

use crate::core::RequestData;
use crate::error::Result;

#[derive(Debug, Clone)]
pub enum CdnProvider {
    Cloudflare,
    Fastly,
    GoogleCdn,
    AzureCdn,
}

#[derive(Debug, Clone)]
pub struct FrontConfig {
    pub front_domain: String,
    pub real_host: String,
    pub sni_domain: String,
    pub provider: CdnProvider,
}

#[derive(Debug, Default, Clone)]
pub struct DomainFrontingProxy {
    mapping: HashMap<String, FrontConfig>,
}

impl DomainFrontingProxy {
    pub fn new() -> Self {
        Self {
            mapping: HashMap::new(),
        }
    }

    pub fn upsert_mapping(&mut self, host: impl Into<String>, cfg: FrontConfig) {
        let host = host.into().trim_end_matches('.').to_ascii_lowercase();
        self.mapping.insert(host, cfg);
    }

    pub fn apply_fronting(&self, req: &mut RequestData) -> Result<()> {
        let parsed = Url::parse(&req.url)?;
        let Some(host) = parsed.host_str() else {
            return Ok(());
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let Some(cfg) = self.mapping.get(&host) else {
            return Ok(());
        };

        let mut new_url = parsed.clone();
        new_url.set_host(Some(&cfg.front_domain))?;
        req.url = new_url.to_string();
        req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
        req.headers.push(("Host".to_owned(), cfg.real_host.clone()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_fronting_rewrites_url_and_host_header() {
        let mut proxy = DomainFrontingProxy::new();
        proxy.upsert_mapping(
            "blocked.example",
            FrontConfig {
                front_domain: "front.cloudflare.example".to_owned(),
                real_host: "blocked.example".to_owned(),
                sni_domain: "front.cloudflare.example".to_owned(),
                provider: CdnProvider::Cloudflare,
            },
        );

        let mut request = RequestData::get("https://blocked.example/path");
        request
            .headers
            .push(("Accept".to_owned(), "*/*".to_owned()));
        request
            .headers
            .push(("Host".to_owned(), "old.example".to_owned()));

        proxy
            .apply_fronting(&mut request)
            .expect("fronting rewrite should succeed");

        assert_eq!(request.url, "https://front.cloudflare.example/path");
        assert_eq!(
            request
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.as_str()),
            Some("blocked.example")
        );
    }

    #[test]
    fn apply_fronting_handles_trailing_dot_in_url() {
        let mut proxy = DomainFrontingProxy::new();
        proxy.upsert_mapping(
            "blocked.example",
            FrontConfig {
                front_domain: "front.cloudflare.example".to_owned(),
                real_host: "blocked.example".to_owned(),
                sni_domain: "front.cloudflare.example".to_owned(),
                provider: CdnProvider::Cloudflare,
            },
        );

        let mut request = RequestData::get("https://blocked.example./path");
        proxy.apply_fronting(&mut request).unwrap();

        assert_eq!(request.url, "https://front.cloudflare.example/path");
    }
}

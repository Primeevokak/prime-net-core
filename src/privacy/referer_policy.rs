use std::collections::HashSet;

use url::Url;

use crate::config::{RefererConfig, RefererMode};

const BUILTIN_SEARCH_ENGINES: &[&str] = &[
    "google.com",
    "www.google.com",
    "bing.com",
    "www.bing.com",
    "duckduckgo.com",
    "www.duckduckgo.com",
    "search.yahoo.com",
    "yandex.com",
    "yandex.ru",
    "ya.ru",
    "baidu.com",
    "www.baidu.com",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefererDecision {
    Kept,
    Stripped,
    OriginOnly,
}

pub fn apply_referer_policy(
    request_url: &Url,
    headers: &mut Vec<(String, String)>,
    cfg: &RefererConfig,
) -> RefererDecision {
    if !cfg.enabled {
        return RefererDecision::Kept;
    }

    let idx = headers
        .iter()
        .position(|(k, _)| k.eq_ignore_ascii_case("referer"));

    let mut decision = RefererDecision::Kept;
    if let Some(i) = idx {
        let current = headers[i].1.clone();
        let effective = resolve_mode(request_url, &current, cfg);
        decision = match effective {
            RefererMode::PassThrough => RefererDecision::Kept,
            RefererMode::Strip => {
                headers.remove(i);
                RefererDecision::Stripped
            }
            RefererMode::OriginOnly => match Url::parse(&current) {
                Ok(parsed) => {
                    headers[i].1 = parsed.origin().ascii_serialization();
                    RefererDecision::OriginOnly
                }
                Err(_) => {
                    headers.remove(i);
                    RefererDecision::Stripped
                }
            },
        };
    }

    upsert_header(
        headers,
        "Referrer-Policy",
        match decision {
            RefererDecision::Kept => "strict-origin-when-cross-origin",
            RefererDecision::Stripped => "no-referrer",
            RefererDecision::OriginOnly => "strict-origin-when-cross-origin",
        },
    );

    decision
}

fn resolve_mode(request_url: &Url, referer: &str, cfg: &RefererConfig) -> RefererMode {
    let Ok(referer_url) = Url::parse(referer) else {
        return RefererMode::Strip;
    };

    let referer_host = referer_url.host_str().map(|v| v.to_ascii_lowercase());
    if cfg.strip_from_search_engines
        && referer_host
            .as_deref()
            .map(|h| is_search_engine_host(h, &cfg.search_engine_domains))
            .unwrap_or(false)
    {
        return RefererMode::Strip;
    }

    if same_origin(request_url, &referer_url) {
        return RefererMode::PassThrough;
    }

    cfg.mode.clone()
}

fn same_origin(a: &Url, b: &Url) -> bool {
    let a_host = a.host_str().unwrap_or_default();
    let b_host = b.host_str().unwrap_or_default();
    a.scheme() == b.scheme()
        && a_host.eq_ignore_ascii_case(b_host)
        && a.port_or_known_default() == b.port_or_known_default()
}

fn is_search_engine_host(host: &str, extras: &[String]) -> bool {
    let host = host.trim().to_ascii_lowercase();
    let mut domains: HashSet<String> = BUILTIN_SEARCH_ENGINES
        .iter()
        .map(|v| (*v).to_owned())
        .collect();
    for extra in extras {
        let v = extra.trim().trim_start_matches("*.").to_ascii_lowercase();
        if !v.is_empty() {
            domains.insert(v);
        }
    }

    domains
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

fn upsert_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some(existing) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
    {
        existing.1 = value.to_owned();
    } else {
        headers.push((name.to_owned(), value.to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_search_referer() {
        let cfg = RefererConfig {
            enabled: true,
            mode: RefererMode::OriginOnly,
            strip_from_search_engines: true,
            search_engine_domains: Vec::new(),
        };
        let mut headers = vec![(
            "Referer".to_owned(),
            "https://www.google.com/search?q=test".to_owned(),
        )];
        let req = Url::parse("https://example.org/").expect("url");
        let decision = apply_referer_policy(&req, &mut headers, &cfg);
        assert_eq!(decision, RefererDecision::Stripped);
        assert!(!headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("referer")));
    }

    #[test]
    fn keeps_same_origin_referer() {
        let cfg = RefererConfig {
            enabled: true,
            mode: RefererMode::Strip,
            strip_from_search_engines: true,
            search_engine_domains: Vec::new(),
        };
        let mut headers = vec![(
            "Referer".to_owned(),
            "https://example.org/path?a=1".to_owned(),
        )];
        let req = Url::parse("https://example.org/next").expect("url");
        let decision = apply_referer_policy(&req, &mut headers, &cfg);
        assert_eq!(decision, RefererDecision::Kept);
    }
}

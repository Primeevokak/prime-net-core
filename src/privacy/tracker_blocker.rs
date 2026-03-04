use std::collections::HashSet;
use std::fs;
use std::path::Path;

use url::Url;

use crate::config::{TrackerBlockerConfig, TrackerBlockerMode};
use crate::error::{EngineError, Result};

const BUILTIN_TRACKER_DOMAINS: &[&str] = &[
    "google-analytics.com",
    "analytics.google.com",
    "analytics.googleapis.com",
    "googletagmanager.com",
    "googletagservices.com",
    "doubleclick.net",
    "stats.g.doubleclick.net",
    "mc.yandex.ru",
    "metrika.yandex.ru",
    "hotjar.com",
    "script.hotjar.com",
    "vars.hotjar.com",
    "mixpanel.com",
    "api.mixpanel.com",
    "cdn.mxpnl.com",
    "amplitude.com",
    "api2.amplitude.com",
    "segment.io",
    "cdn.segment.com",
    "connect.facebook.net",
    "analytics.twitter.com",
    "analytics.tiktok.com",
    "snap.licdn.com",
    "clarity.ms",
    "heapanalytics.com",
    "fullstory.com",
    "edge.fullstory.com",
    "api-iam.intercom.io",
    "api-ping.intercom.io",
    "widget.intercom.io",
];

const BUILTIN_URL_KEYWORDS: &[&str] = &[
    "/collect?",
    "facebook.com/tr?",
    "analytics.js",
    "gtag/js",
    "fbevents.js",
    "adsct",
    "pixel",
];

#[derive(Debug, Clone)]
pub struct TrackerBlockMatch {
    pub host: String,
    pub matched_rule: String,
}

#[derive(Debug, Clone)]
pub struct TrackerBlocker {
    mode: TrackerBlockerMode,
    domains: HashSet<String>,
    keywords: Vec<String>,
    allowlist: HashSet<String>,
}

impl TrackerBlocker {
    pub fn from_config(cfg: &TrackerBlockerConfig) -> Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }

        let mut domains = HashSet::new();
        let mut keywords = Vec::new();

        for list in &cfg.lists {
            load_builtin_list(list, &mut domains, &mut keywords);
        }
        for d in BUILTIN_TRACKER_DOMAINS {
            domains.insert((*d).to_owned());
        }
        for k in BUILTIN_URL_KEYWORDS {
            keywords.push((*k).to_owned());
        }

        for path in &cfg.custom_lists {
            let path_buf = Path::new(path);
            if path_buf.is_absolute() {
                return Err(EngineError::Config(format!(
                    "privacy.tracker_blocker.custom_lists: absolute paths are not allowed for security reasons: '{path}'"
                )));
            }
            if path.contains("..") {
                return Err(EngineError::Config(format!(
                    "privacy.tracker_blocker.custom_lists: path traversal attempts are not allowed: '{path}'"
                )));
            }

            let raw = fs::read_to_string(path).map_err(|e| {
                EngineError::Config(format!(
                    "privacy.tracker_blocker.custom_lists could not read '{path}': {e}"
                ))
            })?;
            parse_custom_list(&raw, &mut domains, &mut keywords);
        }
        keywords.sort();
        keywords.dedup();

        let allowlist = cfg
            .allowlist
            .iter()
            .map(|v| normalize_domain(v))
            .filter(|v| !v.is_empty())
            .collect();

        Ok(Some(Self {
            mode: cfg.mode.clone(),
            domains,
            keywords,
            allowlist,
        }))
    }

    pub fn is_log_only(&self) -> bool {
        matches!(self.mode, TrackerBlockerMode::LogOnly)
    }

    pub fn matches(&self, url: &Url) -> Option<TrackerBlockMatch> {
        let host = normalize_domain(url.host_str().unwrap_or_default());
        if host.is_empty() {
            return None;
        }
        if self.is_allowlisted(&host) {
            return None;
        }

        if let Some(rule) = self.match_domain_rule(&host) {
            return Some(TrackerBlockMatch {
                host,
                matched_rule: rule.to_owned(),
            });
        }

        let url_lc = normalize_url_for_keyword_match(url);
        for keyword in &self.keywords {
            if url_lc.contains(keyword) {
                return Some(TrackerBlockMatch {
                    host,
                    matched_rule: keyword.clone(),
                });
            }
        }
        None
    }

    fn match_domain_rule<'a>(&'a self, host: &str) -> Option<&'a str> {
        if let Some(rule) = self.domains.get(host) {
            return Some(rule.as_str());
        }
        let mut pos = 0usize;
        while let Some(dot) = host[pos..].find('.') {
            pos += dot + 1;
            let suffix = &host[pos..];
            if let Some(rule) = self.domains.get(suffix) {
                return Some(rule.as_str());
            }
        }
        None
    }

    fn is_allowlisted(&self, host: &str) -> bool {
        if self.allowlist.contains(host) {
            return true;
        }
        let mut pos = 0usize;
        while let Some(dot) = host[pos..].find('.') {
            pos += dot + 1;
            if self.allowlist.contains(&host[pos..]) {
                return true;
            }
        }
        false
    }
}

fn load_builtin_list(name: &str, domains: &mut HashSet<String>, keywords: &mut Vec<String>) {
    match name.trim().to_ascii_lowercase().as_str() {
        "easyprivacy" | "easylist" | "ublock" | "ublock_origin" => {
            for d in BUILTIN_TRACKER_DOMAINS {
                domains.insert((*d).to_owned());
            }
            for k in BUILTIN_URL_KEYWORDS {
                keywords.push((*k).to_owned());
            }
        }
        _ => {}
    }
}

fn parse_custom_list(raw: &str, domains: &mut HashSet<String>, keywords: &mut Vec<String>) {
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with('[')
            || line.starts_with("@@") // exception rules: do not parse as block entries
            || line.contains("##") // cosmetic filters
            || line.contains("#@#")
            || line.contains("#?#")
        {
            continue;
        }

        if let Some(rest) = line.strip_prefix("||") {
            let candidate = rest
                .split('^')
                .next()
                .unwrap_or_default()
                .split('/')
                .next()
                .unwrap_or_default();
            let d = normalize_domain(candidate);
            if !d.is_empty() {
                domains.insert(d);
                continue;
            }
        }

        if line.contains("://") {
            if let Ok(url) = Url::parse(line) {
                let d = normalize_domain(url.host_str().unwrap_or_default());
                if !d.is_empty() {
                    domains.insert(d);
                    continue;
                }
            }
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 && is_ip_like(fields[0]) {
            let d = normalize_domain(fields[1]);
            if !d.is_empty() {
                domains.insert(d);
                continue;
            }
        }

        let d = normalize_domain(line);
        if !d.is_empty() {
            domains.insert(d);
            continue;
        }

        if line.contains('/') || line.contains('?') {
            keywords.push(line.to_ascii_lowercase());
        }
    }
}

fn is_ip_like(v: &str) -> bool {
    v.parse::<std::net::IpAddr>().is_ok() || v == "0.0.0.0" || v == "::"
}

fn normalize_domain(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn normalize_url_for_keyword_match(url: &Url) -> String {
    let raw = url.as_str().to_ascii_lowercase();
    decode_percent_encoded(&raw)
}

fn decode_percent_encoded(input: &str) -> String {
    fn hex(v: u8) -> Option<u8> {
        match v {
            b'0'..=b'9' => Some(v - b'0'),
            b'a'..=b'f' => Some(v - b'a' + 10),
            b'A'..=b'F' => Some(v - b'A' + 10),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TrackerBlockAction, TrackerBlockerConfig};

    #[test]
    fn blocks_builtin_tracker_domain() {
        let cfg = TrackerBlockerConfig {
            enabled: true,
            lists: vec!["easyprivacy".to_owned()],
            custom_lists: Vec::new(),
            mode: TrackerBlockerMode::Block,
            on_block: TrackerBlockAction::Error,
            allowlist: Vec::new(),
        };
        let blocker = TrackerBlocker::from_config(&cfg)
            .expect("blocker")
            .expect("enabled");
        let url = Url::parse("https://www.google-analytics.com/collect?v=2").expect("url");
        assert!(blocker.matches(&url).is_some());
    }

    #[test]
    fn allowlist_wins() {
        let cfg = TrackerBlockerConfig {
            enabled: true,
            lists: vec!["easyprivacy".to_owned()],
            custom_lists: Vec::new(),
            mode: TrackerBlockerMode::Block,
            on_block: TrackerBlockAction::Error,
            allowlist: vec!["google-analytics.com".to_owned()],
        };
        let blocker = TrackerBlocker::from_config(&cfg)
            .expect("blocker")
            .expect("enabled");
        let url = Url::parse("https://www.google-analytics.com/collect?v=2").expect("url");
        assert!(blocker.matches(&url).is_none());
    }

    #[test]
    fn matches_percent_encoded_keyword() {
        let cfg = TrackerBlockerConfig {
            enabled: true,
            lists: Vec::new(),
            custom_lists: Vec::new(),
            mode: TrackerBlockerMode::Block,
            on_block: TrackerBlockAction::Error,
            allowlist: Vec::new(),
        };
        let blocker = TrackerBlocker::from_config(&cfg)
            .expect("blocker")
            .expect("enabled");
        let url = Url::parse("https://example.com/a%6ealytics.js").expect("url");
        assert!(blocker.matches(&url).is_some());
    }
}

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use url::Url;

use crate::config::{TrackerBlockerConfig, TrackerBlockerMode};
use crate::error::{EngineError, Result};

const BUILTIN_TRACKER_DOMAINS: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "facebook.net",
    "facebook.com",
    "scorecardresearch.com",
];

const BUILTIN_URL_KEYWORDS: &[&str] = &[
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "fbclid",
    "gclid",
];

#[derive(Debug, Clone)]
pub struct TrackerBlocker {
    #[allow(dead_code)]
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
        for d in BUILTIN_TRACKER_DOMAINS {
            domains.insert((*d).to_owned());
        }

        let mut keywords = Vec::new();
        for k in BUILTIN_URL_KEYWORDS {
            keywords.push((*k).to_owned());
        }

        for path in &cfg.custom_lists {
            let path_buf = Path::new(&path);
            if path_buf.is_absolute() {
                return Err(EngineError::Config(format!(
                    "privacy.tracker_blocker.custom_lists: absolute paths are not allowed: '{path}'"
                )));
            }
            if path.contains("..") {
                return Err(EngineError::Config(format!(
                    "privacy.tracker_blocker.custom_lists: path traversal attempts are not allowed: '{path}'"
                )));
            }

            let raw = fs::read_to_string(&path).map_err(|e| {
                EngineError::Config(format!(
                    "privacy.tracker_blocker.custom_lists could not read '{path}': {e}"
                ))
            })?;
            parse_custom_list(&raw, &mut domains, &mut keywords);
        }
        keywords.sort();
        keywords.dedup();

        let allowlist_vec: Vec<String> = cfg
            .allowlist
            .iter()
            .map(|v| normalize_domain(v))
            .filter(|v: &Option<String>| v.as_ref().map_or(false, |s| !s.is_empty()))
            .map(|v| v.unwrap())
            .collect();
        
        let mut allowlist = HashSet::new();
        for d in allowlist_vec {
            allowlist.insert(d);
        }

        Ok(Some(Self {
            mode: cfg.mode.clone(),
            domains,
            keywords,
            allowlist,
        }))
    }

    pub fn is_log_only(&self) -> bool {
        self.mode == TrackerBlockerMode::LogOnly
    }

    pub fn matches(&self, url: &Url) -> Option<String> {
        let Some(host) = url.host_str() else {
            return None;
        };
        let host = host.to_ascii_lowercase();

        if self.allowlist.contains(&host) {
            return None;
        }

        if self.domains.contains(&host) {
            return Some(host);
        }

        for sub in host.split('.') {
            if self.domains.contains(sub) {
                return Some(sub.to_owned());
            }
        }

        let url_str = url.as_str();
        for kw in &self.keywords {
            if url_str.contains(kw) {
                return Some(format!("kw:{kw}"));
            }
        }

        None
    }

    pub fn should_block(&self, url: &Url) -> bool {
        self.matches(url).is_some()
    }
}

fn parse_custom_list(raw: &str, domains: &mut HashSet<String>, keywords: &mut Vec<String>) {
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        if line.starts_with('/') && line.ends_with('/') {
            keywords.push(line[1..line.len() - 1].to_owned());
        } else {
            domains.insert(line.to_ascii_lowercase());
        }
    }
}

fn normalize_domain(value: &str) -> Option<String> {
    let v = value.trim().trim_start_matches("*.").trim_end_matches('.');
    if v.is_empty() || !v.contains('.') {
        return None;
    }
    if v.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    {
        Some(v.to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TrackerBlockAction;

    #[test]
    fn blocks_builtin_domains() {
        let cfg = TrackerBlockerConfig {
            enabled: true,
            mode: TrackerBlockerMode::Standard,
            on_block: TrackerBlockAction::Error,
            allowlist: Vec::new(),
            custom_lists: Vec::new(),
            lists: Vec::new(),
        };
        let blocker = TrackerBlocker::from_config(&cfg).unwrap().unwrap();
        assert!(blocker.should_block(&Url::parse("https://google-analytics.com/js").unwrap()));
    }

    #[test]
    fn honors_allowlist() {
        let cfg = TrackerBlockerConfig {
            enabled: true,
            mode: TrackerBlockerMode::Standard,
            on_block: TrackerBlockAction::Error,
            allowlist: vec!["google-analytics.com".to_owned()],
            custom_lists: Vec::new(),
            lists: Vec::new(),
        };
        let blocker = TrackerBlocker::from_config(&cfg).unwrap().unwrap();
        assert!(!blocker.should_block(&Url::parse("https://google-analytics.com/js").unwrap()));
    }
}

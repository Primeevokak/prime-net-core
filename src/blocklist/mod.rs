use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use csv::{ReaderBuilder, Trim};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{EngineError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistCache {
    pub source: String,
    pub updated_at_unix: u64,
    pub domains: Vec<String>,
}

impl BlocklistCache {
    pub fn status(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(path)?;
        if let Ok(parsed) = serde_json::from_slice::<BlocklistCache>(&raw) {
            return Ok(Some(parsed));
        }

        // Legacy compatibility: accept `updated_at` string and missing `source`.
        let value: Value =
            serde_json::from_slice(&raw).map_err(|e| EngineError::Config(e.to_string()))?;
        let source = value
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let updated_at_unix = value
            .get("updated_at_unix")
            .and_then(Value::as_u64)
            .or_else(|| {
                value.get("updated_at").and_then(Value::as_str).map(|s| {
                    if s.starts_with("202") {
                        0
                    } else {
                        s.parse::<u64>().unwrap_or(0)
                    }
                })
            })
            .unwrap_or(0);
        let domains = value
            .get("domains")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(|v| v.to_ascii_lowercase())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(Some(BlocklistCache {
            source,
            updated_at_unix,
            domains,
        }))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_vec_pretty(self)
            .map_err(|e| EngineError::Internal(format!("encode blocklist failed: {e}")))?;
        fs::write(path, raw)?;
        Ok(())
    }
}

pub async fn update_blocklist(source: &str, cache_path: &Path) -> Result<BlocklistCache> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| EngineError::Internal(format!("failed to build blocklist client: {e}")))?;

    let bytes = client.get(source).send().await?.bytes().await?;
    let body = String::from_utf8_lossy(&bytes);
    let mut domains = parse_domains_from_text(&body);
    if domains.is_empty() {
        return Err(EngineError::Internal(
            "blocklist source returned no valid domains".to_owned(),
        ));
    }
    domains.sort();
    domains.dedup();

    let updated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EngineError::Internal(format!("clock error: {e}")))?
        .as_secs();
    let cache = BlocklistCache {
        source: source.to_owned(),
        updated_at_unix,
        domains,
    };
    cache.save(cache_path)?;
    Ok(cache)
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn looks_like_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let s = s.trim_start_matches("*.");
    if s.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

fn parse_domains_from_text(body: &str) -> Vec<String> {
    let semicolon = parse_domains_csv(body, b';');
    let comma = parse_domains_csv(body, b',');

    let mut domains = if semicolon.len() >= comma.len() {
        semicolon
    } else {
        comma
    };

    // Fallback: if we got very few domains from a large body, use regex to extract everything that looks like a domain.
    // 10000 is a safe threshold because known blocklists (z-i, antizapret) are much larger.
    if domains.len() < 10000 && body.len() > 1024 * 1024 {
        let re = regex::Regex::new(r"(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}").unwrap();
        let mut regex_domains = Vec::new();
        for cap in re.captures_iter(body) {
            let d = cap[0].to_ascii_lowercase();
            if looks_like_domain(&d) {
                regex_domains.push(d);
            }
        }
        if regex_domains.len() > domains.len() {
            domains = regex_domains;
        }
    }

    if domains.is_empty() {
        return parse_domains_legacy(body);
    }
    domains
}

fn parse_domains_csv(body: &str, delimiter: u8) -> Vec<String> {
    let mut domains = Vec::new();
    let mut rdr = ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .quoting(false)
        .trim(Trim::All)
        .delimiter(delimiter)
        .from_reader(body.as_bytes());

    for record in rdr.records().flatten() {
        domains.extend(pick_domains_from_record(&record));
    }
    domains
}

fn pick_domains_from_record(record: &csv::StringRecord) -> Vec<String> {
    let mut domains = Vec::new();
    for field in record.iter() {
        let candidate = normalize_domain_candidate(field);
        // Split by pipe OR whitespace to catch multiple domains in one field
        for part in candidate.split(|c: char| c == '|' || c.is_whitespace()) {
            let sub_candidate = normalize_domain_candidate(part);
            if looks_like_domain(&sub_candidate) {
                domains.push(sub_candidate);
            }
        }
    }
    domains
}

fn normalize_domain_candidate(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn parse_domains_legacy(body: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for line in body.lines() {
        for field in line.split_whitespace() {
            let domain = normalize_domain_candidate(field);
            if looks_like_domain(&domain) {
                domains.push(domain);
            }
        }
    }
    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domains_handles_semicolon_csv_with_quotes_and_multiline_fields() {
        let body = concat!(
            "\"example.com\";\"1.1.1.1\";\"Org A\"\n",
            "\"sub.example.org\";\"2.2.2.2\";\"Org with, comma\"\n",
            "\"example.net\";\"3.3.3.3\";\"Org with\nmultiline field\"\n",
            "\"not_a_domain\";\"4.4.4.4\";\"bad\"\n"
        );
        let domains = parse_domains_from_text(body);
        assert!(domains.contains(&"example.com".to_owned()));
        assert!(domains.contains(&"sub.example.org".to_owned()));
        assert!(domains.contains(&"example.net".to_owned()));
        assert!(!domains.contains(&"not_a_domain".to_owned()));
    }

    #[test]
    fn parse_domains_handles_comma_csv() {
        let body = "example.com,1.1.1.1,Org\napi.example.org,2.2.2.2,Org B\n";
        let domains = parse_domains_from_text(body);
        assert_eq!(domains, vec!["example.com", "api.example.org"]);
    }

    #[test]
    fn parse_domains_legacy_whitespace_fallback() {
        let body = "example.com\nbad_token\napi.example.org";
        let domains = parse_domains_from_text(body);
        assert_eq!(domains, vec!["example.com", "api.example.org"]);
    }

    #[test]
    fn parse_domains_ignores_ip_literals() {
        let body = "1.1.1.1,org\nexample.com,org\n8.8.8.8,org";
        let domains = parse_domains_from_text(body);
        assert_eq!(domains, vec!["example.com"]);
    }
}

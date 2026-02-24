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
    #[serde(default)]
    pub ips: Vec<String>,
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
        let ips = value
            .get("ips")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(|v| v.to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(Some(BlocklistCache {
            source,
            updated_at_unix,
            domains,
            ips,
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
    let (mut domains, mut ips) = parse_entities_from_text(&body);
    if domains.is_empty() && ips.is_empty() {
        return Err(EngineError::Internal(
            "blocklist source returned no valid domains or IPs".to_owned(),
        ));
    }
    domains.sort();
    domains.dedup();
    ips.sort();
    ips.dedup();

    let updated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| EngineError::Internal(format!("clock error: {e}")))?
        .as_secs();
    let cache = BlocklistCache {
        source: source.to_owned(),
        updated_at_unix,
        domains,
        ips,
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

#[allow(clippy::expect_used)]
fn parse_entities_from_text(body: &str) -> (Vec<String>, Vec<String>) {
    let (mut d1, mut i1) = parse_entities_csv(body, b';');
    let (d2, i2) = parse_entities_csv(body, b',');

    if d2.len() > d1.len() { d1 = d2; }
    if i2.len() > i1.len() { i1 = i2; }

    // Fallback: if we got few domains from a large body, use regex
    if d1.len() < 20000 && body.len() > 1024 * 1024 {
        let re_domain = regex::Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b").expect("valid regex");
        for cap in re_domain.captures_iter(body) {
            let d = cap[0].to_ascii_lowercase();
            if looks_like_domain(&d) {
                d1.push(d);
            }
        }
        
        let re_ip = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").expect("valid regex");
        for cap in re_ip.captures_iter(body) {
            let ip = cap[0].to_owned();
            if ip.parse::<std::net::IpAddr>().is_ok() {
                i1.push(ip);
            }
        }
    }

    if d1.is_empty() && i1.is_empty() {
        return parse_entities_legacy(body);
    }
    (d1, i1)
}

fn parse_entities_csv(body: &str, delimiter: u8) -> (Vec<String>, Vec<String>) {
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    let mut rdr = ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .quoting(false)
        .trim(Trim::All)
        .delimiter(delimiter)
        .from_reader(body.as_bytes());

    for record in rdr.records().flatten() {
        let (d, i) = pick_entities_from_record(&record);
        domains.extend(d);
        ips.extend(i);
    }
    (domains, ips)
}

fn pick_entities_from_record(record: &csv::StringRecord) -> (Vec<String>, Vec<String>) {
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    for field in record.iter() {
        let candidate = normalize_domain_candidate(field);
        for part in candidate.split(|c: char| c == '|' || c.is_whitespace()) {
            let sub = normalize_domain_candidate(part);
            if sub.is_empty() { continue; }
            if sub.parse::<std::net::IpAddr>().is_ok() {
                ips.push(sub);
            } else if looks_like_domain(&sub) {
                domains.push(sub);
            }
        }
    }
    (domains, ips)
}

fn normalize_domain_candidate(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn parse_entities_legacy(body: &str) -> (Vec<String>, Vec<String>) {
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    for line in body.lines() {
        for field in line.split_whitespace() {
            let sub = normalize_domain_candidate(field);
            if sub.is_empty() { continue; }
            if sub.parse::<std::net::IpAddr>().is_ok() {
                ips.push(sub);
            } else if looks_like_domain(&sub) {
                domains.push(sub);
            }
        }
    }
    (domains, ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_entities_handles_semicolon_csv_with_quotes_and_multiline_fields() {
        let body = concat!(
            "\"example.com\";\"1.1.1.1\";\"Org A\"\n",
            "\"sub.example.org\";\"2.2.2.2\";\"Org with, comma\"\n",
            "\"example.net\";\"3.3.3.3\";\"Org with\nmultiline field\"\n",
            "\"not_a_domain\";\"4.4.4.4\";\"bad\"\n"
        );
        let (domains, ips) = parse_entities_from_text(body);
        assert!(domains.contains(&"example.com".to_owned()));
        assert!(domains.contains(&"sub.example.org".to_owned()));
        assert!(domains.contains(&"example.net".to_owned()));
        assert!(!domains.contains(&"not_a_domain".to_owned()));
        assert!(ips.contains(&"1.1.1.1".to_owned()));
        assert!(ips.contains(&"2.2.2.2".to_owned()));
        assert!(ips.contains(&"3.3.3.3".to_owned()));
        assert!(ips.contains(&"4.4.4.4".to_owned()));
    }

    #[test]
    fn parse_entities_handles_comma_csv() {
        let body = "example.com,1.1.1.1,Org\napi.example.org,2.2.2.2,Org B\n";
        let (domains, ips) = parse_entities_from_text(body);
        assert_eq!(domains, vec!["example.com", "api.example.org"]);
        assert_eq!(ips, vec!["1.1.1.1", "2.2.2.2"]);
    }

    #[test]
    fn parse_entities_legacy_whitespace_fallback() {
        let body = "example.com\n1.2.3.4\nbad_token\napi.example.org";
        let (domains, ips) = parse_entities_from_text(body);
        assert_eq!(domains, vec!["example.com", "api.example.org"]);
        assert_eq!(ips, vec!["1.2.3.4"]);
    }

    #[test]
    fn parse_entities_collects_ips_and_domains() {
        let body = "1.1.1.1,org\nexample.com,org\n8.8.8.8,org";
        let (domains, ips) = parse_entities_from_text(body);
        assert_eq!(domains, vec!["example.com"]);
        assert_eq!(ips, vec!["1.1.1.1", "8.8.8.8"]);
    }
}

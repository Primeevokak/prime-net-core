use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::error::{EngineError, Result};

pub const DEFAULT_BLOCKLIST_SOURCE: &str = "https://antifilter.download/list/domains.lst";

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
        if raw.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(None);
        }
        if let Ok(parsed) = serde_json::from_slice::<BlocklistCache>(&raw) {
            return Ok(Some(normalize_cache(parsed)));
        }

        let value: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let source = value
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let updated_at_unix = value
            .get("updated_at_unix")
            .and_then(Value::as_u64)
            .or_else(|| {
                value.get("updated_at").and_then(Value::as_u64).or_else(|| {
                    value
                        .get("updated_at")
                        .and_then(Value::as_i64)
                        .map(|v| v.max(0) as u64)
                })
            })
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
        let domains_raw = value
            .get("domains")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(|v| v.to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let ips_raw = value
            .get("ips")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(|v| v.to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(Some(normalize_cache(BlocklistCache {
            source,
            updated_at_unix,
            domains: domains_raw,
            ips: ips_raw,
        })))
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
    let source_url = if source.is_empty() {
        DEFAULT_BLOCKLIST_SOURCE
    } else {
        source
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .map_err(|e| EngineError::Internal(format!("failed to build blocklist client: {e}")))?;

    let res = client.get(source_url).send().await?;
    if !res.status().is_success() {
        return Err(EngineError::Internal(format!(
            "blocklist source {} returned status {}",
            source_url,
            res.status()
        )));
    }
    // Pre-allocate buffer for the large blocklist to avoid multiple re-allocations
    let content_length = res.content_length().unwrap_or(32 * 1024 * 1024) as usize;
    let mut bytes = Vec::with_capacity(content_length);
    let mut stream = res.bytes_stream();
    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| EngineError::Internal(format!("failed to read blocklist chunk: {e}")))?;
        bytes.extend_from_slice(&chunk);
    }
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
        source: source_url.to_owned(),
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

pub fn looks_like_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let s = s.trim_start_matches("*.");
    if s.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    if !s.contains('.') || s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return false;
    }

    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    if labels
        .iter()
        .any(|label| label.is_empty() || label.len() > 63)
    {
        return false;
    }
    true
}

fn extract_host_from_urlish(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let url_like = if value.contains("://") {
        value.to_owned()
    } else if let Some(rest) = value.strip_prefix("//") {
        format!("http://{rest}")
    } else if value.contains('/') {
        format!("http://{value}")
    } else {
        return None;
    };

    Url::parse(&url_like)
        .ok()
        .and_then(|u| u.host_str().map(normalize_domain_candidate))
}

fn extract_host_from_host_port_token(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        if host.is_empty() || port.parse::<u16>().is_err() {
            return None;
        }
        return Some(normalize_domain_candidate(host));
    }

    let (host, port) = value.rsplit_once(':')?;
    if host.is_empty() || port.parse::<u16>().is_err() {
        return None;
    }
    if host.contains(':') {
        return None;
    }
    Some(normalize_domain_candidate(host))
}

fn push_domain_or_ip(candidate: &str, domains: &mut Vec<String>, ips: &mut Vec<String>) {
    if candidate.is_empty() {
        return;
    }
    if candidate.parse::<std::net::IpAddr>().is_ok() {
        ips.push(candidate.to_owned());
    } else if looks_like_domain(candidate) {
        domains.push(candidate.to_owned());
    }
}

fn collect_entities_from_field(field: &str, domains: &mut Vec<String>, ips: &mut Vec<String>) {
    let field = field.trim();
    if field.is_empty() {
        return;
    }

    for token in field.split(|c: char| c == '|' || c.is_whitespace() || c == ',' || c == ';') {
        let token = normalize_domain_candidate(token);
        if token.is_empty() {
            continue;
        }

        push_domain_or_ip(&token, domains, ips);

        if let Some(host) = extract_host_from_urlish(&token) {
            push_domain_or_ip(&host, domains, ips);
        }
        if let Some(host) = extract_host_from_host_port_token(&token) {
            push_domain_or_ip(&host, domains, ips);
        }
    }
}

fn parse_entities_from_text(body: &str) -> (Vec<String>, Vec<String>) {
    let mut domains = Vec::new();
    let mut ips = Vec::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        for field in line.split(';') {
            let field = field.trim();
            if !field.is_empty() {
                collect_entities_from_field(field, &mut domains, &mut ips);
            }
        }
    }

    let (d_csv, i_csv) = parse_entities_csv(body, b';');
    domains.extend(d_csv);
    ips.extend(i_csv);

    let (d_legacy, i_legacy) = parse_entities_legacy(body);
    domains.extend(d_legacy);
    ips.extend(i_legacy);

    domains.sort();
    domains.dedup();
    ips.sort();
    ips.dedup();

    (domains, ips)
}

fn parse_entities_csv(body: &str, delimiter: u8) -> (Vec<String>, Vec<String>) {
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .quoting(false)
        .trim(csv::Trim::All)
        .delimiter(delimiter)
        .from_reader(body.as_bytes());

    for record in rdr.records() {
        if let Ok(rec) = record {
            let (d, i) = pick_entities_from_record(&rec);
            domains.extend(d);
            ips.extend(i);
        }
    }
    (domains, ips)
}

fn pick_entities_from_record(record: &csv::StringRecord) -> (Vec<String>, Vec<String>) {
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    for field in record.iter() {
        collect_entities_from_field(field, &mut domains, &mut ips);
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
            collect_entities_from_field(field, &mut domains, &mut ips);
        }
    }
    (domains, ips)
}

fn normalize_cache(mut cache: BlocklistCache) -> BlocklistCache {
    cache.domains = cache
        .domains
        .into_iter()
        .map(|v| normalize_domain_candidate(&v))
        .filter(|v| looks_like_domain(v))
        .collect();
    cache.domains.sort();
    cache.domains.dedup();

    cache.ips = cache
        .ips
        .into_iter()
        .map(|v| v.trim().to_owned())
        .filter(|v| v.parse::<std::net::IpAddr>().is_ok())
        .collect();
    cache.ips.sort();
    cache.ips.dedup();
    cache
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
}

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let body = reqwest::get(source).await?.text().await?;
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
    s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

fn parse_domains_from_text(body: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for line in body.lines() {
        for field in split_fields(line) {
            let val = field.trim().trim_matches('"').trim_matches('\'');
            if looks_like_domain(val) {
                domains.push(val.to_ascii_lowercase());
            }
        }
    }
    domains
}

fn split_fields(line: &str) -> Vec<&str> {
    if line.contains(';') {
        return line.split(';').collect();
    }
    if line.contains(',') {
        return line.split(',').collect();
    }
    line.split_whitespace().collect()
}

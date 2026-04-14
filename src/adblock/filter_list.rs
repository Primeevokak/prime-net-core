use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::error::{EngineError, Result};

/// Configuration for a single filter list source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterListSource {
    /// Human-readable name (e.g. "EasyList").
    pub name: String,
    /// Remote URL to download the list from.
    pub url: String,
    /// Whether this source is enabled.
    pub enabled: bool,
    /// Hours between automatic updates (0 = manual only).
    pub update_interval_hours: u64,
}

/// Metadata stored alongside a cached filter list file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterListMeta {
    /// Source URL the list was downloaded from.
    pub url: String,
    /// Unix timestamp of the last successful download.
    pub updated_at_unix: u64,
    /// Number of rules parsed from this list.
    pub rule_count: usize,
    /// SHA-256 hex digest of the downloaded text.
    pub sha256: String,
    /// Content-Length from the HTTP response (for diff detection).
    pub content_length: Option<u64>,
}

/// Built-in default filter list sources.
///
/// Users can override or extend this via configuration.
pub fn default_filter_lists() -> Vec<FilterListSource> {
    vec![
        FilterListSource {
            name: "EasyList".to_owned(),
            url: "https://easylist.to/easylist/easylist.txt".to_owned(),
            enabled: true,
            update_interval_hours: 24,
        },
        FilterListSource {
            name: "EasyPrivacy".to_owned(),
            url: "https://easylist.to/easylist/easyprivacy.txt".to_owned(),
            enabled: true,
            update_interval_hours: 24,
        },
        FilterListSource {
            name: "RuAdList".to_owned(),
            url: "https://easylist-downloads.adblockplus.org/ruadlist+easylist.txt".to_owned(),
            enabled: true,
            update_interval_hours: 24,
        },
        FilterListSource {
            name: "AdGuard Base".to_owned(),
            url: "https://raw.githubusercontent.com/AstarNetwork/AstarFiles/master/AstarGuard/base.txt".to_owned(),
            enabled: false,
            update_interval_hours: 48,
        },
    ]
}

/// Download a single filter list and cache it to disk.
///
/// Returns the raw filter list text on success.
pub async fn update_filter_list(source: &FilterListSource, cache_dir: &Path) -> Result<String> {
    info!(name = %source.name, url = %source.url, "updating adblock filter list");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .no_proxy()
        .build()
        .map_err(|e| EngineError::Internal(format!("adblock http client: {e}")))?;

    let resp = client.get(&source.url).send().await?;
    if !resp.status().is_success() {
        return Err(EngineError::Internal(format!(
            "adblock list '{}' returned HTTP {}",
            source.name,
            resp.status()
        )));
    }

    let content_length = resp.content_length();
    let body = resp.text().await.map_err(|e| {
        EngineError::Internal(format!("adblock list '{}' read body: {e}", source.name))
    })?;

    if body.trim().is_empty() {
        return Err(EngineError::Internal(format!(
            "adblock list '{}' returned empty body",
            source.name
        )));
    }

    // Count rules (non-comment, non-empty lines) for metadata.
    let rule_count = body
        .lines()
        .filter(|l| {
            let l = l.trim();
            !l.is_empty() && !l.starts_with('!') && !l.starts_with('[')
        })
        .count();

    let sha256 = sha256_hex(body.as_bytes());

    let updated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Persist the list text.
    let list_path = list_cache_path(cache_dir, &source.name);
    if let Some(parent) = list_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&list_path, body.as_bytes())?;

    // Persist metadata.
    let meta = FilterListMeta {
        url: source.url.clone(),
        updated_at_unix,
        rule_count,
        sha256,
        content_length,
    };
    let meta_path = meta_cache_path(cache_dir, &source.name);
    let meta_json = serde_json::to_vec_pretty(&meta)
        .map_err(|e| EngineError::Internal(format!("adblock meta serialize: {e}")))?;
    fs::write(&meta_path, meta_json)?;

    info!(
        name = %source.name,
        rules = rule_count,
        "adblock filter list updated"
    );

    Ok(body)
}

/// Download all enabled filter lists, returning results per-source.
pub async fn update_all_lists(
    sources: &[FilterListSource],
    cache_dir: &Path,
) -> Vec<Result<String>> {
    let mut results = Vec::with_capacity(sources.len());
    for source in sources {
        if !source.enabled {
            results.push(Err(EngineError::Internal(format!(
                "list '{}' is disabled",
                source.name
            ))));
            continue;
        }
        results.push(update_filter_list(source, cache_dir).await);
    }
    results
}

/// Load a cached filter list from disk (if it exists and is not stale).
///
/// Returns `None` if the cached file is missing or older than `max_age_secs`.
pub fn load_cached_list(cache_dir: &Path, name: &str, max_age_secs: u64) -> Option<String> {
    let list_path = list_cache_path(cache_dir, name);
    let meta_path = meta_cache_path(cache_dir, name);

    let meta_raw = fs::read(&meta_path).ok()?;
    let meta: FilterListMeta = serde_json::from_slice(&meta_raw).ok()?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if max_age_secs > 0 && now.saturating_sub(meta.updated_at_unix) > max_age_secs {
        warn!(name = name, "adblock cached list is stale");
        return None;
    }

    fs::read_to_string(&list_path).ok()
}

/// Check whether a list needs updating based on its cached metadata.
pub fn needs_update(cache_dir: &Path, source: &FilterListSource) -> bool {
    if source.update_interval_hours == 0 {
        return false;
    }
    let meta_path = meta_cache_path(cache_dir, &source.name);
    let meta_raw = match fs::read(&meta_path) {
        Ok(v) => v,
        Err(_) => return true,
    };
    let meta: FilterListMeta = match serde_json::from_slice(&meta_raw) {
        Ok(v) => v,
        Err(_) => return true,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let max_age = source.update_interval_hours * 3600;
    now.saturating_sub(meta.updated_at_unix) > max_age
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Path to the cached filter list text file.
fn list_cache_path(cache_dir: &Path, name: &str) -> PathBuf {
    let sanitized = sanitize_filename(name);
    cache_dir.join(format!("{sanitized}.txt"))
}

/// Path to the cached filter list metadata file.
fn meta_cache_path(cache_dir: &Path, name: &str) -> PathBuf {
    let sanitized = sanitize_filename(name);
    cache_dir.join(format!("{sanitized}.meta.json"))
}

/// Sanitize a name for use as a filename (replace non-alphanum with `_`).
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Compute SHA-256 hex digest.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod filter_list_tests {
    use super::*;

    #[test]
    fn sanitize_filename_replaces_spaces() {
        assert_eq!(sanitize_filename("Easy List"), "Easy_List");
        assert_eq!(sanitize_filename("RuAdList+EasyList"), "RuAdList_EasyList");
    }

    #[test]
    fn default_lists_not_empty() {
        let lists = default_filter_lists();
        assert!(lists.len() >= 3);
        assert!(lists.iter().any(|l| l.name == "EasyList"));
    }

    #[test]
    fn sha256_hex_deterministic() {
        let a = sha256_hex(b"hello");
        let b = sha256_hex(b"hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // 256 bits = 64 hex chars
    }
}

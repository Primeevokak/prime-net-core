use serde::{Deserialize, Serialize};

use crate::adblock::filter_list::FilterListSource;

/// Configuration for the built-in ad-blocking engine.
///
/// Controls DNS-level blocking, URL-level blocking, cosmetic filtering,
/// filter list sources, and custom user rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdblockConfig {
    /// Master switch — disables all ad-blocking when `false`.
    pub enabled: bool,
    /// Block ads at DNS resolution level (fast, low overhead).
    pub dns_blocking: bool,
    /// Block ads at HTTP URL level (more precise, higher overhead).
    pub url_blocking: bool,
    /// Inject CSS to hide ad elements in web pages.
    pub cosmetic_filtering: bool,
    /// Inject scriptlets to neutralise anti-adblock scripts.
    pub scriptlet_injection: bool,
    /// Filter list sources to download and apply.
    pub lists: Vec<FilterListSource>,
    /// Additional raw filter rules (one per entry, same syntax as list files).
    pub custom_rules: Vec<String>,
    /// Domains that are never blocked regardless of filter rules.
    pub whitelist: Vec<String>,
    /// Hours between automatic list updates (0 = manual only).
    pub update_interval_hours: u64,
    /// Directory to cache downloaded filter lists.
    ///
    /// Relative paths are resolved from the engine's working directory.
    /// Default: `~/.cache/prime-net-engine/adblock/`
    pub cache_dir: String,
}

impl Default for AdblockConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dns_blocking: true,
            url_blocking: true,
            cosmetic_filtering: false,
            scriptlet_injection: false,
            lists: crate::adblock::filter_list::default_filter_lists(),
            custom_rules: Vec::new(),
            whitelist: Vec::new(),
            update_interval_hours: 24,
            cache_dir: default_adblock_cache_dir(),
        }
    }
}

/// Default cache directory for adblock filter lists.
fn default_adblock_cache_dir() -> String {
    if let Some(dir) = dirs::cache_dir() {
        let path = dir.join("prime-net-engine").join("adblock");
        if let Ok(s) = path.into_os_string().into_string() {
            return s;
        }
    }
    "adblock-cache".to_owned()
}

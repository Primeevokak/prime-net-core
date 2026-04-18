use std::path::PathBuf;
use std::sync::OnceLock;

use prime_net_engine_core::adblock::config::AdblockConfig;
use prime_net_engine_core::adblock::filter_list::{self, FilterListSource};
use prime_net_engine_core::adblock::{parse_filter_list, DnsInterceptor};
use prime_net_engine_core::error::Result;
use tracing::{info, warn};

/// Runtime adblock state: DNS interceptor built from parsed filter lists.
struct AdblockState {
    interceptor: DnsInterceptor,
    enabled: bool,
    whitelist: Vec<String>,
}

impl Default for AdblockState {
    fn default() -> Self {
        Self {
            interceptor: DnsInterceptor::from_rules(&[]),
            enabled: false,
            whitelist: Vec::new(),
        }
    }
}

/// Global singleton — initialised once, updated via `RwLock` on hot-reload.
static ADBLOCK: OnceLock<std::sync::RwLock<AdblockState>> = OnceLock::new();

/// Stats returned after initialisation or reload.
#[derive(Debug)]
pub struct AdblockStats {
    pub enabled: bool,
    pub dns_rules_loaded: usize,
}

/// Initialise the adblock engine from config.
///
/// Downloads/caches filter lists if stale, parses rules, and builds the
/// DNS interceptor.  Safe to call multiple times (first call wins for
/// `OnceLock`; subsequent calls update via `RwLock`).
pub async fn initialize_adblock(cfg: &AdblockConfig) -> Result<AdblockStats> {
    let state = build_adblock_state(cfg).await?;
    let stats = AdblockStats {
        enabled: state.enabled,
        dns_rules_loaded: state.interceptor.blocking_count(),
    };

    let rw = ADBLOCK.get_or_init(|| std::sync::RwLock::new(AdblockState::default()));
    match rw.write() {
        Ok(mut guard) => *guard = state,
        Err(poisoned) => {
            warn!("adblock: RwLock was poisoned, recovering");
            *poisoned.into_inner() = state;
        }
    }

    Ok(stats)
}

/// Reload adblock state from a new config (hot-reload path).
pub async fn reload_adblock(cfg: &AdblockConfig) -> Result<AdblockStats> {
    initialize_adblock(cfg).await
}

/// Check whether a domain should be blocked by adblock rules.
///
/// Designed to be stored as `fn(&str) -> bool` in `RelayOptions::adblock_domain_check`.
pub fn is_adblock_blocked(host: &str) -> bool {
    ADBLOCK.get().is_some_and(|rw| {
        rw.read()
            .map(|guard| {
                if !guard.enabled {
                    return false;
                }
                // Whitelist takes priority (suffix match without allocation).
                let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
                for wl in &guard.whitelist {
                    if clean == *wl
                        || (clean.len() > wl.len() + 1
                            && clean.ends_with(wl.as_str())
                            && clean.as_bytes()[clean.len() - wl.len() - 1] == b'.')
                    {
                        return false;
                    }
                }
                guard.interceptor.should_block_dns(&clean)
            })
            .unwrap_or(false)
    })
}

/// Build adblock state from config: load cached lists, download stale ones, parse rules.
async fn build_adblock_state(cfg: &AdblockConfig) -> Result<AdblockState> {
    if !cfg.enabled || !cfg.dns_blocking {
        return Ok(AdblockState {
            enabled: false,
            ..AdblockState::default()
        });
    }

    let cache_dir = PathBuf::from(&cfg.cache_dir);
    if !cache_dir.exists() {
        tokio::fs::create_dir_all(&cache_dir)
            .await
            .map_err(prime_net_engine_core::error::EngineError::Io)?;
    }

    let enabled_lists: Vec<&FilterListSource> = cfg.lists.iter().filter(|l| l.enabled).collect();

    let mut all_rules = Vec::new();

    for source in &enabled_lists {
        let max_age = source.update_interval_hours.saturating_mul(3600);

        // Use cached version; download only if stale.
        let text = if filter_list::needs_update(&cache_dir, source) {
            match filter_list::update_filter_list(source, &cache_dir).await {
                Ok(t) => t,
                Err(e) => {
                    warn!(
                        name = %source.name,
                        error = %e,
                        "adblock: failed to update list, trying cache"
                    );
                    filter_list::load_cached_list(&cache_dir, &source.name, max_age)
                        .unwrap_or_default()
                }
            }
        } else {
            filter_list::load_cached_list(&cache_dir, &source.name, max_age).unwrap_or_default()
        };

        if text.is_empty() {
            continue;
        }

        let parsed = parse_filter_list(&text);
        if !parsed.errors.is_empty() {
            warn!(
                name = %source.name,
                errors = parsed.errors.len(),
                "adblock: parse errors in filter list"
            );
        }
        all_rules.extend(parsed.network_rules);
    }

    // Parse custom rules.
    for raw in &cfg.custom_rules {
        let parsed = parse_filter_list(raw);
        all_rules.extend(parsed.network_rules);
    }

    let interceptor = DnsInterceptor::from_rules(&all_rules);
    let whitelist: Vec<String> = cfg
        .whitelist
        .iter()
        .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    info!(
        dns_rules = interceptor.blocking_count(),
        exceptions = interceptor.exception_count(),
        whitelist = whitelist.len(),
        "adblock engine initialised"
    );

    Ok(AdblockState {
        interceptor,
        enabled: true,
        whitelist,
    })
}

/// Spawn a background task that periodically updates stale filter lists.
pub fn spawn_adblock_updater(cfg: AdblockConfig) {
    if !cfg.enabled || cfg.update_interval_hours == 0 {
        return;
    }

    let interval = std::time::Duration::from_secs(cfg.update_interval_hours.saturating_mul(3600));

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;

            match reload_adblock(&cfg).await {
                Ok(stats) if stats.enabled => {
                    info!(
                        dns_rules = stats.dns_rules_loaded,
                        "adblock: background list update complete"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(error = %e, "adblock: background list update failed");
                }
            }
        }
    });
}

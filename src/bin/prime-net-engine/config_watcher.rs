//! Background task that watches the engine config file for changes and applies
//! hot-reloadable settings without restarting the SOCKS5 server.

use std::path::PathBuf;
use std::time::Duration;

use prime_net_engine_core::EngineConfig;
use tracing::{info, warn};

use crate::blocklist_runtime::reload_blocklist;

/// Spawn a background task that polls `path` for modification time changes
/// every 5 seconds and applies hot-reloadable config changes.
///
/// Hot-reloadable: blocklist source/settings.
/// Requires restart: SOCKS5 bind address, transport type, evasion profiles.
pub fn spawn_config_watcher(path: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(watch_loop(path))
}

async fn watch_loop(path: PathBuf) {
    let Ok(meta) = std::fs::metadata(&path) else {
        warn!(target: "socks_cmd", path = %path.display(), "config watcher: cannot stat config file — hot reload disabled");
        return;
    };
    let Ok(mut last_modified) = meta.modified() else {
        return;
    };

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await; // consume the first immediate tick

    loop {
        interval.tick().await;

        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        if modified <= last_modified {
            continue;
        }
        last_modified = modified;

        match EngineConfig::from_file(&path) {
            Ok(new_cfg) => {
                info!(
                    target: "socks_cmd",
                    path = %path.display(),
                    "config file changed — applying hot reload"
                );
                apply_hot_reload(&new_cfg).await;
            }
            Err(e) => {
                warn!(
                    target: "socks_cmd",
                    error = %e,
                    "config file changed but could not be parsed — keeping current config"
                );
            }
        }
    }
}

async fn apply_hot_reload(cfg: &EngineConfig) {
    match reload_blocklist(&cfg.blocklist).await {
        Ok(stats) => {
            info!(
                target: "socks_cmd",
                domains = stats.domains_loaded,
                "config hot-reloaded: blocklist updated"
            );
        }
        Err(e) => {
            warn!(target: "socks_cmd", error = %e, "config hot-reload: blocklist update failed");
        }
    }

    info!(
        target: "socks_cmd",
        "config hot-reload complete — note: bind address, transport, and evasion profile changes require restart"
    );
}

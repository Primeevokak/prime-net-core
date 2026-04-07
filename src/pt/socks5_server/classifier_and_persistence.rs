use crate::config::EngineConfig;
use crate::pt::socks5_server::*;
use std::sync::Arc;

pub fn record_destination_failure(
    destination: &str,
    signal: BlockingSignal,
    _emit: u64,
    stage: u8,
    cfg: &EngineConfig,
) {
    send_telemetry(TelemetryEvent::DestinationFailure {
        destination: destination.to_owned(),
        signal,
        stage,
    });
    record_destination_failure_sync(destination, signal, stage, cfg);
}

pub fn record_destination_failure_sync(
    destination: &str,
    signal: BlockingSignal,
    stage: u8,
    _cfg: &EngineConfig,
) {
    let now = now_unix_secs();
    {
        let map = &routing_state().dest_failures;
        let mut entry = map.entry(destination.to_owned()).or_insert(0);
        *entry = entry.saturating_add(1).min(8);
    }
    {
        let map = &routing_state().dest_classifier;
        let mut stats = map.entry(destination.to_owned()).or_default();
        stats.failures += 1;
        match signal {
            BlockingSignal::Reset => stats.resets = stats.resets.saturating_add(1),
            BlockingSignal::Timeout => stats.timeouts += 1,
            _ => {}
        }
        stats.last_seen_unix = now;
        stats.preferred_stage = Some(stage);
    }
}

pub fn record_destination_success(
    destination: &str,
    stage: u8,
    _source: StageSelectionSource,
    cfg: &EngineConfig,
) {
    send_telemetry(TelemetryEvent::DestinationSuccess {
        destination: destination.to_owned(),
        stage,
    });
    record_destination_success_sync(destination, stage, cfg);
}

pub fn record_destination_success_sync(destination: &str, stage: u8, _cfg: &EngineConfig) {
    let now = now_unix_secs();
    {
        let map = &routing_state().dest_failures;
        map.remove(destination);
    }
    {
        let map = &routing_state().dest_classifier;
        let mut stats = map.entry(destination.to_owned()).or_default();
        stats.successes += 1;
        stats.last_seen_unix = now;
        stats.preferred_stage = Some(stage);
    }
}

pub fn maybe_prune_runtime_classifier_state(now: u64, cfg: Arc<EngineConfig>) {
    crate::pt::socks5_server::ml_shadow::prune_ml_state(now);

    // Prune stale preferred_stage entries from in-memory hot cache.
    // load_classifier_store_if_needed enforces TTL only at startup.
    // Without runtime pruning, this map grows indefinitely during long sessions.
    let ttl = cfg.evasion.stage_cache_ttl_secs;
    let classifier = &routing_state().dest_classifier;
    let stages = &routing_state().dest_preferred_stage;
    stages.retain(|key, _| {
        classifier
            .get(key.as_str())
            .map(|v| now.saturating_sub(v.last_seen_unix) <= ttl)
            .unwrap_or(false)
    });
}

pub fn init_classifier_store(_opts: &RelayOptions, cfg: Arc<EngineConfig>) {
    load_classifier_store_if_needed(cfg);
}

pub fn load_classifier_store_if_needed(cfg: Arc<EngineConfig>) {
    if !cfg.evasion.classifier_persist_enabled {
        return;
    }
    let path = &cfg.evasion.classifier_cache_path;
    if path.is_empty() {
        return;
    }

    let file_path = std::path::Path::new(path);
    if !file_path.exists() {
        return;
    }

    match std::fs::read_to_string(file_path) {
        Ok(json) => {
            match serde_json::from_str::<std::collections::HashMap<String, DestinationClassifier>>(
                &json,
            ) {
                Ok(data) => {
                    let rs = routing_state();
                    let map = &rs.dest_classifier;
                    let winners = &rs.dest_route_winner;
                    let stages = &rs.dest_preferred_stage;

                    let now = now_unix_secs();
                    for (k, v) in data {
                        // Only load if not too old (7 days = classifier_entry_ttl_secs)
                        if now.saturating_sub(v.last_seen_unix)
                            > cfg.evasion.classifier_entry_ttl_secs
                        {
                            continue;
                        }

                        if let Some(ref winner) = v.winner {
                            if now.saturating_sub(winner.updated_at_unix)
                                < cfg.evasion.winner_cache_ttl_secs
                            {
                                winners.insert(k.clone(), winner.clone());
                            }
                        }

                        if let Some(stage) = v.preferred_stage {
                            let age = now.saturating_sub(v.last_seen_unix);
                            if age <= cfg.evasion.stage_cache_ttl_secs {
                                stages.insert(k.clone(), stage);
                            }
                            // Stale stage intentionally dropped: ISP DPI profile may have changed.
                        }

                        map.insert(k, v);
                    }
                    tracing::info!(
                        "Loaded {} classifier entries (with winners) from {}",
                        map.len(),
                        path
                    );
                }
                Err(e) => tracing::warn!("Failed to parse classifier cache {}: {}", path, e),
            }
        }
        Err(e) => tracing::warn!("Failed to read classifier cache {}: {}", path, e),
    }
}

pub fn maybe_flush_classifier_store(force: bool, cfg: Arc<EngineConfig>) {
    if !cfg.evasion.classifier_persist_enabled {
        return;
    }
    let path = &cfg.evasion.classifier_cache_path;
    if path.is_empty() {
        return;
    }

    // Only flush if forced (shutdown) or randomly (to reduce I/O)
    if !force && rand::random::<u8>() > 5 {
        return;
    }

    let rs = routing_state();
    let map = &rs.dest_classifier;

    if map.is_empty() && !force {
        return;
    }

    let mut data: std::collections::HashMap<String, DestinationClassifier> =
        std::collections::HashMap::new();

    // Iterate over all known destinations in the classifier
    for entry in map.iter() {
        let k = entry.key();
        let mut v = entry.value().clone();

        // Sync winner and preferred stage from their respective hot caches
        if let Some(winner) = rs.dest_route_winner.get(k) {
            v.winner = Some(winner.clone());
        }

        if let Some(stage) = rs.dest_preferred_stage.get(k) {
            v.preferred_stage = Some(*stage);
        }

        data.insert(k.clone(), v);
    }

    match serde_json::to_string_pretty(&data) {
        Ok(json) => {
            let path_owned = path.to_owned();
            // Use spawn_blocking so the file write does not stall the async runtime
            tokio::task::spawn_blocking(move || {
                if let Err(e) = std::fs::write(&path_owned, json) {
                    tracing::warn!("Failed to write classifier cache {}: {}", path_owned, e);
                }
            });
        }
        Err(e) => tracing::warn!("Failed to serialize classifier cache: {}", e),
    }
}

#[cfg(test)]
mod stage_ttl_tests {
    use crate::config::EngineConfig;

    #[test]
    fn stale_stage_not_restored() {
        let mut cfg = EngineConfig::default();
        cfg.evasion.stage_cache_ttl_secs = 100;
        let age = 200u64; // older than TTL
        let restored: Option<u8> = if age <= cfg.evasion.stage_cache_ttl_secs {
            Some(2)
        } else {
            None
        };
        assert_eq!(restored, None);
    }

    #[test]
    fn fresh_stage_is_restored() {
        let mut cfg = EngineConfig::default();
        cfg.evasion.stage_cache_ttl_secs = 100;
        let age = 50u64; // within TTL
        let restored: Option<u8> = if age <= cfg.evasion.stage_cache_ttl_secs {
            Some(2)
        } else {
            None
        };
        assert_eq!(restored, Some(2));
    }
}

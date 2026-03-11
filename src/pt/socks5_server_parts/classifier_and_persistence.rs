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
        let map = DEST_FAILURES.get_or_init(dashmap::DashMap::new);
        let mut entry = map.entry(destination.to_owned()).or_insert(0);
        *entry = entry.saturating_add(1).min(8);
    }
    {
        let map = DEST_CLASSIFIER.get_or_init(dashmap::DashMap::new);
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
        let map = DEST_FAILURES.get_or_init(dashmap::DashMap::new);
        map.remove(destination);
    }
    {
        let map = DEST_CLASSIFIER.get_or_init(dashmap::DashMap::new);
        let mut stats = map.entry(destination.to_owned()).or_default();
        stats.successes += 1;
        stats.last_seen_unix = now;
        stats.preferred_stage = Some(stage);
    }
}

pub fn maybe_prune_runtime_classifier_state(_now: u64, _cfg: Arc<EngineConfig>) {
    crate::pt::socks5_server::ml_shadow::prune_ml_state(_now);
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
                    let map = DEST_CLASSIFIER.get_or_init(dashmap::DashMap::new);
                    let winners = DEST_ROUTE_WINNER.get_or_init(dashmap::DashMap::new);
                    let stages = DEST_PREFERRED_STAGE.get_or_init(dashmap::DashMap::new);

                    let now = now_unix_secs();
                    for (k, v) in data {
                        // Only load if not too old (e.g. 7 days)
                        if now.saturating_sub(v.last_seen_unix) > 604800 {
                            continue;
                        }

                        if let Some(ref winner) = v.winner {
                            // Only restore winner if it's still fresh enough (e.g. 24 hours for persistence)
                            if now.saturating_sub(winner.updated_at_unix) < 86400 {
                                winners.insert(k.clone(), winner.clone());
                            }
                        }

                        if let Some(stage) = v.preferred_stage {
                            stages.insert(k.clone(), stage);
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

    let map = match DEST_CLASSIFIER.get() {
        Some(m) => m,
        None => return,
    };

    if map.is_empty() && !force {
        return;
    }

    let winners = DEST_ROUTE_WINNER.get();
    let stages = DEST_PREFERRED_STAGE.get();

    let mut data: std::collections::HashMap<String, DestinationClassifier> =
        std::collections::HashMap::new();

    // Iterate over all known destinations in the classifier
    for entry in map.iter() {
        let k = entry.key();
        let mut v = entry.value().clone();

        // Sync winner and preferred stage from their respective hot caches
        if let Some(w_map) = winners {
            if let Some(winner) = w_map.get(k) {
                v.winner = Some(winner.clone());
            }
        }

        if let Some(s_map) = stages {
            if let Some(stage) = s_map.get(k) {
                v.preferred_stage = Some(*stage);
            }
        }

        data.insert(k.clone(), v);
    }

    match serde_json::to_string_pretty(&data) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                tracing::warn!("Failed to write classifier cache {}: {}", path, e);
            }
        }
        Err(e) => tracing::warn!("Failed to serialize classifier cache: {}", e),
    }
}

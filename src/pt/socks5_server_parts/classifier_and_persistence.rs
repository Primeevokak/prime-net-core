use super::*;

pub(super) fn destination_failures(destination: &str) -> u8 {
    let map = DEST_FAILURES.get_or_init(DashMap::new);
    map.get(destination).map(|r| *r).unwrap_or(0)
}

pub(super) fn destination_preferred_stage(destination: &str) -> u8 {
    let map = DEST_PREFERRED_STAGE.get_or_init(DashMap::new);
    map.get(destination).map(|r| *r).unwrap_or(0).min(4)
}

pub(super) fn select_race_probe_stage(destination: &str) -> u8 {
    let _ = destination;
    let stats = STAGE_RACE_STATS.get_or_init(DashMap::new);

    let mut candidates = vec![1u8, 2u8];
    candidates.sort_by(|a, b| {
        let sa = stats.get(a).map(|r| r.clone()).unwrap_or_default();
        let sb = stats.get(b).map(|r| r.clone()).unwrap_or_default();
        let ra = stage_penalty(sa.successes, sa.failures);
        let rb = stage_penalty(sb.successes, sb.failures);
        ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
    });

    if candidates.len() >= 2 {
        let idx = (stable_hash(destination) % 2) as usize;
        return candidates[idx];
    }
    candidates.into_iter().next().unwrap_or(1)
}

pub(super) fn stage_penalty(successes: u64, failures: u64) -> f64 {
    let total = successes + failures;
    if total == 0 {
        return 0.5;
    }
    failures as f64 / total as f64
}

pub(super) fn stable_hash(input: &str) -> u64 {
    let mut h = 1469598103934665603u64;
    for b in input.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

pub(super) fn record_stage_source_selected(source: StageSelectionSource) {
    let counters = RACE_SOURCE_COUNTERS.get_or_init(RaceSourceCounters::default);
    match source {
        StageSelectionSource::Cache => counters.cache.fetch_add(1, Ordering::Relaxed),
        StageSelectionSource::Probe => counters.probe.fetch_add(1, Ordering::Relaxed),
        StageSelectionSource::Adaptive => counters.adaptive.fetch_add(1, Ordering::Relaxed),
    };
}

pub(super) fn record_destination_failure(
    destination: &str,
    signal: BlockingSignal,
    _classifier_emit_interval_secs: u64,
    stage: u8,
    _cfg: &EngineConfig,
) {
    send_telemetry(TelemetryEvent::DestinationFailure {
        destination: destination.to_owned(),
        signal,
        stage,
    });
}

pub(super) fn record_destination_failure_sync(
    destination: &str,
    signal: BlockingSignal,
    stage: u8,
    cfg: &EngineConfig,
) {
    let now = now_unix_secs();
    let failures_after_update = {
        let map = DEST_FAILURES.get_or_init(DashMap::new);
        let mut entry = map.entry(destination.to_owned()).or_insert(0);
        *entry = entry.saturating_add(1).min(8);
        *entry
    };

    if let Some(threshold) = learned_bypass_threshold(destination) {
        if failures_after_update == threshold {
            if let Some((host, port)) = split_host_port_for_connect(destination) {
                let promotable = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    should_bypass_by_classifier_ip(ip, port)
                } else {
                    should_bypass_by_classifier_host(&host, port, cfg)
                };
                if promotable {
                    info!(
                        target: "socks5.classifier",
                        destination = %destination,
                        failures = failures_after_update,
                        threshold,
                        "destination promoted to learned bypass routing"
                    );
                }
            }
        }
    }

    {
        let map = DEST_CLASSIFIER.get_or_init(DashMap::new);
        let mut stats = map.entry(destination.to_owned()).or_default();
        stats.failures = stats.failures.saturating_add(1);
        match signal {
            BlockingSignal::Reset => {
                stats.resets = stats.resets.saturating_add(1);
                let threshold = if stage >= 4 { 2 } else { 3 };
                if stats.resets >= threshold {
                    let pref_map = DEST_PREFERRED_STAGE.get_or_init(DashMap::new);
                    if pref_map.remove(destination).is_some() {
                        warn!(target: "socks5.classifier", destination, stage, resets = stats.resets, "cleared preferred stage due to repeated resets (possibly strategy too aggressive)");
                    }
                    stats.resets = 0;
                }
            }
            BlockingSignal::Timeout => stats.timeouts = stats.timeouts.saturating_add(1),
            BlockingSignal::EarlyClose => stats.early_closes = stats.early_closes.saturating_add(1),
            BlockingSignal::BrokenPipe => stats.broken_pipes = stats.broken_pipes.saturating_add(1),
            BlockingSignal::SuspiciousZeroReply => {
                stats.suspicious_zero_replies = stats.suspicious_zero_replies.saturating_add(1)
            }
            BlockingSignal::SilentDrop => stats.silent_drops = stats.silent_drops.saturating_add(1),
        }
        stats.last_seen_unix = now;
    }
    record_stage_outcome(stage, false);
}

pub(super) fn record_destination_success(
    destination: &str,
    stage: u8,
    _source: StageSelectionSource,
    _cfg: &EngineConfig,
) {
    send_telemetry(TelemetryEvent::DestinationSuccess {
        destination: destination.to_owned(),
        stage,
    });
}

pub(super) fn record_destination_success_sync(
    destination: &str,
    stage: u8,
    _cfg: &EngineConfig,
) {
    let now = now_unix_secs();
    {
        let map = DEST_FAILURES.get_or_init(DashMap::new);
        if let Some(mut entry) = map.get_mut(destination) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                drop(entry);
                map.remove(destination);
            }
        }
    }
    {
        let map = DEST_PREFERRED_STAGE.get_or_init(DashMap::new);
        map.insert(destination.to_owned(), stage.min(4));
    }
    {
        let map = DEST_CLASSIFIER.get_or_init(DashMap::new);
        let mut stats = map.entry(destination.to_owned()).or_default();
        stats.successes = stats.successes.saturating_add(1);
        stats.last_seen_unix = now;
    }
    record_stage_outcome(stage, true);
}

pub(super) fn record_stage_outcome(stage: u8, success: bool) {
    if stage == 0 {
        return;
    }
    let stats = STAGE_RACE_STATS.get_or_init(DashMap::new);
    let mut entry = stats.entry(stage.min(4)).or_default();
    if success {
        entry.successes = entry.successes.saturating_add(1);
    } else {
        entry.failures = entry.failures.saturating_add(1);
    }
}

pub(super) fn classify_io_error(e: &std::io::Error) -> BlockingSignal {
    if e.to_string().contains("silent drop") {
        return BlockingSignal::SilentDrop;
    }
    match e.kind() {
        ErrorKind::ConnectionReset => BlockingSignal::Reset,
        ErrorKind::TimedOut => BlockingSignal::Timeout,
        ErrorKind::ConnectionAborted => BlockingSignal::EarlyClose,
        ErrorKind::BrokenPipe => BlockingSignal::BrokenPipe,
        _ => BlockingSignal::EarlyClose,
    }
}

pub(super) fn blocking_signal_label(signal: BlockingSignal) -> &'static str {
    match signal {
        BlockingSignal::Reset => "reset",
        BlockingSignal::Timeout => "timeout",
        BlockingSignal::EarlyClose => "early-close",
        BlockingSignal::BrokenPipe => "broken-pipe",
        BlockingSignal::SuspiciousZeroReply => "suspicious-zero-reply",
        BlockingSignal::SilentDrop => "silent-drop",
    }
}

pub(super) fn should_mark_suspicious_zero_reply(
    port: u16,
    bytes_client_to_upstream: u64,
    bytes_upstream_to_client: u64,
    min_c2u: usize,
) -> bool {
    port == 443 && bytes_upstream_to_client <= 7 && bytes_client_to_upstream >= min_c2u as u64
}

pub(super) static LAST_CLASSIFIER_EMIT_UNIX: AtomicU64 = AtomicU64::new(0);

pub(super) fn maybe_emit_classifier_summary(interval_secs: u64, cfg: &EngineConfig) {
    let now = now_unix_secs();
    let last = LAST_CLASSIFIER_EMIT_UNIX.load(Ordering::Relaxed);
    if now.saturating_sub(last) < interval_secs {
        return;
    }
    if LAST_CLASSIFIER_EMIT_UNIX
        .compare_exchange(last, now, Ordering::SeqCst, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    {
        let map = DEST_CLASSIFIER.get_or_init(DashMap::new);
        if !map.is_empty() {
            let mut entries: Vec<(String, DestinationClassifier)> = map
                .iter()
                .map(|r| (r.key().clone(), r.value().clone()))
                .collect();
            entries.sort_by_key(|(_, s)| std::cmp::Reverse(s.failures));
            let top = entries.into_iter().take(3).collect::<Vec<_>>();
            for (destination, s) in top {
                info!(
                    target: "socks5.classifier",
                    destination = %destination,
                    failures = s.failures,
                    resets = s.resets,
                    timeouts = s.timeouts,
                    silent_drops = s.silent_drops,
                    early_closes = s.early_closes,
                    broken_pipes = s.broken_pipes,
                    suspicious_zero_replies = s.suspicious_zero_replies,
                    successes = s.successes,
                    "blocking classifier summary"
                );
            }
        }
    }

    {
        let counters = RACE_SOURCE_COUNTERS.get_or_init(RaceSourceCounters::default);
        let cache = counters.cache.load(Ordering::Relaxed);
        let probe = counters.probe.load(Ordering::Relaxed);
        let adaptive = counters.adaptive.load(Ordering::Relaxed);
        let total = cache + probe + adaptive;
        if total > 0 {
            info!(
                target: "socks5.classifier",
                cache,
                probe,
                adaptive,
                total,
                "strategy selection source counters"
            );
        }
    }

    {
        let stats_map = STAGE_RACE_STATS.get_or_init(DashMap::new);
        let mut stages: Vec<(u8, StageRaceStats)> = stats_map
            .iter()
            .map(|r| (*r.key(), r.value().clone()))
            .collect();
        stages.sort_by_key(|(stage, _)| *stage);
        for (stage, stats) in stages.into_iter().take(4) {
            let total = stats.successes + stats.failures;
            if total == 0 {
                continue;
            }
            let hit_rate = stats.successes as f64 / total as f64;
            info!(
                target: "socks5.classifier",
                stage,
                successes = stats.successes,
                failures = stats.failures,
                hit_rate = hit_rate,
                "strategy stage hit-rate"
            );
        }
    }

    {
        let m = ROUTE_METRICS.get_or_init(RouteMetrics::default);
        let route_selected_direct = m.route_selected_direct.load(Ordering::Relaxed);
        let route_selected_bypass = m.route_selected_bypass.load(Ordering::Relaxed);
        let race_started = m.race_started.load(Ordering::Relaxed);
        let race_skipped = m.race_skipped.load(Ordering::Relaxed);
        let race_winner_direct = m.race_winner_direct.load(Ordering::Relaxed);
        let race_winner_bypass = m.race_winner_bypass.load(Ordering::Relaxed);
        let winner_cache_hits = m.winner_cache_hits.load(Ordering::Relaxed);
        let winner_cache_misses = m.winner_cache_misses.load(Ordering::Relaxed);

        let selected_total = route_selected_direct + route_selected_bypass;
        let race_wins_total = race_winner_direct + race_winner_bypass;
        let winner_cache_total = winner_cache_hits + winner_cache_misses;

        if selected_total > 0 || race_started > 0 || race_skipped > 0 {
            info!(
                target: "socks5.classifier",
                selected_total,
                selected_direct = route_selected_direct,
                selected_bypass = route_selected_bypass,
                races_started = race_started,
                races_skipped = race_skipped,
                race_wins_total,
                race_wins_direct = race_winner_direct,
                race_wins_bypass = race_winner_bypass,
                route_success_direct = m.route_success_direct.load(Ordering::Relaxed),
                route_success_bypass = m.route_success_bypass.load(Ordering::Relaxed),
                route_failure_direct = m.route_failure_direct.load(Ordering::Relaxed),
                route_failure_bypass = m.route_failure_bypass.load(Ordering::Relaxed),
                soft_zero_reply_direct = m.route_soft_zero_reply_direct.load(Ordering::Relaxed),
                soft_zero_reply_bypass = m.route_soft_zero_reply_bypass.load(Ordering::Relaxed),
                connect_fail_direct = m.connect_failure_direct.load(Ordering::Relaxed),
                connect_fail_bypass = m.connect_failure_bypass.load(Ordering::Relaxed),
                "adaptive route counters"
            );
        }
        if winner_cache_total > 0 {
            let winner_cache_hit_rate = winner_cache_hits as f64 / winner_cache_total as f64;
            info!(
                target: "socks5.classifier",
                winner_cache_hits,
                winner_cache_misses,
                winner_cache_hit_rate,
                reason_no_winner = m.race_reason_no_winner.load(Ordering::Relaxed),
                reason_empty_winner = m.race_reason_empty_winner.load(Ordering::Relaxed),
                reason_winner_stale = m.race_reason_winner_stale.load(Ordering::Relaxed),
                reason_winner_weak = m.race_reason_winner_weak.load(Ordering::Relaxed),
                reason_winner_missing = m.race_reason_winner_missing.load(Ordering::Relaxed),
                reason_winner_healthy = m.race_reason_winner_healthy.load(Ordering::Relaxed),
                reason_single_candidate = m.race_reason_single_candidate.load(Ordering::Relaxed),
                reason_non_tls = m.race_reason_non_tls.load(Ordering::Relaxed),
                "adaptive route race diagnostics"
            );
        }
    }

    {
        let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);
        if !map.is_empty() {
            let mut profiles: Vec<(String, BypassProfileHealth)> = map
                .iter()
                .map(|r| (r.key().clone(), r.value().clone()))
                .collect();
            profiles.sort_by(|a, b| {
                let a_score = bypass_profile_score_from_health(&a.1, now, cfg);
                let b_score = bypass_profile_score_from_health(&b.1, now, cfg);
                b_score.cmp(&a_score).then_with(|| a.0.cmp(&b.0))
            });
            for (route_id, health) in profiles.into_iter().take(3) {
                info!(
                    target: "socks5.classifier",
                    route = %route_id,
                    score = bypass_profile_score_from_health(&health, now, cfg),
                    successes = health.successes,
                    failures = health.failures,
                    connect_failures = health.connect_failures,
                    soft_zero_replies = health.soft_zero_replies,
                    io_errors = health.io_errors,
                    "global bypass profile health"
                );
            }
        }
    }
    maybe_flush_classifier_store(false, Arc::new(cfg.clone()));
}

pub(super) static CLASSIFIER_RUNTIME_LAST_PRUNE_UNIX: AtomicU64 = AtomicU64::new(0);
pub(super) const CLASSIFIER_RUNTIME_PRUNE_INTERVAL_SECS: u64 = 30;
pub(super) const CLASSIFIER_RUNTIME_MAX_DEST_ENTRIES: usize = 6000;
pub(super) const CLASSIFIER_RUNTIME_KEEP_DEST_ENTRIES: usize = 4500;
pub(super) const CLASSIFIER_RUNTIME_MAX_GLOBAL_BYPASS_ENTRIES: usize = 256;
pub(super) const CLASSIFIER_RUNTIME_KEEP_GLOBAL_BYPASS_ENTRIES: usize = 192;

pub(super) fn maybe_prune_runtime_classifier_state(now: u64, cfg: Arc<EngineConfig>) {
    let last = CLASSIFIER_RUNTIME_LAST_PRUNE_UNIX.load(Ordering::Relaxed);
    if now.saturating_sub(last) < CLASSIFIER_RUNTIME_PRUNE_INTERVAL_SECS {
        return;
    }
    if CLASSIFIER_RUNTIME_LAST_PRUNE_UNIX
        .compare_exchange(last, now, Ordering::SeqCst, Ordering::Relaxed)
        .is_ok()
    {
        let (removed_destinations, removed_global_profiles) =
            prune_runtime_classifier_state_with_caps(
                CLASSIFIER_RUNTIME_MAX_DEST_ENTRIES,
                CLASSIFIER_RUNTIME_KEEP_DEST_ENTRIES,
                CLASSIFIER_RUNTIME_MAX_GLOBAL_BYPASS_ENTRIES,
                CLASSIFIER_RUNTIME_KEEP_GLOBAL_BYPASS_ENTRIES,
                &cfg,
            );
        if removed_destinations > 0 || removed_global_profiles > 0 {
            info!(
                target: "socks5.classifier",
                removed_destinations,
                removed_global_profiles,
                "runtime classifier cache pruned"
            );
        }
    }
}

fn prune_runtime_classifier_state_with_caps(
    max_dest_entries: usize,
    keep_dest_entries: usize,
    max_global_bypass_entries: usize,
    keep_global_bypass_entries: usize,
    cfg: &EngineConfig,
) -> (usize, usize) {
    let removed_destinations =
        prune_destination_runtime_state(max_dest_entries, keep_dest_entries, cfg);
    let removed_global_profiles = prune_global_bypass_runtime_state(
        max_global_bypass_entries,
        keep_global_bypass_entries,
        cfg,
    );
    (removed_destinations, removed_global_profiles)
}

fn prune_destination_runtime_state(
    max_entries: usize,
    keep_entries: usize,
    _cfg: &EngineConfig,
) -> usize {
    if max_entries == 0 {
        return 0;
    }
    let failures = DEST_FAILURES.get_or_init(DashMap::new);
    let preferred = DEST_PREFERRED_STAGE.get_or_init(DashMap::new);
    let classifier = DEST_CLASSIFIER.get_or_init(DashMap::new);
    let bypass_idx = DEST_BYPASS_PROFILE_IDX.get_or_init(DashMap::new);
    let bypass_failures = DEST_BYPASS_PROFILE_FAILURES.get_or_init(DashMap::new);
    let route_winner = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
    let route_health = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);

    let mut last_seen_by_destination: HashMap<String, u64> = HashMap::new();
    for r in failures.iter() {
        last_seen_by_destination.entry(r.key().clone()).or_insert(0);
    }
    for r in preferred.iter() {
        last_seen_by_destination.entry(r.key().clone()).or_insert(0);
    }
    for r in bypass_idx.iter() {
        last_seen_by_destination.entry(r.key().clone()).or_insert(0);
    }
    for r in bypass_failures.iter() {
        last_seen_by_destination.entry(r.key().clone()).or_insert(0);
    }
    for r in classifier.iter() {
        let entry = last_seen_by_destination.entry(r.key().clone()).or_insert(0);
        *entry = (*entry).max(r.value().last_seen_unix);
    }
    for r in route_winner.iter() {
        let entry = last_seen_by_destination.entry(r.key().clone()).or_insert(0);
        *entry = (*entry).max(r.value().updated_at_unix);
    }
    for r in route_health.iter() {
        let mut last_seen = 0u64;
        for health in r.value().iter() {
            last_seen = last_seen.max(route_health_last_seen_unix(health.value()));
        }
        let entry = last_seen_by_destination.entry(r.key().clone()).or_insert(0);
        *entry = (*entry).max(last_seen);
    }

    if last_seen_by_destination.len() <= max_entries {
        return 0;
    }

    let keep = keep_entries.min(max_entries).max(1);
    let mut ranked: Vec<(String, u64)> = last_seen_by_destination.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let keep_keys: std::collections::HashSet<String> =
        ranked.iter().take(keep).map(|(k, _)| k.clone()).collect();
    let evict_keys: Vec<String> = ranked
        .into_iter()
        .skip(keep)
        .map(|(key, _)| key)
        .filter(|key| !keep_keys.contains(key))
        .collect();

    for key in &evict_keys {
        failures.remove(key);
        preferred.remove(key);
        classifier.remove(key);
        bypass_idx.remove(key);
        bypass_failures.remove(key);
        route_winner.remove(key);
        route_health.remove(key);
    }

    ml_shadow::prune_ml_state(now_unix_secs());

    evict_keys.len()
}

fn prune_global_bypass_runtime_state(
    max_entries: usize,
    keep_entries: usize,
    _cfg: &EngineConfig,
) -> usize {
    if max_entries == 0 {
        return 0;
    }
    let map = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);
    if map.len() <= max_entries {
        return 0;
    }
    let keep = keep_entries.min(max_entries).max(1);
    let mut ranked: Vec<(String, u64)> = map
        .iter()
        .map(|r| {
            (
                r.key().clone(),
                bypass_profile_health_last_seen_unix(r.value()),
            )
        })
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let keep_keys: std::collections::HashSet<String> =
        ranked.iter().take(keep).map(|(k, _)| k.clone()).collect();
    let evict_keys: Vec<String> = ranked
        .into_iter()
        .skip(keep)
        .map(|(key, _)| key)
        .filter(|key| !keep_keys.contains(key))
        .collect();
    for key in &evict_keys {
        map.remove(key);
    }
    evict_keys.len()
}

#[cfg(test)]
pub(super) fn prune_runtime_classifier_state_for_test(
    max_dest_entries: usize,
    keep_dest_entries: usize,
    max_global_bypass_entries: usize,
    keep_global_bypass_entries: usize,
) -> (usize, usize) {
    prune_runtime_classifier_state_with_caps(
        max_dest_entries,
        keep_dest_entries,
        max_global_bypass_entries,
        keep_global_bypass_entries,
        &EngineConfig::default(),
    )
}

pub(super) static CLASSIFIER_STORE_CFG: OnceLock<Option<ClassifierStoreConfig>> = OnceLock::new();
pub(super) static CLASSIFIER_STORE_LOADED: AtomicBool = AtomicBool::new(false);
pub(super) static CLASSIFIER_STORE_DIRTY: AtomicBool = AtomicBool::new(false);
pub(super) static CLASSIFIER_STORE_LAST_FLUSH_UNIX: AtomicU64 = AtomicU64::new(0);
use crate::config::EngineConfig;

pub(super) const CLASSIFIER_PERSIST_DEBOUNCE_SECS: u64 = 30;
pub(super) const CLASSIFIER_PERSIST_MAX_ENTRIES: usize = 5000;

pub(super) fn init_classifier_store(relay_opts: &RelayOptions, cfg: Arc<EngineConfig>) {
    let _ = CLASSIFIER_STORE_CFG.get_or_init(|| {
        if !relay_opts.classifier_persist_enabled {
            return None;
        }
        let path_str = relay_opts.classifier_cache_path.clone();
        let path = if path_str.is_empty() {
            default_classifier_store_path()
        } else {
            expand_tilde(&path_str)
        };
        Some(ClassifierStoreConfig {
            path,
            entry_ttl_secs: relay_opts.classifier_entry_ttl_secs.max(60),
            cfg,
        })
    });
}
pub(super) fn default_classifier_store_path() -> PathBuf {
    if let Some(dir) = dirs::cache_dir() {
        return dir.join("prime-net-engine").join("relay-classifier.json");
    }
    expand_tilde("~/.cache/prime-net-engine/relay-classifier.json")
}

pub(super) fn load_classifier_store_if_needed(cfg_arg: Arc<EngineConfig>) {
    if CLASSIFIER_STORE_LOADED.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(cfg) = CLASSIFIER_STORE_CFG.get().and_then(Clone::clone) else {
        return;
    };
    let Ok(Some(snapshot)) = read_classifier_snapshot(&cfg.path) else {
        return;
    };
    let now = now_unix_secs();
    let mut restored = 0usize;
    let failures = DEST_FAILURES.get_or_init(DashMap::new);
    let preferred = DEST_PREFERRED_STAGE.get_or_init(DashMap::new);
    let classifier = DEST_CLASSIFIER.get_or_init(DashMap::new);
    let bypass_failures = DEST_BYPASS_PROFILE_FAILURES.get_or_init(DashMap::new);
    let route_health = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);
    let global_bypass = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);

    let ClassifierSnapshot {
        entries,
        global_bypass_health,
        ..
    } = snapshot;
    for (destination, mut entry) in entries {
        entry.preferred_stage = entry.preferred_stage.min(4);
        let last_seen = snapshot_entry_last_seen_unix(&entry);
        if last_seen > 0 && now.saturating_sub(last_seen) > cfg.entry_ttl_secs {
            continue;
        }
        if entry.failures > 0 {
            failures.insert(destination.clone(), entry.failures.min(8));
        }
        if entry.preferred_stage > 0 {
            preferred.insert(destination.clone(), entry.preferred_stage);
        }
        if !destination_classifier_is_empty(&entry.stats) {
            classifier.insert(destination.clone(), entry.stats);
        }
        // Do not restore pinned bypass profile indexes across restarts.
        // Profile order/tuning can change between builds; stale pins hurt recovery.
        let _ = entry.bypass_profile_idx.take();
        if entry.bypass_profile_failures > 0 {
            bypass_failures.insert(destination.clone(), entry.bypass_profile_failures);
        }
        // Do not restore cached route winners across process restarts.
        // Network conditions and bypass backend profile ordering can change between
        // runs; restoring winner IDs causes startup stickiness on stale routes.
        let _ = entry.route_winner.take();
        if !entry.route_health.is_empty() {
            let per_route = DashMap::new();
            for (route_id, mut health) in entry.route_health {
                let route_id = route_id.trim();
                if route_id.is_empty() {
                    continue;
                }
                health.consecutive_failures = health.consecutive_failures.min(32);
                // Weak cooldowns are process-local. Reset them on restore to force
                // fresh probing after startup.
                health.weak_until_unix = 0;
                if route_health_is_empty(&health) {
                    continue;
                }
                per_route.insert(route_id.to_owned(), health);
            }
            if !per_route.is_empty() {
                route_health.insert(destination.clone(), per_route);
            }
        }
        restored = restored.saturating_add(1);
    }
    for (route_id, health) in global_bypass_health {
        let route_id_trim = route_id.trim();
        if route_id_trim.is_empty() || !route_id_trim.starts_with("bypass:") {
            continue;
        }
        if bypass_profile_health_is_empty(&health) {
            continue;
        }
        let last_seen = bypass_profile_health_last_seen_unix(&health);
        if last_seen > 0 && now.saturating_sub(last_seen) > cfg.entry_ttl_secs {
            continue;
        }
        global_bypass.insert(route_id_trim.to_owned(), health);
    }
    if restored > 0 {
        info!(
            target: "socks5.classifier",
            restored,
            path = %cfg.path.display(),
            "restored persisted relay classifier entries"
        );
    }
    maybe_prune_runtime_classifier_state(now, cfg_arg);
}

pub(super) fn destination_classifier_is_empty(stats: &DestinationClassifier) -> bool {
    stats.failures == 0
        && stats.resets == 0
        && stats.timeouts == 0
        && stats.early_closes == 0
        && stats.broken_pipes == 0
        && stats.suspicious_zero_replies == 0
        && stats.successes == 0
}

pub(super) fn route_health_is_empty(health: &RouteHealth) -> bool {
    health.successes == 0
        && health.failures == 0
        && health.consecutive_failures == 0
        && health.weak_until_unix == 0
        && health.last_success_unix == 0
        && health.last_failure_unix == 0
}

pub(super) fn route_health_last_seen_unix(health: &RouteHealth) -> u64 {
    health
        .last_success_unix
        .max(health.last_failure_unix)
        .max(health.weak_until_unix)
}

pub(super) fn snapshot_entry_last_seen_unix(entry: &ClassifierSnapshotEntry) -> u64 {
    let mut last_seen = entry.stats.last_seen_unix;
    if let Some(winner) = entry.route_winner.as_ref() {
        last_seen = last_seen.max(winner.updated_at_unix);
    }
    for health in entry.route_health.values() {
        last_seen = last_seen.max(route_health_last_seen_unix(health));
    }
    last_seen
}

pub(super) fn read_classifier_snapshot(path: &Path) -> std::io::Result<Option<ClassifierSnapshot>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(path)?;
    let parsed: ClassifierSnapshot = serde_json::from_slice(&raw)
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
    Ok(Some(parsed))
}

pub(super) fn maybe_flush_classifier_store(force: bool, _cfg: Arc<EngineConfig>) {
    let Some(cfg) = CLASSIFIER_STORE_CFG.get().and_then(Clone::clone) else {
        return;
    };
    CLASSIFIER_STORE_DIRTY.store(true, Ordering::Relaxed);
    let now = now_unix_secs();
    let last = CLASSIFIER_STORE_LAST_FLUSH_UNIX.load(Ordering::Relaxed);
    if !force && now.saturating_sub(last) < CLASSIFIER_PERSIST_DEBOUNCE_SECS {
        return;
    }
    if CLASSIFIER_STORE_LAST_FLUSH_UNIX
        .compare_exchange(last, now, Ordering::SeqCst, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    if !CLASSIFIER_STORE_DIRTY.swap(false, Ordering::SeqCst) {
        return;
    }
    if let Err(e) = write_classifier_snapshot(&cfg) {
        CLASSIFIER_STORE_DIRTY.store(true, Ordering::Relaxed);
        warn!(
            target: "socks5.classifier",
            error = %e,
            path = %cfg.path.display(),
            "failed to persist relay classifier cache"
        );
    }
}

pub(super) fn write_classifier_snapshot(cfg: &ClassifierStoreConfig) -> std::io::Result<()> {
    let failures = DEST_FAILURES.get_or_init(DashMap::new);
    let preferred = DEST_PREFERRED_STAGE.get_or_init(DashMap::new);
    let classifier = DEST_CLASSIFIER.get_or_init(DashMap::new);
    let bypass_idx = DEST_BYPASS_PROFILE_IDX.get_or_init(DashMap::new);
    let bypass_failures = DEST_BYPASS_PROFILE_FAILURES.get_or_init(DashMap::new);
    let route_health = DEST_ROUTE_HEALTH.get_or_init(DashMap::new);
    let route_winner = DEST_ROUTE_WINNER.get_or_init(DashMap::new);
    let global_bypass = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(DashMap::new);

    let now = now_unix_secs();
    let mut entries: HashMap<String, ClassifierSnapshotEntry> = HashMap::new();
    for r in classifier.iter() {
        entries.insert(
            r.key().clone(),
            ClassifierSnapshotEntry {
                failures: 0,
                preferred_stage: 0,
                stats: r.value().clone(),
                bypass_profile_idx: None,
                bypass_profile_failures: 0,
                route_winner: None,
                route_health: HashMap::new(),
            },
        );
    }
    for r in failures.iter() {
        entries.entry(r.key().clone()).or_default().failures = (*r.value()).min(8);
    }
    for r in preferred.iter() {
        entries.entry(r.key().clone()).or_default().preferred_stage = (*r.value()).min(4);
    }
    for r in bypass_idx.iter() {
        entries
            .entry(r.key().clone())
            .or_default()
            .bypass_profile_idx = Some(*r.value());
    }
    for r in bypass_failures.iter() {
        entries
            .entry(r.key().clone())
            .or_default()
            .bypass_profile_failures = *r.value();
    }
    for r in route_winner.iter() {
        if r.value().route_id.trim().is_empty() {
            continue;
        }
        entries.entry(r.key().clone()).or_default().route_winner = Some(r.value().clone());
    }
    for r in route_health.iter() {
        let (destination, per_route) = (r.key(), r.value());
        if per_route.is_empty() {
            continue;
        }
        let mut filtered = HashMap::new();
        for hr in per_route.iter() {
            let (route_id, health) = (hr.key(), hr.value());
            if route_id.trim().is_empty() || route_health_is_empty(health) {
                continue;
            }
            filtered.insert(route_id.clone(), health.clone());
        }
        if !filtered.is_empty() {
            entries.entry(destination.clone()).or_default().route_health = filtered;
        }
    }
    entries.retain(|_, entry| {
        let last_seen = snapshot_entry_last_seen_unix(entry);
        if last_seen > 0 && now.saturating_sub(last_seen) > cfg.entry_ttl_secs {
            return false;
        }
        entry.failures > 0
            || entry.preferred_stage > 0
            || !destination_classifier_is_empty(&entry.stats)
            || entry.bypass_profile_idx.is_some()
            || entry.bypass_profile_failures > 0
            || entry
                .route_winner
                .as_ref()
                .map(|winner| !winner.route_id.trim().is_empty())
                .unwrap_or(false)
            || !entry.route_health.is_empty()
    });
    if entries.len() > CLASSIFIER_PERSIST_MAX_ENTRIES {
        let mut ranked: Vec<(String, u64)> = entries
            .iter()
            .map(|(k, v)| (k.clone(), snapshot_entry_last_seen_unix(v)))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let keep: std::collections::HashSet<String> = ranked
            .into_iter()
            .take(CLASSIFIER_PERSIST_MAX_ENTRIES)
            .map(|(k, _)| k)
            .collect();
        entries.retain(|k, _| keep.contains(k));
    }
    let mut global_bypass_health = HashMap::new();
    for r in global_bypass.iter() {
        let (route_id, health) = (r.key(), r.value());
        let route_id_trim = route_id.trim();
        if route_id_trim.is_empty() || !route_id_trim.starts_with("bypass:") {
            continue;
        }
        if bypass_profile_health_is_empty(health) {
            continue;
        }
        let last_seen = bypass_profile_health_last_seen_unix(health);
        if last_seen > 0 && now.saturating_sub(last_seen) > cfg.entry_ttl_secs {
            continue;
        }
        global_bypass_health.insert(route_id_trim.to_owned(), health.clone());
    }

    let snapshot = ClassifierSnapshot {
        version: 2,
        updated_at_unix: now,
        entries,
        global_bypass_health,
    };
    if let Some(parent) = cfg.path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data =
        serde_json::to_vec_pretty(&snapshot).map_err(|e| std::io::Error::other(e.to_string()))?;
    write_snapshot_atomic(&cfg.path, &data)?;
    Ok(())
}

pub(super) fn write_snapshot_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("relay-classifier.json");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_name = format!("{file_name}.{}.{}.tmp", std::process::id(), nonce);
    let tmp_path = path.with_file_name(tmp_name);

    fs::write(&tmp_path, data)?;
    match fs::rename(&tmp_path, path) {
        Ok(()) => Ok(()),
        Err(_rename_err) => {
            #[cfg(windows)]
            {
                if path.exists() {
                    let _ = fs::remove_file(path);
                }
                match fs::rename(&tmp_path, path) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        let _ = fs::remove_file(&tmp_path);
                        Err(e)
                    }
                }
            }
            #[cfg(not(windows))]
            {
                let _ = fs::remove_file(&tmp_path);
                Err(_rename_err)
            }
        }
    }
}

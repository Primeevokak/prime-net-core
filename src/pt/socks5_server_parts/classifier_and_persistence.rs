fn destination_failures(destination: &str) -> u8 {
    let map = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = map.lock() else {
        return 0;
    };
    guard.get(destination).copied().unwrap_or(0)
}

fn destination_preferred_stage(destination: &str) -> u8 {
    let map = DEST_PREFERRED_STAGE.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = map.lock() else {
        return 0;
    };
    guard.get(destination).copied().unwrap_or(0).min(4)
}

fn select_race_probe_stage(destination: &str) -> u8 {
    // Гонка v1: выбор между стадиями 1/2/3 по здоровью стадий и хэшу назначения,
    // чтобы разнести первые пробы по разным профилям.
    let stats = STAGE_RACE_STATS.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = stats.lock() else {
        return 1;
    };
    let mut candidates = vec![1u8, 2u8, 3u8];
    candidates.sort_by(|a, b| {
        let sa = guard.get(a).cloned().unwrap_or_default();
        let sb = guard.get(b).cloned().unwrap_or_default();
        let ra = stage_penalty(sa.successes, sa.failures);
        let rb = stage_penalty(sb.successes, sb.failures);
        ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
    });
    // Сохраняем исследование: выбираем один из двух лучших профилей по хэшу назначения.
    if candidates.len() >= 2 {
        let idx = (stable_hash(destination) % 2) as usize;
        return candidates[idx];
    }
    candidates.into_iter().next().unwrap_or(1)
}

fn stage_penalty(successes: u64, failures: u64) -> f64 {
    let total = successes + failures;
    if total == 0 {
        return 0.5;
    }
    failures as f64 / total as f64
}

fn stable_hash(input: &str) -> u64 {
    let mut h = 1469598103934665603u64;
    for b in input.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

fn record_stage_source_selected(source: StageSelectionSource) {
    let counters = RACE_SOURCE_COUNTERS.get_or_init(|| Mutex::new(RaceSourceCounters::default()));
    if let Ok(mut guard) = counters.lock() {
        match source {
            StageSelectionSource::Cache => guard.cache = guard.cache.saturating_add(1),
            StageSelectionSource::Probe => guard.probe = guard.probe.saturating_add(1),
            StageSelectionSource::Adaptive => guard.adaptive = guard.adaptive.saturating_add(1),
        }
    }
}

fn record_destination_failure(
    destination: &str,
    signal: BlockingSignal,
    classifier_emit_interval_secs: u64,
    stage: u8,
) {
    let now = now_unix_secs();
    let map = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut failures_after_update = 0u8;
    if let Ok(mut guard) = map.lock() {
        let entry = guard.entry(destination.to_owned()).or_insert(0);
        *entry = entry.saturating_add(1).min(8);
        failures_after_update = *entry;
    }
    if let Some(threshold) = learned_bypass_threshold(destination) {
        if failures_after_update == threshold {
            if let Some((host, port)) = split_host_port_for_connect(destination) {
                let promotable = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    should_bypass_by_classifier_ip(ip, port)
                } else {
                    should_bypass_by_classifier_host(&host, port)
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
    let map = DEST_CLASSIFIER.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        let stats = guard.entry(destination.to_owned()).or_default();
        stats.failures = stats.failures.saturating_add(1);
        match signal {
            BlockingSignal::Reset => stats.resets = stats.resets.saturating_add(1),
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
    maybe_flush_classifier_store(false);
    maybe_emit_classifier_summary(classifier_emit_interval_secs.max(5));
}

fn record_destination_success(destination: &str, stage: u8, _source: StageSelectionSource) {
    let now = now_unix_secs();
    let map = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        if let Some(entry) = guard.get_mut(destination) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                guard.remove(destination);
            }
        }
    }
    let map = DEST_PREFERRED_STAGE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        guard.insert(destination.to_owned(), stage.min(4));
    }
    let map = DEST_CLASSIFIER.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = map.lock() {
        let stats = guard.entry(destination.to_owned()).or_default();
        stats.successes = stats.successes.saturating_add(1);
        stats.last_seen_unix = now;
    }
    record_stage_outcome(stage, true);
    maybe_flush_classifier_store(false);
}

fn record_stage_outcome(stage: u8, success: bool) {
    if stage == 0 {
        return;
    }
    let stats = STAGE_RACE_STATS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = stats.lock() {
        let entry = guard.entry(stage.min(4)).or_default();
        if success {
            entry.successes = entry.successes.saturating_add(1);
        } else {
            entry.failures = entry.failures.saturating_add(1);
        }
    }
}

fn classify_io_error(e: &std::io::Error) -> BlockingSignal {
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

fn blocking_signal_label(signal: BlockingSignal) -> &'static str {
    match signal {
        BlockingSignal::Reset => "reset",
        BlockingSignal::Timeout => "timeout",
        BlockingSignal::EarlyClose => "early-close",
        BlockingSignal::BrokenPipe => "broken-pipe",
        BlockingSignal::SuspiciousZeroReply => "suspicious-zero-reply",
        BlockingSignal::SilentDrop => "silent-drop",
    }
}

fn should_mark_suspicious_zero_reply(
    port: u16,
    bytes_client_to_upstream: u64,
    bytes_upstream_to_client: u64,
    min_c2u: usize,
) -> bool {
    port == 443 && bytes_upstream_to_client == 0 && bytes_client_to_upstream >= min_c2u as u64
}

fn maybe_emit_classifier_summary(interval_secs: u64) {
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
    let map = DEST_CLASSIFIER.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(guard) = map.lock() else {
        return;
    };
    if !guard.is_empty() {
        let mut entries: Vec<(&String, &DestinationClassifier)> = guard.iter().collect();
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
    if let Ok(guard) = RACE_SOURCE_COUNTERS
        .get_or_init(|| Mutex::new(RaceSourceCounters::default()))
        .lock()
    {
        let total = guard.cache + guard.probe + guard.adaptive;
        if total > 0 {
            info!(
                target: "socks5.classifier",
                cache = guard.cache,
                probe = guard.probe,
                adaptive = guard.adaptive,
                total,
                "strategy selection source counters"
            );
        }
    }
    if let Ok(guard) = STAGE_RACE_STATS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
    {
        let mut stages: Vec<(u8, StageRaceStats)> =
            guard.iter().map(|(k, v)| (*k, v.clone())).collect();
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
    if let Ok(guard) = ROUTE_METRICS
        .get_or_init(|| Mutex::new(RouteMetrics::default()))
        .lock()
    {
        let selected_total = guard.route_selected_direct + guard.route_selected_bypass;
        let race_wins_total = guard.race_winner_direct + guard.race_winner_bypass;
        let winner_cache_total = guard.winner_cache_hits + guard.winner_cache_misses;
        if selected_total > 0 || guard.race_started > 0 || guard.race_skipped > 0 {
            info!(
                target: "socks5.classifier",
                selected_total,
                selected_direct = guard.route_selected_direct,
                selected_bypass = guard.route_selected_bypass,
                races_started = guard.race_started,
                races_skipped = guard.race_skipped,
                race_wins_total,
                race_wins_direct = guard.race_winner_direct,
                race_wins_bypass = guard.race_winner_bypass,
                route_success_direct = guard.route_success_direct,
                route_success_bypass = guard.route_success_bypass,
                route_failure_direct = guard.route_failure_direct,
                route_failure_bypass = guard.route_failure_bypass,
                soft_zero_reply_direct = guard.route_soft_zero_reply_direct,
                soft_zero_reply_bypass = guard.route_soft_zero_reply_bypass,
                connect_fail_direct = guard.connect_failure_direct,
                connect_fail_bypass = guard.connect_failure_bypass,
                "adaptive route counters"
            );
        }
        if winner_cache_total > 0 {
            let winner_cache_hit_rate = guard.winner_cache_hits as f64 / winner_cache_total as f64;
            info!(
                target: "socks5.classifier",
                winner_cache_hits = guard.winner_cache_hits,
                winner_cache_misses = guard.winner_cache_misses,
                winner_cache_hit_rate,
                reason_no_winner = guard.race_reason_no_winner,
                reason_empty_winner = guard.race_reason_empty_winner,
                reason_winner_stale = guard.race_reason_winner_stale,
                reason_winner_weak = guard.race_reason_winner_weak,
                reason_winner_missing = guard.race_reason_winner_missing,
                reason_winner_healthy = guard.race_reason_winner_healthy,
                reason_single_candidate = guard.race_reason_single_candidate,
                reason_non_tls = guard.race_reason_non_tls,
                "adaptive route race diagnostics"
            );
        }
    }
    if let Ok(guard) = GLOBAL_BYPASS_PROFILE_HEALTH
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
    {
        if !guard.is_empty() {
            let mut profiles: Vec<(&String, &BypassProfileHealth)> = guard.iter().collect();
            profiles.sort_by(|a, b| {
                let a_score = bypass_profile_score_from_health(a.1, now);
                let b_score = bypass_profile_score_from_health(b.1, now);
                b_score.cmp(&a_score).then_with(|| a.0.cmp(b.0))
            });
            for (route_id, health) in profiles.into_iter().take(3) {
                info!(
                    target: "socks5.classifier",
                    route = %route_id,
                    score = bypass_profile_score_from_health(health, now),
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
    maybe_flush_classifier_store(false);
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn init_classifier_store(relay_opts: &RelayOptions) {
    let _ = CLASSIFIER_STORE_CFG.get_or_init(|| {
        if !relay_opts.classifier_persist_enabled {
            return None;
        }
        let path = relay_opts
            .classifier_cache_path
            .clone()
            .map(|p| expand_tilde(&p))
            .unwrap_or_else(default_classifier_store_path);
        Some(ClassifierStoreConfig {
            path,
            entry_ttl_secs: relay_opts.classifier_entry_ttl_secs.max(60),
        })
    });
}

fn default_classifier_store_path() -> PathBuf {
    if let Some(dir) = dirs::cache_dir() {
        return dir.join("prime-net-engine").join("relay-classifier.json");
    }
    expand_tilde("~/.cache/prime-net-engine/relay-classifier.json")
}

fn load_classifier_store_if_needed() {
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
    let failures = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let preferred = DEST_PREFERRED_STAGE.get_or_init(|| Mutex::new(HashMap::new()));
    let classifier = DEST_CLASSIFIER.get_or_init(|| Mutex::new(HashMap::new()));
    let bypass_idx = DEST_BYPASS_PROFILE_IDX.get_or_init(|| Mutex::new(HashMap::new()));
    let bypass_failures = DEST_BYPASS_PROFILE_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let route_health = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let route_winner = DEST_ROUTE_WINNER.get_or_init(|| Mutex::new(HashMap::new()));
    let global_bypass = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut failures_guard) = failures.lock() else {
        return;
    };
    let Ok(mut preferred_guard) = preferred.lock() else {
        return;
    };
    let Ok(mut classifier_guard) = classifier.lock() else {
        return;
    };
    let Ok(mut bypass_idx_guard) = bypass_idx.lock() else {
        return;
    };
    let Ok(mut bypass_failures_guard) = bypass_failures.lock() else {
        return;
    };
    let Ok(mut route_health_guard) = route_health.lock() else {
        return;
    };
    let Ok(mut route_winner_guard) = route_winner.lock() else {
        return;
    };
    let Ok(mut global_bypass_guard) = global_bypass.lock() else {
        return;
    };
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
            failures_guard.insert(destination.clone(), entry.failures.min(8));
        }
        if entry.preferred_stage > 0 {
            preferred_guard.insert(destination.clone(), entry.preferred_stage);
        }
        if !destination_classifier_is_empty(&entry.stats) {
            classifier_guard.insert(destination.clone(), entry.stats);
        }
        if let Some(idx) = entry.bypass_profile_idx {
            bypass_idx_guard.insert(destination.clone(), idx);
        }
        if entry.bypass_profile_failures > 0 {
            bypass_failures_guard.insert(destination.clone(), entry.bypass_profile_failures);
        }
        if let Some(winner) = entry.route_winner.take() {
            if !winner.route_id.trim().is_empty() {
                route_winner_guard.insert(destination.clone(), winner);
            }
        }
        if !entry.route_health.is_empty() {
            let mut per_route: HashMap<String, RouteHealth> = HashMap::new();
            for (route_id, mut health) in entry.route_health {
                let route_id = route_id.trim();
                if route_id.is_empty() {
                    continue;
                }
                health.consecutive_failures = health.consecutive_failures.min(32);
                if route_health_is_empty(&health) {
                    continue;
                }
                per_route.insert(route_id.to_owned(), health);
            }
            if !per_route.is_empty() {
                route_health_guard.insert(destination.clone(), per_route);
            }
        }
        restored = restored.saturating_add(1);
    }
    for (route_id, health) in global_bypass_health {
        let route_id = route_id.trim();
        if route_id.is_empty() || !route_id.starts_with("bypass:") {
            continue;
        }
        if bypass_profile_health_is_empty(&health) {
            continue;
        }
        let last_seen = bypass_profile_health_last_seen_unix(&health);
        if last_seen > 0 && now.saturating_sub(last_seen) > cfg.entry_ttl_secs {
            continue;
        }
        global_bypass_guard.insert(route_id.to_owned(), health);
    }
    if restored > 0 {
        info!(
            target: "socks5.classifier",
            restored,
            path = %cfg.path.display(),
            "restored persisted relay classifier entries"
        );
    }
}

fn destination_classifier_is_empty(stats: &DestinationClassifier) -> bool {
    stats.failures == 0
        && stats.resets == 0
        && stats.timeouts == 0
        && stats.early_closes == 0
        && stats.broken_pipes == 0
        && stats.suspicious_zero_replies == 0
        && stats.successes == 0
}

fn route_health_is_empty(health: &RouteHealth) -> bool {
    health.successes == 0
        && health.failures == 0
        && health.consecutive_failures == 0
        && health.weak_until_unix == 0
        && health.last_success_unix == 0
        && health.last_failure_unix == 0
}

fn route_health_last_seen_unix(health: &RouteHealth) -> u64 {
    health
        .last_success_unix
        .max(health.last_failure_unix)
        .max(health.weak_until_unix)
}

fn snapshot_entry_last_seen_unix(entry: &ClassifierSnapshotEntry) -> u64 {
    let mut last_seen = entry.stats.last_seen_unix;
    if let Some(winner) = entry.route_winner.as_ref() {
        last_seen = last_seen.max(winner.updated_at_unix);
    }
    for health in entry.route_health.values() {
        last_seen = last_seen.max(route_health_last_seen_unix(health));
    }
    last_seen
}

fn read_classifier_snapshot(path: &Path) -> std::io::Result<Option<ClassifierSnapshot>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(path)?;
    let parsed: ClassifierSnapshot = serde_json::from_slice(&raw)
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
    Ok(Some(parsed))
}

fn maybe_flush_classifier_store(force: bool) {
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

fn write_classifier_snapshot(cfg: &ClassifierStoreConfig) -> std::io::Result<()> {
    let failures = DEST_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let preferred = DEST_PREFERRED_STAGE.get_or_init(|| Mutex::new(HashMap::new()));
    let classifier = DEST_CLASSIFIER.get_or_init(|| Mutex::new(HashMap::new()));
    let bypass_idx = DEST_BYPASS_PROFILE_IDX.get_or_init(|| Mutex::new(HashMap::new()));
    let bypass_failures = DEST_BYPASS_PROFILE_FAILURES.get_or_init(|| Mutex::new(HashMap::new()));
    let route_health = DEST_ROUTE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let route_winner = DEST_ROUTE_WINNER.get_or_init(|| Mutex::new(HashMap::new()));
    let global_bypass = GLOBAL_BYPASS_PROFILE_HEALTH.get_or_init(|| Mutex::new(HashMap::new()));

    let failures_guard = failures.lock().map_err(|_| {
        std::io::Error::other("failed to lock destination failures while persisting classifier")
    })?;
    let preferred_guard = preferred.lock().map_err(|_| {
        std::io::Error::other("failed to lock preferred stages while persisting classifier")
    })?;
    let classifier_guard = classifier.lock().map_err(|_| {
        std::io::Error::other("failed to lock classifier stats while persisting classifier")
    })?;
    let bypass_idx_guard = bypass_idx.lock().map_err(|_| {
        std::io::Error::other("failed to lock bypass profile index while persisting classifier")
    })?;
    let bypass_failures_guard = bypass_failures.lock().map_err(|_| {
        std::io::Error::other("failed to lock bypass profile failures while persisting classifier")
    })?;
    let route_health_guard = route_health.lock().map_err(|_| {
        std::io::Error::other("failed to lock route health while persisting classifier")
    })?;
    let route_winner_guard = route_winner.lock().map_err(|_| {
        std::io::Error::other("failed to lock route winner while persisting classifier")
    })?;
    let global_bypass_guard = global_bypass.lock().map_err(|_| {
        std::io::Error::other("failed to lock global bypass health while persisting classifier")
    })?;

    let now = now_unix_secs();
    let mut entries: HashMap<String, ClassifierSnapshotEntry> = HashMap::new();
    for (destination, stats) in classifier_guard.iter() {
        entries.insert(
            destination.clone(),
            ClassifierSnapshotEntry {
                failures: 0,
                preferred_stage: 0,
                stats: stats.clone(),
                bypass_profile_idx: None,
                bypass_profile_failures: 0,
                route_winner: None,
                route_health: HashMap::new(),
            },
        );
    }
    for (destination, value) in failures_guard.iter() {
        entries.entry(destination.clone()).or_default().failures = (*value).min(8);
    }
    for (destination, stage) in preferred_guard.iter() {
        entries
            .entry(destination.clone())
            .or_default()
            .preferred_stage = (*stage).min(4);
    }
    for (destination, idx) in bypass_idx_guard.iter() {
        entries
            .entry(destination.clone())
            .or_default()
            .bypass_profile_idx = Some(*idx);
    }
    for (destination, value) in bypass_failures_guard.iter() {
        entries
            .entry(destination.clone())
            .or_default()
            .bypass_profile_failures = *value;
    }
    for (destination, winner) in route_winner_guard.iter() {
        if winner.route_id.trim().is_empty() {
            continue;
        }
        entries.entry(destination.clone()).or_default().route_winner = Some(winner.clone());
    }
    for (destination, per_route) in route_health_guard.iter() {
        if per_route.is_empty() {
            continue;
        }
        let mut filtered = HashMap::new();
        for (route_id, health) in per_route.iter() {
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
    let mut global_bypass_health = HashMap::new();
    for (route_id, health) in global_bypass_guard.iter() {
        let route_id = route_id.trim();
        if route_id.is_empty() || !route_id.starts_with("bypass:") {
            continue;
        }
        if bypass_profile_health_is_empty(health) {
            continue;
        }
        let last_seen = bypass_profile_health_last_seen_unix(health);
        if last_seen > 0 && now.saturating_sub(last_seen) > cfg.entry_ttl_secs {
            continue;
        }
        global_bypass_health.insert(route_id.to_owned(), health.clone());
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

fn write_snapshot_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
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

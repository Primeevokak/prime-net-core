use prime_net_engine_core::config::{DnsResolverKind, EchMode, EvasionStrategy};
use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::EngineConfig;

pub fn apply_preset(cfg: &mut EngineConfig, name: &str, strict_conflicts: bool) -> Result<()> {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() || name == "none" {
        return Ok(());
    }

    match name.as_str() {
        "strict-privacy" => apply_strict_privacy(cfg, strict_conflicts),
        "balanced-privacy" => apply_balanced_privacy(cfg, strict_conflicts),
        "max-compatibility" => apply_max_compatibility(cfg, strict_conflicts),
        "aggressive-evasion" => apply_aggressive_evasion(cfg, strict_conflicts),
        other => Err(EngineError::InvalidInput(format!(
            "unknown preset: {other} (expected strict-privacy|balanced-privacy|max-compatibility|aggressive-evasion)"
        ))),
    }
}

fn apply_strict_privacy(cfg: &mut EngineConfig, strict: bool) -> Result<()> {
    let def = EngineConfig::default();

    // DNS: DoH only, no system DNS.
    conflict_bool(
        strict,
        "anticensorship.system_dns_enabled",
        cfg.anticensorship.system_dns_enabled,
        def.anticensorship.system_dns_enabled,
        false,
    )?;
    cfg.anticensorship.system_dns_enabled = false;

    conflict_vec(
        strict,
        "anticensorship.dns_fallback_chain",
        &cfg.anticensorship.dns_fallback_chain,
        &def.anticensorship.dns_fallback_chain,
        &[DnsResolverKind::Doh],
    )?;
    cfg.anticensorship.dns_fallback_chain = vec![DnsResolverKind::Doh];
    cfg.anticensorship.doh_enabled = true;
    cfg.anticensorship.dot_enabled = false;
    cfg.anticensorship.doq_enabled = false;

    // ECH: "mandatory" (Real). Note: Real can still fail at runtime if no ECH configs are available.
    conflict_opt(
        strict,
        "anticensorship.ech_mode",
        cfg.anticensorship.ech_mode.clone(),
        def.anticensorship.ech_mode.clone(),
        Some(EchMode::Real),
    )?;
    cfg.anticensorship.ech_mode = Some(EchMode::Real);

    // Enable fragmentation.
    conflict_opt(
        strict,
        "evasion.strategy",
        cfg.evasion.strategy.clone(),
        def.evasion.strategy.clone(),
        Some(EvasionStrategy::Fragment),
    )?;
    cfg.evasion.strategy = Some(EvasionStrategy::Fragment);

    conflict_bool(
        strict,
        "privacy.tracker_blocker.enabled",
        cfg.privacy.tracker_blocker.enabled,
        def.privacy.tracker_blocker.enabled,
        true,
    )?;
    cfg.privacy.tracker_blocker.enabled = true;

    conflict_value(
        strict,
        "privacy.referer.mode",
        &cfg.privacy.referer.mode,
        &def.privacy.referer.mode,
        &prime_net_engine_core::config::RefererMode::Strip,
    )?;
    cfg.privacy.referer.enabled = true;
    cfg.privacy.referer.mode = prime_net_engine_core::config::RefererMode::Strip;
    cfg.privacy.referer.strip_from_search_engines = true;

    cfg.privacy.signals.send_dnt = true;
    cfg.privacy.signals.send_gpc = true;

    Ok(())
}

fn apply_balanced_privacy(cfg: &mut EngineConfig, strict: bool) -> Result<()> {
    let def = EngineConfig::default();

    conflict_bool(
        strict,
        "privacy.tracker_blocker.enabled",
        cfg.privacy.tracker_blocker.enabled,
        def.privacy.tracker_blocker.enabled,
        false,
    )?;
    cfg.privacy.tracker_blocker.enabled = false;

    conflict_value(
        strict,
        "privacy.referer.mode",
        &cfg.privacy.referer.mode,
        &def.privacy.referer.mode,
        &prime_net_engine_core::config::RefererMode::OriginOnly,
    )?;
    cfg.privacy.referer.enabled = true;
    cfg.privacy.referer.mode = prime_net_engine_core::config::RefererMode::OriginOnly;
    cfg.privacy.referer.strip_from_search_engines = true;

    cfg.privacy.signals.send_dnt = false;
    cfg.privacy.signals.send_gpc = true;

    Ok(())
}

fn apply_max_compatibility(cfg: &mut EngineConfig, strict: bool) -> Result<()> {
    let def = EngineConfig::default();

    // DNS: allow system fallback.
    conflict_bool(
        strict,
        "anticensorship.system_dns_enabled",
        cfg.anticensorship.system_dns_enabled,
        def.anticensorship.system_dns_enabled,
        true,
    )?;
    cfg.anticensorship.system_dns_enabled = true;
    cfg.anticensorship.doh_enabled = true;

    // ECH: grease (most compatible "looks like ECH" without requiring real ECH configs).
    conflict_opt(
        strict,
        "anticensorship.ech_mode",
        cfg.anticensorship.ech_mode.clone(),
        def.anticensorship.ech_mode.clone(),
        Some(EchMode::Grease),
    )?;
    cfg.anticensorship.ech_mode = Some(EchMode::Grease);

    // Disable fragmentation/desync.
    conflict_opt(
        strict,
        "evasion.strategy",
        cfg.evasion.strategy.clone(),
        def.evasion.strategy.clone(),
        None,
    )?;
    cfg.evasion.strategy = None;

    Ok(())
}

fn apply_aggressive_evasion(cfg: &mut EngineConfig, strict: bool) -> Result<()> {
    let def = EngineConfig::default();

    // DNS chain: DoH + DoT + DoQ (no system fallback by default).
    conflict_bool(
        strict,
        "anticensorship.system_dns_enabled",
        cfg.anticensorship.system_dns_enabled,
        def.anticensorship.system_dns_enabled,
        false,
    )?;
    cfg.anticensorship.system_dns_enabled = false;
    cfg.anticensorship.doh_enabled = true;
    cfg.anticensorship.dot_enabled = true;
    cfg.anticensorship.doq_enabled = true;

    conflict_vec(
        strict,
        "anticensorship.dns_fallback_chain",
        &cfg.anticensorship.dns_fallback_chain,
        &def.anticensorship.dns_fallback_chain,
        &[
            DnsResolverKind::Doh,
            DnsResolverKind::Dot,
            DnsResolverKind::Doq,
        ],
    )?;
    cfg.anticensorship.dns_fallback_chain = vec![
        DnsResolverKind::Doh,
        DnsResolverKind::Dot,
        DnsResolverKind::Doq,
    ];

    // ECH: auto.
    conflict_opt(
        strict,
        "anticensorship.ech_mode",
        cfg.anticensorship.ech_mode.clone(),
        def.anticensorship.ech_mode.clone(),
        Some(EchMode::Auto),
    )?;
    cfg.anticensorship.ech_mode = Some(EchMode::Auto);

    // Fragment + desync: use auto strategy with split offsets to enable desync path selection.
    conflict_opt(
        strict,
        "evasion.strategy",
        cfg.evasion.strategy.clone(),
        def.evasion.strategy.clone(),
        Some(EvasionStrategy::Auto),
    )?;
    cfg.evasion.strategy = Some(EvasionStrategy::Auto);

    if cfg.evasion.client_hello_split_offsets.is_empty() {
        cfg.evasion.client_hello_split_offsets = vec![1, 5, 40, 64];
    }
    cfg.evasion.split_at_sni = true;
    cfg.evasion.fragment_sleep_ms = 0;
    cfg.evasion.fragment_budget_bytes = 32 * 1024;
    cfg.evasion.prime_mode = true;
    #[cfg(windows)]
    {
        cfg.evasion.first_packet_ttl = 5;
    }
    cfg.evasion.traffic_shaping_enabled = true;

    Ok(())
}

fn conflict_bool(
    strict: bool,
    path: &str,
    current: bool,
    default: bool,
    preset: bool,
) -> Result<()> {
    if strict && current != default && current != preset {
        return Err(EngineError::Config(format!(
            "preset conflict: {path} is set to {current}, but preset requires {preset}"
        )));
    }
    Ok(())
}

fn conflict_opt<T: std::fmt::Debug + PartialEq>(
    strict: bool,
    path: &str,
    current: Option<T>,
    default: Option<T>,
    preset: Option<T>,
) -> Result<()> {
    if strict && current != default && current != preset {
        return Err(EngineError::Config(format!(
            "preset conflict: {path} is set to {:?}, but preset requires {:?}",
            current, preset
        )));
    }
    Ok(())
}

fn conflict_vec<T: std::fmt::Debug + PartialEq>(
    strict: bool,
    path: &str,
    current: &[T],
    default: &[T],
    preset: &[T],
) -> Result<()> {
    if strict && current != default && current != preset {
        return Err(EngineError::Config(format!(
            "preset conflict: {path} is set to {:?}, but preset requires {:?}",
            current, preset
        )));
    }
    Ok(())
}

fn conflict_value<T: std::fmt::Debug + PartialEq>(
    strict: bool,
    path: &str,
    current: &T,
    default: &T,
    preset: &T,
) -> Result<()> {
    if strict && current != default && current != preset {
        return Err(EngineError::Config(format!(
            "preset conflict: {path} is set to {:?}, but preset requires {:?}",
            current, preset
        )));
    }
    Ok(())
}

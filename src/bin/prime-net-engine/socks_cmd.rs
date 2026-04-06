use std::sync::Arc;

use prime_net_engine_core::anticensorship::ResolverChain;
use prime_net_engine_core::config::EvasionStrategy;
use prime_net_engine_core::config::SystemProxyMode;
use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::evasion::TcpDesyncEngine;
use prime_net_engine_core::platform::system_proxy_manager;
use prime_net_engine_core::pt::direct::DirectOutbound;
use prime_net_engine_core::pt::socks5_server::{start_socks5_server, RelayOptions};
use prime_net_engine_core::{EngineConfig, PrimeEngine};
use tracing::{info, warn};

use crate::blocklist_runtime::{
    initialize_runtime_blocklist, is_bypass_domain_runtime, log_runtime_blocklist_stats,
};

#[derive(Debug, Clone)]
pub struct SocksOpts {
    pub bind: String,
    pub silent_drop: bool,
}

struct SystemProxyCleanupGuard {
    armed: bool,
}

impl SystemProxyCleanupGuard {
    fn new(armed: bool) -> Self {
        Self { armed }
    }
}

impl Drop for SystemProxyCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = system_proxy_manager().disable();
        }
    }
}

pub async fn run_socks(mut cfg: EngineConfig, opts: &SocksOpts) -> Result<()> {
    // Keep system proxy endpoint consistent with runtime bind, otherwise
    // auto-configured proxy can point to a different port than actual listener.
    if !opts.bind.trim().is_empty() {
        cfg.system_proxy.socks_endpoint = opts.bind.clone();
    }
    // Arm cleanup early, but enable system proxy only after listener is ready.
    let mut proxy_cleanup = SystemProxyCleanupGuard::new(false);

    // Initialize Pluggable Transports if configured
    if let Some(ref mut pt) = cfg.pt {
        info!(target: "socks_cmd", pt_kind = ?pt.kind, bind = %pt.local_socks5_bind, "starting SOCKS with pluggable transport");
        if !opts.bind.trim().is_empty() {
            pt.local_socks5_bind = opts.bind.clone();
        }
        pt.silent_drop = opts.silent_drop;

        match PrimeEngine::new(cfg.clone()).await {
            Ok(eng) => {
                let addr = eng
                    .pt_socks5_addr()
                    .ok_or_else(|| EngineError::Internal("pt socks5 addr is missing".to_owned()))?;

                println!("SOCKS5 listening on {addr}");
                println!("Hint (TUN): run tun2socks and point it to this SOCKS5 endpoint.");

                proxy_cleanup.armed = maybe_auto_configure_system_proxy(&cfg);
                let _keep = eng;
                wait_for_shutdown().await;
                return Ok(());
            }
            Err(e) => {
                warn!(target: "socks_cmd", error = %e, "failed to start pluggable transport; falling back to internal relay mode");
            }
        }
    }

    // No PT: Initialize runtime blocklist and native bypass engine.
    let blocklist_stats = initialize_runtime_blocklist(&cfg.blocklist).await?;
    log_runtime_blocklist_stats(&blocklist_stats);

    let mut relay_opts = build_direct_relay_options(&cfg);

    // Wire the runtime domain-check function so route scoring can classify blocked domains.
    if cfg.evasion.packet_bypass_enabled || relay_opts.fragment_client_hello {
        relay_opts.bypass_domain_check = Some(is_bypass_domain_runtime);
    } else {
        warn!(target: "socks_cmd", "no bypass transport or internal evasion active; running as plain SOCKS5 proxy");
    }

    if relay_opts.fragment_client_hello {
        info!(
            target: "socks_cmd",
            fragment_size_min = relay_opts.fragment_size_min,
            fragment_size_max = relay_opts.fragment_size_max,
            fragment_sleep_ms = relay_opts.fragment_sleep_ms,
            fragment_budget_bytes = relay_opts.fragment_budget_bytes,
            "prime-mode is enabled (offline DPI bypass relay)"
        );
    }

    // Initialize in-process TcpDesyncEngine (native bypass) — no binary required.
    // Enabled alongside packet bypass or whenever evasion is active.
    if cfg.evasion.packet_bypass_enabled || relay_opts.fragment_client_hello {
        let mut engine = TcpDesyncEngine::with_config(&cfg.evasion);

        // Run profile discovery synchronously (with 10 s timeout) so that the ML scorer
        // encounters the most effective profiles first from the very first connection.
        let cache_path = prime_net_engine_core::evasion::profile_discovery::cache_path();
        let mut cache = prime_net_engine_core::evasion::ProfileDiscoveryCache::load(&cache_path);
        if !cache.all_fresh((0..engine.profile_count()).map(|i| engine.profile_name(i))) {
            info!(target: "socks_cmd", "running profile discovery (first run or stale cache)");
            let discovery_result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                prime_net_engine_core::evasion::profile_discovery::run_profile_discovery(
                    &engine, &mut cache,
                ),
            )
            .await;
            match discovery_result {
                Ok(reordered) if !reordered.is_empty() => {
                    info!(
                        target: "socks_cmd",
                        profiles = reordered.len(),
                        "profile discovery complete — profiles reordered by effectiveness"
                    );
                    engine.set_profiles(reordered);
                    cache.save(&cache_path);
                }
                Ok(_) => {
                    info!(target: "socks_cmd", "profile discovery returned no results");
                }
                Err(_) => {
                    warn!(target: "socks_cmd", "profile discovery timed out — using default ordering");
                }
            }
        }

        let profiles = engine.profile_count();
        relay_opts.native_bypass = Some(Arc::new(engine));
        info!(
            target: "socks_cmd",
            profiles,
            "native TLS/TCP desync engine active"
        );
    }

    let resolver = Arc::new(ResolverChain::from_config(&cfg.anticensorship)?);
    let outbound =
        Arc::new(DirectOutbound::new(resolver).with_first_packet_ttl(cfg.evasion.first_packet_ttl));

    let bind_addr: std::net::SocketAddr = opts
        .bind
        .parse()
        .map_err(|e| EngineError::Config(format!("invalid bind address: {}", e)))?;
    let guard = start_socks5_server(
        bind_addr,
        outbound,
        Arc::new(cfg.clone()),
        opts.silent_drop,
        relay_opts,
    )
    .await?;
    let listen_addr = guard.listen_addr();
    println!("SOCKS5 listening on {listen_addr}");
    println!("Hint (TUN): run tun2socks and point it to this SOCKS5 endpoint.");

    proxy_cleanup.armed = maybe_auto_configure_system_proxy(&cfg);

    // Spawn the kill switch monitor after the listener is ready so the first
    // liveness check reliably finds the port open.
    let _kill_switch = prime_net_engine_core::platform::kill_switch::spawn_kill_switch_monitor(
        listen_addr,
        cfg.evasion.kill_switch_enabled,
    );

    let _keep = guard;
    wait_for_shutdown().await;
    Ok(())
}

fn build_direct_relay_options(cfg: &EngineConfig) -> RelayOptions {
    let env_forced_off = std::env::var("PRIME_DIRECT_EVASION")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off"
            )
        })
        .unwrap_or(false);
    if env_forced_off {
        return RelayOptions::default();
    }

    // prime-mode keeps offline bypass enabled out of the box for direct SOCKS mode.
    let enabled = matches!(
        cfg.evasion.strategy,
        Some(EvasionStrategy::Fragment)
            | Some(EvasionStrategy::Desync)
            | Some(EvasionStrategy::Auto)
    ) || (cfg.pt.is_none() && cfg.evasion.prime_mode);
    if !enabled {
        return RelayOptions::default();
    }
    let mut split_offsets = if cfg.evasion.client_hello_split_offsets.is_empty() {
        vec![1, 5, 40, 64]
    } else {
        cfg.evasion.client_hello_split_offsets.clone()
    };
    split_offsets.sort_unstable();
    split_offsets.dedup();
    split_offsets.retain(|v| *v > 0);

    let mut sleep_ms = cfg.evasion.fragment_sleep_ms;

    // Hard-reset sleep to 0 for bypass performance, unless user explicitly set something else than wizard's 10ms
    if sleep_ms == 10 || sleep_ms == 2 {
        sleep_ms = 0;
    }

    if sleep_ms > 50 {
        sleep_ms = 50;
    }

    RelayOptions {
        fragment_client_hello: true,
        split_at_sni: cfg.evasion.split_at_sni,
        client_hello_split_offsets: split_offsets,
        fragment_size_min: 40,
        fragment_size_max: cfg.evasion.fragment_size_max.clamp(40, 512),
        randomize_fragment_size: true,
        fragment_sleep_ms: sleep_ms,
        fragment_budget_bytes: cfg.evasion.fragment_budget_bytes.max(128 * 1024), // Ensure at least 128KB budget
        tcp_window_size: cfg.evasion.tcp_window_size as u16,
        classifier_persist_enabled: cfg.evasion.classifier_persist_enabled,
        classifier_cache_path: Some(cfg.evasion.classifier_cache_path.clone().into()),
        classifier_entry_ttl_secs: cfg.evasion.classifier_entry_ttl_secs,
        strategy_race_enabled: cfg.evasion.strategy_race_enabled,
        ..RelayOptions::default()
    }
}

fn maybe_auto_configure_system_proxy(cfg: &EngineConfig) -> bool {
    if !cfg.system_proxy.auto_configure {
        return false;
    }
    let mgr = system_proxy_manager();
    match cfg.system_proxy.mode {
        SystemProxyMode::Off => {
            if let Err(e) = mgr.disable() {
                warn!(target: "socks_cmd", error = %e, "failed to disable system proxy on startup");
                eprintln!("warning: failed to disable system proxy: {e}");
            }
            false
        }
        SystemProxyMode::All => match mgr.enable(&cfg.system_proxy.socks_endpoint) {
            Ok(()) => {
                info!(target: "socks_cmd", endpoint = %cfg.system_proxy.socks_endpoint, "system proxy enabled (all mode)");
                true
            }
            Err(e) => {
                warn!(target: "socks_cmd", endpoint = %cfg.system_proxy.socks_endpoint, error = %e, "failed to enable system proxy (all mode)");
                eprintln!("warning: failed to enable system proxy: {e}");
                false
            }
        },
        SystemProxyMode::Pac => {
            let url = format!("http://127.0.0.1:{}/proxy.pac", cfg.system_proxy.pac_port);
            match mgr.enable_pac(&url) {
                Ok(()) => {
                    info!(target: "socks_cmd", pac_url = %url, "system proxy enabled (PAC mode)");
                    true
                }
                Err(e) => {
                    warn!(target: "socks_cmd", pac_url = %url, error = %e, "failed to enable PAC proxy");
                    eprintln!("warning: failed to enable PAC proxy: {e}");
                    false
                }
            }
        }
        SystemProxyMode::Custom => false,
    }
}

async fn wait_for_shutdown() {
    #[cfg(windows)]
    {
        let mut ctrl_break = tokio::signal::windows::ctrl_break().ok();
        let mut ctrl_close = tokio::signal::windows::ctrl_close().ok();
        let mut ctrl_shutdown = tokio::signal::windows::ctrl_shutdown().ok();
        let mut ctrl_logoff = tokio::signal::windows::ctrl_logoff().ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = async {
                if let Some(s) = ctrl_break.as_mut() {
                    let _ = s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
            _ = async {
                if let Some(s) = ctrl_close.as_mut() {
                    let _ = s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
            _ = async {
                if let Some(s) = ctrl_shutdown.as_mut() {
                    let _ = s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
            _ = async {
                if let Some(s) = ctrl_logoff.as_mut() {
                    let _ = s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
        }
    }

    #[cfg(not(windows))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

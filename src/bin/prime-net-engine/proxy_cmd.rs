use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use prime_net_engine_core::config::{BlocklistConfig, SystemProxyConfig};
use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::pac::PacGenerator;
use prime_net_engine_core::platform::diagnostics::{DiagnosticLevel, ProxyDiagnostics};
use prime_net_engine_core::platform::{system_proxy_manager, ProxyMode};

use crate::blocklist_cmd::load_domains_or_empty;

#[derive(Debug, Clone)]
pub enum ProxyAction {
    Enable {
        mode: String,
        custom_pac_url: Option<String>,
    },
    Disable,
    Status,
    GeneratePac {
        output: PathBuf,
        socks_endpoint: String,
    },
    ServePac {
        port: u16,
        socks_endpoint: String,
    },
}

#[derive(Debug, Clone)]
pub struct ProxyOpts {
    pub action: ProxyAction,
}

pub async fn run_proxy(
    opts: &ProxyOpts,
    proxy_cfg: &SystemProxyConfig,
    blocklist_cfg: &BlocklistConfig,
) -> Result<()> {
    let mgr = system_proxy_manager();
    match &opts.action {
        ProxyAction::Enable {
            mode,
            custom_pac_url,
        } => {
            let mode = mode.trim().to_ascii_lowercase();
            match mode.as_str() {
                "all" => {
                    let diag = ProxyDiagnostics::check_socks5_listening(&proxy_cfg.socks_endpoint);
                    if diag.level != DiagnosticLevel::Ok {
                        eprintln!(
                            "warning: SOCKS5 endpoint {} is not responding; system proxy may fail until SOCKS5 server starts",
                            proxy_cfg.socks_endpoint
                        );
                    }
                    mgr.enable(&proxy_cfg.socks_endpoint)?;
                    println!(
                        "system proxy enabled (all traffic via {})",
                        proxy_cfg.socks_endpoint
                    );
                    if let Err(e) = mgr.set_dns("127.0.0.1") {
                        eprintln!("warning: failed to set system DNS: {e}");
                    } else {
                        println!("system DNS set to 127.0.0.1 (leak protection active)");
                    }
                }
                "pac" => {
                    let pac_url = format!("http://127.0.0.1:{}/proxy.pac", proxy_cfg.pac_port);
                    mgr.enable_pac(&pac_url)?;
                    println!("system proxy enabled (PAC: {pac_url})");
                    if let Err(e) = mgr.set_dns("127.0.0.1") {
                        eprintln!("warning: failed to set system DNS: {e}");
                    } else {
                        println!("system DNS set to 127.0.0.1 (leak protection active)");
                    }
                    println!(
                        "tip: run `prime-net-engine proxy serve-pac --port {}`",
                        proxy_cfg.pac_port
                    );
                }
                "custom" => {
                    let url = custom_pac_url.as_deref().ok_or_else(|| {
                        EngineError::InvalidInput("custom mode requires --pac-url".to_owned())
                    })?;
                    mgr.enable_pac(url)?;
                    println!("system proxy enabled (custom PAC: {url})");
                    let _ = mgr.set_dns("127.0.0.1");
                }
                _ => {
                    return Err(EngineError::InvalidInput(
                        "proxy mode must be all|pac|custom".to_owned(),
                    ));
                }
            }
        }
        ProxyAction::Disable => {
            mgr.disable()?;
            let _ = mgr.reset_dns();
            println!("system proxy disabled and DNS restored");
        }
        ProxyAction::Status => {
            let status = mgr.status()?;
            println!(
                "status: {}",
                if status.enabled {
                    "ENABLED"
                } else {
                    "DISABLED"
                }
            );
            println!(
                "mode: {}",
                match status.mode {
                    ProxyMode::Off => "off",
                    ProxyMode::All => "all",
                    ProxyMode::Pac => "pac",
                }
            );
            if let Some(v) = status.socks_endpoint.clone() {
                println!("socks: {v}");
                let d = ProxyDiagnostics::check_socks5_listening(&v);
                let probe = match d.level {
                    DiagnosticLevel::Ok => "listening",
                    DiagnosticLevel::Info => "responding with info",
                    DiagnosticLevel::Warn => "not running (warning)",
                    DiagnosticLevel::Error => "not running",
                };
                println!("socks5 diagnostics: {probe}");
            }
            if let Some(v) = status.pac_url {
                println!("pac: {v}");
            }
            if status.socks_endpoint.is_none() {
                println!("socks5 diagnostics: not running");
            }
        }
        ProxyAction::GeneratePac {
            output,
            socks_endpoint,
        } => {
            let domains = load_domains_or_empty(blocklist_cfg)?;
            let generator = PacGenerator {
                blocked_domains: domains,
                socks_endpoint: socks_endpoint.clone(),
            };
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(output, generator.generate_pac_script())?;
            println!("PAC generated: {}", output.display());
        }
        ProxyAction::ServePac {
            port,
            socks_endpoint,
        } => {
            let domains = load_domains_or_empty(blocklist_cfg)?;
            let generator = PacGenerator {
                blocked_domains: domains,
                socks_endpoint: socks_endpoint.clone(),
            };
            let _server = generator.serve_pac(*port)?;
            println!("PAC server started: http://127.0.0.1:{port}/proxy.pac");
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
    }
    Ok(())
}

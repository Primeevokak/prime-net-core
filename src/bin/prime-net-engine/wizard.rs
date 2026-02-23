use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use prime_net_engine_core::config::{DomainFrontingRule, EvasionStrategy, FrontingProvider};
use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::{EngineConfig, PrimeEngine, RequestData};
use reqwest::Method;

use crate::config_check::{run_config_check, ConfigCheckOpts};
use crate::preset::apply_preset;

#[derive(Debug, Clone)]
pub struct WizardOpts {
    pub out_path: PathBuf,
    pub force: bool,
}

pub async fn run_wizard(opts: &WizardOpts) -> Result<()> {
    if opts.out_path.exists() && !opts.force {
        return Err(EngineError::InvalidInput(format!(
            "refusing to overwrite existing config: {} (use --force)",
            opts.out_path.display()
        )));
    }

    let mut cfg = EngineConfig::default();

    let preset = prompt_string(
        "Preset (none|strict-privacy|balanced-privacy|max-compatibility|aggressive-evasion)",
        Some("none"),
    )?;
    if !preset.trim().eq_ignore_ascii_case("none") && !preset.trim().is_empty() {
        apply_preset(&mut cfg, &preset, false)?;
    }

    println!("prime-net-engine wizard");
    println!();

    let doh_enabled = prompt_bool("Enable DoH (DNS over HTTPS)?", true)?;
    cfg.anticensorship.doh_enabled = doh_enabled;
    if doh_enabled {
        let providers = prompt_string(
            "DoH providers (comma-separated, e.g. adguard,google,quad9)",
            Some("adguard,google,quad9"),
        )?;
        cfg.anticensorship.doh_providers = split_csv(&providers);

        let bootstrap = prompt_string(
            "Bootstrap IPs for DoH endpoint hostnames (comma-separated, optional)",
            None,
        )?;
        cfg.anticensorship.bootstrap_ips = split_csv(&bootstrap)
            .into_iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();

        let test = prompt_bool("Test DoH providers now?", true)?;
        if test {
            let rep = run_config_check(
                &cfg,
                &ConfigCheckOpts {
                    offline: false,
                    probe_domain: "example.com".to_owned(),
                },
            )
            .await?;

            for (name, ok, msg) in rep.doh_results {
                println!("DoH {name}: {} ({msg})", if ok { "OK" } else { "FAIL" });
            }
            println!();
        }
    }

    let fronting_enabled = prompt_bool("Enable domain fronting?", false)?;
    cfg.anticensorship.domain_fronting_enabled = fronting_enabled;
    if fronting_enabled {
        let target_host = prompt_string("Target host (the hostname you will request)", None)?;
        let real_host = prompt_string(
            "Real host for Host header (usually same as target host)",
            Some(&target_host),
        )?;
        let front_domains = prompt_string(
            "Front domain candidates (comma-separated, e.g. cdn1.example,cdn2.example)",
            None,
        )?;

        cfg.anticensorship.domain_fronting_rules = vec![DomainFrontingRule {
            target_host: target_host.trim().to_owned(),
            front_domain: String::new(),
            front_domains: split_csv(&front_domains),
            real_host: real_host.trim().to_owned(),
            sni_domain: None,
            provider: FrontingProvider::Cloudflare,
        }];

        let test = prompt_bool("Probe front domain candidates now?", true)?;
        if test {
            let rep = run_config_check(
                &cfg,
                &ConfigCheckOpts {
                    offline: false,
                    probe_domain: "example.com".to_owned(),
                },
            )
            .await?;

            for (label, ok, msg) in rep.fronting_results {
                println!("{label}: {} ({msg})", if ok { "OK" } else { "FAIL" });
            }
            println!();
        }
    }

    let evasion_enabled = prompt_bool(
        "Enable DPI evasion (TCP fragmentation for TLS ClientHello)?",
        false,
    )?;
    if evasion_enabled {
        cfg.evasion.strategy = Some(EvasionStrategy::Fragment);

        let tune = prompt_bool(
            "Auto-tune fragment_size (requires a test HTTPS request)?",
            true,
        )?;
        if tune {
            let url = prompt_string("Test URL", Some("https://example.com/"))?;
            let picked = auto_tune_fragment_size(&mut cfg, &url).await;
            match picked {
                Ok(sz) => {
                    cfg.evasion.fragment_size_max = sz;
                    println!("Picked fragment_size_max={sz}");
                }
                Err(e) => {
                    println!(
                        "Auto-tune failed: {e}. Keeping fragment_size_max={}",
                        cfg.evasion.fragment_size_max
                    );
                }
            }
            println!();
        } else {
            let sz = prompt_u64("fragment_size_max (bytes)", cfg.evasion.fragment_size_max as u64)?;
            cfg.evasion.fragment_size_max = sz as usize;
        }
    }

    // Emit a minimal TOML without comments (serde/toml limitation).
    let toml = toml::to_string_pretty(&cfg).map_err(|e| EngineError::Internal(e.to_string()))?;
    write_atomic(&opts.out_path, toml.as_bytes()).map_err(EngineError::Io)?;

    println!("Wrote config to {}", opts.out_path.display());
    Ok(())
}

async fn auto_tune_fragment_size(cfg: &mut EngineConfig, test_url: &str) -> Result<usize> {
    let candidates = [64usize, 48, 32, 16, 8];
    for &sz in &candidates {
        cfg.evasion.fragment_size_max = sz;
        cfg.evasion.fragment_size_min = sz.min(10);
        cfg.evasion.fragment_sleep_ms = 10;

        let client = PrimeEngine::new(cfg.clone()).await?.client();
        let req = RequestData::new(test_url.to_owned(), Method::HEAD);
        let res = client.fetch(req, None).await;
        if res.is_ok() {
            return Ok(sz);
        }
    }
    Err(EngineError::Internal(
        "no fragment_size candidate succeeded".to_owned(),
    ))
}

fn prompt_bool(question: &str, default: bool) -> io::Result<bool> {
    let def = if default { "Y/n" } else { "y/N" };
    let s = prompt_string(&format!("{question} [{def}]"), None)?;
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Ok(default);
    }
    Ok(matches!(s.as_str(), "y" | "yes" | "1" | "true"))
}

fn prompt_u64(question: &str, default: u64) -> io::Result<u64> {
    let s = prompt_string(&format!("{question} [{default}]"), None)?;
    let s = s.trim();
    if s.is_empty() {
        return Ok(default);
    }
    match s.parse::<u64>() {
        Ok(v) => Ok(v),
        Err(_) => Ok(default),
    }
}

fn prompt_string(question: &str, default: Option<&str>) -> io::Result<String> {
    let mut out = String::new();
    if let Some(def) = default {
        print!("{question} [{def}]: ");
    } else {
        print!("{question}: ");
    }
    io::stdout().flush()?;
    io::stdin().read_line(&mut out)?;
    let out = out.trim_end_matches(&['\r', '\n'][..]).to_owned();
    if out.trim().is_empty() {
        if let Some(def) = default {
            return Ok(def.to_owned());
        }
    }
    Ok(out)
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .collect()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(tmp, path)?;
    Ok(())
}

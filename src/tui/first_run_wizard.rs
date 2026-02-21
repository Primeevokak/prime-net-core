use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::config::DnsResolverKind;
use crate::config::EchMode;
use crate::config::EngineConfig;
use crate::config::EvasionStrategy;
use crate::error::{EngineError, Result};

pub struct FirstRunWizard {
    selected_preset: usize,
    enable_proxy: bool,
}

impl Default for FirstRunWizard {
    fn default() -> Self {
        Self::new()
    }
}

impl FirstRunWizard {
    pub fn new() -> Self {
        Self {
            selected_preset: 0,
            enable_proxy: true,
        }
    }

    pub fn run(&mut self) -> Result<EngineConfig> {
        println!("prime-net-engine: мастер первого запуска");
        println!();
        println!("Выберите пресет:");
        println!("  1) aggressive-evasion");
        println!("  2) strict-privacy");
        println!("  3) balanced-privacy");
        println!("  4) max-compatibility");
        self.selected_preset = prompt_choice("Номер пресета", 1, 4)? - 1;
        self.enable_proxy = prompt_yes_no("Включить системный прокси сейчас?", true)?;
        self.build_config()
    }

    fn build_config(&self) -> Result<EngineConfig> {
        let mut config = EngineConfig::default();
        match self.selected_preset {
            0 => {
                config.evasion.strategy = Some(EvasionStrategy::Auto);
                config.evasion.client_hello_split_offsets = vec![1, 6, 40];
                config.evasion.traffic_shaping_enabled = true;
                config.anticensorship.dot_enabled = true;
                config.anticensorship.doq_enabled = true;
                config.anticensorship.dns_fallback_chain = vec![
                    DnsResolverKind::Doh,
                    DnsResolverKind::Dot,
                    DnsResolverKind::Doq,
                    DnsResolverKind::System,
                ];
                config.anticensorship.ech_mode = Some(EchMode::Auto);
            }
            1 => {
                config.anticensorship.system_dns_enabled = false;
                config.anticensorship.dns_fallback_chain = vec![DnsResolverKind::Doh];
                config.anticensorship.ech_mode = Some(EchMode::Grease);
                config.privacy.tracker_blocker.enabled = true;
                config.privacy.referer.enabled = true;
                config.privacy.referer.mode = crate::config::RefererMode::Strip;
            }
            2 => {
                config.privacy.tracker_blocker.enabled = false;
                config.privacy.referer.enabled = true;
                config.privacy.referer.mode = crate::config::RefererMode::OriginOnly;
            }
            3 => {
                config.evasion.strategy = None;
                config.evasion.traffic_shaping_enabled = false;
                config.anticensorship.domain_fronting_enabled = false;
                config.anticensorship.dot_enabled = false;
                config.anticensorship.doq_enabled = false;
                config.anticensorship.system_dns_enabled = true;
                config.anticensorship.dns_fallback_chain =
                    vec![DnsResolverKind::Doh, DnsResolverKind::System];
            }
            _ => {}
        }
        if self.enable_proxy {
            config.system_proxy.auto_configure = true;
            config.system_proxy.mode = crate::config::SystemProxyMode::All;
        }
        Ok(config)
    }
}

pub fn is_first_run(config_path: &Path) -> bool {
    !config_path.exists()
}

pub fn ensure_config_exists(config_path: &Path) -> Result<EngineConfig> {
    if !is_first_run(config_path) {
        return EngineConfig::from_file(config_path);
    }

    let mut wizard = FirstRunWizard::new();
    let config = wizard.run()?;
    let content = toml::to_string_pretty(&config)
        .map_err(|e| EngineError::Internal(format!("config serialize failed: {e}")))?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(config_path, content)?;
    Ok(config)
}

pub fn default_config_path() -> PathBuf {
    if let Some(dir) = dirs::config_dir() {
        return dir.join("prime-net-engine").join("config.toml");
    }
    PathBuf::from("config.toml")
}

fn prompt_choice(prompt: &str, min: usize, max: usize) -> Result<usize> {
    print!("{prompt} [{min}-{max}]: ");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let parsed = buf
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|v| *v >= min && *v <= max)
        .unwrap_or(min);
    Ok(parsed)
}

fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    let default_hint = if default { "Д/н" } else { "д/Н" };
    print!("{prompt} [{default_hint}]: ");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let v = buf.trim().to_ascii_lowercase();
    if v.is_empty() {
        return Ok(default);
    }
    Ok(matches!(v.as_str(), "y" | "yes" | "д" | "да"))
}

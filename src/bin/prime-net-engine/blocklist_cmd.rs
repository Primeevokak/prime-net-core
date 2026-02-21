use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prime_net_engine_core::blocklist::{expand_tilde, update_blocklist, BlocklistCache};
use prime_net_engine_core::config::BlocklistConfig;
use prime_net_engine_core::error::Result;

#[derive(Debug, Clone)]
pub enum BlocklistAction {
    Update,
    Status,
}

#[derive(Debug, Clone)]
pub struct BlocklistOpts {
    pub action: BlocklistAction,
    pub source_override: Option<String>,
}

pub async fn run_blocklist(opts: &BlocklistOpts, cfg: &BlocklistConfig) -> Result<()> {
    match opts.action {
        BlocklistAction::Update => {
            let source = opts.source_override.as_deref().unwrap_or(&cfg.source);
            let path = cache_path(&cfg.cache_path);
            let cache = update_blocklist(source, &path).await?;
            println!(
                "blocklist updated: {} domains cached at {}",
                cache.domains.len(),
                path.display()
            );
        }
        BlocklistAction::Status => {
            let path = cache_path(&cfg.cache_path);
            match BlocklistCache::status(&path)? {
                Some(c) => {
                    println!("blocklist source: {}", c.source);
                    println!("domains: {}", c.domains.len());
                    println!("updated_at_unix: {}", c.updated_at_unix);
                    println!("cache: {}", path.display());
                    let age = cache_age(c.updated_at_unix);
                    if age > Duration::from_secs(cfg.update_interval_hours.saturating_mul(3600)) {
                        println!(
                            "status: outdated (last update {} hours ago, interval={}h)",
                            age.as_secs() / 3600,
                            cfg.update_interval_hours
                        );
                    } else {
                        println!("status: fresh ({} hours old)", age.as_secs() / 3600);
                    }
                }
                None => {
                    println!("blocklist source: {}", cfg.source);
                    println!("domains: 0");
                    println!("cache: {}", path.display());
                    println!("status: cache not found (run `blocklist update`)");
                }
            }
        }
    }
    Ok(())
}

pub fn load_domains_or_empty(cfg: &BlocklistConfig) -> Result<Vec<String>> {
    let path = cache_path(&cfg.cache_path);
    Ok(BlocklistCache::status(&path)?
        .map(|c| c.domains)
        .unwrap_or_default())
}

fn cache_path(path: &str) -> PathBuf {
    expand_tilde(path)
}

fn cache_age(updated_at_unix: u64) -> Duration {
    let updated = UNIX_EPOCH + Duration::from_secs(updated_at_unix);
    SystemTime::now()
        .duration_since(updated)
        .unwrap_or_else(|_| Duration::from_secs(0))
}

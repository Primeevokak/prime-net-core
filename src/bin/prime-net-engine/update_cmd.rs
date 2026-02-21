use prime_net_engine_core::config::{UpdateChannel, UpdaterConfig};
use prime_net_engine_core::error::Result;
use prime_net_engine_core::updater::{AutoUpdater, UpdateInfo};
use prime_net_engine_core::version::APP_VERSION;

#[derive(Debug, Clone)]
pub enum UpdateAction {
    Check { channel: Option<UpdateChannel> },
    Install { version: Option<String> },
    Rollback,
}

#[derive(Debug, Clone)]
pub struct UpdateOpts {
    pub action: UpdateAction,
}

pub async fn run_update(opts: &UpdateOpts, cfg: &UpdaterConfig) -> Result<()> {
    let updater = AutoUpdater::new(APP_VERSION, cfg.repo.clone(), "prime-net-engine");
    match &opts.action {
        UpdateAction::Check { channel } => {
            let ch = channel.as_ref().unwrap_or(&cfg.channel);
            match updater.check_for_updates_for_channel(ch).await? {
                Some(info) => {
                    println!(
                        "update available [{}]: {} ({})",
                        channel_name(ch),
                        info.version,
                        info.url
                    );
                }
                None => {
                    println!(
                        "up to date [{}] ({})",
                        channel_name(ch),
                        updater.get_current_version()
                    );
                }
            }
        }
        UpdateAction::Install { version } => {
            let info = if let Some(v) = version {
                let tag = if v.starts_with('v') {
                    v.clone()
                } else {
                    format!("v{v}")
                };
                UpdateInfo {
                    version: v.trim_start_matches('v').to_owned(),
                    tag,
                    url: String::new(),
                }
            } else {
                match updater.check_for_updates_for_channel(&cfg.channel).await? {
                    Some(v) => v,
                    None => {
                        println!("already up to date ({})", updater.get_current_version());
                        return Ok(());
                    }
                }
            };
            updater.download_and_install(info).await?;
            println!("update installed");
        }
        UpdateAction::Rollback => {
            updater.rollback()?;
            println!("rollback complete");
        }
    }
    Ok(())
}

fn channel_name(ch: &UpdateChannel) -> &'static str {
    match ch {
        UpdateChannel::Stable => "stable",
        UpdateChannel::Beta => "beta",
        UpdateChannel::Nightly => "nightly",
    }
}

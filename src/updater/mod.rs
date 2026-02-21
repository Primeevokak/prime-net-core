use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::UpdateChannel;
use crate::error::{EngineError, Result};

pub mod rollback;
pub mod verification;

use rollback::RollbackManager;
use verification::SignatureVerifier;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    pub tag: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub tag_name: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

pub struct AutoUpdater {
    current_version: String,
    repo: String,
    bin_name: String,
}

impl AutoUpdater {
    pub fn new(
        current_version: impl Into<String>,
        repo: impl Into<String>,
        bin_name: impl Into<String>,
    ) -> Self {
        Self {
            current_version: current_version.into(),
            repo: repo.into(),
            bin_name: bin_name.into(),
        }
    }

    pub fn get_current_version(&self) -> &str {
        &self.current_version
    }

    pub async fn check_for_updates(&self) -> Result<Option<UpdateInfo>> {
        self.check_for_updates_for_channel(&UpdateChannel::Stable)
            .await
    }

    pub async fn check_for_updates_for_channel(
        &self,
        channel: &UpdateChannel,
    ) -> Result<Option<UpdateInfo>> {
        let release = self.get_latest_for_channel(channel).await?;
        let version = release.tag_name.trim_start_matches('v').to_owned();
        if version.is_empty() || version == self.current_version {
            return Ok(None);
        }
        Ok(Some(UpdateInfo {
            version,
            tag: release.tag_name.clone(),
            url: if release.html_url.is_empty() {
                self.release_web_url(&release.tag_name)
            } else {
                release.html_url.clone()
            },
        }))
    }

    pub async fn get_latest_for_channel(&self, channel: &UpdateChannel) -> Result<ReleaseInfo> {
        match channel {
            UpdateChannel::Stable => {
                let latest = self.fetch_latest_release().await?;
                if self.matches_channel(&latest, channel) {
                    Ok(latest)
                } else {
                    let all = self.fetch_all_releases().await?;
                    all.into_iter()
                        .find(|r| self.matches_channel(r, channel))
                        .ok_or_else(|| {
                            EngineError::Internal(format!(
                                "no releases found for channel: {channel:?}"
                            ))
                        })
                }
            }
            _ => {
                let all = self.fetch_all_releases().await?;
                all.into_iter()
                    .find(|r| self.matches_channel(r, channel))
                    .ok_or_else(|| {
                        EngineError::Internal(format!("no releases found for channel: {channel:?}"))
                    })
            }
        }
    }

    fn matches_channel(&self, release: &ReleaseInfo, channel: &UpdateChannel) -> bool {
        let tag = release.tag_name.to_ascii_lowercase();
        match channel {
            UpdateChannel::Stable => {
                !release.prerelease && !tag.contains("beta") && !tag.contains("nightly")
            }
            UpdateChannel::Beta => release.prerelease || tag.contains("beta"),
            UpdateChannel::Nightly => tag.contains("nightly"),
        }
    }

    async fn fetch_latest_release(&self) -> Result<ReleaseInfo> {
        let api = format!("{}/repos/{}/releases/latest", self.api_base(), self.repo);
        self.fetch_release(&api).await
    }

    async fn fetch_all_releases(&self) -> Result<Vec<ReleaseInfo>> {
        let api = format!("{}/repos/{}/releases", self.api_base(), self.repo);
        self.fetch_releases(&api).await
    }

    fn api_base(&self) -> String {
        std::env::var("GITHUB_API_URL")
            .map(|v| v.trim_end_matches('/').to_owned())
            .unwrap_or_else(|_| "https://api.github.com".to_owned())
    }

    fn release_web_url(&self, tag: &str) -> String {
        format!("https://github.com/{}/releases/tag/{}", self.repo, tag)
    }

    async fn fetch_release(&self, url: &str) -> Result<ReleaseInfo> {
        let client = reqwest::Client::new();
        let resp = client
            .get(url)
            .header("User-Agent", "prime-net-engine-updater")
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(EngineError::Internal(format!(
                "GitHub API error: {}",
                resp.status()
            )));
        }
        resp.json()
            .await
            .map_err(|e| EngineError::Internal(format!("invalid update response: {e}")))
    }

    async fn fetch_releases(&self, url: &str) -> Result<Vec<ReleaseInfo>> {
        let client = reqwest::Client::new();
        let resp = client
            .get(url)
            .header("User-Agent", "prime-net-engine-updater")
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(EngineError::Internal(format!(
                "GitHub API error: {}",
                resp.status()
            )));
        }
        resp.json()
            .await
            .map_err(|e| EngineError::Internal(format!("invalid update response: {e}")))
    }

    pub async fn download_and_install(&self, update: UpdateInfo) -> Result<()> {
        let rollback_mgr = RollbackManager::new()?;
        let backup = rollback_mgr.backup_current_binary()?;

        let repo = self.repo.clone();
        let bin_name = self.bin_name.clone();
        let current_version = self.current_version.clone();
        let tag = update.tag.clone();
        let install_result = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut parts = repo.split('/');
            let owner = parts
                .next()
                .ok_or_else(|| EngineError::InvalidInput("invalid updater repo".to_owned()))?;
            let name = parts
                .next()
                .ok_or_else(|| EngineError::InvalidInput("invalid updater repo".to_owned()))?;

            let status = self_update::backends::github::Update::configure()
                .repo_owner(owner)
                .repo_name(name)
                .bin_name(&bin_name)
                .target_version_tag(&tag)
                .show_download_progress(true)
                .current_version(&current_version)
                .build()
                .map_err(|e| EngineError::Internal(format!("updater build failed: {e}")))?
                .update()
                .map_err(|e| EngineError::Internal(format!("update install failed: {e}")))?;
            if status.version() == current_version {
                return Err(EngineError::Internal(
                    "update did not change binary version".to_owned(),
                ));
            }
            Ok(())
        })
        .await?;

        match install_result {
            Ok(()) => {
                rollback_mgr.cleanup_old_backups(3)?;
                Ok(())
            }
            Err(e) => {
                rollback_mgr.restore_backup(&backup)?;
                Err(e)
            }
        }
    }

    pub fn rollback(&self) -> Result<()> {
        let rollback_mgr = RollbackManager::new()?;
        rollback_mgr.rollback_to_previous()
    }

    pub async fn download_and_verify(&self, release: &ReleaseInfo) -> Result<PathBuf> {
        let binary_url = self
            .find_binary_asset(release)
            .ok_or_else(|| EngineError::Internal("no suitable binary asset found".to_owned()))?;
        let binary = self.download_file(&binary_url).await?;
        let sig_url = format!("{binary_url}.sig");
        let signature = self.download_file(&sig_url).await.ok();

        if let Some(sig) = signature {
            let verifier = SignatureVerifier::new();
            if !verifier.verify_release(&binary, &sig)? {
                return Err(EngineError::Internal(
                    "signature verification failed - update rejected".to_owned(),
                ));
            }
        } else if cfg!(feature = "require-signatures") {
            return Err(EngineError::Internal(
                "signature verification required but .sig not found".to_owned(),
            ));
        }

        self.save_to_temp(&binary)
    }

    pub async fn install_with_rollback(&self, new_binary: &Path) -> Result<()> {
        let rollback_mgr = RollbackManager::new()?;
        let backup = rollback_mgr.backup_current_binary()?;
        if let Err(e) = rollback_mgr.replace_current_binary(new_binary) {
            rollback_mgr.restore_backup(&backup)?;
            return Err(e);
        }
        rollback_mgr.cleanup_old_backups(3)?;
        Ok(())
    }

    fn find_binary_asset(&self, release: &ReleaseInfo) -> Option<String> {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        release
            .assets
            .iter()
            .find(|a| {
                let n = a.name.to_ascii_lowercase();
                n.contains("prime-net-engine") && n.contains(os) && n.contains(arch)
            })
            .or_else(|| {
                release
                    .assets
                    .iter()
                    .find(|a| a.name.contains("prime-net-engine"))
            })
            .map(|a| a.browser_download_url.clone())
    }

    async fn download_file(&self, url: &str) -> Result<Vec<u8>> {
        let client = reqwest::Client::new();
        let response = client.get(url).send().await?;
        if !response.status().is_success() {
            return Err(EngineError::Internal(format!(
                "download failed: {}",
                response.status()
            )));
        }
        let bytes = response.bytes().await?;
        Ok(bytes.to_vec())
    }

    fn save_to_temp(&self, data: &[u8]) -> Result<PathBuf> {
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(format!(
            "prime-net-engine-update-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        ));

        std::fs::write(&temp_path, data)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&temp_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&temp_path, perms)?;
        }

        Ok(temp_path)
    }
}

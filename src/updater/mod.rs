use std::path::{Path, PathBuf};

use reqwest::redirect::Policy;
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

    async fn fetch_release_by_tag(&self, tag: &str) -> Result<ReleaseInfo> {
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(EngineError::InvalidInput(
                "update tag must not be empty".to_owned(),
            ));
        }
        let api = format!(
            "{}/repos/{}/releases/tags/{}",
            self.api_base(),
            self.repo,
            tag
        );
        self.fetch_release(&api).await
    }

    async fn fetch_all_releases(&self) -> Result<Vec<ReleaseInfo>> {
        let api = format!("{}/repos/{}/releases", self.api_base(), self.repo);
        self.fetch_releases(&api).await
    }

    fn api_base(&self) -> String {
        "https://api.github.com".to_owned()
    }

    fn release_web_url(&self, tag: &str) -> String {
        format!("https://github.com/{}/releases/tag/{}", self.repo, tag)
    }

    async fn fetch_release(&self, url: &str) -> Result<ReleaseInfo> {
        validate_update_api_url(url)?;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .map_err(|e| EngineError::Internal(format!("failed to build updater client: {e}")))?;
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
        validate_update_api_url(url)?;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .map_err(|e| EngineError::Internal(format!("failed to build updater client: {e}")))?;
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
        let release = self.fetch_release_by_tag(&update.tag).await?;
        let new_binary = self.download_and_verify(&release).await?;
        let result = self.install_with_rollback(&new_binary).await;
        let _ = std::fs::remove_file(&new_binary);
        result
    }

    pub fn rollback(&self) -> Result<()> {
        let rollback_mgr = RollbackManager::new()?;
        rollback_mgr.rollback_to_previous()
    }

    pub async fn download_and_verify(&self, release: &ReleaseInfo) -> Result<PathBuf> {
        let binary_url = self
            .find_binary_asset(release)
            .ok_or_else(|| EngineError::Internal("no suitable binary asset found".to_owned()))?;
        validate_update_download_url(&binary_url)?;
        let binary = self.download_file(&binary_url).await?;
        let sig_url = format!("{binary_url}.sig");
        validate_update_download_url(&sig_url)?;
        let signature = self.download_file(&sig_url).await.map_err(|e| {
            EngineError::Internal(format!(
                "update signature not found or failed to download ('{sig_url}'): {e}"
            ))
        })?;

        let verifier = SignatureVerifier::new();
        if !verifier.verify_release(&binary, &signature)? {
            return Err(EngineError::Internal(
                "signature verification failed - update rejected".to_owned(),
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
        let wanted_bin = self.bin_name.to_ascii_lowercase();
        release
            .assets
            .iter()
            .find(|a| {
                let n = a.name.to_ascii_lowercase();
                n.contains(&wanted_bin) && n.contains(os) && n.contains(arch)
            })
            .or_else(|| {
                release
                    .assets
                    .iter()
                    .find(|a| a.name.to_ascii_lowercase().contains(&wanted_bin))
            })
            .map(|a| a.browser_download_url.clone())
    }

    async fn download_file(&self, url: &str) -> Result<Vec<u8>> {
        validate_update_download_url(url)?;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .map_err(|e| EngineError::Internal(format!("failed to build updater client: {e}")))?;
        let response = client
            .get(url)
            .header("User-Agent", "prime-net-engine-updater")
            .send()
            .await?;
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
        let mut temp_file = tempfile::Builder::new()
            .prefix("prime-net-engine-update-")
            .rand_bytes(8)
            .tempfile()
            .map_err(|e| EngineError::Internal(format!("failed to create temporary file for update: {e}")))?;

        use std::io::Write;
        temp_file.write_all(data).map_err(|e| {
            EngineError::Internal(format!("failed to write update data to temporary file: {e}"))
        })?;

        let (file, path) = temp_file.keep().map_err(|e| {
            EngineError::Internal(format!("failed to persist temporary update file: {e}"))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o755);
            file.set_permissions(perms)?;
        }

        Ok(path)
    }
}

fn validate_update_api_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| EngineError::Internal(format!("invalid updater API URL '{url}': {e}")))?;
    if parsed.scheme() != "https" {
        return Err(EngineError::Internal(format!(
            "updater API URL must use https: '{url}'"
        )));
    }
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    if host != "api.github.com" {
        return Err(EngineError::Internal(format!(
            "updater API host is not allowed: '{host}'"
        )));
    }
    Ok(())
}

fn validate_update_download_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| EngineError::Internal(format!("invalid updater download URL '{url}': {e}")))?;
    if parsed.scheme() != "https" {
        return Err(EngineError::Internal(format!(
            "updater download URL must use https: '{url}'"
        )));
    }
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let allowed = host == "github.com"
        || host == "objects.githubusercontent.com"
        || host == "github-releases.githubusercontent.com"
        || host.ends_with(".githubusercontent.com");
    if !allowed {
        return Err(EngineError::Internal(format!(
            "updater download host is not allowed: '{host}'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_update_api_url, validate_update_download_url};

    #[test]
    fn updater_api_url_must_be_https_and_github_api() {
        assert!(validate_update_api_url("https://api.github.com/repos/o/r/releases").is_ok());
        assert!(validate_update_api_url("http://api.github.com/repos/o/r/releases").is_err());
        assert!(validate_update_api_url("https://evil.example/repos/o/r/releases").is_err());
    }

    #[test]
    fn updater_download_url_allows_only_github_hosts() {
        assert!(validate_update_download_url(
            "https://github.com/openai/example/releases/download/v1/bin"
        )
        .is_ok());
        assert!(
            validate_update_download_url("https://objects.githubusercontent.com/asset").is_ok()
        );
        assert!(validate_update_download_url("https://downloads.evil.example/asset").is_err());
    }
}

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{EngineError, Result};
use crate::version::APP_VERSION;

pub struct RollbackManager {
    backup_dir: PathBuf,
}

impl RollbackManager {
    pub fn new() -> Result<Self> {
        let backup_dir = dirs::data_dir()
            .ok_or_else(|| EngineError::Internal("cannot determine data directory".to_owned()))?
            .join("prime-net-engine")
            .join("backups");
        fs::create_dir_all(&backup_dir)?;
        Ok(Self { backup_dir })
    }

    pub fn backup_current_binary(&self) -> Result<PathBuf> {
        let current = std::env::current_exe()?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup_path = self
            .backup_dir
            .join(format!("prime-net-engine-{}-{}.backup", APP_VERSION, ts));
        fs::copy(&current, &backup_path)?;
        Ok(backup_path)
    }

    pub fn rollback_to_previous(&self) -> Result<()> {
        let backups = self.list_backups()?;
        let latest = backups
            .into_iter()
            .max_by_key(|p| fs::metadata(p).and_then(|m| m.modified()).ok())
            .ok_or_else(|| EngineError::Internal("no backups found".to_owned()))?;
        self.restore_backup(&latest)
    }

    pub fn restore_backup(&self, backup: &Path) -> Result<()> {
        if !backup.exists() {
            return Err(EngineError::Internal(format!(
                "backup not found: {}",
                backup.display()
            )));
        }
        self.replace_current_binary(backup)
    }

    pub fn replace_current_binary(&self, source: &Path) -> Result<()> {
        let current = std::env::current_exe()?;
        self.replace_binary(source, &current)
    }

    pub fn cleanup_old_backups(&self, keep: usize) -> Result<()> {
        let mut backups = self.list_backups()?;
        if backups.len() <= keep {
            return Ok(());
        }
        backups.sort_by_key(|p| fs::metadata(p).and_then(|m| m.modified()).ok());
        let remove_count = backups.len() - keep;
        for old in backups.into_iter().take(remove_count) {
            fs::remove_file(old)?;
        }
        Ok(())
    }

    fn list_backups(&self) -> Result<Vec<PathBuf>> {
        let entries = fs::read_dir(&self.backup_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("backup"))
            .collect::<Vec<_>>();
        Ok(entries)
    }

    fn replace_binary(&self, source: &Path, dest: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            let temp_dest = dest.with_extension("tmp-update");
            fs::copy(source, &temp_dest)?;

            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&temp_dest)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&temp_dest, perms)?;

            fs::rename(&temp_dest, dest)?;
        }

        #[cfg(windows)]
        {
            let dest_backup = dest.with_extension("old");

            // Remove any stale .old left by a previous failed update before we move the
            // current binary there. Without this, fs::rename would fail on Windows if the
            // file already exists.
            if dest_backup.exists() {
                fs::remove_file(&dest_backup).map_err(|e| {
                    EngineError::Internal(format!(
                        "failed to remove stale binary backup ({}): {e}",
                        dest_backup.display()
                    ))
                })?;
            }

            fs::rename(dest, &dest_backup).map_err(|e| EngineError::Internal(format!("failed to move current binary to backup: {e}")))?;
            match fs::copy(source, dest) {
                Ok(_) => {
                    if let Err(e) = fs::remove_file(&dest_backup) {
                        tracing::warn!(error = %e, path = %dest_backup.display(), "failed to remove old binary backup (non-critical)");
                    }
                }
                Err(copy_err) => {
                    // Recovery: restore the old binary only if the backup still exists.
                    // It may have been removed by antivirus or a concurrent process.
                    if dest_backup.exists() {
                        fs::rename(&dest_backup, dest).map_err(|e2| {
                            EngineError::Internal(format!(
                                "CRITICAL: update failed and recovery failed too. Original: {copy_err}, Recovery: {e2}"
                            ))
                        })?;
                    } else {
                        return Err(EngineError::Internal(format!(
                            "CRITICAL: update failed and backup is missing — binary may be gone. Original error: {copy_err}"
                        )));
                    }
                    return Err(copy_err.into());
                }
            }
        }

        Ok(())
    }
}

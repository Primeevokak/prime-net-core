use std::process::Command;

use prime_net_engine_core::error::{EngineError, Result};

#[derive(Debug, Clone)]
pub struct TuiOpts {
    pub config: Option<String>,
}

pub fn run_tui(opts: &TuiOpts) -> Result<()> {
    let mut bin = std::env::current_exe()?;
    bin.set_file_name(if cfg!(windows) {
        "prime-tui.exe"
    } else {
        "prime-tui"
    });

    let mut cmd = Command::new(&bin);
    if let Some(cfg) = &opts.config {
        cmd.arg("--config").arg(cfg);
    }

    let status = cmd.status()?;
    if status.success() {
        return Ok(());
    }
    Err(EngineError::Internal(format!(
        "prime-tui failed with status: {status}"
    )))
}

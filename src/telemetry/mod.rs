use serde::Serialize;

use crate::error::Result;

pub mod connection_tracker;
pub mod tui_layer;

#[derive(Debug, Clone, Serialize)]
pub struct CrashReport<'a> {
    pub stack_trace: &'a str,
    pub os: &'a str,
    pub os_version: &'a str,
    pub config_hash: &'a str,
    pub last_logs: Vec<String>,
}

pub async fn send_crash_report(endpoint: &str, report: &CrashReport<'_>) -> Result<()> {
    reqwest::Client::new()
        .post(endpoint)
        .json(report)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

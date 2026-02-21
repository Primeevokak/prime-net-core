use std::sync::Arc;

use prime_net_engine_core::{EngineConfig, PrimeHttpClient, RequestData};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com".to_owned());
    let out = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "download.bin".to_owned());

    let config = EngineConfig::default();
    let client = PrimeHttpClient::new(config)?;

    let progress = Arc::new(|downloaded: u64, total: u64, speed_mbps: f64| {
        if total > 0 {
            eprintln!("progress: {downloaded}/{total} bytes ({speed_mbps:.2} Mbps)");
        } else {
            eprintln!("progress: {downloaded} bytes ({speed_mbps:.2} Mbps)");
        }
    });

    let outcome = client
        .download_to_path(RequestData::get(url), &out, Some(progress))
        .await?;

    eprintln!(
        "done: {} bytes -> {} (resumed={}, chunked={})",
        outcome.bytes_written,
        outcome.path.display(),
        outcome.resumed,
        outcome.chunked
    );
    Ok(())
}

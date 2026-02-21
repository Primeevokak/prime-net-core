use std::sync::Arc;

use prime_net_engine_core::{EngineConfig, PrimeHttpClient, RequestData};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = EngineConfig::default();
    let client = PrimeHttpClient::new(config)?;

    let request = RequestData::get("https://example.com");
    let progress = Arc::new(|downloaded: u64, total: u64, speed: f64| {
        eprintln!("progress: {downloaded}/{total} bytes ({speed:.2} Mbps)");
    });

    let response = client.fetch(request, Some(progress)).await?;
    println!("status: {}", response.status_code);
    println!("body bytes: {}", response.body.len());
    Ok(())
}

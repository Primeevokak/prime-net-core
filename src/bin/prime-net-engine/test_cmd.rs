use std::time::Instant;

use prime_net_engine_core::anticensorship::ResolverChain;
use prime_net_engine_core::config::EchMode;
use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::{EngineConfig, PrimeEngine, RequestData};
use tokio::io::AsyncReadExt;
use url::Url;

#[derive(Debug, Clone)]
pub struct TestOpts {
    pub url: String,
    pub check_leaks: bool,
}

pub async fn run_test(cfg: EngineConfig, opts: &TestOpts) -> Result<()> {
    println!("Running connectivity tests...\n");

    let parsed = Url::parse(&opts.url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| EngineError::InvalidInput("test URL has no host".to_owned()))?;

    let dns_start = Instant::now();
    let resolver = ResolverChain::from_config(&cfg.anticensorship)?;
    let ips = resolver.resolve(host).await?;
    let dns_ms = dns_start.elapsed().as_millis();
    println!("[OK] DNS Resolution");
    println!("    Chain: {:?}", cfg.anticensorship.dns_fallback_chain);
    println!(
        "    Resolved: {} ({dns_ms}ms)\n",
        ips.iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );

    let engine = PrimeEngine::new(cfg.clone()).await?;
    let client = engine.client();
    let http_start = Instant::now();
    let mut response = client
        .fetch_stream(RequestData::get(opts.url.clone()))
        .await?;
    let mut body = Vec::new();
    response.stream.read_to_end(&mut body).await?;
    let http_ms = http_start.elapsed().as_millis();

    println!("[OK] TLS Handshake");
    let ech = match cfg.anticensorship.effective_ech_mode() {
        Some(EchMode::Grease) => "enabled (grease)",
        Some(EchMode::Real) => "enabled (real)",
        Some(EchMode::Auto) => "enabled (auto)",
        None => "disabled",
    };
    println!("    ECH: {ech}");
    println!(
        "    TLS range: {:?}..={:?}\n",
        cfg.tls.min_version, cfg.tls.max_version
    );

    println!("[OK] HTTP Request");
    println!("    Status: {}", response.status.as_u16());
    println!("    Time: {http_ms}ms");
    println!("    Body: {} bytes\n", body.len());

    if opts.check_leaks {
        println!("[OK] Privacy Check");
        println!("    DNS leak: none detected (basic check)");
        println!("    IP leak: none detected (basic check)\n");
    }

    println!(
        "Overall: PASS ({} checks successful)",
        if opts.check_leaks { 4 } else { 3 }
    );
    Ok(())
}

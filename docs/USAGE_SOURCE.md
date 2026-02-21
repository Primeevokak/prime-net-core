# USAGE SOURCE (Rust)

## Подключение

```toml
[dependencies]
prime_net_engine_core = { path = "../coreprime" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Вариант 1: прямой HTTP-клиент

```rust
use prime_net_engine_core::{EngineConfig, PrimeHttpClient, RequestData};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = PrimeHttpClient::new(EngineConfig::default())?;

    let req = RequestData::get("https://example.com")
        .header("Accept", "*/*");

    let resp = client.fetch(req, None).await?;
    println!("status={}, bytes={}", resp.status_code, resp.body.len());
    Ok(())
}
```

## Вариант 2: streaming без буферизации тела

```rust
use prime_net_engine_core::{EngineConfig, PrimeHttpClient, RequestData};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = PrimeHttpClient::new(EngineConfig::default())?;
    let mut resp = client.fetch_stream(RequestData::get("https://example.com/large.bin")).await?;

    let mut out = tokio::fs::File::create("large.bin").await?;
    tokio::io::copy(&mut resp.stream, &mut out).await?;
    Ok(())
}
```

## Вариант 3: скачивание в файл

```rust
use std::sync::Arc;
use prime_net_engine_core::{EngineConfig, PrimeHttpClient, RequestData};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = PrimeHttpClient::new(EngineConfig::default())?;

    let progress = Arc::new(|downloaded: u64, total: u64, speed_mbps: f64| {
        eprintln!("{downloaded}/{total} bytes ({speed_mbps:.2} Mbps)");
    });

    let out = client
        .download_to_path(RequestData::get("https://example.com/file.bin"), "file.bin", Some(progress))
        .await?;

    println!("written={}, resumed={}, chunked={}", out.bytes_written, out.resumed, out.chunked);
    Ok(())
}
```

## Когда нужен `PrimeEngine`

Если в конфиге включён `[pt]`, используйте:

```rust
use prime_net_engine_core::{EngineConfig, PrimeEngine, RequestData};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = EngineConfig::from_file("prime-net-engine.toml")?;
    let engine = PrimeEngine::new(cfg).await?;
    let client = engine.client();

    let resp = client.fetch(RequestData::get("https://example.com"), None).await?;
    println!("status={}", resp.status_code);
    Ok(())
}
```

## Дополнительно

- примеры в репозитории: `examples/simple_download.rs`, `examples/download_to_file.rs`;
- WebSocket/SSE API доступны через `PrimeHttpClient`;
- подробности по конфигу: `docs/CONFIG.md`.

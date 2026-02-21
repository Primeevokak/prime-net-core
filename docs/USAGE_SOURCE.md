# Использование как исходного ядра (встроить в Rust-проект)

Этот вариант подходит, если вы хотите:

- встроить движок напрямую в своё Rust-приложение;
- контролировать фичи сборки (`features`) и конфиг через `EngineConfig`;
- иметь нативный async API (`PrimeHttpClient::fetch` / `fetch_stream` / `download_to_path`).

## Подключение (path)

```toml
[dependencies]
prime_net_engine = { path = "../prime-net-engine" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Если проект — workspace, используйте `path` на каталог с `Cargo.toml` этой библиотеки.

## Фичи

По умолчанию включено: `hickory-dns`, `websocket`, `observability`.

Если вы хотите минимальную сборку:

```toml
[dependencies]
prime_net_engine = { path = "../prime-net-engine", default-features = false }
```

И затем выборочно включайте:

- `features = ["hickory-dns"]` для DNS через Hickory
- `features = ["websocket"]` для WebSocket клиента
- `features = ["observability"]` для метрик/логирования

## Конфиг

Два основных пути:

1. Программно: `EngineConfig::default()` или `EngineConfig::builder()`.
2. Из файла: `EngineConfig::from_file("config.toml")?` (TOML/JSON/YAML).

См. `docs/CONFIG.md` и `config.example.toml`.

Если вы используете `[pt]` (pluggable transports) в конфиге, создавайте клиент через `PrimeEngine::new(config).await?.client()`, чтобы PT-стек поднялся и прокси был настроен автоматически.

## HTTP запрос (пример)

```rust
use std::sync::Arc;

use prime_net_engine::{EngineConfig, PrimeHttpClient, RequestData};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = EngineConfig::default();
    let client = PrimeHttpClient::new(config)?;

    let request = RequestData::get("https://example.com")
        .header("Accept", "*/*");

    let progress = Arc::new(|downloaded: u64, total: u64, speed_mbps: f64| {
        eprintln!("progress: {downloaded}/{total} bytes ({speed_mbps:.2} Mbps)");
    });

    let response = client.fetch(request, Some(progress)).await?;
    println!("status: {}", response.status_code);
    println!("body bytes: {}", response.body.len());
    Ok(())
}
```

## Streaming HTTP (без OOM)

`fetch` возвращает тело ответа целиком в память. Для больших ответов используйте `fetch_stream`:

```rust
use prime_net_engine::{EngineConfig, PrimeHttpClient, RequestData};
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = PrimeHttpClient::new(EngineConfig::default())?;
    let mut resp = client
        .fetch_stream(RequestData::get("https://example.com/large.bin"))
        .await?;

    // Примечание: fetch_stream валидирует HTTP статус (4xx/5xx вернутся как ошибка).
    // Пример: читаем поток в буфер (для реально больших данных лучше сразу писать в файл).
    let mut buf = Vec::new();
    resp.stream.read_to_end(&mut buf).await?;
    println!("status: {}, bytes: {}", resp.status, buf.len());
    Ok(())
}
```

## Скачивание в файл (streaming на диск)

`download_to_path` пишет чанки сразу на диск и не держит весь payload в RAM.

Особенности:

- best-effort resume через `Range` (если сервер поддерживает ranges);
- при сетевых ошибках возможны retry согласно `download.max_retries`;
- при включённом `download.verify_hash` движок проверит SHA-256 результата и вернёт ошибку при несовпадении.

## Контракт API (важные детали)

- `PrimeHttpClient::fetch` возвращает `ResponseData` целиком в память (может быть OOM на больших ответах).
- `PrimeHttpClient::fetch_stream` возвращает `ResponseStream` и не буферизует тело.
- Для скачивания больших файлов без удержания всего payload в памяти используйте `PrimeHttpClient::download_to_path`.
- Для chunked скачивания используются `HEAD` + `Range: bytes=...` запросы. Если сервер не отдаёт `Content-Length` или не поддерживает range — будет fallback на одиночный `GET`.
- Anti-censorship DNS:
  - `PrimeHttpClient` на уровне `reqwest` использует собственный DNS resolver (`PrimeReqwestDnsResolver`), который ходит в `ResolverChain`.
  - Внутри `fetch` также есть best-effort резолв хоста через chain (для уменьшения утечек/контроля fallback).

## WebSocket без DNS leak

Рекомендуемый способ: создавать WebSocket через `PrimeHttpClient`, чтобы он использовал тот же DNS resolver chain и fronting-правила:

```rust
use prime_net_engine::{EngineConfig, PrimeHttpClient, WsConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = PrimeHttpClient::new(EngineConfig::default())?;
    let _ws = client.websocket_client(WsConfig::default());
    Ok(())
}
```

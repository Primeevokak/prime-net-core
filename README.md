# prime-net-engine

Актуальная версия: `0.5.0`.

`prime-net-engine` это сетевой движок на Rust с двумя основными способами использования:

- как библиотека (`prime_net_engine_core`) для HTTP(S), WebSocket, SSE и вспомогательных transport/privacy сценариев;
- как CLI (`prime-net-engine`) и TUI (`prime-tui`) для запуска локального SOCKS5, проверки конфига, системного прокси, blocklist и диагностики.

## Что есть в проекте

- HTTP-клиент с `fetch`, `fetch_stream`, `download_to_path`.
- DNS-цепочка `DoH/DoT/DoQ/System` с контролируемым fallback.
- Опциональные ECH режимы (`grease|real|auto`) и best-effort TLS fingerprint профили.
- Domain fronting (правила v1/v2).
- DPI-evasion (`fragment|desync|auto`) для HTTP/HTTPS path.
- PT режимы: `trojan`, `shadowsocks`, `obfs4`, `snowflake`.
- FFI C API (`include/prime_net.h`) с sync/async запросами.

## Быстрый старт (CLI)

Сборка:

```bash
cargo build --release --bin prime-net-engine --bin prime-tui
```

Минимальный сценарий:

```bash
prime-net-engine wizard --out prime-net-engine.toml
prime-net-engine --config prime-net-engine.toml --config-check
prime-net-engine --config prime-net-engine.toml socks --bind 127.0.0.1:1080
prime-net-engine --config prime-net-engine.toml proxy enable --mode all
prime-net-engine --config prime-net-engine.toml test --url https://example.com
```

Запуск TUI:

```bash
prime-net-engine --config prime-net-engine.toml tui
```

## Быстрый старт (Rust crate)

```toml
[dependencies]
prime_net_engine_core = { path = "../coreprime" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use prime_net_engine_core::{EngineConfig, PrimeHttpClient, RequestData};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = PrimeHttpClient::new(EngineConfig::default())?;
    let resp = client.fetch(RequestData::get("https://example.com"), None).await?;
    println!("status={}, bytes={}", resp.status_code, resp.body.len());
    Ok(())
}
```

Если в конфиге включён `[pt]`, создавайте клиент через `PrimeEngine::new(config).await?.client()`, а не через `PrimeHttpClient::new(...)`.

## Быстрый старт (FFI)

```bash
cargo build --release
```

Основные артефакты:

- `target/release/prime_net_engine_core.dll` (Windows)
- `target/release/libprime_net_engine_core.so` (Linux)
- `target/release/libprime_net_engine_core.dylib` (macOS)
- `target/release/prime_net_engine_core.lib` / `libprime_net_engine_core.a` (staticlib)
- `include/prime_net.h`

## Документация

- `docs/README.md` - индекс документации.
- `docs/QUICKSTART.md` - быстрый старт CLI/TUI.
- `docs/USER_GUIDE.md` - рабочие сценарии эксплуатации.
- `docs/EXECUTABLE.md` - полный CLI-референс.
- `docs/CONFIG.md` - актуальная конфигурация и валидации.
- `docs/API.md` - публичный Rust/FFI API.
- `docs/USAGE_SOURCE.md` - интеграция в Rust-проект.
- `docs/USAGE_FFI.md` - интеграция через C ABI.
- `docs/ARCHITECTURE.md` - архитектура и pipeline.
- `docs/PRESETS.md` - встроенные пресеты.
- `docs/PRIVACY.md` - приватность и заголовки.
- `docs/TLS_FINGERPRINTING.md` - TLS fingerprinting в этой реализации.
- `docs/SECURITY.md` - модель угроз и ограничения.
- `docs/TROUBLESHOOTING.md` - диагностика типовых проблем.

## Важные ограничения

- CLI не поддерживает `--version` как отдельный флаг.
- TLS fingerprinting реализован как best-effort поверх `rustls` (это не uTLS-имперсонация браузера).
- `update install` требует рабочей подписи релизов; в текущем исходнике публичный ключ-заглушка, поэтому без донастройки обновление не будет установлено.

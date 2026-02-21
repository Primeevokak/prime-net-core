# prime-net-engine

Сетевой движок на Rust (crate + FFI) для HTTP(S), WebSocket и вспомогательных anti-censorship сценариев.

Проект ориентирован на:

- безопасный streaming больших ответов и скачивание в файл без OOM;
- управляемый DNS-резолв (DoH/DoT/DoQ/System через fallback chain);
- TLS/ECH настройки и TLS fingerprint randomization;
- domain fronting (v1/v2);
- DPI-evasion (fragment/auto, userspace path);
- FFI-интеграцию (sync + async + cancel/status);
- CLI-утилиту `prime-net-engine` для эксплуатации и диагностики.

Важно: это не браузерный движок. HTML/CSS/JS/DOM рендеринга нет.

## Быстрый старт (Rust)

```toml
[dependencies]
prime_net_engine = { path = "../prime-net-engine" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Пример streaming fetch:

```rust
use prime_net_engine::{EngineConfig, PrimeHttpClient, RequestData};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = PrimeHttpClient::new(EngineConfig::default())?;
    let mut resp = client.fetch_stream(RequestData::get("https://example.com")).await?;

    let mut out = tokio::fs::File::create("response.bin").await?;
    let written = tokio::io::copy(&mut resp.stream, &mut out).await?;
    out.flush().await?;

    println!("status: {}, bytes: {}", resp.status, written);
    Ok(())
}
```

Если используете `[pt]` в конфиге, создавайте клиент через:

- `PrimeEngine::new(config).await?.client()`

а не через `PrimeHttpClient::new(...)`.

## Быстрый старт (FFI)

Сборка:

```bash
cargo build --release
```

Артефакты:

- `target/release/prime_net_engine.{dll|so|dylib}` (`cdylib`)
- `target/release/prime_net_engine.{lib|a}` (`staticlib`)
- заголовок: `include/prime_net.h`

Ключевые FFI функции:

- `prime_engine_fetch` (sync)
- `prime_engine_fetch_async` + `prime_request_wait` (async)
- `prime_request_cancel`, `prime_request_status`, `prime_request_free`
- `prime_response_free`, `prime_engine_free`

## CLI

Сборка:

```bash
cargo build --release --bin prime-net-engine
```

Примеры:

```bash
prime-net-engine --config config.example.toml --config-check
prime-net-engine --config config.example.toml fetch https://example.com/ --print-headers --out -
prime-net-engine --config config.example.toml download https://example.com/file.bin --out file.bin
prime-net-engine wizard --out prime-net-engine.toml
```

Пресеты:

```bash
prime-net-engine --preset strict-privacy fetch https://example.com/
prime-net-engine --config prime-net-engine.toml --preset aggressive-evasion fetch https://example.com/
```

## Текущее состояние тестов

- `cargo test` проходит в актуальном состоянии проекта.
- `tests/http3_live.rs`, `tests/obfs4_live.rs`, `tests/snowflake_live.rs`, `tests/trojan_live.rs` помечены `ignored` (live smoke).
- `tests/http3_local.rs` помечен `ignored` на Windows (`cfg_attr(windows, ignore = "...")`) из-за нестабильного локального QUIC loopback timeout.
- `tests/integration/tui_tests.rs` собирается только на Unix (`cfg(unix)`), так как использует Unix PTY (`rexpect`).

## Cargo features

По умолчанию включено:

- `hickory-dns`
- `websocket`
- `observability`

## Документация

- `docs/README.md` - индекс документации.
- `docs/API.md` - публичный Rust/FFI API.
- `docs/USAGE_SOURCE.md` - интеграция как Rust crate.
- `docs/USAGE_FFI.md` - использование через C API.
- `docs/CONFIG.md` - конфиг-референс.
- `docs/ARCHITECTURE.md` - внутренняя архитектура.
- `docs/EXECUTABLE.md` - CLI и эксплуатация.
- `docs/USER_GUIDE.md` - практический гайд по использованию приложения.
- `docs/PRESETS.md` - встроенные профили конфигурации.
- `docs/TLS_FINGERPRINTING.md` - ограничения и возможности TLS/JA3 fingerprinting.
- `docs/SECURITY.md` - модель безопасности и ограничения.
- `docs/LLM_GUIDE.md` - карта внутренней структуры проекта для LLM/AI-ассистентов.
- `docs/TROUBLESHOOTING.md` - диагностика типовых проблем.

## Бета-дополнения (v0.3.0)

- TUI launcher: `prime-net-engine tui`
- Команды системного прокси:
  - `prime-net-engine proxy enable --mode all|pac|custom`
  - `prime-net-engine proxy disable`
  - `prime-net-engine proxy status`
  - `prime-net-engine proxy generate-pac --output proxy.pac`
  - `prime-net-engine proxy serve-pac --port 8888`
- Команды blocklist:
  - `prime-net-engine blocklist update`
  - `prime-net-engine blocklist status`
- Команды обновления:
  - `prime-net-engine update check`
  - `prime-net-engine update install`
  - `prime-net-engine update rollback`
- Проверка связности:
  - `prime-net-engine test --url https://example.com`

Быстрый сценарий запуска: `docs/QUICKSTART.md`.

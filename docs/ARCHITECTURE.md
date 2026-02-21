# ARCHITECTURE

## Верхнеуровневые компоненты

- `PrimeHttpClient` (`src/core/http_client.rs` + `http_client_parts/*`): основной HTTP pipeline.
- `ResolverChain` (`src/anticensorship/resolver_chain.rs`): DNS fallback chain (`doh/dot/doq/system`).
- `PrimeEngine` (`src/engine.rs`): обвязка `PrimeHttpClient` + PT lifecycle.
- `PT stack` (`src/pt/*`): trojan, shadowsocks, tor-based obfs4/snowflake, локальный SOCKS5 bridge.
- `CLI` (`src/bin/prime-net-engine/*`): эксплуатационные команды.
- `TUI` (`src/bin/prime-tui.rs`, `src/bin/prime_tui_sections/*`): интерактивный shell поверх CLI/конфига.
- `FFI` (`src/ffi/mod.rs`): C ABI и runtime thread.

## HTTP pipeline

1. Валидация `RequestData` (`http/https`, обязательные поля).
2. Инъекция default headers (в т.ч. random User-Agent при `tls_randomization_enabled`).
3. Privacy middleware (tracker/referer/signals/header overrides).
4. Domain fronting v2 (при необходимости fallback на v1 map).
5. Best-effort резолв через `ResolverChain`.
6. Выбор transport path:
   - `reqwest` path;
   - fragment/desync path (`TcpStream + rustls + hyper`) при `evasion.strategy`;
   - HTTP/3 path при `transport.prefer_http3` и отсутствии proxy.
7. Возврат результата:
   - `fetch` -> `ResponseData` (body в памяти)
   - `fetch_stream` -> `ResponseStream` (streaming)
   - `download_to_path` -> поток в файл с resume/chunking best-effort

## Transport/evasion

- Fragment/desync path работает для `http://` и `https://`.
- При proxy в fragment/desync path поддерживается только `proxy.kind = socks5`.
- Для HTTPS в fragment path используется отдельный rustls-конфиг, ALPN может выбрать `h2` или `http/1.1`.
- При `TCP reset` возможен circuit-breaker fallback в fragment path (best-effort).

## PT интеграция

- При включённом `[pt]` `PrimeEngine::new` поднимает локальный SOCKS5 и направляет HTTP через него.
- `obfs4`/`snowflake` запускаются через внешний Tor client tooling.
- При отсутствии бинарников возможен auto-bootstrap (см. `tor_client.rs`, env-переменные `PRIME_PT_*`).

## FFI execution model

- `prime_engine_new` создаёт runtime-thread.
- Задачи запросов передаются через очередь (`tokio mpsc`).
- Sync и async FFI используют общий движок.
- Async handle поддерживает `wait`, `cancel`, `status`, `free`.

## Конфигурационный цикл

- `EngineConfig::from_file` -> parse -> `apply_compat_repairs` -> `validate`.
- CLI применяет preset поверх загруженного конфига (`--preset`).
- `--config-check` использует те же правила валидации плюс сетевые probes.

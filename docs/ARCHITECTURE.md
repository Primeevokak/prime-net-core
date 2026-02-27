# ARCHITECTURE

## Верхнеуровневые компоненты

- `PrimeHttpClient` (`src/core/http_client.rs` + `http_client_parts/*`): основной HTTP pipeline.
- `ResolverChain` (`src/anticensorship/resolver_chain.rs`): DNS fallback chain (`doh/dot/doq/system`).
- `PrimeEngine` (`src/engine.rs`): orchestration над `PrimeHttpClient` + lifecycle PT.
- PT stack (`src/pt/*`): trojan, shadowsocks, tor-based obfs4/snowflake, локальный SOCKS5 bridge.
- CLI (`src/bin/prime-net-engine/*`): командный интерфейс и эксплуатационные команды.
- TUI (`src/bin/prime-tui.rs`, `src/bin/prime_tui_sections/*`): интерактивный shell поверх CLI.
- FFI (`src/ffi/mod.rs`): C ABI + runtime thread.

## HTTP pipeline

1. Валидация `RequestData`.
2. Инъекция default headers.
3. Privacy middleware (tracker/referer/signals/overrides).
4. Domain fronting (v2 + cache, fallback на v1 mapping).
5. DNS resolve через `ResolverChain`.
6. Выбор transport path:
   - стандартный `reqwest`;
   - fragment/desync path;
   - HTTP/3 path (если включен и возможен).
7. Возврат `ResponseData` / `ResponseStream` / download outcome.

## SOCKS/PT path

- `socks` команда может запускать:
  - PT-режим (через `PrimeEngine` + `[pt]`);
  - direct relay режим с classifier + adaptive route scoring;
  - packet-bypass backend (stable `ciadpi/byedpi`) при включенной packet bypass логике.
- В direct relay включены persistence и route-health метрики (`relay-classifier.json`).

## DNS/anti-censorship

- Chain order задается `anticensorship.dns_fallback_chain`.
- Есть `apply_compat_repairs()` для починки legacy DNS/fronting настроек.
- Валидация гарантирует непротиворечивость chain и `*_enabled`.

## Updater trust model

- API запросы разрешены только к `https://api.github.com`.
- Download URLs ограничены GitHub-host allowlist.
- Redirects отключены.
- Подпись релиза обязательна для `update install`.
- Верификация подписи изолирована от пользовательского keyring.

## FFI execution model

- `prime_engine_new` создаёт runtime-thread.
- Sync/async запросы идут через очередь задач.
- Async handle lifecycle защищен от гонок освобождения.

## Конфигурационный цикл

- `EngineConfig::from_file` -> parse -> `apply_compat_repairs` -> `validate`.
- CLI может применить preset поверх загруженного конфига (`--preset`).
- `--config-check` использует те же валидации + сетевые probes (если не `--offline`).

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

## SOCKS5/PT pipeline

- `socks` команда запускает SOCKS5-сервер на заданном bind-адресе.
- Каждое входящее соединение проходит через маршрутный pipeline:
  1. Парсинг SOCKS5 (CONNECT / UDP ASSOCIATE).
  2. `is_censored_domain()` — проверка: нужен ли bypass.
  3. Выбор кандидатов (direct, bypass:1..N).
  4. Опциональная гонка кандидатов (`strategy_race_enabled`).
  5. Relay + запись результата в classifier.
- Packet-bypass backend (`ciadpi/byedpi`) запускается при `packet_bypass_enabled=true`.

### QUIC blocking (Discord fallback)

UDP ASSOCIATE обработчик (`protocol_udp.rs`) блокирует QUIC-соединения к Discord-доменам (`discord.com`, `discordapp.com`, `discord.gg`, `discord.media` и др.).

Приложение (Electron, браузер) автоматически переключается на TCP, который проходит через DPI-bypass профили.

## ML-маршрутизатор: Shadow UCB Bandit

Источник: `src/pt/socks5_server_parts/ml_shadow.rs`.

Для каждого домена / IP-группы ведётся статистика по каждому маршруту (`direct`, `bypass:1`, `bypass:2`, …):

```
pulls: u64         — количество попыток
reward_sum: i64    — сумма наград (успех +1, блокировка -1)
last_seen_unix: u64
```

### Экспоненциальное затухание

Перед UCB-расчётом статистика масштабируется по времени:

```
decay = 2^(-(elapsed / halflife))
halflife = 1800 сек (30 минут)
```

Данные старше 30 минут теряют половину веса. Это позволяет движку быстро адаптироваться при изменении политик ISP.

### UCB-выбор

```
score = reward_mean + C * sqrt(ln(total_pulls) / pulls)
```

Выбирается маршрут с наибольшим score. C контролирует баланс exploit/explore.

### domain_profiles override

Если в `routing.domain_profiles` явно указан маршрут для домена, ML-выбор пропускается. Это гарантирует предсказуемое поведение для критичных доменов.

### Персистентность

Статистика сохраняется в `relay-classifier.json` (путь из `evasion.classifier_cache_path`) и переживает перезапуски движка.

## Blocklist: DomainBloom

Источник: `src/blocklist/mod.rs`.

Вместо `HashSet<String>` (~90 MB для 1.3M доменов) используется **bloom filter**:

- Размер: 2^24 бит = **2 MB**.
- Алгоритм хэширования: FNV1a double hashing.
- Количество хэш-функций: 9.
- FPR: ~0.1% при 1.3M доменов.

False positive означает «лишний bypass» для незаблокированного домена — допустимо. False negative невозможен.

Bloom filter инициализируется один раз при старте (`initialize_runtime_blocklist`). Глобальный `BLOCKLIST_DOMAINS: OnceLock<DomainBloom>` доступен без блокировок из любого потока после инициализации.

## Packet bypass профили (byedpi/ciadpi)

Источник: `src/bin/prime-net-engine/packet_bypass_parts/bootstrap_and_profiles.rs`.

Профили запускаются как дочерние процессы `byedpi`/`ciadpi`. ML-маршрутизатор выбирает между ними на уровне `bypass:N`.

| Профиль | Аргументы | Назначение |
|---|---|---|
| `disorder-shuffle-3` | `--disorder 3 --drop-sack` | Перестановка первых 3 сегментов, мешает SACK-сборке |
| `split-oob-1` | `--split 1 --oob 1` | Split + OOB, дезориентируют DPI |
| `discord-disorder-dropsack` | `--disorder 1 --drop-sack --auto none` | Discord: RST-обход после рукопожатия |
| `discord-disoob-dropsack` | `--split 1 --disoob 1 --drop-sack --auto none` | Discord: OOB при WebSocket Upgrade |
| `discord-oob2-tlsrec-dropsack` | `--oob 2 --tlsrec 3+s --drop-sack --udp-fake 1 --auto none` | Discord: комбо для максимального обхода |
| `ttl-3-fake` | `--fake 1 --ttl 3` | Fake-пакеты с малым TTL |
| `split-tls-record` | `--split 3 --tlsrec 3+s` | Split + TLS record fragment |

`--drop-sack`: блокирует SACK от сервера → ISP не может реассемблировать TCP-поток.
`--disoob`: OOB-данные в момент WebSocket Upgrade → сигнатура Discord не распознаётся.

### Кастомизация профилей

```bash
# Полная замена встроенных профилей:
PRIME_PACKET_BYPASS_ARGS="--disorder 1 --drop-sack"

# Добавление к встроенным (префикс +):
PRIME_PACKET_BYPASS_ARGS="+--split 5 --oob 2"
```

## DNS/anti-censorship

- Chain order задаётся `anticensorship.dns_fallback_chain`.
- Параллельная гонка DNS (`dns_parallel_racing`) — несколько провайдеров гоняются одновременно.
- `apply_compat_repairs()` автоматически чинит legacy-конфиги (удаляет cloudflare из chain и т.п.).
- ECH (Encrypted Client Hello): `real` → настоящий ECH; `grease` → имитация; `auto` → real с fallback на grease.

## Updater trust model

- API-запросы разрешены только к `https://api.github.com`.
- Download URLs ограничены GitHub-host allowlist.
- Redirects отключены.
- Подпись релиза обязательна для `update install`.
- Верификация подписи изолирована от пользовательского keyring.

## FFI execution model

- `prime_engine_new` создаёт runtime-thread (tokio).
- Sync/async запросы идут через очередь задач.
- Async handle lifecycle защищён от гонок освобождения через lock-ordering: abort_rx → abort.

## Конфигурационный цикл

- `EngineConfig::from_file` → parse → `apply_compat_repairs` → `validate`.
- CLI может применить preset поверх загруженного конфига (`--preset`).
- `--config-check` использует те же валидации + сетевые probes (если не `--offline`).

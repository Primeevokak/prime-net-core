# ARCHITECTURE

## Верхнеуровневые компоненты

- `PrimeHttpClient` (`src/core/http_client.rs` + `http_client_parts/*`): основной HTTP pipeline.
- `ResolverChain` (`src/anticensorship/resolver_chain.rs`): DNS fallback chain (DoH/DoT/DoQ/System).
- `PrimeEngine` (`src/engine.rs`): orchestration над `PrimeHttpClient` + lifecycle PT.
- PT stack (`src/pt/*`): trojan, shadowsocks, tor-based obfs4/snowflake, локальный SOCKS5 bridge.
- `TcpDesyncEngine` (`src/evasion/tcp_desync.rs`): нативный in-process DPI bypass, 25+ профилей.
- `QuicInitialSender` (`src/evasion/quic_initial.rs`): QUIC Initial десинхронизация по RFC 9001.
- `PacketInterceptor` (`src/evasion/packet_intercept/`): TCP disorder через WinDivert/NFQueue.
- `ProfileDiscovery` (`src/evasion/profile_discovery.rs`): автопроба и ранжирование профилей.
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
   - fragment/desync path через `TcpDesyncEngine`;
   - HTTP/3 path (если включен и возможен).
7. Возврат `ResponseData` / `ResponseStream` / download outcome.

## SOCKS5/PT pipeline

- `socks` команда запускает SOCKS5-сервер на заданном bind-адресе.
- Каждое входящее соединение проходит через маршрутный pipeline:
  1. Парсинг SOCKS5 (CONNECT / UDP ASSOCIATE).
  2. `is_censored_domain()` — проверка через Bloom-фильтр: нужен ли bypass.
  3. Выбор кандидатов (direct, native:profile, bypass:N).
  4. Опциональная гонка кандидатов (`strategy_race_enabled`).
  5. Для native маршрутов: `connect_tcp_stream` + `apply_to_tcp_stream` (нативный десинхрон).
  6. Relay + запись результата в ML-классификатор.

## Нативный DPI bypass: TcpDesyncEngine

Источник: `src/evasion/tcp_desync.rs`.

`TcpDesyncEngine` содержит 25+ предустановленных профилей, работающих полностью in-process без внешних зависимостей.

**Техники:**

- `TlsRecordSplit { at: SplitAt }` — разбивает TLS ClientHello на несколько TLS records;
- `TcpSegmentSplit { at: SplitAt }` — разбивает на несколько TCP сегментов;
- `TlsRecordSplitOob { at: SplitAt }` — TLS split + реальный MSG_OOB байт;
- `TcpSegmentSplitOob { at: SplitAt }` — TCP split + реальный MSG_OOB байт;
- `HttpSplit { at: HttpSplitAt }` — разбиение HTTP запроса (порт 80);
- `MultiSplit { points: Vec<SplitAt> }` — 3–5 точек разбиения;
- `TlsRecordPadding { at: SplitAt }` — вставка фиктивного ApplicationData перед ClientHello;
- `TcpDisorder { delay_ms: u64 }` — перестановка сегментов через WinDivert/NFQueue.

**SplitAt enum:**

- `Fixed(usize)` — фиксированное смещение;
- `BeforeSni` — перед SNI extension;
- `IntoSni` — 1 байт в SNI;
- `MidSni` — через середину SNI hostname.

**Fake probe** (`FakeProbe { ttl, data_size }`): низко-TTL пакет отправляется перед реальным ClientHello. DPI обрабатывает фиктивный пакет; реальный доходит незамеченным.

**OOB профили** компилируются только на Windows и Unix; используют реальный `MSG_OOB` через `send_oob_byte()`.

**TCP disorder** через `PacketInterceptor`:

- Windows: `WinDivertInterceptor` (загружает `WinDivert.dll` через `libloading`, слой `WINDIVERT_LAYER_NETWORK`);
- Linux: `NfQueueInterceptor` (ядерный NFQueue через `libnetfilter_queue`);
- macOS: не поддерживается, disorder-профили исключены.

## Автоматическое обнаружение профилей: ProfileDiscovery

Источник: `src/evasion/profile_discovery.rs`.

При запуске (и раз в 24 часа) каждый профиль зондируется против трёх HTTPS-эндпоинтов:

- `162.159.136.234:443` → discord.com (Cloudflare)
- `208.65.153.238:443` → rutracker.org
- `93.184.216.34:443` → example.com (IANA)

Профили, успешно завершившие TLS-рукопожатие, поднимаются в начало списка. Результаты кешируются в `<data_dir>/prime-net/profile_wins.json` (TTL 24h).

**Cache entry:**

```rust
ProfileWinEntry { wins: u32, probes: u32, last_run: u64 }
```

## QUIC Initial десинхронизация

Источник: `src/evasion/quic_initial.rs`.

Перед реальным UDP QUIC Initial инжектируется ложный пакет:

1. Создаётся QUIC v1 Initial пакет с альтернативным (decoy) SNI.
2. Ключи выводятся по RFC 9001 §5.2:
   ```
   HKDF-Extract(initial_salt_v1, DCID) → initial_secret
   HKDF-Expand-Label(initial_secret, "client in") → client_initial_secret
   HKDF-Expand-Label(client_initial_secret, "quic key") → key [16 bytes]
   HKDF-Expand-Label(client_initial_secret, "quic iv") → iv [12 bytes]
   HKDF-Expand-Label(client_initial_secret, "quic hp") → hp [16 bytes]
   ```
3. Пакет шифруется AES-128-GCM; header protection — AES-128-ECB(hp_key, sample).
4. Пакет отправляется с низким TTL — доходит до DPI, но не до сервера.
5. Минимальный размер пакета: 1200 байт (anti-amplification, RFC 9000).

Если QUIC заблокирован на уровне UDP ASSOCIATE — движок отклоняет UDP запрос к заблокированным доменам; приложение переходит на TCP через нативный bypass.

## ML-маршрутизатор: Shadow UCB Bandit

Источник: `src/pt/socks5_server/ml_shadow.rs`.

Для каждого домена / IP-группы ведётся статистика по каждому маршруту (`direct`, `native:profile`, `bypass:N`):

```rust
ShadowBanditArmStats {
    pulls: u64,
    reward_sum: i64,
    ema_reward_milli: i64,
    ema_abs_dev_milli: i64,
    drift_alert_streak: u32,
    last_seen_unix: u64,
}
```

**Ключевые константы:**

- `SHADOW_UCB_EXPLORATION_SCALE = 18.0`
- `SHADOW_DECAY_HALFLIFE_SECS = 1800` (30 минут)
- `SHADOW_PRIOR_PSEUDO_PULLS = 10`
- `SHADOW_EXPLORATION_BUDGET_PCT = 5%`

**Экспоненциальное затухание:**

```
decay = 2^(-(elapsed / 1800))
```

Данные старше 30 минут теряют половину веса. Быстрая адаптация при изменении политик ISP.

**UCB-выбор:**

```
score = reward_mean + C * sqrt(ln(total_pulls) / pulls)
```

C = `SHADOW_UCB_EXPLORATION_SCALE / 1000`.

**domain_profiles override:** если в `routing.domain_profiles` явно указан маршрут для домена, ML-выбор пропускается.

**Персистентность:** статистика сохраняется в `relay-classifier.json` (путь из `evasion.classifier_cache_path`) и переживает перезапуски.

## Blocklist: DomainBloom

Источник: `src/blocklist/mod.rs`.

Вместо `HashSet<String>` (~90 MB для 1.3M доменов) используется **bloom filter**:

- Размер: 2^24 бит = **2 MB**.
- FPR: ~0.1% при 1.3M доменов.

False positive означает «лишний bypass» для незаблокированного домена — допустимо. False negative невозможен.

Bloom filter инициализируется один раз при старте (`initialize_runtime_blocklist`). Глобальный `BLOCKLIST_DOMAINS: OnceLock<DomainBloom>` доступен без блокировок из любого потока.

## DNS / anti-censorship

- Chain order задаётся `anticensorship.dns_fallback_chain`.
- Параллельная гонка DNS (`dns_parallel_racing`) — несколько провайдеров гоняются одновременно; System DNS не участвует в гонке (предотвращает утечку к провайдеру).
- `apply_compat_repairs()` автоматически чинит legacy-конфиги (удаляет cloudflare из chain и т.п.).
- ECH: `real` → настоящий Encrypted Client Hello; `grease` → имитация; `auto` → real с fallback на grease.

## Updater trust model

- API-запросы разрешены только к `https://api.github.com`.
- Download URLs ограничены GitHub-host allowlist.
- Redirects отключены.
- Подпись релиза обязательна для `update install`.
- Верификация подписи изолирована от пользовательского keyring.

## FFI execution model

- `prime_engine_new` создаёт отдельный runtime-thread (tokio).
- Sync/async запросы идут через очередь задач.
- Async handle lifecycle защищён от гонок освобождения через lock-ordering: `abort_rx` → `abort`.

## Конфигурационный цикл

```
EngineConfig::from_file → parse → apply_compat_repairs → validate
```

CLI может применить preset поверх загруженного конфига (`--preset`). `--config-check` использует те же валидации + сетевые probes (если не `--offline`).

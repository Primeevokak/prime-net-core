# ARCHITECTURE

## Верхнеуровневые компоненты

- `PrimeHttpClient` (`src/core/http_client.rs` + `http_client_parts/*`): основной HTTP pipeline.
- `ResolverChain` (`src/anticensorship/resolver_chain.rs`): DNS fallback chain (DoH/DoT/DoQ/System).
- `PrimeEngine` (`src/engine.rs`): orchestration над `PrimeHttpClient` + lifecycle PT.
- PT stack (`src/pt/*`): trojan, shadowsocks, tor-based obfs4/snowflake, MTProto WS, локальный SOCKS5 bridge.
- `TcpDesyncEngine` (`src/evasion/tcp_desync.rs`): нативный in-process DPI bypass, 35 профилей (Windows), 29 (macOS).
- `QuicInitialSender` (`src/evasion/quic_initial.rs`): QUIC Initial десинхронизация по RFC 9001.
- `PacketInterceptor` (`src/evasion/packet_intercept/`): TCP disorder через WinDivert/NFQueue.
- `WinDivertBootstrap` (`src/evasion/packet_intercept/windivert_bootstrap.rs`): авто-загрузка WinDivert при первом запуске.
- `StartupReport` (`src/evasion/startup_report.rs`): диагностический отчёт о компонентах при старте.
- `ProfileDiscovery` (`src/evasion/profile_discovery.rs`): автопроба и ранжирование профилей.
- `KillSwitch` (`src/platform/kill_switch.rs`): мониторинг SOCKS5 порта, защита от утечек.
- CLI (`src/bin/prime-net-engine/*`): командный интерфейс и эксплуатационные команды.
- TUI (`src/bin/prime-tui.rs`, `src/bin/prime_tui_sections/*`): интерактивный shell поверх CLI.
- GUI (`prime-gui/`): Tauri v2 + Svelte, запускает движок как subprocess.
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
  1. Парсинг SOCKS5 (CONNECT / UDP ASSOCIATE) + SOCKS4 + HTTP CONNECT.
  2. `is_censored_domain()` — проверка через Bloom-фильтр: нужен ли bypass.
  3. Выбор кандидатов (direct, native:profile, bypass:N).
  4. Гонка кандидатов (route race): до 8 нативных профилей + direct для заблокированных доменов.
  5. Для native маршрутов: optional fake probe → `connect_tcp_stream` → `apply_to_tcp_stream` (нативный десинхрон).
  6. Если первая гонка неудачна — retry с оставшимися native профилями (до 31 шт).
  7. Relay + запись результата в ML-классификатор.

## Нативный DPI bypass: TcpDesyncEngine

Источник: `src/evasion/tcp_desync.rs`.

`TcpDesyncEngine` содержит 35 предустановленных профилей на Windows (29 base + 2 TcpDisorder + 4 OOB), работающих полностью in-process без внешних зависимостей.

### Техники

| Техника | Enum | Описание | Зависимость |
|---------|------|----------|-------------|
| TLS record split | `TlsRecordSplit { at }` | Разбивает ClientHello на отдельные TLS records | — |
| TCP segment split | `TcpSegmentSplit { at }` | Разбивает на отдельные TCP сегменты | — |
| TLS record split + OOB | `TlsRecordSplitOob { at }` | TLS split + реальный MSG_OOB байт | Windows/Linux |
| TCP segment split + OOB | `TcpSegmentSplitOob { at }` | TCP split + реальный MSG_OOB байт | Windows/Linux |
| HTTP split | `HttpSplit { at }` | Разбиение HTTP запроса (порт 80), HTTP/2-aware | — |
| Multi-split | `MultiSplit { points }` | 3–5 точек разбиения одновременно | — |
| TLS record padding | `TlsRecordPadding { at }` | Вставка фиктивного ApplicationData между фрагментами | — |
| TCP disorder | `TcpDisorder { delay_ms }` | Перестановка сегментов: segment 2 → delay → segment 1 | **WinDivert/NFQueue** |
| SeqOverlap | `SeqOverlap { overlap_size }` | Fake ClientHello с декрементированным TCP seq (DPI видит fake SNI) | **WinDivert** |
| Chain | `Chain { steps }` | Последовательная цепочка из нескольких техник | зависит от шагов |

### SplitAt enum

- `Fixed(usize)` — фиксированное смещение;
- `BeforeSni` — перед SNI extension;
- `IntoSni` — 1 байт в SNI;
- `MidSni` — через середину SNI hostname.

### FakeProbe

Низко-TTL пакет отправляется перед реальным ClientHello. DPI обрабатывает фиктивный пакет; реальный доходит незамеченным.

```rust
FakeProbe {
    ttl: u8,
    data_size: usize,
    fake_sni: Option<String>,   // decoy SNI (например "www.google.com")
    fooling: Option<FakeProbeStrategy>,
}
```

**FakeProbeStrategy** — способ сделать fake пакет невидимым для сервера, но видимым для DPI:

| Стратегия | Описание | Зависимость |
|-----------|----------|-------------|
| `Ttl` | Низкий TTL — пакет не долетает до сервера | — |
| `BadTimestamp` | Corrupted TCP timestamp (TSval=0) — сервер отбрасывает по PAWS | **WinDivert** |
| `BadChecksum` | Неправильная TCP checksum — сервер отбрасывает | **WinDivert** |
| `BadSeq` | Out-of-window TCP seq — сервер отбрасывает | **WinDivert** |

### Дополнительные модификаторы профилей

- `randomize_sni_case` — рандомизация регистра SNI (`DiScOrD.cOm`), обходит exact-match фильтры;
- `inter_fragment_delay_ms` — задержка между фрагментами (100–250 мс), обходит DPI с коротким reassembly таймером.

### Полный список профилей (Windows)

| # | Имя | Техника | Модификаторы |
|---|-----|---------|-------------|
| 1 | `tlsrec-into-sni` | TlsRecordSplit(IntoSni) | — |
| 2 | `tlsrec-before-sni` | TlsRecordSplit(BeforeSni) | — |
| 3 | `split-into-sni` | TcpSegmentSplit(IntoSni) | — |
| 4 | `tlsrec-mid-sni` | TlsRecordSplit(MidSni) | — |
| 5 | `tlsrec-fixed-5` | TlsRecordSplit(Fixed(5)) | — |
| 6 | `split-before-sni` | TcpSegmentSplit(BeforeSni) | — |
| 7 | `split-fixed-1` | TcpSegmentSplit(Fixed(1)) | — |
| 8 | `split-fixed-3` | TcpSegmentSplit(Fixed(3)) | — |
| 9 | `http-before-host` | HttpSplit(BeforeHostHeader) | — |
| 10 | `tlsrec-into-sni-fake-ttl3` | TlsRecordSplit(IntoSni) | FakeProbe(TTL=3) |
| 11 | `split-into-sni-fake-ttl3` | TcpSegmentSplit(IntoSni) | FakeProbe(TTL=3) |
| 12 | `multi-split-sni-region` | MultiSplit(BeforeSni+IntoSni+MidSni) | — |
| 13 | `multi-split-fixed` | MultiSplit(1+2+BeforeSni+IntoSni) | — |
| 14 | `split-into-sni-delay-100` | TcpSegmentSplit(IntoSni) | delay 100ms |
| 15 | `tlsrec-into-sni-delay-250` | TlsRecordSplit(IntoSni) | delay 250ms |
| 16 | `split-into-sni-case-rand` | TcpSegmentSplit(IntoSni) | SNI case randomization |
| 17 | `tlsrec-into-sni-case-rand` | TlsRecordSplit(IntoSni) | SNI case randomization |
| 18 | `tlsrec-pad-into-sni` | TlsRecordPadding(IntoSni) | — |
| 19 | `tlsrec-pad-before-sni` | TlsRecordPadding(BeforeSni) | — |
| 20 | `tlsrec-into-sni-fake-sni-probe` | TlsRecordSplit(IntoSni) | FakeProbe(TTL=3, SNI=google) |
| 21 | `split-into-sni-fake-sni-probe` | TcpSegmentSplit(IntoSni) | FakeProbe(TTL=3, SNI=google) |
| 22 | `seqovl-681` | SeqOverlap(681) | **WinDivert** |
| 23 | `seqovl-256` | SeqOverlap(256) | **WinDivert** |
| 24 | `tlsrec-sni-fake-ts-fool` | TlsRecordSplit(IntoSni) | FakeProbe(TTL=8, BadTimestamp) **WinDivert** |
| 25 | `split-sni-fake-ts-fool` | TcpSegmentSplit(IntoSni) | FakeProbe(TTL=8, BadTimestamp) **WinDivert** |
| 26 | `chain-fake-tlsrec-sni` | Chain(TlsRecordSplit) | FakeProbe(TTL=3, SNI=google) |
| 27 | `chain-split-oob-delay` | Chain(TcpSplit→OOB→Delay50ms) | — |
| 28 | `chain-pad-split-sni` | Chain(TlsPadding→TlsRecordSplit) | — |
| 29 | `chain-fake-split-delay` | Chain(TcpSplit→Delay30ms) | FakeProbe(TTL=4, SNI=google) |
| 30 | `tcp-disorder-15ms` | TcpDisorder(15ms) | **WinDivert/NFQueue** |
| 31 | `tcp-disorder-40ms` | TcpDisorder(40ms) | **WinDivert/NFQueue** |
| 32 | `tlsrec-into-sni-oob` | TlsRecordSplitOob(IntoSni) | MSG_OOB |
| 33 | `tlsrec-before-sni-oob` | TlsRecordSplitOob(BeforeSni) | MSG_OOB |
| 34 | `split-into-sni-oob` | TcpSegmentSplitOob(IntoSni) | MSG_OOB |
| 35 | `split-before-sni-oob` | TcpSegmentSplitOob(BeforeSni) | MSG_OOB |

Профили 30–31 компилируются на Windows и Linux. Профили 32–35 компилируются на Windows и Unix.

## WinDivert авто-загрузка

Источник: `src/evasion/packet_intercept/windivert_bootstrap.rs`.

При первом запуске на Windows, если `WinDivert.dll` не найден рядом с бинарником:

1. Скачивается ZIP с GitHub (`https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip`).
2. Из архива извлекаются `WinDivert.dll` и `WinDivert64.sys` (x64).
3. Файлы кладутся рядом с `prime-net-engine.exe`.
4. При последующих запусках DLL находится на месте — повторная загрузка не требуется.

При ошибке загрузки — движок продолжает работу с деградированными профилями (WARN в логах).

## Стартовый отчёт о компонентах

Источник: `src/evasion/startup_report.rs`.

При старте движок анализирует доступность компонентов и логирует детальный отчёт:

```
INFO  desync: packet interceptor loaded (TCP disorder available) backend="WinDivert"
INFO  desync: raw packet injector available (SeqOverlap / fake probe injection active)
INFO  desync: all 35 desync profiles fully operational
```

Или, если WinDivert отсутствует:

```
WARN  desync: packet interceptor unavailable — 2 profile(s) fall back to plain TCP split
WARN  desync: raw packet injector unavailable — 2 SeqOverlap profile(s) fall back to TLS split
WARN  desync: raw packet injector unavailable — 2 profile(s) lose their fake-probe injection
WARN  desync: 29/35 desync profiles operational, 6 degraded (install WinDivert)
```

Деградированные профили продолжают работать, но с менее эффективной fallback-техникой.

## Автоматическое обнаружение профилей: ProfileDiscovery

Источник: `src/evasion/profile_discovery.rs`.

При запуске (и раз в 24 часа) каждый профиль зондируется против трёх HTTPS-эндпоинтов:

- `162.159.136.234:443` → discord.com (Cloudflare)
- `208.65.153.238:443` → rutracker.org
- `93.184.216.34:443` → example.com (IANA)

Профили, успешно завершившие TLS-рукопожатие, поднимаются в начало списка. Результаты кешируются в `<data_dir>/prime-net/profile_wins.json` (TTL 24h).

## QUIC Initial десинхронизация

Источник: `src/evasion/quic_initial.rs`.

Перед реальным UDP QUIC Initial инжектируется ложный пакет:

1. Создаётся QUIC v1 Initial пакет с альтернативным (decoy) SNI.
2. Ключи выводятся по RFC 9001 §5.2 (HKDF-Extract/Expand → key/iv/hp).
3. Пакет шифруется AES-128-GCM; header protection — AES-128-ECB.
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

**Экспоненциальное затухание:** `decay = 2^(-(elapsed / 1800))`. Данные старше 30 минут теряют половину веса.

**UCB-выбор:** `score = reward_mean + C * sqrt(ln(total_pulls) / pulls)`

**ML state pruning:** автоматическая очистка устаревших записей по TTL.

**domain_profiles override:** если в `routing.domain_profiles` явно указан маршрут для домена, ML-выбор пропускается.

**Персистентность:** статистика сохраняется в `relay-classifier.json` и переживает перезапуски.

## Kill Switch

Источник: `src/platform/kill_switch.rs`.

Включается через `evasion.kill_switch_enabled = true`.

Мониторит доступность SOCKS5 порта. Если движок падает или порт становится недоступен, kill switch перенаправляет системный прокси на мёртвый порт — весь трафик блокируется вместо утечки через прямое соединение.

## Blocklist: DomainBloom

Источник: `src/blocklist/mod.rs`.

Bloom filter для 1.3M доменов:

- Размер: 2^24 бит = **2 MB** (вместо ~90 MB для HashSet).
- FPR: ~0.1%.
- Глобальный `BLOCKLIST_DOMAINS: OnceLock<DomainBloom>` доступен без блокировок из любого потока.
- Авто-обновление из `antifilter.download` (настраивается в `[blocklist]`).

## DNS / anti-censorship

- Chain order задаётся `anticensorship.dns_fallback_chain`.
- Параллельная гонка DNS (`dns_parallel_racing`) — несколько провайдеров гоняются одновременно; System DNS не участвует в гонке.
- `apply_compat_repairs()` автоматически чинит legacy-конфиги.
- ECH: `real` → настоящий Encrypted Client Hello; `grease` → имитация; `auto` → real с fallback.

## MTProto WebSocket (Telegram)

Источник: `src/pt/mtproto_ws.rs`.

Обфускированный WebSocket прокси для Telegram MTProto. Слушает на `127.0.0.1:1443` (по умолчанию), принимает MTProto-трафик и проксирует через Cloudflare CDN.

## Ad-blocking engine

Источник: `src/adblock/`.

- EasyList/AdGuard синтаксис фильтров;
- DNS-level блокировка доменов;
- URL-level блокировка запросов;
- Cosmetic CSS injection;
- Auto-update из filter lists.

## GUI (Tauri)

Отдельный проект: `prime-gui/` (sibling directory, не в workspace).

**Архитектура:**

- Backend: `src-tauri/` (Rust) — запускает `prime-net-engine.exe` как subprocess, парсит stderr.
- Frontend: `ui/` (Svelte + Vite) — frameless окно, system tray, tabs.
- Engine binary: `src-tauri/bin/prime-net-engine-x86_64-pc-windows-msvc.exe`.

**Tabs:**

- SimpleView — кнопка старт/стоп, uptime, copy proxy address, presets.
- Logs — фильтрация и просмотр логов движка в реальном времени.
- Diagnostics — тест связности, ISP/ТСПУ анализ.
- Settings — все секции конфига.
- Stats — live статистика: route metrics, ML bandit top arms, uptime.

**Билд:** `cd prime-gui/src-tauri && npx tauri build` → NSIS + MSI installer.

## Updater trust model

- API-запросы разрешены только к `https://api.github.com`.
- Download URLs ограничены GitHub-host allowlist.
- Redirects отключены.
- Подпись релиза обязательна для `update install`.
- Верификация подписи изолирована от пользовательского keyring.

## FFI execution model

- `prime_engine_new` создаёт отдельный runtime-thread (tokio).
- Sync/async запросы идут через очередь задач.
- Async handle lifecycle защищён от гонок освобождения через lock-ordering.

## Конфигурационный цикл

```
EngineConfig::from_file → parse → apply_compat_repairs → validate
```

CLI может применить preset поверх загруженного конфига (`--preset`). `--config-check` использует те же валидации + сетевые probes.

Hot-reload: `config_watcher.rs` отслеживает mtime конфига каждые 5 секунд и перезагружает blocklist без перезапуска.

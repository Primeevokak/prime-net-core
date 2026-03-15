# prime-net-engine

Сетевой движок на Rust для обхода блокировок и цензуры. Работает как локальный SOCKS5-прокси с адаптивным ML-маршрутизатором, нативным DPI-обходом (без внешних утилит), QUIC-десинхронизацией и антицензурным DNS.

## Что это такое

`prime-net-engine` — полный сетевой стек, который:

- запускает **локальный SOCKS5-сервер** (порт 1080 по умолчанию), принимая TCP и UDP трафик;
- **автоматически определяет** заблокированные домены через Bloom-фильтр (до 1.3M доменов);
- **нативно обходит DPI** — 25+ техник десинхронизации встроены в процесс, без запуска byedpi/ciadpi;
- **автопробует профили** и ранжирует их по результатам реальных зондирований;
- **самообучается**: каждое соединение обновляет Shadow UCB bandit, адаптируясь к настройкам провайдера;
- **обходит QUIC-блокировки** — инжектирует ложные QUIC Initial пакеты с альтернативным SNI перед реальным соединением;
- поддерживает **pluggable transports** (Trojan, Shadowsocks, Obfs4, Snowflake) для случаев тотальной блокировки.

---

## Как именно обходятся блокировки

### 1. DNS — утечки и подмена ответов

Стандартный DNS (UDP, порт 53) перехватывается и фальсифицируется провайдерами.

Движок использует зашифрованный DNS через цепочку распознавателей:

- **DoH** (DNS-over-HTTPS) — запросы неотличимы от HTTPS-трафика;
- **DoT** (DNS-over-TLS) — зашифрованный TCP, порт 853;
- **DoQ** (DNS-over-QUIC) — зашифрованный UDP, порт 784.

Провайдеры по умолчанию: **AdGuard, Google, Quad9**. Cloudflare исключён из цепочки из-за известных ограничений в РФ.

Дополнительно:
- **DNSSEC** — проверка подлинности DNS-записей;
- **Параллельная гонка DNS** — запросы идут одновременно ко всем провайдерам, побеждает первый валидный ответ (System DNS не участвует в гонке — это предотвращает утечку к провайдеру);
- **DNS-кеш** на 4096 записей.

### 2. TLS ClientHello — SNI-анализ

DPI-системы читают **Server Name Indication (SNI)** — открытое поле в TLS ClientHello, которое раскрывает целевой домен.

Движок применяет несколько техник:

- **ECH (Encrypted Client Hello)** — шифрует SNI полностью, передавая имя сайта внутри TLS 1.3. Режимы: `real`, `grease`, `auto` (real → grease fallback);
- **TLS Record Split** — разбивает ClientHello на несколько TLS-записей. DPI, работающее пакет-за-пакетом, не собирает полный SNI;
- **TCP Segment Split** — разбиение ClientHello на несколько TCP-сегментов;
- **Multi-Split** — 3–5 точек разбиения одновременно;
- **SNI case randomization** — рандомизация регистра символов в SNI;
- **TLS Record Padding** — вставка фиктивного ApplicationData record перед ClientHello;
- **JA3-профили** — имитация TLS-отпечатка Chrome/Firefox через рандомизацию.

### 3. Нативный DPI-bypass — 25+ встроенных профилей

Движок содержит полноценный TCP-десинхронизирующий стек **без внешних зависимостей**. Профили пробуются против реальных HTTPS-эндпоинтов при запуске и сортируются по результатам.

**Базовые профили (все платформы):**

| Профиль | Техника |
|---|---|
| `tlsrec-into-sni` | TLS record split на границе SNI |
| `tlsrec-before-sni` | TLS record split перед SNI |
| `tlsrec-mid-sni` | TLS record split через середину SNI |
| `tlsrec-fixed-5` | TLS record split на байте 5 |
| `split-into-sni` | TCP segment split на границе SNI |
| `split-before-sni` | TCP segment split перед SNI |
| `split-fixed-1` | TCP segment split на байте 1 |
| `split-fixed-3` | TCP segment split на байте 3 |
| `http-before-host` | HTTP split перед заголовком Host: (порт 80) |
| `tlsrec-into-sni-fake-ttl3` | TLS split + fake probe с TTL=3 |
| `split-into-sni-fake-ttl3` | TCP split + fake probe с TTL=3 |
| `multi-split-sni-region` | 3 точки разбиения в области SNI |
| `multi-split-fixed` | 4 точки разбиения с фиксированными смещениями |
| `split-into-sni-delay-100` | TCP split + 100ms задержка между фрагментами |
| `tlsrec-into-sni-delay-250` | TLS split + 250ms задержка |
| `split-into-sni-case-rand` | TCP split + рандомизация регистра SNI |
| `tlsrec-into-sni-case-rand` | TLS split + рандомизация регистра SNI |
| `tlsrec-pad-into-sni` | TLS split + фиктивный ApplicationData padding |
| `tlsrec-pad-before-sni` | TLS split перед SNI + padding |
| `tlsrec-into-sni-fake-sni-probe` | TLS split + fake ClientHello с SNI="www.google.com" |
| `split-into-sni-fake-sni-probe` | TCP split + fake ClientHello probe |

**Windows/Linux — TCP disorder (WinDivert/NFQueue):**

| Профиль | Техника |
|---|---|
| `tcp-disorder-15ms` | Сегмент 2 доходит раньше сегмента 1, задержка 15ms |
| `tcp-disorder-40ms` | Сегмент 2 доходит раньше сегмента 1, задержка 40ms |

**OOB-профили (Windows, Linux — реальный MSG_OOB):**

| Профиль | Техника |
|---|---|
| `tlsrec-into-sni-oob` | TLS split + OOB байт |
| `tlsrec-before-sni-oob` | TLS split перед SNI + OOB байт |
| `split-into-sni-oob` | TCP split в SNI + OOB байт |
| `split-before-sni-oob` | TCP split перед SNI + OOB байт |

### 4. Автоматическое обнаружение профилей

При первом запуске (и раз в 24 часа) движок зондирует каждый профиль против трёх HTTPS-эндпоинтов:

- `162.159.136.234:443` → discord.com (Cloudflare)
- `208.65.153.238:443` → rutracker.org
- `93.184.216.34:443` → example.com (IANA)

Профили, успешно завершившие TLS-рукопожатие, поднимаются в начало списка. Результаты кешируются в `<data_dir>/prime-net/profile_wins.json`.

### 5. QUIC Initial — десинхронизация UDP

Discord, YouTube и другие сервисы используют **QUIC/HTTP3 (UDP)**. Некоторые провайдеры блокируют QUIC-трафик, оставляя TCP рабочим.

Движок применяет двухуровневую стратегию:

1. **QUIC Initial inject** — перед реальным UDP QUIC Initial инжектируется ложный пакет с альтернативным SNI (decoy) при низком TTL. DPI обрабатывает ложный пакет, реальный проходит.
   - QUIC v1, AES-128-GCM + HP (header protection AES-128-ECB)
   - Минимальный размер пакета: 1200 байт (anti-amplification)
   - Ключи: HKDF-Extract(initial_salt_v1, DCID) → client_in → key/iv/hp (RFC 9001 §5.2)

2. **QUIC blocking fallback** — если QUIC заблокирован на уровне UDP ASSOCIATE, движок отклоняет UDP запрос к заблокированным доменам. Приложение переходит на TCP, который обрабатывается нативным DPI-bypass.

### 6. ML-адаптация — Shadow UCB Bandit

Ядро адаптивного маршрутинга — **многорукий бандит UCB** с теневой статистикой.

Для каждого домена движок ведёт статистику по каждому методу:
- `pulls` — количество попыток;
- `reward_sum` — сумма наград (успех = +1, блокировка = -1);
- `ema_reward_milli` — EMA вознаграждения с адаптивным дрейфом.

**Ключевые параметры:**
- `SHADOW_UCB_EXPLORATION_SCALE`: 18.0 — коэффициент исследования;
- `SHADOW_DECAY_HALFLIFE_SECS`: 1800 — экспоненциальное затухание (период полураспада 30 минут);
- `SHADOW_PRIOR_PSEUDO_PULLS`: 10 — сглаживающий prior;
- `SHADOW_EXPLORATION_BUDGET_PCT`: 5% — бюджет на теневое исследование.

**`domain_profiles`**: явное закрепление домена за маршрутом через конфиг, обходит ML-выбор.

Статистика персистентно хранится в `relay-classifier.json`.

### 7. Pluggable Transports

Для случаев полной блокировки прямого трафика:

- **Trojan** — HTTPS-туннель, трафик неотличим от обычного HTTPS;
- **Shadowsocks** — шифрованный AEAD-туннель (поддержка cipher-2022);
- **Obfs4** — обфускация через Tor PT (требует `tor` + `obfs4proxy`);
- **Snowflake** — туннель через WebRTC/Tor (требует `tor` + `snowflake-client`).

### 8. Privacy middleware

- **Tracker blocker** — блокировка трекеров на уровне движка (режимы: Lax/Standard/Strict/LogOnly);
- **User-Agent override** — замена User-Agent на Chrome/Firefox/Safari/Custom;
- **Referer policy** — управление Referer: Strip/OriginOnly/PassThrough;
- **DNT/GPC сигналы** — `Do Not Track` и `Global Privacy Control`;
- **IP spoofing** — замена IP в заголовках (опционально);
- **Domain fronting** — перенаправление через CDN-фронт.

---

## Возможности

| Категория | Функционал |
|---|---|
| SOCKS5 | TCP + UDP ASSOCIATE, IPv4/IPv6 |
| DNS | DoH / DoT / DoQ / System, DNSSEC, параллельная гонка, кеш 4096 записей |
| TLS | ECH (real/grease/auto), TLS record split, TCP segment split, JA3-профили, TLS 1.2/1.3 |
| DPI bypass | 25+ нативных профилей, без внешних утилит, автопроба и ранжирование |
| QUIC | QUIC Initial inject (RFC 9001), UDP blocking fallback |
| Packet disorder | TCP disorder через WinDivert (Windows) / NFQueue (Linux) |
| ML routing | Shadow UCB bandit, экспоненциальное затухание, domain_profiles override |
| Blocklist | Bloom filter 2MB для 1.3M доменов, авто-обновление |
| PT | Trojan, Shadowsocks, Obfs4, Snowflake |
| Privacy | Tracker blocker, User-Agent override, Referer policy, DNT/GPC, IP spoof |
| Domain fronting | v1/v2 mapping + TTL кеш |
| HTTP клиент | HTTP/1.1, HTTP/2, HTTP/3 (QUIC), SSE, WebSocket, chunked download с возобновлением |
| FFI | C ABI (`prime_net.h`), sync + async запросы, lifecycle management |
| TUI | Интерактивный терминальный интерфейс (ratatui) |
| TUN | VPN-режим (`--features tun`, виртуальный сетевой интерфейс) |
| Обновления | Self-update через GitHub Releases, rollback, опциональная GPG-верификация |
| System proxy | Автоконфигурация системного прокси, PAC-файл (HTTP и SOCKS5) |

---

## Быстрый старт

### Сборка

```bash
cargo build --release --bin prime-net-engine --bin prime-tui
```

С TUN-режимом:

```bash
cargo build --release --features tun --bin prime-net-engine
```

### Создание конфига

```bash
prime-net-engine wizard --out prime-net-engine.toml
```

### Проверка конфига

```bash
prime-net-engine --config prime-net-engine.toml --config-check
```

### Запуск SOCKS5 прокси

```bash
prime-net-engine --config prime-net-engine.toml socks --bind 127.0.0.1:1080
```

Настройте браузер / систему на SOCKS5 `127.0.0.1:1080`.

### Системный прокси

```bash
prime-net-engine --config prime-net-engine.toml proxy enable --mode all
```

С PAC-файлом:

```bash
prime-net-engine --config prime-net-engine.toml proxy enable --mode pac
```

### TUI-интерфейс

```bash
prime-tui
```

---

## CLI-справочник

### Глобальные флаги

| Флаг | Описание |
|---|---|
| `--config <path>` | Путь к конфиг-файлу |
| `--preset <name>` | Имя встроенного пресета |
| `--config-check` | Проверить конфиг и выйти |
| `--offline` | Запустить без сетевых проверок |
| `--probe-domain <domain>` | Домен для зондирования (по умолчанию: example.com) |
| `--log-level <level>` | DEBUG / INFO / WARN / ERROR |
| `--log-format <format>` | text / json |
| `--log-file <path>` | Путь к лог-файлу |
| `--log-rotation <mode>` | daily / hourly / never |

### Подкоманды

```
socks [--bind <addr>] [--silent-drop]
    Запустить SOCKS5 прокси (по умолчанию: 127.0.0.1:1080)

fetch <url> [-H header]... [--method M] [--body B] [--out path] [--print-headers]
    Выполнить HTTP-запрос через движок

download <url> --out <path>
    Загрузить файл с поддержкой возобновления

wizard [--out <path>] [--force]
    Интерактивная генерация конфига

proxy enable [--mode all|pac] [--pac-url <url>]
proxy disable
proxy status
proxy generate-pac [--output <path>] [--socks-endpoint <addr>]
proxy serve-pac [--port <port>] [--socks-endpoint <addr>]
    Управление системным прокси

blocklist update [--source <url>]
blocklist test
    Управление Bloom-фильтром доменов

update check
update apply
    Self-update движка

test
    Диагностика конфигурации и сети

tun
    VPN/TUN режим (только с --features tun)
```

---

## Конфигурация

Конфиг в формате TOML. Полный пример — `config.example.toml`.

### Ключевые секции

```toml
[anticensorship]
doh_enabled = true
doh_providers = ["adguard", "google", "quad9"]
dnssec_enabled = true
dns_cache_size = 4096
dns_parallel_racing = true
ech_mode = "grease"            # "real" / "grease" / "auto"
ech_enabled = false

[evasion]
prime_mode = true
packet_bypass_enabled = true
strategy_race_enabled = true   # гонка профилей
classifier_persist_enabled = true

[routing]
ml_routing_enabled = true

# Явное закрепление домена за маршрутом (обходит ML):
[routing.domain_profiles]
"discord.com" = "native:tlsrec-into-sni"
"rutracker.org" = "native:split-into-sni"
"example.com" = "direct"

[blocklist]
enabled = true
auto_update = true
update_interval_hours = 24

[privacy.user_agent]
enabled = false
preset = "ChromeWindows"    # ChromeWindows / FirefoxWindows / FirefoxLinux / SafariMacOs / Custom

[privacy.tracker_blocker]
enabled = false
mode = "Standard"           # Lax / Standard / Strict / LogOnly / Block
```

### Pluggable Transports

```toml
[pt]
kind = "Shadowsocks"
local_socks5_bind = "127.0.0.1:1080"

[pt.shadowsocks]
server = "your.server:8388"
password = "your_password"
method = "chacha20-ietf-poly1305"
```

```toml
[pt]
kind = "Trojan"

[pt.trojan]
server = "your.server:443"
password = "your_password"
sni = "your.domain.com"
```

```toml
[pt]
kind = "Obfs4"

[pt.obfs4]
server = "bridge_ip:port"
cert = "bridge_cert_string"
tor_bin = "/usr/bin/tor"
obfs4proxy_bin = "/usr/bin/obfs4proxy"
```

---

## Переменные среды

| Переменная | Описание |
|---|---|
| `PRIME_WORKER_THREADS` | Количество потоков Tokio (по умолчанию: CPU count) |
| `PRIME_PACKET_BYPASS=0` | Отключить packet bypass |
| `PRIME_PACKET_BYPASS_ARGS=<args>` | Дополнительные аргументы bypass |
| `PRIME_PACKET_BYPASS_TAG=<tag>` | Версия byedpi (для внешнего bypass) |
| `PRIME_PACKET_BYPASS_BINARY_SHA256` | SHA256 бинаря для верификации |
| `PRIME_PACKET_BYPASS_PAYLOAD_SHA256` | SHA256 payload для верификации |
| `PRIME_PACKET_BYPASS_TRUST_REMOTE_CHECKSUM=1` | Доверять remote checksum (небезопасно) |
| `PRIME_PT_AUTO_BOOTSTRAP` | Авто-загрузка PT-бинарей |
| `PRIME_PT_BOOTSTRAP_DIR` | Директория для PT-бинарей |
| `PRIME_PT_BOOTSTRAP_PROXY` | Прокси для загрузки PT-бинарей |
| `PRIME_NET_DEV` | Dev-режим (отключает SSL верификацию) |
| `GITHUB_API_URL` | Кастомный GitHub API (для обновлений) |

---

## C FFI

Движок экспортирует C ABI для встраивания в другие приложения.

```c
#include "prime_net.h"

// Создать движок из конфиг-файла
PrimeEngine* prime_engine_new(const char* config_path);

// Синхронный запрос
PrimeResponse* prime_engine_fetch(
    PrimeEngine* engine,
    const PrimeRequest* request,
    ProgressCallback callback,
    void* user_data
);

// Освободить движок
void prime_engine_free(PrimeEngine* engine);

// Коды ошибок
#define PRIME_OK                   0
#define PRIME_ERR_NULL_PTR         1
#define PRIME_ERR_INVALID_UTF8     2
#define PRIME_ERR_INVALID_REQUEST  3
#define PRIME_ERR_RUNTIME          4
```

Полный API — `include/prime_net.h`.

---

## Структура проекта

```
prime-net-engine/
├── src/
│   ├── lib.rs                         # Публичный API библиотеки
│   ├── anticensorship/                # DoH/DoT/DoQ, ECH, domain fronting, TLS rand
│   ├── blocklist/                     # DomainBloom, парсинг, авто-обновление
│   ├── config/                        # EngineConfig, валидация, пресеты
│   ├── core/                          # PrimeHttpClient, HTTP pipeline, HTTP/3
│   ├── dns/                           # DNS протокол, DNSSEC
│   ├── evasion/
│   │   ├── tcp_desync.rs              # TcpDesyncEngine: 25+ профилей
│   │   ├── quic_initial.rs            # QUIC Initial inject (RFC 9001)
│   │   ├── profile_discovery.rs       # Автопроба и ранжирование профилей
│   │   ├── packet_intercept/          # WinDivert (Win) / NFQueue (Linux)
│   │   ├── dpi_bypass.rs              # OOB, fake probe, TCP desync helpers
│   │   ├── fragmenting_io.rs          # Фрагментирующий writer
│   │   ├── tls_parser.rs              # TLS ClientHello parser (hot path)
│   │   └── traffic_shaping.rs         # Timing jitter, shaped write
│   ├── ffi/                           # C ABI
│   ├── health/                        # Health checks
│   ├── observability/                 # Logging, tracing
│   ├── pac/                           # PAC-файл генерация
│   ├── platform/                      # Platform-specific (Windows/Linux/macOS)
│   ├── privacy/                       # UA, Referer, tracker blocker, IP spoof
│   ├── proxy/                         # Системный прокси
│   ├── pt/
│   │   ├── direct.rs                  # Прямое TCP/UDP соединение
│   │   ├── trojan.rs                  # Trojan protocol
│   │   ├── shadowsocks.rs             # Shadowsocks AEAD
│   │   ├── tor_client.rs              # Tor/PT бинарники
│   │   └── socks5_server/
│   │       ├── mod.rs
│   │       ├── ml_shadow.rs           # Shadow UCB bandit
│   │       ├── route_scoring.rs       # Health scoring, blocklist lookup
│   │       ├── route_connection.rs    # Маршрутизация + race
│   │       ├── protocol_udp.rs        # UDP ASSOCIATE + QUIC blocking
│   │       └── relay_and_io_helpers.rs
│   ├── telemetry/                     # Телеметрия
│   ├── tls/                           # TLS конфигурация
│   ├── updater/                       # Self-update, rollback
│   └── websocket/                     # WebSocket клиент
├── src/bin/
│   ├── prime-net-engine/              # CLI бинарь
│   │   ├── main.rs                    # Subcommand dispatch
│   │   ├── socks_cmd.rs               # SOCKS5 сервер startup
│   │   ├── blocklist_runtime.rs       # Bloom filter инициализация
│   │   ├── tun_cmd.rs                 # TUN/VPN режим
│   │   └── packet_bypass_parts/       # Профили и процесс bypass
│   └── prime-tui.rs                   # TUI бинарь
├── docs/                              # Документация
├── include/prime_net.h                # C FFI заголовок
└── config.example.toml                # Пример конфигурации
```

---

## Документация

| Файл | Описание |
|---|---|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Быстрый старт шаг за шагом |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Рабочие сценарии |
| [docs/CONFIG.md](docs/CONFIG.md) | Все параметры конфигурации |
| [docs/EXECUTABLE.md](docs/EXECUTABLE.md) | CLI-референс |
| [docs/PRESETS.md](docs/PRESETS.md) | Встроенные пресеты |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Архитектура и подсистемы |
| [docs/API.md](docs/API.md) | Rust API и C FFI |
| [docs/PRIVACY.md](docs/PRIVACY.md) | Privacy middleware |
| [docs/TLS_FINGERPRINTING.md](docs/TLS_FINGERPRINTING.md) | TLS/JA3 поведение |
| [docs/SECURITY.md](docs/SECURITY.md) | Модель угроз |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Диагностика проблем |

---

## Лицензия

Смотри `LICENSE`.

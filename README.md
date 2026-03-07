# prime-net-engine

Сетевой движок на Rust для обхода блокировок и цензуры. Работает как локальный SOCKS5-прокси с адаптивным ML-маршрутизатором, DPI-обходом и антицензурным DNS.

## Что это такое

`prime-net-engine` — это не просто прокси-клиент. Это полный сетевой стек, который:

- запускает **локальный SOCKS5-сервер** (порт 1080 по умолчанию), принимая трафик от любого браузера или приложения;
- **автоматически определяет**, нужен ли обход для каждого конкретного домена — и если нужен, выбирает метод;
- **самообучается**: результат каждого соединения (успех / RST / таймаут) используется как сигнал для следующего выбора маршрута;
- **переключается между методами обхода** в реальном времени без перезапуска.

---

## Как именно обходятся блокировки

Российские (и аналогичные) блокировки работают на нескольких уровнях. `prime-net-engine` закрывает каждый из них.

### 1. DNS-уровень: утечки и подмена ответов

Стандартный DNS (UDP, порт 53) перехватывается и фальсифицируется провайдерами.

Движок использует **зашифрованный DNS** через цепочку распознавателей:

- **DoH** (DNS-over-HTTPS) — запросы выглядят как обычный HTTPS-трафик;
- **DoT** (DNS-over-TLS) — зашифрованный TCP, порт 853;
- **DoQ** (DNS-over-QUIC) — зашифрованный UDP, порт 784.

Провайдеры по умолчанию: AdGuard, Google, Quad9. Cloudflare исключён из цепочки из-за известных ограничений в РФ (compatibility repair).

Дополнительно:

- **DNSSEC** — проверка подлинности DNS-записей;
- **Параллельный гонка DNS** (`dns_parallel_racing`) — запросы идут одновременно к нескольким провайдерам, побеждает первый валидный ответ;
- **DNS-кеш** на 4096 записей с настраиваемым TTL.

### 2. SNI-уровень: определение сайта по TLS-рукопожатию

DPI-системы читают **Server Name Indication (SNI)** — открытое поле в TLS ClientHello, которое сообщает, к какому домену подключается клиент.

Движок применяет несколько техник:

- **ECH (Encrypted Client Hello)** — шифрует SNI полностью, передавая имя сайта внутри TLS 1.3. Режимы: `real` (настоящий ECH), `grease` (имитация для совместимости), `auto` (real → grease fallback);
- **TLS-фрагментация** — разбивает ClientHello на несколько TCP-сегментов. DPI-системы, работающие пакет-за-пакетом, не могут собрать полный SNI;
- **Split at SNI** — точное разбиение прямо в области SNI-поля;
- **TLS record рандомизация** — случайные смещения и размеры фрагментов затрудняют сигнатурный анализ;
- **JA3-профили** — имитация TLS-отпечатка Chrome 120, Firefox 121, или рандомизированный профиль.

### 3. TCP/DPI-уровень: инспекция соединения после рукопожатия

Некоторые блокировки срабатывают **после** TLS-рукопожатия — ISP видит первый зашифрованный пакет с данными и вводит RST (принудительный разрыв).

Для этого используется **packet bypass** — внешний инструмент (`byedpi`/`ciadpi`), запускаемый как дочерний процесс:

| Профиль                | Метод                                          | Назначение                                      |
|------------------------|------------------------------------------------|-------------------------------------------------|
| `discord-disorder-oob` | `--disorder 1 --oob 1`                         | Discord: disorder + OOB дезориентируют DPI      |
| `discord-shuffle3-oob` | `--disorder 3 --oob 1 --udp-fake 1`            | Discord: shuffle 3 сегмента + OOB + UDP fake    |
| `discord-disoob`       | `--split 1 --disoob 1`                         | Discord: disordered OOB при WebSocket Upgrade   |
| `discord-oob2-tlsrec`  | `--oob 2 --tlsrec 3+s --udp-fake 1`            | Discord: OOB + TLS record + UDP fake для голоса |
| `split-2-oob-disorder` | `--split 2 --oob 1 --disorder 1`               | Универсальный: split + OOB + disorder           |
| `modern-mix-all`       | `--split 2 --disorder 1 --oob 1 --tlsrec 3+s`  | Комбо всех методов                              |
| `tlsrec-5-fake-ttl`    | `--tlsrec 5+s --fake 1 --ttl 5`                | TLS record + fake с низким TTL                  |

**`--oob`**: out-of-band байты в TCP-потоке — DPI теряет контекст сборки.
**`--disoob`**: OOB-байты прямо в момент WebSocket Upgrade — именно там срабатывает инспекция Discord.
**`--udp-fake`**: UDP-фейки для вытеснения QUIC, Discord переходит на TCP через bypass.

Профили можно переопределить через `PRIME_PACKET_BYPASS_ARGS`. Префикс `+` добавляет к встроенным, без префикса — полная замена.

### 4. QUIC-уровень: принудительный TCP-fallback

Discord, YouTube и другие сервисы используют **QUIC/HTTP3 (UDP)**. Провайдеры могут блокировать UDP-трафик к конкретным IP, оставляя TCP рабочим.

Движок **блокирует QUIC-соединения к Discord-доменам** прямо в UDP ASSOCIATE обработчике SOCKS5. Приложение (Electron, браузер) автоматически переключается на TCP, который уже идёт через DPI-bypass профили.

### 5. Pluggable Transports: полная обёртка трафика

Для случаев, когда DPI-обход недостаточен:

- **Trojan** — HTTPS-туннель, трафик неотличим от обычного HTTPS;
- **Shadowsocks** — шифрованный SOCKS5-туннель;
- **Obfs4** — обфускация через Tor PT (требует `tor` + `obfs4proxy`);
- **Snowflake** — туннель через WebRTC/Tor (требует `tor` + `snowflake-client`).

### 6. ML-адаптация: Shadow UCB Bandit

Ядро системы адаптивного маршрутинга — **многорукий бандит (Upper Confidence Bound)** с теневой статистикой.

Для каждого домена / группы доменов движок ведёт статистику по каждому методу обхода:
- `pulls` — количество попыток;
- `reward_sum` — сумма наград (успех = +1, блокировка = -1);
- `last_seen_unix` — время последней попытки.

**Экспоненциальное затухание** (halflife = 30 минут): старые данные теряют вес по формуле `decay = 2^(-(elapsed / 1800))`. Это позволяет быстро адаптироваться к изменениям настроек ISP.

**UCB-выбор**: предпочтение отдаётся методу с наибольшим `reward + C * sqrt(ln(total) / pulls)` — баланс между эксплуатацией известно-хорошего и исследованием новых вариантов.

**domain_profiles**: явное закрепление домена за маршрутом через конфиг (`routing.domain_profiles`), обходит ML-выбор.

Статистика персистентно хранится в `relay-classifier.json` (переживает перезапуски).

---

## Возможности

| Категория       | Функционал                                                                 |
|-----------------|----------------------------------------------------------------------------|
| SOCKS5          | TCP + UDP ASSOCIATE, IPv4/IPv6                                             |
| DNS             | DoH / DoT / DoQ / System, DNSSEC, параллельная гонка, кеш 4096 записей     |
| TLS             | ECH (real/grease/auto), фрагментация ClientHello, JA3-профили, TLS 1.2/1.3 |
| DPI bypass      | 7+ профилей byedpi, disorder/split/OOB/disoob/tlsrec/TTL/fake-пакеты       |
| ML routing      | Shadow UCB bandit, экспоненциальное затухание, domain_profiles override    |
| Blocklist       | Bloom filter 2MB для 1.3M доменов (antifilter.download), авто-обновление   |
| PT              | Trojan, Shadowsocks, Obfs4, Snowflake                                      |
| Privacy         | Tracker blocker, Referer policy, DNT/GPC signals, User-Agent override      |
| Domain fronting | v1/v2 mapping + TTL кеш                                                    |
| HTTP клиент     | HTTP/1.1, HTTP/2, HTTP/3 (QUIC), SSE, WebSocket, chunked download          |
| FFI             | C ABI (`prime_net.h`), sync + async запросы, lifecycle management          |
| TUI             | Интерактивный терминальный интерфейс (ratatui)                             |
| Обновления      | Self-update через GitHub Releases, rollback, опциональная GPG-верификация  |

---

## Быстрый старт

### Сборка

```bash
cargo build --release --bin prime-net-engine --bin prime-tui
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

Настройте браузер / систему на использование SOCKS5 `127.0.0.1:1080`.

### Системный прокси (автоматически)

```bash
prime-net-engine --config prime-net-engine.toml proxy enable --mode all
```

### TUI-интерфейс

```bash
prime-tui
```

---

## Структура проекта

```
prime-net-engine/
├── src/
│   ├── lib.rs                          # Публичный API библиотеки
│   ├── anticensorship/                 # DoH/DoT/DoQ, ECH, domain fronting
│   ├── blocklist/                      # DomainBloom, парсинг, кеш
│   ├── config/                         # EngineConfig, валидация, пресеты
│   ├── core/                           # PrimeHttpClient, HTTP pipeline
│   ├── evasion/                        # TLS фрагментация, desync
│   ├── ffi/                            # C ABI
│   ├── pt/                             # SOCKS5, PT (trojan/ss/obfs4/snowflake)
│   │   └── socks5_server_parts/
│   │       ├── ml_shadow.rs            # Shadow UCB bandit
│   │       ├── route_scoring.rs        # Health scoring, blocklist lookup
│   │       └── protocol_udp.rs         # UDP ASSOCIATE + QUIC blocking
│   ├── updater/                        # Self-update, rollback
│   └── websocket/                      # WebSocket клиент
├── src/bin/
│   ├── prime-net-engine/               # CLI бинарь
│   │   ├── blocklist_runtime.rs        # Bloom filter инициализация
│   │   └── packet_bypass_parts/        # DPI bypass профили, byedpi процесс
│   └── prime-tui.rs                    # TUI бинарь
├── docs/                               # Документация
├── include/prime_net.h                 # C FFI заголовок
└── config.example.toml                 # Пример конфигурации
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

## Переменные среды

| Переменная | Описание |
|---|---|
| `PRIME_PACKET_BYPASS=0` | Отключить packet bypass |
| `PRIME_PACKET_BYPASS_ARGS=<args>` | Заменить профили bypass. Префикс `+` — добавить к встроенным |
| `PRIME_PACKET_BYPASS_TAG=<tag>` | Версия byedpi (иначе — pinned stable) |
| `PRIME_PACKET_BYPASS_PAYLOAD_SHA256` | SHA256 payload для верификации |
| `PRIME_PACKET_BYPASS_BINARY_SHA256` | SHA256 бинаря для верификации |
| `PRIME_PACKET_BYPASS_TRUST_REMOTE_CHECKSUM=1` | Доверять remote checksum (небезопасно) |

---

## Лицензия

Смотри `LICENSE`.

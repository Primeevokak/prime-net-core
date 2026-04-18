# CONFIG

Источник истины: `src/config/config_sections/*`.

## Форматы загрузки

`EngineConfig::from_file(path)` поддерживает:

- TOML (`.toml`)
- JSON (`.json`)
- YAML (`.yaml`, `.yml`)

Если расширение неизвестно, пробуется TOML → JSON → YAML.

После парсинга всегда выполняются:

1. `apply_compat_repairs()`
2. `validate()`

## Compatibility repairs

Автоматические правки для legacy-конфигов:

- отключение `anticensorship.domain_fronting_enabled`, если нет правил;
- синхронизация `anticensorship.dns_fallback_chain` с `*_enabled`;
- удаление `cloudflare` из `doh_providers`, fallback на `adguard/google/quad9`;
- удаление cloudflare endpoint-ов из `dot_servers`/`doq_servers` с восстановлением безопасных дефолтов.

## Секции и дефолты

### `[download]`

- `initial_concurrency = 4`
- `max_concurrency = 16`
- `chunk_size_mb = 4`
- `max_retries = 2`
- `adaptive_enabled = true`
- `adaptive_threshold_mbps = 25.0`
- `request_timeout_secs = 30`
- `connect_timeout_secs = 10`
- `max_idle_per_host = 16`
- `pool_idle_timeout_secs = 30`
- `http2_max_concurrent_reset_streams = null`
- `verify_hash = null`

`verify_hash`:

- `sha256:<64 hex>`
- `auto` (ожидается соседний файл `<output>.sha256`)

### `[transport]`

- `prefer_http3 = false`
- `http3_only = false`
- `http3_connect_timeout_ms = 10000`
- `http3_idle_timeout_ms = 30000`
- `http3_keep_alive_interval_ms = null`
- `http3_insecure_skip_verify = false`

### `[tls]`

- `min_version = "tls1_2"`
- `max_version = "tls1_3"`
- `alpn_protocols = ["h2", "http/1.1"]`
- `ja3_fingerprint = "rustls_default"`

`ja3_fingerprint`:

- `rustls_default`
- `chrome_120`
- `firefox_121`
- `random`

### `[anticensorship]`

- `doh_enabled = true`
- `doh_providers = ["adguard", "google", "quad9"]`
- `doh_cache_ttl_secs = 300`
- `bootstrap_ips = [8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9, 149.112.112.112, 94.140.14.14, 94.140.15.15]`
- `dnssec_enabled = true`
- `dns_cache_size = 4096`
- `dns_query_timeout_secs = 5`
- `dns_attempts = 2`
- `dot_enabled = false`
- `dot_servers = ["94.140.14.14:853", "94.140.15.15:853", "8.8.8.8:853", "8.8.4.4:853"]`
- `dot_sni = "dns.adguard-dns.com"`
- `doq_enabled = false`
- `doq_servers = ["94.140.14.14:784", "94.140.15.15:784"]`
- `doq_sni = "dns.adguard-dns.com"`
- `dns_fallback_chain = ["doh"]`
- `system_dns_enabled = false`
- `dns_parallel_racing = true`
- `ech_mode = null`
- `ech_enabled = false` (legacy)
- `domain_fronting_enabled = false`
- `domain_fronting_rules = []`
- `fronting_probe_ttl_secs = 600`
- `fronting_probe_timeout_secs = 5`
- `tls_randomization_enabled = true`

`ech_mode`:

- `grease`
- `real`
- `auto`

### `[evasion]`

- `prime_mode = true`
- `strategy = null`
- `fragment_size_min = 16`
- `fragment_size_max = 128`
- `randomize_fragment_size = true`
- `fragment_sleep_ms = 1`
- `tcp_window_size = 0`
- `fake_packets_count = 0`
- `fake_packets_ttl = 2`
- `fake_packets_data_size = 16`
- `tls_record_max_fragment_size = null`
- `rst_retry_max = 2`
- `traffic_shaping_enabled = false`
- `timing_jitter_ms_min = 5`
- `timing_jitter_ms_max = 35`
- `client_hello_split_offsets = [1, 5, 40]`
- `split_at_sni = true`
- `first_packet_ttl = 0`
- `fragment_budget_bytes = 16384`
- `packet_bypass_enabled = true`
- `classifier_persist_enabled = true`
- `classifier_cache_path = <platform cache dir>/prime-net-engine/relay-classifier.json`
- `classifier_entry_ttl_secs = 604800`
- `strategy_race_enabled = true`
- `kill_switch_enabled = false` — перенаправляет системный прокси на мёртвый порт если SOCKS5 упал
- `quic_probe_timeout_ms = 3000` — timeout для QUIC Initial зондирования
- `quic_fake_repeat_count = 8` — количество fake QUIC Initial пакетов
- `quic_udp_padding_bytes = 0` — дополнительный UDP padding
- `aggressive_fragment_domains = []` — домены с принудительной агрессивной фрагментацией (например `"soundcloud.com"`)
- `stage_cache_ttl_secs = 172800` — TTL кеша стадий классификатора (48 часов)
- `winner_cache_ttl_secs = 86400` — TTL кеша победителей маршрутов (24 часа)
- `native_profiles = []` — пользовательские нативные профили (дополняют или заменяют дефолтные)
- `disable_default_native_profiles = false` — если `true`, используются только пользовательские профили

`strategy`:

- `fragment`
- `desync`
- `auto`

### `[privacy]`

#### `[privacy.tracker_blocker]`

- `enabled = false`
- `lists = ["easyprivacy", "easylist"]`
- `custom_lists = []`
- `mode = "block"`
- `on_block = "error"`
- `allowlist = []`

`mode`: `block|log_only`.

`on_block`: `error|empty_200`.

#### `[privacy.referer]`

- `enabled = false`
- `mode = "origin_only"`
- `strip_from_search_engines = true`
- `search_engine_domains = []`

`mode`: `strip|origin_only|pass_through`.

#### `[privacy.signals]`

- `send_dnt = true`
- `send_gpc = true`

#### Дополнительные privacy-секции

- `[privacy.user_agent]`: `enabled=false`, `preset=custom`, `custom_value=""`
- `[privacy.referer_override]`: `enabled=false`, `value="https://primeevolution.com"`
- `[privacy.ip_spoof]`: `enabled=false`, `spoofed_ip="77.88.21.10"`
- `[privacy.webrtc]`: `block_enabled=false`
- `[privacy.location_api]`: `block_enabled=false`

### `[proxy]` (опционально)

- `kind = "http"|"https"|"socks5"`
- `address = "host:port"` (или URL)

Важно: `[proxy]` и `[pt]` одновременно недопустимы.

### `[pt]` (опционально)

- `kind = "trojan"|"shadowsocks"|"obfs4"|"snowflake"`
- `local_socks5_bind = "127.0.0.1:0"`
- `silent_drop = false`

Подсекции:

- `[pt.trojan]`: `server`, `password`, optional `sni`, `alpn_protocols` (default `['h2','http/1.1']`), `insecure_skip_verify`
- `[pt.shadowsocks]`: `server`, `password`, `method`
- `[pt.obfs4]`: `server`, `cert` (обязателен), optional `fingerprint`, optional `iat_mode`, `tor_bin`, `obfs4proxy_bin`, args
- `[pt.snowflake]`: `tor_bin`, `snowflake_bin`, optional `broker/front/amp_cache/bridge`, `stun_servers`, args

### `[system_proxy]`

- `auto_configure = false`
- `mode = "off"`
- `pac_port = 8888`
- `socks_endpoint = "127.0.0.1:1080"`

`mode`: `off|all|pac|custom`.

### `[blocklist]`

- `enabled = true`
- `source = "https://antifilter.download/list/domains.lst"`
- `auto_update = true`
- `update_interval_hours = 24`
- `cache_path = <platform cache dir>/prime-net-engine/blocklist.json`

### `[updater]`

- `enabled = true`
- `auto_check = true`
- `check_interval_hours = 24`
- `repo = "your-username/prime-net-engine"`
- `channel = "stable"`

### `[routing]`

- `censored_groups = {}` — группы доменов, которые всегда идут через bypass. Ключ: название группы, значение: список доменов.
- `ml_routing_enabled = true` — включить ML-маршрутизатор (Shadow UCB Bandit).
- `domain_profiles = {}` — явное закрепление домена за маршрутом. Ключ: домен, значение: маршрут. Переопределяет ML-выбор.

**Форматы значений domain_profiles:**

- `"direct"` — прямое соединение без bypass;
- `"bypass:<N>"` — внешний bypass-процесс номер N (если настроен);
- `"native:<profile_name>"` — нативный профиль по имени (например `"native:tlsrec-into-sni"`);
- `"native:<N>"` — нативный профиль по индексу.

Пример:

```toml
[routing.domain_profiles]
"discord.com"    = "native:tlsrec-into-sni"
"discordapp.com" = "native:tlsrec-into-sni"
"rutracker.org"  = "native:split-into-sni"
"youtube.com"    = "native:split-into-sni-fake-ttl3"
"github.com"     = "direct"
```

Валидация: значение должно быть `"direct"`, `"bypass:<число>"`, `"native:<имя>"` или `"native:<число>"`.

### `[telemetry]`

- `crash_reports = false`
- `endpoint = "https://crashes.example.com"`

### `[mtproto_ws]`

MTProto WebSocket прокси для Telegram.

- `enabled = false`
- `listen_addr = "127.0.0.1:1443"`
- `secret_hex = ""` — 16 случайных байт в hex (секрет для MTProto obfuscation)
- `cf_proxy_enabled = false` — проксирование через Cloudflare CDN
- `cf_proxy_domain = ""` — домен для Cloudflare fronting

### `[adblock]`

DNS/URL-level блокировка рекламы и трекеров.

- `enabled = false`
- `lists = ["easylist"]` — builtin list aliases: `easylist`, `easyprivacy`, `ublock`, `ublock_origin`
- `custom_lists = []` — пользовательские filter lists (файлы или URL)
- `auto_update = true`
- `update_interval_hours = 24`

Поддерживает EasyList/AdGuard синтаксис, включая `||domain^`, `/regex/`, cosmetic `##` правила.

## Основные валидации

- `download.initial_concurrency <= download.max_concurrency`, и оба > 0.
- Таймауты и размеры, где ожидается > 0, проверяются.
- `transport.http3_only=true` требует `transport.prefer_http3=true`.
- `dns_fallback_chain` не пустой, без дублей, согласован с `*_enabled`.
- `dot_enabled/doq_enabled` требуют непустые `dot_servers/doq_servers`.
- `domain_fronting_enabled=true` требует валидные `domain_fronting_rules`.
- `pt` и `proxy` одновременно запрещены.
- `pt.obfs4` требует заполненного `cert` (обязательно для рукопожатия).
- `pt.snowflake` требует `tor_bin` и `snowflake_bin`.
- `system_proxy.socks_endpoint` должен быть `host:port` (`[::1]:port` для IPv6).
- `updater.repo` должен быть `owner/name`.
- `download.verify_hash` должен быть `auto` или `sha256:<64hex>`.
- ECH (`ech_mode`/`ech_enabled`) требует, чтобы диапазон TLS включал TLS 1.3.

Практический шаблон: `config.example.toml`.

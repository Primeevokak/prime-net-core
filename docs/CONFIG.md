# CONFIG

Источник истины для структуры: `src/config/config_sections/*`.

## Форматы и загрузка

`EngineConfig::from_file(path)` поддерживает:

- `.toml`
- `.json`
- `.yaml` / `.yml`

Если расширение неизвестно, парсинг пробуется последовательно: TOML -> JSON -> YAML.

После загрузки автоматически выполняются:

1. `apply_compat_repairs()`
2. `validate()`

## Compatibility repairs (автоматические починки)

При чтении из файла движок может автоматически исправить старые конфиги:

- выключить `domain_fronting_enabled`, если нет правил;
- почистить `dns_fallback_chain` от отключённых резолверов;
- удалить `cloudflare` из `doh_providers`, если нужно - подставить `adguard,google,quad9`;
- убрать Cloudflare endpoint-ы из `dot_servers`/`doq_servers`, при необходимости подставить безопасные дефолты AdGuard/Google.

## Секции

### `[download]`

Дефолты:

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

- `"sha256:<64 hex>"`
- `"auto"` (ожидает файл `<target>.sha256` рядом с итоговым файлом)

### `[transport]`

Дефолты:

- `prefer_http3 = false`
- `http3_only = false`
- `http3_connect_timeout_ms = 10000`
- `http3_idle_timeout_ms = 30000`
- `http3_keep_alive_interval_ms = null`
- `http3_insecure_skip_verify = false`

### `[tls]`

Дефолты:

- `min_version = "tls1_2"`
- `max_version = "tls1_3"`
- `alpn_protocols = ["h2", "http/1.1"]`
- `ja3_fingerprint = "rustls_default"`

Поддерживаемые `ja3_fingerprint`:

- `rustls_default`
- `chrome_120`
- `firefox_121`
- `random`

### `[anticensorship]`

Ключевые дефолты:

- `doh_enabled = true`
- `doh_providers = ["adguard", "google", "quad9"]`
- `doh_cache_ttl_secs = 300`
- `bootstrap_ips = []`
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
- `dns_fallback_chain = ["doh", "system"]`
- `system_dns_enabled = true`
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

Дефолты:

- `prime_mode = true`
- `strategy = null`
- `fragment_size = 64`
- `fragment_sleep_ms = 10`
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
- `classifier_cache_path = "~/.cache/prime-net-engine/relay-classifier.json"` (или platform cache dir)
- `classifier_entry_ttl_secs = 604800`
- `strategy_race_enabled = true`

`strategy`:

- `fragment`
- `desync`
- `auto`

### `[privacy]`

#### `[privacy.tracker_blocker]`

Дефолты:

- `enabled = false`
- `lists = ["easyprivacy", "easylist"]`
- `custom_lists = []`
- `mode = "block"`
- `on_block = "error"`
- `allowlist = []`

#### `[privacy.referer]`

Дефолты:

- `enabled = false`
- `mode = "origin_only"`
- `strip_from_search_engines = true`
- `search_engine_domains = []`

#### `[privacy.signals]`

Дефолты:

- `send_dnt = true`
- `send_gpc = true`

#### Дополнительные privacy-поля

- `[privacy.user_agent]`: `enabled=false`, `preset=custom`, `custom_value=""`
- `[privacy.referer_override]`: `enabled=false`, `value="https://primeevolution.com"`
- `[privacy.ip_spoof]`: `enabled=false`, `spoofed_ip="77.88.21.10"`
- `[privacy.webrtc]`: `block_enabled=false`
- `[privacy.location_api]`: `block_enabled=false`

### `[proxy]` (опционально)

- `kind = "http" | "https" | "socks5"`
- `address = "host:port"` или URL

Важно: нельзя одновременно задавать `[proxy]` и `[pt]`.

### `[pt]` (опционально)

- `kind = "trojan" | "shadowsocks" | "obfs4" | "snowflake"`
- `local_socks5_bind` (дефолт `127.0.0.1:0`)
- `silent_drop` (дефолт `false`)

Подсекции по `kind`:

- `[pt.trojan]`: `server`, `password`, optional `sni`, `alpn_protocols`, `insecure_skip_verify`
- `[pt.shadowsocks]`: `server`, `password`, `method`
- `[pt.obfs4]`: `server`, `cert`, optional `fingerprint`, optional `iat_mode`, `tor_bin`, `obfs4proxy_bin`, args
- `[pt.snowflake]`: `tor_bin`, `snowflake_bin`, optional `broker/front/amp_cache/bridge`, `stun_servers`, args

### `[system_proxy]`

Дефолты:

- `auto_configure = false`
- `mode = "off"`
- `pac_port = 8888`
- `socks_endpoint = "127.0.0.1:1080"`

`mode`: `off|all|pac|custom`

### `[blocklist]`

Дефолты:

- `enabled = true`
- `source = "https://github.com/zapret-info/z-i/raw/master/dump.csv"`
- `auto_update = true`
- `update_interval_hours = 24`
- `cache_path = "~/.cache/prime-net-engine/blocklist.json"` (или platform cache dir)

### `[updater]`

Дефолты:

- `enabled = true`
- `auto_check = true`
- `check_interval_hours = 24`
- `repo = "your-username/prime-net-engine"`
- `channel = "stable"`

### `[telemetry]`

Дефолты:

- `crash_reports = false`
- `endpoint = "https://crashes.example.com"`
- `include_config = false`

## Основные валидации

- `initial_concurrency`, `max_concurrency`, `chunk_size_mb`, таймауты > 0.
- `initial_concurrency <= max_concurrency`.
- `http3_only=true` требует `prefer_http3=true`.
- `dns_fallback_chain` не пустой, без дублей, и согласован с `*_enabled`.
- при `dot_enabled=true` и `doq_enabled=true` соответствующие списки серверов не пустые.
- `domain_fronting_enabled=true` требует непустые валидные `domain_fronting_rules`.
- `pt` и `proxy` одновременно запрещены.
- `system_proxy.socks_endpoint` должен быть `host:port` (`[::1]:port` для IPv6).
- `updater.repo` должен быть формата `owner/name`.
- `download.verify_hash` должен быть `auto` или `sha256:<64 hex>`.
- `ech_mode` требует доступности TLS 1.3 в диапазоне `tls.min_version..tls.max_version`.

Практический шаблон: `config.example.toml`.

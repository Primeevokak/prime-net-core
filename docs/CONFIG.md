# Конфигурация движка (`EngineConfig`)

Пример файла: `config.example.toml`.

Поддерживаемые форматы:

- TOML (`.toml`)
- JSON (`.json`)
- YAML (`.yaml` / `.yml`)

Загрузка из файла: `EngineConfig::from_file(path)`.

Если расширение неизвестно, движок пытается распарсить по очереди TOML -> JSON -> YAML.

## `[download]`

Настройки HTTP-клиента и загрузки на диск.

- `initial_concurrency` (usize): начальная параллельность чанков для chunked download.
- `max_concurrency` (usize): верхняя граница параллельности.
- `chunk_size_mb` (usize): размер чанка в MiB (используется, если включён chunked режим).
- `max_retries` (usize): число retry на сетевых ошибках (используется для `HEAD`/`GET` и для каждого чанка).
- `adaptive_enabled` (bool): включить chunked download (best-effort) для больших файлов.
- `adaptive_threshold_mbps` (f64): порог (Mbps) для адаптации параллельности (chunk manager).
- `request_timeout_secs` (u64): общий timeout запроса.
- `connect_timeout_secs` (u64): timeout на TCP connect.
- `max_idle_per_host` (usize): max idle connections per host.
- `pool_idle_timeout_secs` (u64): idle timeout для пула.
- `http2_max_concurrent_reset_streams` (usize, optional): best-effort защита для проблемных серверов при высокой конкуренции.
  Важно: `reqwest` не даёт прямого доступа к hyper knob; в этой сборке значение используется для ограничения внутренних probe-операций, которые могут приводить к RESET.
- `verify_hash` (string, optional): опциональная проверка целостности скачанного файла.

`verify_hash` поддерживает:

- `"sha256:<64 hex>"`: проверка результата по заданному SHA-256.
- `"auto"`: прочитать ожидаемый SHA-256 из файла `"<target>.sha256"` рядом с целевым файлом.

Поведение `verify_hash`:

- проверка запускается после успешного скачивания (`download_to_path`) и на fast-path, когда движок считает, что файл уже полностью скачан (например, resume/skip);
- при несовпадении хеша возвращается ошибка;
- режим `"auto"` строгий: если `"<target>.sha256"` отсутствует или не содержит digest, возвращается ошибка.
 - проверка читает файл целиком и может быть заметной по времени на больших файлах.

Форматы `.sha256`, которые поддерживает `"auto"`:

- `<hex>  filename`
- `SHA256 (filename) = <hex>`
- любая строка, содержащая 64 hex подряд (движок пытается извлечь digest из текста)

## `[tls]`

TLS-параметры (backend: `rustls`).

- `min_version` / `max_version`: минимальная/максимальная версия TLS.
  Фактически поддерживаются TLS 1.2 и TLS 1.3.
- `alpn_protocols`: список ALPN (например `["h2", "http/1.1"]`).
- `ja3_fingerprint`: best-effort профиль ClientHello.

`ja3_fingerprint`:

- `"rustls_default"`: дефолтный ClientHello от rustls.
- `"chrome_120"`: best-effort rustls-профиль, ориентированный на Chrome-подобный fingerprint.
- `"firefox_121"`: best-effort rustls-профиль, ориентированный на Firefox-подобный fingerprint.
- `"random"`: рандомизация части параметров (в рамках ограничений rustls).

Важно: это не full uTLS-impersonation; профили реализованы поверх rustls и могут отличаться от реальных браузеров.

## `[anticensorship]`

Антицензурные компоненты: DNS fallback chain, DoH/DoT/DoQ, ECH, domain fronting.

### DNS fallback chain

- `dns_fallback_chain`: порядок попыток резолва. Возможные значения: `"doh"`, `"dot"`, `"doq"`, `"system"`.
- `system_dns_enabled` (bool): разрешить/запретить системный DNS как fallback.

Важно:

- DoH/DoT/DoQ требуют cargo feature `hickory-dns`. Без неё `ResolverChain::from_config` вернёт ошибку вида `"DoH requires feature \"hickory-dns\""` и т.п.
- `bootstrap_ips` позволяет избежать утечки на системный DNS при доступе к DoH endpoint (когда сам upstream домен нужно резолвить).

### DoH

- `doh_enabled` (bool)
- `doh_providers` (array of string): алиасы провайдеров (см. `config.example.toml`).
- `doh_cache_ttl_secs` (u64)
- `bootstrap_ips` (array of IP): IP для bootstrap резолва upstream-ов

### DNSSEC/cache (Hickory)

- `dnssec_enabled` (bool)
- `dns_cache_size` (usize)
- `dns_query_timeout_secs` (u64)
- `dns_attempts` (usize)

### DoT

- `dot_enabled` (bool)
- `dot_servers` (array of string): `host[:port]` или `ip[:port]`, порт по умолчанию 853
- `dot_sni` (string): SNI/hostname для TLS

### DoQ

- `doq_enabled` (bool)
- `doq_servers` (array of string): порт по умолчанию 784
- `doq_sni` (string): SNI/hostname для TLS

### ECH

- `ech_mode` (string, optional): `"grease" | "real" | "auto"`
- `ech_enabled` (bool): legacy switch, эквивалент `"grease"`. Предпочитайте `ech_mode`.

Поведение:

- `ech_mode="grease"`: включает ECH GREASE (placeholder).
- `ech_mode="real"`: пытается включить реальный ECH через ECHConfigList из DNS HTTPS RR (best-effort).
- `ech_mode="auto"`: сначала пытается `real`, затем fallback на `grease`.

Ограничения:

- Любой включённый ECH (через `ech_mode` или `ech_enabled`) требует, чтобы TLS 1.3 был разрешён в `tls.min_version`/`tls.max_version`.
- Для IP-литералов (когда host это IP) ECH `real` не применяется, а `auto` может использовать `grease`.

### Domain fronting (v1/v2)

- `domain_fronting_enabled` (bool)
- `domain_fronting_rules` (array): правила fronting
- `fronting_probe_ttl_secs` (u64): TTL кэша результатов probe (v2)
- `fronting_probe_timeout_secs` (u64): timeout probe (v2)

Поля правила (`domain_fronting_rules[*]`):

- `target_host` (string): какой hostname считать "таргетом" (матч по host из URL, case-insensitive).
- `front_domain` (string): legacy v1 front domain.
- `front_domains` (array of string): v2 кандидаты front domain (если не пусто, имеет приоритет над `front_domain`).
- `real_host` (string): значение для `Host:` header (то, что "на самом деле" запрашиваем).
- `sni_domain` (string, optional): зарезервировано под будущий SNI override, в текущей реализации не применяется.
- `provider` (string): `"cloudflare" | "fastly" | "googlecdn" | "azurecdn"` (сейчас используется для классификации, но не влияет на HTTP-логику).

Как работает v2:

- при `front_domains` движок выполняет `HEAD https://<front_domain>/` с `Host: <real_host>`;
- первый кандидат, который отвечает со статусом `< 500`, считается рабочим и кэшируется на `fronting_probe_ttl_secs`.

Примечание про WebSocket:

- WebSocket использует domain fronting v2 (probe `HEAD https://<front>/` + кэширование) и v1 fallback (первый кандидат) для совместимости.

### `tls_randomization_enabled`

- `tls_randomization_enabled` (bool): если `true`, движок добавляет дефолтный `User-Agent`, если в запросе нет `User-Agent`.
  В текущей реализации это не меняет TLS handshake.

## `[evasion]`

DPI-evasion и "circuit breaker" по TCP RST.

- `strategy` (string, optional): `"fragment" | "desync" | "auto"`
  - `"fragment"`: userspace TLS fragmentation во время рукопожатия (HTTPS only).
  - `"auto"`: выбрать лучший доступный вариант (по умолчанию `"fragment"`, переключается на `"desync"`, если задан `client_hello_split_offsets`).
  - `"desync"`: userspace TCP segmentation для первых TLS байт (best-effort split ClientHello по `client_hello_split_offsets`, затем обычная фрагментация; HTTPS only).
- `fragment_size` (usize): размер фрагментов для последующих write (после первого).
- `fragment_sleep_ms` (u64): пауза между фрагментами.
- `rst_retry_max` (usize): max retry для fallback по TCP RST (если запрос упал на reset, движок пробует повторить через fragment path).

Ограничения fragment-режима:

- применяется только для `https://`;
- поддерживается прокси только `proxy.kind="socks5"` (в fragment/desync пути не поддерживаются HTTP/HTTPS прокси; SOCKS5-аутентификация тоже не поддерживается);
- fragment/desync path использует отдельный стек (TCP + rustls + hyper), чтобы контролировать запись TLS рукопожатия; ALPN согласуется, поддерживаются HTTP/1.1 и HTTP/2.

Traffic shaping / timing jitter:

- `traffic_shaping_enabled` (bool): если `true`, fragment/desync path будет добавлять случайный jitter между фрагментами и (best-effort) рандомизировать размер последующих фрагментов.
- `timing_jitter_ms_min` / `timing_jitter_ms_max` (u64): диапазон jitter (мс), применяется только при `traffic_shaping_enabled=true`.
- `client_hello_split_offsets` (array of usize): best-effort split для `strategy="desync"` (байтовые оффсеты внутри первого TLS write).

## `[pt]` (Pluggable Transports, 2026-02-14)

Update (2026-02-15):

- `kind="obfs4"` and `kind="snowflake"` are implemented via an external Tor client instance.
- This requires `tor` plus the corresponding client transport binary:
  - obfs4: `obfs4proxy`
  - snowflake: `snowflake-client`
- The engine will start Tor, wait for its SOCKS5 port to become ready, and then route HTTP through it.

### `[pt.obfs4]` (Tor obfs4 bridges)

- `server`: `"host:port"` (bridge address)
- `fingerprint` (optional): 40 hex chars (bridge identity fingerprint)
- `cert`: `cert=...` value from the Tor bridge line
- `iat_mode` (u8, optional): `0..=2` (default = 0)
- `tor_bin` (string): default `"tor"`
- `tor_args` (array): extra CLI args for tor (advanced)
- `obfs4proxy_bin` (string): default `"obfs4proxy"`
- `obfs4proxy_args` (array): extra args for obfs4proxy (advanced)

### `[pt.snowflake]` (Tor snowflake)

- `tor_bin` (string): default `"tor"`
- `tor_args` (array): extra CLI args for tor (advanced)
- `snowflake_bin` (string): default `"snowflake-client"`
- `broker` (optional): broker URL
- `front` (optional): front domain (domain fronting)
- `amp_cache` (optional): AMP cache URL
- `stun_servers` (array): STUN servers (each is passed as `-stun <server>` to snowflake-client)
- `bridge` (optional): placeholder bridge address (a safe dummy is used if unset)
- `snowflake_args` (array): extra args for snowflake-client (advanced)

Клиентский PT-режим: движок поднимает локальный SOCKS5 и направляет HTTP через него.

- `kind`: `"trojan" | "shadowsocks" | "obfs4" | "snowflake"`
  - `"trojan"`: реализовано (клиент).
  - `"shadowsocks"`: реализовано (TCP-клиент).
  - `"obfs4"`: Tor PT (client) via external `tor` + `obfs4proxy` (compatible with Tor obfs4 bridges).
  - `"snowflake"`: Tor PT (client) via external `tor` + `snowflake-client`.
- `local_socks5_bind`: например `"127.0.0.1:0"` (порт `0` = выбрать случайный).
- `silent_drop`: best-effort "active probing resistance" для локального SOCKS5 (молча закрывать на мусорных handshakes).

### `[pt.trojan]`

- `server`: `"host:port"`
- `password`: строка
- `sni` (optional): SNI override
- `alpn_protocols` (array): ALPN list (по умолчанию `["http/1.1"]`)
- `insecure_skip_verify` (bool): DANGEROUS; только для тестов

## `[proxy]`

Прокси применяется в двух местах:

- Обычный путь (`fetch`/`fetch_stream`/`download_to_path`) использует `reqwest::Client` и поддерживает `kind="http"|"https"|"socks5"`.
- Fragment/desync путь использует ручное подключение (TCP + rustls + hyper) и поддерживает только `kind="socks5"` (без аутентификации).

- `kind`: `"http" | "https" | "socks5"`
- `address`: `"host:port"` или полный URL со схемой

Для `socks5` используется схема `socks5h://` (DNS через прокси).
Для IPv6 используйте формат `"[::1]:1080"` (в квадратных скобках).

## `[transport]` (2026-02-14)

- `prefer_http3` (bool): prefer HTTP/3 (QUIC) for `https://` requests (best-effort; disabled when `proxy != None`).
- `http3_only` (bool): if `true`, do not fall back to TCP transports when HTTP/3 was selected.
- `http3_connect_timeout_ms` (u64): QUIC connect timeout.
- `http3_idle_timeout_ms` (u64): QUIC idle timeout.
- `http3_keep_alive_interval_ms` (u64, optional): QUIC keep-alive interval.
- `http3_insecure_skip_verify` (bool): DANGEROUS; accept invalid certificates for HTTP/3 (intended for testing).

## `[evasion]` update (2026-02-15)

- `tls_record_max_fragment_size` (usize, optional): максимальный TLS fragment size (bytes), применяется только для fragment/desync пути (best-effort; зависит от поддержки на стороне сервера).
- Fragment path больше не форсит HTTP/1.1: ALPN согласуется, поддерживаются HTTP/1.1 и HTTP/2.
- Fragment/desync path поддерживает SOCKS5-прокси (без auth) при `proxy.kind="socks5"`.

## `[privacy]`

### `[privacy.tracker_blocker]`

- `enabled` (bool): enable tracker blocker.
- `lists` (array<string>): built-in presets (`easyprivacy`, `easylist`, `ublock`).
- `custom_lists` (array<string>): file paths with hosts/adblock-like rules.
- `mode` (string): `block|log_only`.
- `on_block` (string): `error|empty_200`.
- `allowlist` (array<string>): domains excluded from blocking.

### `[privacy.referer]`

- `enabled` (bool): enable referer policy processing.
- `mode` (string): `strip|origin_only|pass_through`.
- `strip_from_search_engines` (bool): force strip for known search referers.
- `search_engine_domains` (array<string>): extra search engine domains.

### `[privacy.signals]`

- `send_dnt` (bool): add `DNT: 1`.
- `send_gpc` (bool): add `Sec-GPC: 1`.

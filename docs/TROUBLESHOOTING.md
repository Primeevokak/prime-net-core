# TROUBLESHOOTING

## 1. `SOCKS5 connection refused`

Проверьте, что сервер реально запущен:

```bash
prime-net-engine --config prime-net-engine.toml socks --bind 127.0.0.1:1080
```

Проверьте системный статус:

```bash
prime-net-engine --config prime-net-engine.toml proxy status
```

## 2. `--config-check` падает на DNS/DoH

- выполните локальную валидацию без сети:

```bash
prime-net-engine --config prime-net-engine.toml --config-check --offline
```

- проверьте `anticensorship.doh_providers`, `bootstrap_ips`, `dns_fallback_chain`;
- для диагностики сравните с пресетом `max-compatibility`.

## 3. System proxy не включается

Проверьте:

- права/политики ОС;
- формат `system_proxy.socks_endpoint` (`host:port`, для IPv6: `[::1]:port`);
- что SOCKS endpoint действительно слушает.

## 4. `update install` завершается ошибкой подписи

Частые причины:

- сборка без feature `signature-verification`;
- не настроены release signing key/fingerprint в `src/updater/verification.rs`;
- недоступны системные зависимости `gpgme/gpg-error` в окружении сборки.

## 5. Packet bypass не стартует

Проверьте:

- включение `evasion.packet_bypass_enabled` и отсутствие `PRIME_PACKET_BYPASS=0`;
- доступность pinned release asset;
- корректность digest-переменных (`PRIME_PACKET_BYPASS_PAYLOAD_SHA256` / `PRIME_PACKET_BYPASS_BINARY_SHA256`).

## 6. PT (`obfs4`/`snowflake`) не стартует

Проверьте наличие внешних инструментов:

- `tor`
- `obfs4proxy` (для obfs4)
- `snowflake-client` (для snowflake)

## 7. Низкая скорость / нестабильный throughput

Проверьте:

- `evasion.strategy` и `prime_mode`;
- `evasion.fragment_*` параметры;
- `download.*` таймауты/конкурентность;
- влияние `traffic_shaping_enabled`.

## 8. CI падает на `tempfile`/`fmt`

Если ошибка вида `use of unresolved crate tempfile`:

- проверьте, что dependency подключена в `[dependencies]` (не только `dev-dependencies`) для соответствующей feature.

Если падает `cargo fmt --all -- --check`:

- выполните локально `cargo fmt --all` и перезапустите checks.

## 9. Что прикладывать к баг-репорту

- ОС и архитектуру;
- команду запуска;
- редактированный конфиг (без секретов);
- логи с `--log-level debug --log-format json`;
- при необходимости: browser/network консоль и таймштампы.

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

- запустите локальную проверку без сети:

```bash
prime-net-engine --config prime-net-engine.toml --config-check --offline
```

- проверьте рабочие провайдеры в `anticensorship.doh_providers`;
- при необходимости временно используйте более совместимый пресет:

```bash
prime-net-engine --config prime-net-engine.toml --preset max-compatibility test --url https://example.com
```

## 3. System proxy не включается

Проверьте:

- права пользователя/политики ОС;
- корректность `system_proxy.socks_endpoint` (`host:port`);
- что SOCKS endpoint действительно слушает.

Полезные команды:

```bash
prime-net-engine --config prime-net-engine.toml proxy enable --mode all
prime-net-engine --config prime-net-engine.toml proxy status
```

## 4. `update install` завершается ошибкой подписи

Это ожидаемо, если:

- сборка без feature `signature-verification`;
- в коде не заменён публичный ключ-заглушка.

В таком состоянии используйте `update check` только для информирования, а установку делайте вручную через доверенный release pipeline.

## 5. PT (`obfs4`/`snowflake`) не стартует

Проверьте наличие внешних инструментов:

- `tor`
- `obfs4proxy` (для obfs4)
- `snowflake-client` (для snowflake)

Также учитывайте env-переключатели авто-bootstrap (`PRIME_PT_AUTO_BOOTSTRAP`, `PRIME_PT_*_URLS`).

## 6. Низкая скорость / нестабильный throughput

Проверьте:

- `evasion.traffic_shaping_enabled`
- агрессивность `evasion.strategy`
- таймауты и concurrency в `[download]`

Для сравнения можно быстро переключиться:

```bash
prime-net-engine --config prime-net-engine.toml --preset max-compatibility test --url https://example.com
```

## 7. Что приложить при разборе инцидента

- ОС и версия;
- используемый конфиг (без секретов);
- точная команда запуска;
- фрагмент логов (`--log-format json --log-level debug`).

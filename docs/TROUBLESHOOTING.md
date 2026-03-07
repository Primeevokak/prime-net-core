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
- наличие бинаря движка рядом (packet bypass требует `prime-net-engine` в той же директории);
- доступность pinned release asset;
- корректность digest-переменных (`PRIME_PACKET_BYPASS_PAYLOAD_SHA256` / `PRIME_PACKET_BYPASS_BINARY_SHA256`).

При ненадёжной сети для загрузки byedpi можно разрешить remote checksum:

```bash
PRIME_PACKET_BYPASS_TRUST_REMOTE_CHECKSUM=1 prime-net-engine ...
```

## 6. PT (`obfs4`/`snowflake`) не стартует

Проверьте наличие внешних инструментов:

- `tor`
- `obfs4proxy` (для obfs4)
- `snowflake-client` (для snowflake)

Убедитесь, что пути к бинарям указаны в `[pt.obfs4]` / `[pt.snowflake]` секциях конфига.

## 7. Discord / мессенджеры не работают

Discord использует **QUIC (UDP)** и часто блокируется через RST-инъекцию после TCP-рукопожатия.

Шаги диагностики:

1. Убедитесь, что движок запущен и принимает трафик (проверьте `proxy status`).
2. Дайте ML-маршрутизатору 2–3 минуты: он пробует разные bypass-профили и запоминает рабочие.
3. Если Discord зависает в браузере — проверьте, что QUIC отключён в настройках браузера (`chrome://flags/#enable-quic` → Disabled). Движок делает это автоматически для Electron-клиента через SOCKS5 UDP ASSOCIATE.
4. Явно задайте Discord маршрут через `routing.domain_profiles`:

```toml
[routing.domain_profiles]
"discord.com" = "bypass:1"
"discordapp.com" = "bypass:1"
"discord.media" = "bypass:1"
```

5. Запустите движок с `--log-level debug` и ищите в логах строки с `discord` — там будет видно, какой профиль выбирается.

## 8. Низкая скорость / нестабильный throughput

Проверьте:

- `evasion.strategy` и `prime_mode`;
- `evasion.fragment_*` параметры;
- `download.*` таймауты/конкурентность;
- влияние `traffic_shaping_enabled`.

Для максимальной скорости попробуйте пресет `max-compatibility` — он отключает агрессивные техники:

```bash
prime-net-engine --preset max-compatibility --config prime-net-engine.toml socks
```

## 9. Сайты не открываются, хотя раньше работали

ML-маршрутизатор накапливает историю. Если ISP изменил политику блокировок, старые «победители» могут стать нерабочими.

Статистика обновится автоматически (экспоненциальное затухание, halflife 30 минут). Для немедленного сброса:

```bash
# Удалить файл статистики (путь из evasion.classifier_cache_path):
rm ~/.cache/prime-net-engine/relay-classifier.json
```

## 10. CI падает на `tempfile`/`fmt`

Если ошибка вида `use of unresolved crate tempfile`:

- проверьте, что dependency подключена в `[dependencies]` (не только `dev-dependencies`) для соответствующей feature.

Если падает `cargo fmt --all -- --check`:

- выполните локально `cargo fmt --all` и перезапустите checks.

## 11. Что прикладывать к баг-репорту

- ОС и архитектуру;
- команду запуска;
- редактированный конфиг (без секретов — убрать пароли, cert, сервера PT);
- логи с `--log-level debug --log-format json`;
- при необходимости: browser/network консоль и таймштампы.

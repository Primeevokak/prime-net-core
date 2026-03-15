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

## 5. Нативный bypass не работает / профили не применяются

Нативный bypass встроен в процесс — внешние утилиты (byedpi/ciadpi) для него не нужны.

Проверьте:

- включение `evasion.packet_bypass_enabled = true` в конфиге;
- отсутствие `PRIME_PACKET_BYPASS=0` в окружении;
- что в логах есть строки вида `native desync: applying profile 'tlsrec-into-sni'`.

Для TCP disorder (профили `tcp-disorder-*`) дополнительно требуется:
- **Windows**: `WinDivert.dll` в той же директории, что и `prime-net-engine.exe`, или в `PATH`;
- **Linux**: ядерный модуль `nfqueue` (`modprobe nfnetlink_queue`) и права на создание NFQueue правил.

При отсутствии WinDivert/NFQueue движок автоматически пропустит disorder-профили — остальные 20+ профилей работают без них.

## 6. PT (`obfs4`/`snowflake`) не стартует

Проверьте наличие внешних инструментов:

- `tor`
- `obfs4proxy` (для obfs4)
- `snowflake-client` (для snowflake)

Убедитесь, что пути к бинарям указаны в `[pt.obfs4]` / `[pt.snowflake]` секциях конфига. Для obfs4 поле `cert` обязательно.

## 7. Discord / мессенджеры не работают

Discord использует **QUIC (UDP)** и часто блокируется через RST-инъекцию после TCP-рукопожатия.

**Шаги диагностики:**

1. Убедитесь, что движок запущен и принимает трафик (`proxy status`).

2. Движок автоматически применяет QUIC Initial десинхронизацию — перед реальным QUIC пакетом отправляется ложный Initial с decoy SNI при низком TTL. Дайте ему 1–2 минуты на зондирование профилей.

3. Если Discord зависает в браузере — проверьте, что QUIC отключён в настройках браузера (`chrome://flags/#enable-quic` → Disabled). Для Electron-клиента движок делает это автоматически через UDP ASSOCIATE.

4. Явно задайте Discord маршрут через `routing.domain_profiles`:

```toml
[routing.domain_profiles]
"discord.com"    = "native:tlsrec-into-sni"
"discordapp.com" = "native:tlsrec-into-sni"
"discord.media"  = "native:tlsrec-into-sni"
"discord.gg"     = "native:tlsrec-into-sni"
```

5. Запустите с `--log-level debug` и ищите в логах строки с `discord` — там будет видно, какой профиль выбирается и его результат.

6. Если один профиль не помогает — попробуйте другие:

```toml
"discord.com" = "native:split-into-sni-oob"
# или
"discord.com" = "native:multi-split-sni-region"
```

## 8. Низкая скорость / нестабильный throughput

Проверьте:

- `evasion.strategy` и `prime_mode`;
- `evasion.fragment_*` параметры;
- `download.*` таймауты/конкурентность;
- влияние `traffic_shaping_enabled`.

Для максимальной скорости попробуйте пресет `max-compatibility`:

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

Также можно сбросить кеш автообнаружения профилей:

```bash
rm ~/.local/share/prime-net/profile_wins.json
```

## 10. Профили зондируются слишком долго при запуске

Profile discovery запускается в фоне и не блокирует старт прокси. Результаты предыдущего зондирования кешируются на 24 часа. Если прокси уже слушает — всё работает, discovery продолжается параллельно.

## 11. CI падает на `tempfile`/`fmt`

Если ошибка вида `use of unresolved crate tempfile`:

- проверьте, что dependency подключена в `[dependencies]` (не только `dev-dependencies`) для соответствующей feature.

Если падает `cargo fmt --all -- --check`:

- выполните локально `cargo fmt --all` и перезапустите checks.

## 12. Что прикладывать к баг-репорту

- ОС и архитектуру;
- команду запуска;
- редактированный конфиг (без секретов — убрать пароли, cert, сервера PT);
- логи с `--log-level debug --log-format json`;
- при необходимости: browser/network консоль и таймштампы.

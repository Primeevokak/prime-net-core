# TROUBLESHOOTING

## 1. YouTube / Google сервисы не открываются

YouTube — приоритетная цель DPI (ТСПУ). Простые техники (split, OOB) часто недостаточны.

**Проверьте стартовый отчёт в логах:**

```
WARN  desync: 29/35 desync profiles operational, 6 degraded (install WinDivert)
```

Если видите это предупреждение — WinDivert не установлен, а именно он нужен для YouTube.

**Шаги:**

1. WinDivert должен автоматически скачаться при первом запуске. Если этого не произошло (ошибка сети, права доступа), скачайте вручную:
   - [WinDivert 2.2.2](https://reqrypt.org/windivert.html)
   - Положите `WinDivert.dll` + `WinDivert64.sys` (из `x64/`) рядом с `prime-net-engine.exe`

2. Запускайте **от администратора** — WinDivert загружает kernel driver.

3. После запуска проверьте логи:
   ```
   INFO  desync: packet interceptor loaded (TCP disorder available) backend="WinDivert"
   INFO  desync: all 35 desync profiles fully operational
   ```

4. Если всё равно не работает — закрепите профиль:

```toml
[routing.domain_profiles]
"youtube.com"      = "native:seqovl-681"
"googlevideo.com"  = "native:seqovl-681"
"ytimg.com"        = "native:seqovl-681"
"ggpht.com"        = "native:seqovl-681"
```

5. Альтернативные профили для YouTube: `tcp-disorder-15ms`, `tlsrec-sni-fake-ts-fool`, `chain-fake-split-delay`.

## 2. `SOCKS5 connection refused`

Проверьте, что сервер реально запущен:

```bash
prime-net-engine --config prime-net-engine.toml socks --bind 127.0.0.1:1080
```

Проверьте системный статус:

```bash
prime-net-engine --config prime-net-engine.toml proxy status
```

## 3. `--config-check` падает на DNS/DoH

- Выполните локальную валидацию без сети:

```bash
prime-net-engine --config prime-net-engine.toml --config-check --offline
```

- Проверьте `anticensorship.doh_providers`, `bootstrap_ips`, `dns_fallback_chain`.

## 4. `update install` завершается ошибкой подписи

Частые причины:

- сборка без feature `signature-verification`;
- не настроены release signing key/fingerprint;
- недоступны системные зависимости `gpgme/gpg-error`.

## 5. Нативный bypass не работает / профили не применяются

Проверьте:

- `evasion.packet_bypass_enabled = true` в конфиге;
- отсутствие `PRIME_PACKET_BYPASS=0` в окружении;
- что в логах есть строки вида `native desync: applying profile 'tlsrec-into-sni'`.

**Стартовый отчёт покажет деградированные профили:**

```
WARN  desync: packet interceptor unavailable — 2 profile(s) fall back to plain TCP split
```

Для TCP disorder (профили `tcp-disorder-*`) дополнительно требуется:
- **Windows**: `WinDivert.dll` (авто-загрузка при первом запуске, или вручную);
- **Linux**: ядерный модуль `nfqueue` (`modprobe nfnetlink_queue`).

## 6. WinDivert авто-загрузка не работает

Возможные причины:

- Нет доступа к GitHub (сеть заблокирована до старта прокси);
- Нет прав на запись рядом с `prime-net-engine.exe` (`C:\Program Files\` защищён);
- Антивирус блокирует загрузку `WinDivert64.sys`.

**Решение:** скачайте вручную и положите файлы рядом с бинарником. См. п.1.

В логах ошибка будет выглядеть так:

```
WARN  socks_cmd: WinDivert auto-download failed — TCP disorder and raw injection profiles will run in degraded mode error="download failed: ..."
```

## 7. PT (`obfs4`/`snowflake`) не стартует

Проверьте наличие внешних инструментов:

- `tor`
- `obfs4proxy` (для obfs4)
- `snowflake-client` (для snowflake)

Пути к бинарям указываются в `[pt.obfs4]` / `[pt.snowflake]`. Для obfs4 поле `cert` обязательно.

## 8. Discord / мессенджеры не работают

Discord использует **QUIC (UDP)** и часто блокируется.

1. Движок автоматически применяет QUIC Initial десинхронизацию. Дайте 1–2 минуты на зондирование.

2. Если QUIC в браузере — отключите: `chrome://flags/#enable-quic` → Disabled.

3. Закрепите маршрут:

```toml
[routing.domain_profiles]
"discord.com"    = "native:tlsrec-into-sni"
"discordapp.com" = "native:tlsrec-into-sni"
"discord.media"  = "native:tlsrec-into-sni"
"discord.gg"     = "native:tlsrec-into-sni"
```

4. Альтернативные профили: `split-into-sni-oob`, `multi-split-sni-region`, `chain-split-oob-delay`.

## 9. Низкая скорость / нестабильный throughput

- Проверьте `evasion.fragment_*` параметры;
- Попробуйте пресет `max-compatibility`;
- Отключите `traffic_shaping_enabled` если включён.

## 10. Сайты не открываются, хотя раньше работали

ML-маршрутизатор адаптируется автоматически (halflife 30 минут). Для немедленного сброса:

```bash
# Windows:
del %LOCALAPPDATA%\prime-net-engine\relay-classifier.json

# Linux/macOS:
rm ~/.cache/prime-net-engine/relay-classifier.json
```

Сброс кеша профилей:

```bash
# Windows:
del %LOCALAPPDATA%\prime-net\profile_wins.json

# Linux/macOS:
rm ~/.local/share/prime-net/profile_wins.json
```

## 11. Профили зондируются слишком долго при запуске

Profile discovery не блокирует старт прокси (timeout 10 секунд). Результаты кешируются на 24 часа. Если discovery таймаутит — значит тестовые эндпоинты недоступны; движок работает с дефолтным порядком профилей.

## 12. Kill switch блокирует весь трафик

Если `evasion.kill_switch_enabled = true` и движок упал — kill switch перенаправляет системный прокси на мёртвый порт. Весь трафик блокируется.

Для восстановления:

```bash
prime-net-engine proxy disable
```

Или вручную отключите системный прокси в настройках ОС.

## 13. System proxy не включается

- Проверьте права/политики ОС;
- Формат `system_proxy.socks_endpoint` (`host:port`, для IPv6: `[::1]:port`);
- Что SOCKS endpoint действительно слушает.

## 14. Что прикладывать к баг-репорту

- ОС и архитектуру;
- Вывод стартового отчёта (`INFO/WARN desync: ...`);
- Команду запуска;
- Редактированный конфиг (без секретов);
- Логи с `--log-level debug --log-format json`.

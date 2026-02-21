# USER GUIDE

## Базовый ежедневный сценарий

1. Создать или обновить конфиг:

```bash
prime-net-engine wizard --out prime-net-engine.toml
```

2. Проверить валидность:

```bash
prime-net-engine --config prime-net-engine.toml --config-check
```

3. Поднять локальный SOCKS5:

```bash
prime-net-engine --config prime-net-engine.toml socks --bind 127.0.0.1:1080
```

4. Включить системный прокси:

```bash
prime-net-engine --config prime-net-engine.toml proxy enable --mode all
```

5. Проверить связность:

```bash
prime-net-engine --config prime-net-engine.toml test --url https://example.com
```

## Работа через TUI

Запуск:

```bash
prime-net-engine --config prime-net-engine.toml tui
```

Что обычно делают в TUI:

- вкладка `Конфиг`: редактирование + сохранение (`s`) и reload (`r`);
- вкладка `Прокси`: запуск/остановка ядра (`a`/`x`) и диагностика (`u`);
- вкладка `Логи` (в advanced режиме): фильтры, поиск, экспорт.

## Preset-first сценарий

Если нужно быстро стартовать с понятным профилем:

```bash
prime-net-engine --config prime-net-engine.toml --preset strict-privacy --config-check
```

или

```bash
prime-net-engine --config prime-net-engine.toml --preset aggressive-evasion test --url https://example.com
```

## Blocklist обслуживание

```bash
prime-net-engine --config prime-net-engine.toml blocklist update
prime-net-engine --config prime-net-engine.toml blocklist status
```

## Обновления

Проверка:

```bash
prime-net-engine --config prime-net-engine.toml update check
```

Установка:

```bash
prime-net-engine --config prime-net-engine.toml update install
```

Важно: установка обновления требует успешной проверки подписи. Если сборка без `signature-verification` или в коде не настроен публичный ключ релизов, `update install` завершится ошибкой.

## PT сценарий (Trojan/Shadowsocks/Obfs4/Snowflake)

- настройте секцию `[pt]` в конфиге;
- не задавайте одновременно `[pt]` и `[proxy]`;
- запускайте через `socks`, чтобы движок поднял локальный SOCKS5 endpoint.

Пример запуска:

```bash
prime-net-engine --config prime-net-engine.toml socks --bind 127.0.0.1:1080
```

## Логи для диагностики

```bash
prime-net-engine --config prime-net-engine.toml --log-level debug --log-format json --log-file prime.log test --url https://example.com
```

Дальше: `docs/TROUBLESHOOTING.md`.

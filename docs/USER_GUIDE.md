# USER GUIDE

## Базовый ежедневный сценарий

1. Создать/обновить конфиг:

```bash
prime-net-engine wizard --out prime-net-engine.toml
```

2. Проверить конфиг:

```bash
prime-net-engine --config prime-net-engine.toml --config-check
```

3. Запустить локальный SOCKS5:

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

Обычно в TUI:

- `Config`: правка/сохранение конфигурации;
- `Proxy`: запуск ядра и диагностика прокси;
- `Logs`: фильтры и анализ событий.

## Preset-first сценарии

Строгая приватность:

```bash
prime-net-engine --config prime-net-engine.toml --preset strict-privacy --config-check
```

Агрессивный обход:

```bash
prime-net-engine --config prime-net-engine.toml --preset aggressive-evasion test --url https://example.com
```

## Blocklist обслуживание

```bash
prime-net-engine --config prime-net-engine.toml blocklist update
prime-net-engine --config prime-net-engine.toml blocklist status
```

## Обновления

Проверка доступных релизов:

```bash
prime-net-engine --config prime-net-engine.toml update check
```

Установка:

```bash
prime-net-engine --config prime-net-engine.toml update install
```

Важно: `update install` требует рабочей цепочки signature verification и настроенного release signing key/fingerprint.

## PT сценарий (Trojan/Shadowsocks/Obfs4/Snowflake)

- заполните `[pt]` секцию;
- не задавайте одновременно `[pt]` и `[proxy]`;
- запускайте через `socks`.

## Диагностический запуск с логами

```bash
prime-net-engine --config prime-net-engine.toml --log-level debug --log-format json --log-file prime.log test --url https://example.com
```

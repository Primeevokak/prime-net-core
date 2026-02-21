# Краткий старт (v0.3.0)

Полный практический сценарий: `docs/USER_GUIDE.md`.

## Сборка

```bash
cargo build --release --bin prime-net-engine --bin prime-tui
```

Артефакты:
- `target/release/prime-net-engine`
- `target/release/prime-tui`

## Быстрый старт через TUI (рекомендуется)

1. Запустите:
```bash
prime-net-engine tui
```
2. Переключите режим интерфейса клавишей `m`:
- `Простой` — базовые действия для обычного пользователя.
- `Продвинутый` — все вкладки и тонкая настройка.
3. В разделе `Ядро/Прокси`:
- `a` — включить ядро (системный прокси на `socks_endpoint`).
- `x` — выключить ядро.
- `u` — обновить диагностику.

## Горячие клавиши TUI

- `q` — выход
- `Tab` — следующая вкладка
- `1..4` — перейти на вкладку
- `m` — переключить режим `Простой/Продвинутый`
- `?` — контекстная справка

## CLI путь (без TUI)

```bash
prime-net-engine wizard --out prime-net-engine.toml
prime-net-engine --config prime-net-engine.toml --config-check
prime-net-engine --config prime-net-engine.toml socks --bind 127.0.0.1:1080
prime-net-engine --config prime-net-engine.toml proxy enable --mode all
prime-net-engine --config prime-net-engine.toml test https://example.com --check-leaks
```

## Проверка работы

```bash
prime-net-engine --config prime-net-engine.toml proxy status
prime-net-engine --config prime-net-engine.toml blocklist status
prime-net-engine --config prime-net-engine.toml update check
```

## Если что-то не работает

- `SOCKS5 not running`:
  - `prime-net-engine socks --bind 127.0.0.1:1080`
- PAC проблемы:
  - `prime-net-engine proxy serve-pac --port 8888`
  - `prime-net-engine proxy status`
- Ошибки конфига:
  - откройте TUI > `Конфиг`
  - выберите поле и смотрите встроенную подсказку справа

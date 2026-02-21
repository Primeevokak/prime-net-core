# Руководство пользователя `prime-net-engine` (v0.3.0)

Документ описывает повседневную работу через CLI и TUI.

## 1. Подготовка

Сборка из исходников:

```bash
cargo build --release --bin prime-net-engine --bin prime-tui
```

После сборки бинарники находятся в:
- `target/release/prime-net-engine`
- `target/release/prime-tui`

## 2. Рекомендуемый путь: TUI

Запуск:

```bash
prime-net-engine --config prime-net-engine.toml tui
```

Если конфига нет, сначала создайте его:

```bash
prime-net-engine wizard --out prime-net-engine.toml
```

### Режимы интерфейса

- `Простой` (по умолчанию): только ключевые экраны и базовые настройки.
- `Продвинутый`: полный набор вкладок и детальный контроль.

Переключение режима: `m`.

### Вкладки и действия

- `Конфиг`
  - Редактирование параметров.
  - Справа показывается контекстная подсказка по выбранному пункту.
  - `s` — сохранить, `r` — перезагрузить конфиг, `?` — справка.
- `Ядро/Прокси`
  - `a` — включить ядро (включить системный прокси на endpoint из конфига).
  - `x` — выключить ядро.
  - `u` — обновить диагностику.
- `Монитор` (только в продвинутом)
  - Наблюдение соединений в реальном времени.
- `Логи` (только в продвинутом)
  - Фильтр, поиск, экспорт логов.

### Базовые горячие клавиши

- `q` — выход
- `Tab` — следующая вкладка
- `1..4` — переход на вкладку
- `m` — смена режима интерфейса
- `?` — контекстная справка

## 3. Базовый CLI сценарий

1. Создать конфиг:

```bash
prime-net-engine wizard --out prime-net-engine.toml
```

2. Проверить конфиг:

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
prime-net-engine --config prime-net-engine.toml test https://example.com
```

## 4. Blocklist

Обновить:

```bash
prime-net-engine --config prime-net-engine.toml blocklist update
```

Статус:

```bash
prime-net-engine --config prime-net-engine.toml blocklist status
```

## 5. Обновления приложения

Проверить доступные версии:

```bash
prime-net-engine --config prime-net-engine.toml update check
```

Установить обновление:

```bash
prime-net-engine --config prime-net-engine.toml update install
```

Откат:

```bash
prime-net-engine --config prime-net-engine.toml update rollback
```

## 6. Частые проблемы

- Не включается системный прокси:
  - проверьте права пользователя и политику ОС.
  - выполните `prime-net-engine proxy status`.
- TUI не показывает эффекта от включения ядра:
  - убедитесь, что `socks_endpoint` корректен и сервер SOCKS5 действительно запущен.
- Ошибки в конфиге:
  - откройте `Конфиг` в TUI и посмотрите подсказку справа для выбранного поля.

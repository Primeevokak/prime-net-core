# QUICKSTART

## 1. Сборка

```bash
cargo build --release --bin prime-net-engine --bin prime-tui
```

С TUN/VPN режимом:

```bash
cargo build --release --features tun --bin prime-net-engine
```

Бинарники:

- `target/release/prime-net-engine`
- `target/release/prime-tui`

## 2. Создание конфига

Интерактивно (рекомендуется):

```bash
prime-net-engine wizard --out prime-net-engine.toml
```

## 3. Проверка конфига

Онлайн-валидация + probes:

```bash
prime-net-engine --config prime-net-engine.toml --config-check
```

Офлайн (без сети):

```bash
prime-net-engine --config prime-net-engine.toml --config-check --offline
```

## 4. Запуск локального SOCKS5

```bash
prime-net-engine --config prime-net-engine.toml socks --bind 127.0.0.1:1080
```

При первом запуске движок автоматически зондирует нативные DPI bypass профили против тестовых HTTPS-эндпоинтов и сортирует их по результатам. Это происходит в фоне — прокси доступен сразу.

## 5. Подключение системного прокси

```bash
prime-net-engine --config prime-net-engine.toml proxy enable --mode all
prime-net-engine --config prime-net-engine.toml proxy status
```

## 6. Тест связности

```bash
prime-net-engine --config prime-net-engine.toml test --url https://example.com
```

## 7. Явное закрепление профилей для проблемных доменов

Если ML-маршрутизатор не нашёл рабочий маршрут автоматически, добавьте в конфиг:

```toml
[routing.domain_profiles]
"discord.com"    = "native:tlsrec-into-sni"
"discordapp.com" = "native:tlsrec-into-sni"
"rutracker.org"  = "native:split-into-sni"
```

Список доступных профилей — в `docs/ARCHITECTURE.md` и `README.md`.

## 8. Запуск TUI

```bash
prime-net-engine --config prime-net-engine.toml tui
```

## 9. GUI (графический интерфейс)

Если собран GUI (отдельный проект `prime-gui`):

```bash
cd prime-gui/src-tauri && npx tauri dev
```

Или используйте скомпилированный installer: `Prime_0.1.0_x64-setup.exe`.

## 10. WinDivert (Windows)

На Windows при первом запуске WinDivert 2.2 автоматически скачивается и устанавливается рядом с движком. Это необходимо для полной работы DPI bypass (YouTube, Google).

Если авто-загрузка не сработала — скачайте вручную с [reqrypt.org/windivert.html](https://reqrypt.org/windivert.html) и положите `WinDivert.dll` + `WinDivert64.sys` рядом с `prime-net-engine.exe`.

Запускайте от администратора для работы WinDivert.

## 11. Минимальный preflight перед коммитом

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

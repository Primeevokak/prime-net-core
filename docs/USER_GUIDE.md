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

Агрессивный обход (включает все техники, все DNS-резолверы):

```bash
prime-net-engine --config prime-net-engine.toml --preset aggressive-evasion socks
```

## Ручное закрепление профилей для конкретных доменов

ML-маршрутизатор автоматически находит рабочие профили. Для приоритетных доменов можно закрепить профиль явно — это обходит ML и гарантирует предсказуемый маршрут:

```toml
[routing.domain_profiles]
"discord.com"    = "native:tlsrec-into-sni"
"discordapp.com" = "native:tlsrec-into-sni"
"rutracker.org"  = "native:split-into-sni"
"youtube.com"    = "native:split-into-sni-fake-ttl3"
"github.com"     = "direct"
```

Полный список нативных профилей — в `README.md` и `ARCHITECTURE.md`.

## Сброс ML-статистики

Если ISP изменил политику и старые «победители» перестали работать — экспоненциальное затухание (halflife 30 минут) адаптирует маршрутизатор автоматически. Для немедленного сброса:

```bash
rm ~/.cache/prime-net-engine/relay-classifier.json
```

## Сброс кеша автообнаружения профилей

```bash
rm ~/.local/share/prime-net/profile_wins.json
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

## Kill switch (защита от утечек)

При включении `evasion.kill_switch_enabled = true` движок мониторит SOCKS5 порт. Если движок падает — системный прокси перенаправляется на мёртвый порт, блокируя весь трафик вместо утечки.

```toml
[evasion]
kill_switch_enabled = true
```

Для восстановления после аварии: `prime-net-engine proxy disable`.

## GUI (графический интерфейс)

Проект `prime-gui` (отдельный от движка) предоставляет Tauri-приложение:

1. Скомпилируйте движок: `cargo build --release --bin prime-net-engine`
2. Скопируйте бинарник в `prime-gui/src-tauri/bin/prime-net-engine-x86_64-pc-windows-msvc.exe`
3. Соберите GUI: `cd prime-gui/src-tauri && npx tauri build`
4. Или для разработки: `cd prime-gui && npm run tauri dev`

GUI автоматически запускает движок, показывает логи, статистику, позволяет менять конфиг и применять пресеты.

## Закрепление профилей для YouTube

YouTube требует WinDivert для эффективного обхода. При первом запуске WinDivert скачается автоматически.

Если ML-маршрутизатор не находит рабочий маршрут — закрепите профили:

```toml
[routing.domain_profiles]
"youtube.com"      = "native:seqovl-681"
"googlevideo.com"  = "native:seqovl-681"
"ytimg.com"        = "native:seqovl-681"
```

Профили для YouTube: `seqovl-681`, `tcp-disorder-15ms`, `tlsrec-sni-fake-ts-fool`, `chain-fake-split-delay`.

## PT сценарий (Trojan/Shadowsocks/Obfs4/Snowflake)

- заполните `[pt]` секцию в конфиге;
- не задавайте одновременно `[pt]` и `[proxy]`;
- для obfs4 обязательно поле `cert`;
- для snowflake обязательны `tor_bin` и `snowflake_bin`;
- запускайте через `socks`.

## TUN/VPN режим

Требует компиляции с `--features tun`:

```bash
cargo build --release --features tun
prime-net-engine --config prime-net-engine.toml tun
```

В TUN режиме весь системный трафик проходит через виртуальный сетевой интерфейс — не нужно настраивать каждое приложение отдельно.

## Диагностический запуск с логами

```bash
prime-net-engine --config prime-net-engine.toml \
  --log-level debug --log-format json --log-file prime.log \
  test --url https://example.com --check-leaks
```

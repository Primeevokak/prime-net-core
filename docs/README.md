# Документация `prime-net-engine`

Актуализировано под состояние кода на `2026-04-18`.

## Карта раздела `docs/`

- `docs/QUICKSTART.md` — быстрый запуск CLI/TUI/GUI.
- `docs/USER_GUIDE.md` — рабочие сценарии эксплуатации.
- `docs/EXECUTABLE.md` — полный CLI-референс `prime-net-engine`.
- `docs/CONFIG.md` — структура `EngineConfig`, дефолты, валидации, compatibility-repair.
- `docs/API.md` — публичный Rust API и FFI C ABI.
- `docs/USAGE_SOURCE.md` — интеграция в Rust-проект.
- `docs/USAGE_FFI.md` — интеграция через `include/prime_net.h`.
- `docs/ARCHITECTURE.md` — архитектура pipeline, нативный DPI bypass (35 профилей), WinDivert авто-загрузка, QUIC Initial inject, ML-маршрутизатор, profile discovery, Bloom filter, kill switch, GUI.
- `docs/PRESETS.md` — встроенные пресеты CLI.
- `docs/PRIVACY.md` — privacy middleware и трекер-блокер.
- `docs/TLS_FINGERPRINTING.md` — TLS/JA3 поведение в текущей реализации.
- `docs/SECURITY.md` — модель угроз, нативный bypass trust model, WinDivert auto-download, updater security.
- `docs/TROUBLESHOOTING.md` — типовые проблемы и диагностика (включая YouTube, Discord, QUIC, WinDivert, native bypass).

## Ключевые подсистемы (краткий указатель)

| Подсистема | Источник | Документация |
|---|---|---|
| Нативный DPI bypass (35 профилей) | `src/evasion/tcp_desync.rs` | ARCHITECTURE.md |
| WinDivert авто-загрузка | `src/evasion/packet_intercept/windivert_bootstrap.rs` | ARCHITECTURE.md |
| Стартовый отчёт компонентов | `src/evasion/startup_report.rs` | ARCHITECTURE.md |
| QUIC Initial inject | `src/evasion/quic_initial.rs` | ARCHITECTURE.md |
| Profile auto-discovery | `src/evasion/profile_discovery.rs` | ARCHITECTURE.md |
| TCP disorder (WinDivert/NFQ) | `src/evasion/packet_intercept/` | ARCHITECTURE.md |
| Shadow UCB Bandit | `src/pt/socks5_server/ml_shadow.rs` | ARCHITECTURE.md |
| DNS chain (DoH/DoT/DoQ) | `src/anticensorship/resolver_chain.rs` | CONFIG.md |
| Bloom-фильтр доменов | `src/blocklist/` | ARCHITECTURE.md |
| Kill switch | `src/platform/kill_switch.rs` | ARCHITECTURE.md |
| MTProto WebSocket (Telegram) | `src/pt/mtproto_ws.rs` | CONFIG.md |
| Ad-blocking engine | `src/adblock/` | CONFIG.md |
| C FFI | `src/ffi/mod.rs`, `include/prime_net.h` | API.md, USAGE_FFI.md |
| TUN/VPN режим | `src/bin/prime-net-engine/tun_cmd.rs` | EXECUTABLE.md |
| GUI (Tauri) | `prime-gui/` (отдельный проект) | ARCHITECTURE.md |

## Бинарники

| Бинарник | Назначение |
|---|---|
| `prime-net-engine` | Основной движок (CLI) |
| `prime-tui` | Терминальный UI (TUI) |
| `prime-gui` | Графический интерфейс (Tauri + Svelte, отдельный проект) |

## Базовые проверки перед пушем

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

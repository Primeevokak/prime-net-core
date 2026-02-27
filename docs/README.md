# Документация `prime-net-engine`

Актуализировано под состояние кода на `2026-02-27`.

## Карта раздела `docs/`

- `docs/QUICKSTART.md` - быстрый запуск CLI/TUI.
- `docs/USER_GUIDE.md` - рабочие сценарии эксплуатации.
- `docs/EXECUTABLE.md` - полный CLI-референс `prime-net-engine`.
- `docs/CONFIG.md` - структура `EngineConfig`, дефолты, валидации, compatibility-repair.
- `docs/API.md` - публичный Rust API и FFI C ABI.
- `docs/USAGE_SOURCE.md` - интеграция в Rust-проект.
- `docs/USAGE_FFI.md` - интеграция через `include/prime_net.h`.
- `docs/ARCHITECTURE.md` - архитектура pipeline и основных подсистем.
- `docs/PRESETS.md` - встроенные пресеты CLI.
- `docs/PRIVACY.md` - privacy middleware и трекер-блокер.
- `docs/TLS_FINGERPRINTING.md` - TLS/JA3 поведение в текущей реализации.
- `docs/SECURITY.md` - модель угроз и security-ограничения.
- `docs/TROUBLESHOOTING.md` - типовые проблемы и диагностика.

## Базовые проверки перед пушем

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test -p prime-net-engine --lib --no-run
```

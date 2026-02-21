# Документация

- `docs/QUICKSTART.md` - быстрый старт (TUI/CLI).
- `docs/USER_GUIDE.md` - повседневные сценарии использования.
- `docs/EXECUTABLE.md` - полный CLI-референс `prime-net-engine`.
- `docs/CONFIG.md` - описание `EngineConfig` и всех секций конфига.
- `docs/API.md` - публичный Rust/FFI API.
- `docs/USAGE_SOURCE.md` - интеграция как Rust crate.
- `docs/USAGE_FFI.md` - интеграция через C ABI.
- `docs/ARCHITECTURE.md` - внутренняя архитектура.
- `docs/PRESETS.md` - встроенные пресеты CLI.
- `docs/TLS_FINGERPRINTING.md` - как работает TLS/JA3 fingerprinting на `rustls`.
- `docs/SECURITY.md` - модель безопасности и ограничения.
- `docs/TROUBLESHOOTING.md` - диагностика типовых проблем.
- `docs/PRIME_MODE_IMPLEMENTATION.md` - отчёт по внедрению offline DPI bypass (`prime-mode`).
- `docs/LLM_GUIDE.md` - карта проекта для LLM/AI-ассистентов: структура, инварианты, workflow.

## Актуальные заметки (2026-02-18)

- На Windows `tests/http3_local.rs` отмечен `ignored` из-за нестабильного локального QUIC loopback timeout.
- На Windows `tests/pt_trojan_local.rs` отмечен `ignored` из-за спорадического `early eof` в параллельном CI-прогоне.
- На Windows `websocket::tests::websocket_handshake_and_echo_frames_over_tcp` отмечен `ignored` из-за спорадического reconnect race в параллельном прогоне.
- Live smoke тесты `http3_live`, `obfs4_live`, `snowflake_live`, `trojan_live` отмечены `ignored` по умолчанию.
- `tests/integration/tui_tests.rs` собирается только на Unix (`cfg(unix)`), так как использует Unix PTY (`rexpect`).

set shell := ["powershell", "-NoProfile", "-Command"]

gui     := "../prime-gui"
gui_bin := "../prime-gui/src-tauri/bin/prime-net-engine-x86_64-pc-windows-msvc.exe"

# Собрать движок + скопировать в GUI + запустить dev
dev: _engine _copy
    powershell -NoProfile -File "{{justfile_directory()}}/dev-gui.ps1"

# Только собрать и скопировать движок (без запуска GUI)
engine: _engine _copy

# Собрать движок + полная release сборка GUI (installer)
build: _engine _copy
    powershell -NoProfile -File "{{justfile_directory()}}/build-gui.ps1"

# Быстрая проверка без сборки
check:
    cargo check --all-targets

# Clippy
lint:
    cargo clippy --all-targets -- -D warnings

# Тесты
test:
    cargo test --locked

# ── Внутренние ───────────────────────────────────────────────────────────────

_engine:
    cargo build --release --bin prime-net-engine

_copy:
    Copy-Item target/release/prime-net-engine.exe {{gui_bin}} -Force

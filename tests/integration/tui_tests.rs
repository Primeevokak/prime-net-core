#![cfg(unix)]

use rexpect::spawn;
use std::io::Write;

fn tui_tests_enabled() -> bool {
    std::env::var("PRIME_NET_ENGINE_RUN_TUI_IT").ok().as_deref() == Some("1")
}

fn create_config_file() -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let cfg = toml::to_string_pretty(&prime_net_engine_core::EngineConfig::default()).unwrap();
    f.write_all(cfg.as_bytes()).unwrap();
    f
}

fn command_with_config(cfg_path: &str) -> String {
    let bin = std::env::var("CARGO_BIN_EXE_prime-net-engine")
        .unwrap_or_else(|_| "prime-net-engine".to_owned());
    format!("\"{bin}\" tui --config \"{cfg_path}\"")
}

#[test]
fn test_tui_launches_and_shows_tabs() {
    if !tui_tests_enabled() {
        return;
    }
    let cfg = create_config_file();
    let cmd = command_with_config(cfg.path().to_str().unwrap());
    let mut p = spawn(&cmd, Some(8000)).unwrap();

    p.exp_string("prime-tui").unwrap();
    p.exp_string("1 Config").unwrap();
    p.exp_string("4 Proxy").unwrap();

    p.send("q").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn test_tui_config_navigation() {
    if !tui_tests_enabled() {
        return;
    }
    let cfg = create_config_file();
    let cmd = command_with_config(cfg.path().to_str().unwrap());
    let mut p = spawn(&cmd, Some(8000)).unwrap();

    p.send("1").unwrap();
    p.exp_string("Configuration Editor").unwrap();

    p.send("q").unwrap();
}

#[test]
fn test_tui_proxy_status_screen() {
    if !tui_tests_enabled() {
        return;
    }
    let cfg = create_config_file();
    let cmd = command_with_config(cfg.path().to_str().unwrap());
    let mut p = spawn(&cmd, Some(8000)).unwrap();

    p.send("4").unwrap();
    p.exp_string("System Proxy Settings").unwrap();
    p.exp_regex("(ENABLED|DISABLED)").unwrap();

    p.send("q").unwrap();
}

#[test]
fn test_tui_help_screen() {
    if !tui_tests_enabled() {
        return;
    }
    let cfg = create_config_file();
    let cmd = command_with_config(cfg.path().to_str().unwrap());
    let mut p = spawn(&cmd, Some(8000)).unwrap();

    p.send("?").unwrap();
    p.exp_string("Help").unwrap();
    p.exp_string("Keyboard Shortcuts").unwrap();

    p.send(" ").unwrap();
    p.exp_string("prime-tui").unwrap();

    p.send("q").unwrap();
}

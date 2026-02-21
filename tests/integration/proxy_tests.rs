use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use std::net::TcpListener;
use std::process::Command as ProcessCommand;
use std::thread;
use std::time::Duration;

fn destructive_proxy_tests_enabled() -> bool {
    std::env::var("PRIME_NET_ENGINE_RUN_PROXY_IT")
        .ok()
        .as_deref()
        == Some("1")
}

#[test]
fn test_proxy_enable_with_socks5_running() {
    if !destructive_proxy_tests_enabled() {
        return;
    }

    let mut socks_child = ProcessCommand::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["socks", "--bind", "127.0.0.1:9999"])
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_secs(2));
    assert!(
        TcpListener::bind("127.0.0.1:9999").is_err(),
        "Port should be in use"
    );

    AssertCommand::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["proxy", "enable", "--mode", "all"])
        .assert()
        .success();

    AssertCommand::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["proxy", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ENABLED").or(predicate::str::contains("enabled")));

    AssertCommand::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["proxy", "disable"])
        .assert()
        .success();

    let _ = socks_child.kill();
    let _ = socks_child.wait();
}

#[test]
fn test_proxy_pac_mode_serves_pac_file() {
    let mut pac_child = ProcessCommand::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["proxy", "serve-pac", "--port", "9998"])
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_secs(2));

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get("http://127.0.0.1:9998/proxy.pac")
        .send()
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().unwrap();
    assert!(body.contains("FindProxyForURL"));
    assert!(body.contains("SOCKS5"));

    let _ = pac_child.kill();
    let _ = pac_child.wait();
}

#[test]
fn test_proxy_enable_without_socks5_shows_warning() {
    if !destructive_proxy_tests_enabled() {
        return;
    }

    let output = AssertCommand::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["proxy", "enable", "--mode", "all"])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_ascii_lowercase().contains("warning") || stderr.contains("SOCKS5"),
        "Should warn about missing SOCKS5 server"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn test_windows_registry_modifications() {
    if !destructive_proxy_tests_enabled() {
        return;
    }

    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let internet_settings = hkcu
        .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
        .unwrap();
    let original_enable: u32 = internet_settings.get_value("ProxyEnable").unwrap_or(0);

    AssertCommand::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["proxy", "enable", "--mode", "all"])
        .assert()
        .success();

    let current_enable: u32 = internet_settings.get_value("ProxyEnable").unwrap();
    assert_eq!(current_enable, 1);

    AssertCommand::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["proxy", "disable"])
        .assert()
        .success();

    let restored_enable: u32 = internet_settings.get_value("ProxyEnable").unwrap_or(0);
    assert_eq!(restored_enable, original_enable);
}

#[test]
fn test_proxy_status_shows_diagnostics() {
    AssertCommand::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["proxy", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SOCKS5").or(predicate::str::contains("socks")))
        .stdout(
            predicate::str::contains("listening")
                .or(predicate::str::contains("not running"))
                .or(predicate::str::contains("responding")),
        );
}

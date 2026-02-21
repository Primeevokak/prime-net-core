use assert_cmd::Command;
use mockito::Server;
use predicates::prelude::*;
use serde_json::json;
use std::fs;

fn write_config(cache_path: &std::path::Path) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    let cfg = format!(
        r#"
[blocklist]
enabled = true
source = "https://example.com/dump.csv"
auto_update = true
update_interval_hours = 24
cache_path = "{}"
"#,
        cache_path.display().to_string().replace('\\', "\\\\")
    );
    std::io::Write::write_all(&mut file, cfg.as_bytes()).unwrap();
    file
}

#[test]
fn test_blocklist_download_and_cache() {
    let mut server = Server::new();
    let mock = server
        .mock("GET", "/dump.csv")
        .with_status(200)
        .with_header("content-type", "text/csv")
        .with_body("blocked.com;reason;date\ncensored.net;reason;date\ntest.ru;reason;date")
        .create();

    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("blocklist.json");
    let cfg = write_config(&cache_path);

    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args([
            "--config",
            cfg.path().to_str().unwrap(),
            "blocklist",
            "update",
            "--source",
            &format!("{}/dump.csv", server.url()),
        ])
        .assert()
        .success();

    mock.assert();
    assert!(cache_path.exists(), "Cache file should exist");

    let cached = fs::read_to_string(cache_path).unwrap();
    assert!(cached.contains("blocked.com"));
    assert!(cached.contains("censored.net"));
    assert!(cached.contains("test.ru"));
}

#[test]
fn test_blocklist_status_shows_count() {
    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["blocklist", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("domains"));
}

#[test]
fn test_blocklist_update_with_invalid_url() {
    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args([
            "blocklist",
            "update",
            "--source",
            "https://invalid-url-that-does-not-exist.com/dump.csv",
        ])
        .assert()
        .failure();
}

#[test]
fn test_pac_generation_includes_blocklist() {
    let mut server = Server::new();
    let mock = server
        .mock("GET", "/dump.csv")
        .with_status(200)
        .with_body("blocked.com;reason;date\ncensored.net;reason;date")
        .create();

    let temp_dir = tempfile::tempdir().unwrap();
    let cache_path = temp_dir.path().join("blocklist.json");
    let cfg = write_config(&cache_path);

    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args([
            "--config",
            cfg.path().to_str().unwrap(),
            "blocklist",
            "update",
            "--source",
            &format!("{}/dump.csv", server.url()),
        ])
        .assert()
        .success();
    mock.assert();

    let pac_path = temp_dir.path().join("proxy.pac");
    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args([
            "--config",
            cfg.path().to_str().unwrap(),
            "proxy",
            "generate-pac",
            "--output",
            pac_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let pac_content = fs::read_to_string(pac_path).unwrap();
    assert!(pac_content.contains("FindProxyForURL"));
    assert!(pac_content.contains("blocked.com") || pac_content.contains("*.blocked.com"));
    assert!(pac_content.contains("censored.net") || pac_content.contains("*.censored.net"));
}

#[test]
fn test_blocklist_cache_expiry() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cache_path = temp_dir.path().join("blocklist.json");
    let cfg = write_config(&cache_path);

    let old_data = json!({
        "domains": ["old.com"],
        "updated_at": "2020-01-01T00:00:00Z"
    });
    fs::write(&cache_path, old_data.to_string()).unwrap();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args([
            "--config",
            cfg.path().to_str().unwrap(),
            "blocklist",
            "status",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("outdated") || stdout.contains("old") || stdout.contains("update"),
        "Should indicate cache is old"
    );
}

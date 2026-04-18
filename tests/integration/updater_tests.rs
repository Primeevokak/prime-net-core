use assert_cmd::Command;
use mockito::Server;
use predicates::prelude::*;
use serde_json::json;

fn write_config(repo: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
    let cfg = format!(
        r#"
[updater]
enabled = true
auto_check = true
check_interval_hours = 24
repo = "{repo}"
channel = "Stable"
"#
    );
    std::io::Write::write_all(&mut file, cfg.as_bytes()).unwrap();
    file
}

#[test]
fn test_update_check_finds_new_version() {
    let mut server = Server::new();
    let cfg = write_config("user/prime-net-engine");
    let mock = server
        .mock("GET", "/repos/user/prime-net-engine/releases/latest")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "tag_name": "v99.0.0",
                "name": "Release 99.0.0",
                "prerelease": false,
                "assets": [{
                    "name": "prime-net-engine-linux-x64",
                    "browser_download_url": format!("{}/download/binary", server.url()),
                }]
            })
            .to_string(),
        )
        .create();

    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .env("GITHUB_API_URL", server.url())
        .args(["--config", cfg.path().to_str().unwrap(), "update", "check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("99.0.0"));

    mock.assert();
}

#[test]
fn test_update_check_no_updates_available() {
    let mut server = Server::new();
    let cfg = write_config("user/prime-net-engine");
    let current_version = env!("CARGO_PKG_VERSION");
    let mock = server
        .mock("GET", "/repos/user/prime-net-engine/releases/latest")
        .with_status(200)
        .with_body(
            json!({
                "tag_name": format!("v{}", current_version),
                "name": format!("Release {}", current_version),
                "prerelease": false,
            })
            .to_string(),
        )
        .create();

    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .env("GITHUB_API_URL", server.url())
        .args(["--config", cfg.path().to_str().unwrap(), "update", "check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("up to date").or(predicate::str::contains("latest")));

    mock.assert();
}

#[test]
fn test_update_check_network_error() {
    let cfg = write_config("user/prime-net-engine");
    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .env("GITHUB_API_URL", "https://invalid-url-12345.com")
        .args(["--config", cfg.path().to_str().unwrap(), "update", "check"])
        .assert()
        .failure();
}

#[test]
fn test_update_check_respects_channel() {
    let mut server = Server::new();
    let cfg = write_config("user/prime-net-engine");
    let mock = server
        .mock("GET", "/repos/user/prime-net-engine/releases")
        .with_status(200)
        .with_body(
            json!([
                {"tag_name": "v0.3.0", "prerelease": false},
                {"tag_name": "v0.3.0-beta.1", "prerelease": true},
                {"tag_name": "v0.2.0", "prerelease": false},
            ])
            .to_string(),
        )
        .create();

    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .env("GITHUB_API_URL", server.url())
        .args([
            "--config",
            cfg.path().to_str().unwrap(),
            "update",
            "check",
            "--channel",
            "beta",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("beta"));

    mock.assert();
}

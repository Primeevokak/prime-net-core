use assert_cmd::Command;
use predicates::prelude::*;
use std::thread;
use tiny_http::{Response, Server};

fn start_http_server() -> String {
    let server = Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_string();
    thread::spawn(move || {
        if let Ok(req) = server.recv() {
            let response = Response::from_string("ok");
            let _ = req.respond(response);
        }
    });
    format!("http://{addr}/")
}

#[test]
fn test_connectivity_check_success() {
    let url = start_http_server();
    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["test", &url])
        .assert()
        .success()
        .stdout(predicate::str::contains("DNS Resolution"))
        .stdout(predicate::str::contains("TLS Handshake"))
        .stdout(predicate::str::contains("HTTP Request"));
}

#[test]
fn test_connectivity_check_with_preset() {
    let url = start_http_server();
    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["--preset", "max-compatibility", "test", &url])
        .assert()
        .success();
}

#[test]
fn test_connectivity_check_invalid_url() {
    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["test", "not-a-valid-url"])
        .assert()
        .failure();
}

#[test]
fn test_connectivity_check_with_leak_detection() {
    let url = start_http_server();
    Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["test", &url, "--check-leaks"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DNS leak").or(predicate::str::contains("IP leak")));
}

#[test]
fn test_connectivity_shows_timing() {
    let url = start_http_server();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("prime-net-engine"))
        .args(["test", &url])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ms") || stdout.contains("seconds") || stdout.contains("Time"));
}

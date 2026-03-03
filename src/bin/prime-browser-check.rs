use std::process::Stdio;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::env;
use tokio::process::Command;
use tokio::io::{BufReader, AsyncBufReadExt};

fn find_chrome() -> Option<PathBuf> {
    let paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ];
    for p in paths {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let chrome_path = find_chrome().expect("Chrome not found in standard paths!");
    println!("Found Chrome at: {:?}", chrome_path);

    let current_dir = env::current_dir()?;
    let engine_bin = current_dir.join("target").join("release").join("prime-net-engine.exe");
    
    if !engine_bin.exists() {
        println!("Engine binary not found! Building it first...");
        let status = std::process::Command::new("cargo")
            .args(["build", "--release", "--bin", "prime-net-engine"])
            .status()?;
        if !status.success() {
            panic!("Failed to build engine");
        }
    }

    println!("Starting Prime Net Engine on 127.0.0.1:1080 with aggressive-evasion preset...");
    let mut engine_child = Command::new(&engine_bin)
        .args(["--preset", "aggressive-evasion", "socks", "--bind", "127.0.0.1:1080"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stderr = engine_child.stderr.take().unwrap();
    let reader = BufReader::new(stderr);
    let mut lines = reader.lines();

    tokio::time::sleep(Duration::from_secs(5)).await;

    let args: Vec<String> = env::args().collect();
    let test_url = args.get(1).map(|s| s.as_str()).unwrap_or("https://www.youtube.com");
    println!("Launching Chrome to visit: {}", test_url);

    let user_data_dir = current_dir.join("target").join("chrome-test-profile");
    if !user_data_dir.exists() {
        std::fs::create_dir_all(&user_data_dir)?;
    }
    let user_data_str = user_data_dir.to_str().unwrap();

    let mut browser_child = Command::new(chrome_path)
        .args([
            &format!("--proxy-server=socks5://127.0.0.1:1080"),
            &format!("--user-data-dir={}", user_data_str),
            "--incognito",
            "--no-first-run",
            "--no-default-browser-check",
            test_url,
        ])
        .spawn()?;

    println!("Monitoring engine logs for activity (timeout 60s)...");
    let start_time = Instant::now();
    let mut success = false;
    let mut connection_seen = false;
    let mut data_flowing = false;

    loop {
        let timeout_check = tokio::time::timeout(Duration::from_millis(100), lines.next_line());
        
        match timeout_check.await {
            Ok(Ok(Some(line))) => {
                println!("  [ENGINE] {}", line);
                if line.contains("starting route selection") || line.contains("SOCKS5 connection") || line.contains("trying route candidate") {
                    connection_seen = true;
                }
                if line.contains("won the race!") || line.contains("relay_bidirectional") || line.contains("session finished normally") {
                    data_flowing = true;
                }
                if connection_seen && data_flowing {
                    success = true;
                    println!("\n=== BROWSER TEST PASSED SUCCESSFULLY ===");
                    break;
                }
            },
            Ok(Ok(None)) => break,
            Ok(Err(_)) => break,
            Err(_) => {}
        }

        if start_time.elapsed() > Duration::from_secs(60) {
            println!("\n=== BROWSER TEST TIMED OUT (60s reached) ===");
            break;
        }
    }

    println!("Terminating processes...");
    let _ = browser_child.kill().await;
    let _ = engine_child.kill().await;
    
    if success {
        println!("Result: SUCCESS");
        std::process::exit(0);
    } else {
        println!("Result: FAILURE");
        std::process::exit(1);
    }
}

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use prime_net_engine_core::{EngineConfig, PrimeHttpClient, RequestData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn parse_headers(req: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in req.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            out.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    out
}

fn parse_range(value: &str) -> Option<(u64, Option<u64>)> {
    // bytes=START-END or bytes=START-
    let v = value.trim();
    let rest = v.strip_prefix("bytes=")?;
    let (a, b) = rest.split_once('-')?;
    let start = a.parse::<u64>().ok()?;
    let end = if b.trim().is_empty() {
        None
    } else {
        Some(b.parse::<u64>().ok()?)
    };
    Some((start, end))
}

#[tokio::test]
async fn download_to_path_supports_chunked_and_resume_parts() {
    let total_len: usize = 2 * 1024 * 1024; // 2 MiB
    let mut data = vec![0u8; total_len];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let range_gets = Arc::new(AtomicUsize::new(0));
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let data_arc = Arc::new(data);

    let server = {
        let range_gets = range_gets.clone();
        let data_arc = data_arc.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() { break; }
                    }
                    accept = listener.accept() => {
                        let (mut sock, _) = match accept {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let range_gets = range_gets.clone();
                        let data_arc = data_arc.clone();
                        tokio::spawn(async move {
                            // Read until headers end.
                            let mut buf = Vec::new();
                            let mut tmp = [0u8; 4096];
                            loop {
                                let n = sock.read(&mut tmp).await.ok().unwrap_or(0);
                                if n == 0 {
                                    return;
                                }
                                buf.extend_from_slice(&tmp[..n]);
                                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                                if buf.len() > 64 * 1024 {
                                    return;
                                }
                            }

                            let text = String::from_utf8_lossy(&buf);
                            let mut lines = text.split("\r\n");
                            let request_line = lines.next().unwrap_or_default();
                            let mut parts = request_line.split_whitespace();
                            let method = parts.next().unwrap_or("");

                            let headers = parse_headers(&text);
                            let range = headers.get("range").and_then(|v| parse_range(v));

                            if method == "HEAD" {
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                                    data_arc.len()
                                );
                                let _ = sock.write_all(resp.as_bytes()).await;
                                let _ = sock.shutdown().await;
                                return;
                            }

                            if method == "GET" {
                                if let Some((start, end_opt)) = range {
                                    range_gets.fetch_add(1, Ordering::Relaxed);
                                    let end = end_opt.unwrap_or((data_arc.len() as u64).saturating_sub(1));
                                    let start_u = start as usize;
                                    let end_u = end as usize;
                                    if start_u >= data_arc.len() || end_u >= data_arc.len() || start_u > end_u {
                                        let resp = "HTTP/1.1 416 Range Not Satisfiable\r\nConnection: close\r\n\r\n";
                                        let _ = sock.write_all(resp.as_bytes()).await;
                                        let _ = sock.shutdown().await;
                                        return;
                                    }

                                    let slice = &data_arc[start_u..=end_u];
                                    let resp = format!(
                                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                                        slice.len(),
                                        start,
                                        end,
                                        data_arc.len()
                                    );
                                    let _ = sock.write_all(resp.as_bytes()).await;
                                    let _ = sock.write_all(slice).await;
                                    let _ = sock.shutdown().await;
                                    return;
                                }

                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                                    data_arc.len()
                                );
                                let _ = sock.write_all(resp.as_bytes()).await;
                                let _ = sock.write_all(&data_arc[..]).await;
                                let _ = sock.shutdown().await;
                                return;
                            }

                            let resp = "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n";
                            let _ = sock.write_all(resp.as_bytes()).await;
                            let _ = sock.shutdown().await;
                        });
                    }
                }
            }
        })
    };

    let out_dir = PathBuf::from(".tmp_test");
    std::fs::create_dir_all(&out_dir).expect("create out dir");
    let out_path = out_dir.join("download.bin");

    // Force chunking for this test by using 1 MiB chunks.
    let mut cfg = EngineConfig::default();
    cfg.download.chunk_size_mb = 1;
    cfg.download.initial_concurrency = 2;
    cfg.download.max_concurrency = 2;
    let client = PrimeHttpClient::new(cfg).expect("client");

    // Pre-create the first part so the engine should resume (skip it).
    let parts_dir = PathBuf::from(format!("{}.prime.parts", out_path.to_string_lossy()));
    std::fs::create_dir_all(&parts_dir).expect("create parts dir");
    let first_part_path = parts_dir.join("00000000.part");
    std::fs::write(&first_part_path, &data_arc[..1024 * 1024]).expect("write first part");

    let url = format!("http://{addr}/file");
    let outcome = client
        .download_to_path(RequestData::get(url), &out_path, None)
        .await
        .expect("download");

    assert!(outcome.chunked);
    assert!(outcome.resumed);
    assert_eq!(outcome.bytes_written as usize, total_len);
    let got = std::fs::read(&out_path).expect("read downloaded file");
    assert_eq!(got, &data_arc[..]);

    // Stop server.
    let _ = stop_tx.send(true);
    let _ = server.await;

    let _ = std::fs::remove_dir_all(&out_dir);
}

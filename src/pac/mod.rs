use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tiny_http::{Response, Server};

use crate::error::{EngineError, Result};

pub struct PacGenerator {
    pub blocked_domains: Vec<String>,
    pub socks_endpoint: String,
}

impl PacGenerator {
    pub fn generate_pac_script(&self) -> String {
        let mut out = String::new();
        out.push_str("function FindProxyForURL(url, host) {\n");
        out.push_str("    var blocked = [\n");
        for d in &self.blocked_domains {
            out.push_str(&format!("        \"{}\",\n", escape_js(d)));
        }
        out.push_str("    ];\n\n");
        out.push_str("    for (var i = 0; i < blocked.length; i++) {\n");
        out.push_str("        if (shExpMatch(host, blocked[i])) {\n");
        out.push_str(&format!(
            "            return \"SOCKS5 {}; DIRECT\";\n",
            self.socks_endpoint
        ));
        out.push_str("        }\n");
        out.push_str("    }\n\n");
        out.push_str("    return \"DIRECT\";\n");
        out.push_str("}\n");
        out
    }

    pub fn serve_pac(&self, port: u16) -> Result<PacServer> {
        let server = Server::http(("127.0.0.1", port))
            .map_err(|e| EngineError::Internal(format!("pac server failed: {e}")))?;
        let script = self.generate_pac_script();
        let running = Arc::new(AtomicBool::new(true));
        let running2 = Arc::clone(&running);
        let handle = thread::spawn(move || {
            while running2.load(Ordering::Relaxed) {
                match server.recv_timeout(Duration::from_millis(200)) {
                    Ok(Some(req)) => {
                        if req.url() == "/proxy.pac" {
                            let mut response =
                                Response::from_string(script.clone()).with_status_code(200);
                            if let Ok(h) = tiny_http::Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/x-ns-proxy-autoconfig"[..],
                            ) {
                                response = response.with_header(h);
                            }
                            let _ = req.respond(response);
                        } else {
                            let _ = req
                                .respond(Response::from_string("not found").with_status_code(404));
                        }
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        });

        Ok(PacServer {
            running,
            handle: Some(handle),
            port,
        })
    }
}

pub struct PacServer {
    running: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    port: u16,
}

impl PacServer {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for PacServer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn escape_js(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

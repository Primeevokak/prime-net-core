//! Built-in MTProto-over-WebSocket proxy for Telegram.
//!
//! Telegram's IP ranges (149.154.x.x, 91.105.x.x) are blocked at ISP level in
//! some regions.  This proxy tunnels MTProto obfuscated traffic through
//! `kws{N}.web.telegram.org` (served via Cloudflare CDN), which remains reachable
//! even when direct Telegram IPs are blocked.
//!
//! Configure Telegram Desktop with:
//! ```text
//! tg://proxy?server=127.0.0.1&port=1443&secret=dd{secret_hex}
//! ```
//! The `dd` prefix selects padded-intermediate transport (recommended).

mod handshake;
mod relay;

pub use handshake::{AesCtr, MtProtoTransport, ParsedInit};

use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::config::MtprotoWsConfig;
use crate::error::{EngineError, Result};

/// Start the MTProto WebSocket proxy server and return the `tg://` deep-link.
///
/// Spawns a Tokio task that accepts connections indefinitely.  The returned
/// string can be shown to the user so they can configure Telegram Desktop.
pub async fn start_mtproto_ws_proxy(cfg: &MtprotoWsConfig) -> Result<String> {
    let secret = resolve_secret(cfg);
    let port = listen_port(&cfg.listen_addr);
    let link = format!("tg://proxy?server=127.0.0.1&port={port}&secret=dd{secret}");

    let listener = TcpListener::bind(&cfg.listen_addr)
        .await
        .map_err(EngineError::Io)?;
    info!(addr = %cfg.listen_addr, "MTProto WS proxy listening");

    let cfg = Arc::new(cfg.clone());
    let secret_bytes = Arc::new(
        hex::decode(&secret)
            .map_err(|_| EngineError::Internal("MTProto secret is not valid hex".to_owned()))?,
    );

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let cfg = cfg.clone();
                    let secret = secret_bytes.clone();
                    tokio::spawn(async move {
                        if let Err(e) = relay::handle_connection(stream, &cfg, &secret).await {
                            warn!(peer = %peer, error = %e, "MTProto WS proxy connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "MTProto WS proxy accept error");
                }
            }
        }
    });

    Ok(link)
}

/// Resolve the proxy secret from config, auto-generating one if the configured
/// value is missing or not a valid 32-character hex string.
fn resolve_secret(cfg: &MtprotoWsConfig) -> String {
    if cfg.secret_hex.len() == 32 && cfg.secret_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return cfg.secret_hex.clone();
    }
    // Auto-generate a random 16-byte secret (not persisted).
    let mut bytes = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut bytes[..]);
    hex::encode(bytes)
}

/// Extract the port number from a `"host:port"` listen address string.
fn listen_port(addr: &str) -> u16 {
    addr.rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(1443)
}

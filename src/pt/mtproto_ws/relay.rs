//! WebSocket server connection and bidirectional MTProto relay.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::config::MtprotoWsConfig;
use crate::error::{EngineError, Result};

use super::handshake::{parse_init, AesCtr, MtProtoTransport};

/// Maximum allowed size for a single WS frame or MTProto packet (16 MiB).
///
/// Prevents OOM when a malicious or broken peer sends an absurdly large length.
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Telegram DC fallback IPs used when DNS resolution of the CF proxy domain fails.
const DC_IPS: &[(i16, &str)] = &[
    (1, "149.154.175.50"),
    (2, "149.154.167.51"),
    (3, "149.154.175.100"),
    (4, "149.154.167.91"),
    (5, "149.154.171.5"),
    (203, "91.105.192.100"),
];

/// Handle a single client connection from Telegram Desktop.
///
/// Reads the 64-byte MTProto obfuscated init packet, connects to the appropriate
/// Telegram DC via WSS, and relays data bidirectionally.
pub async fn handle_connection(
    mut client: TcpStream,
    cfg: &MtprotoWsConfig,
    secret: &[u8],
) -> Result<()> {
    // Read the 64-byte MTProto obfuscated init packet from Telegram Desktop.
    let mut raw_init = [0u8; 64];
    tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        client.read_exact(&mut raw_init),
    )
    .await
    .map_err(|_| EngineError::Internal("MTProto init read timed out".to_owned()))?
    .map_err(EngineError::Io)?;

    let client_init = parse_init(&raw_init, secret).ok_or_else(|| {
        EngineError::Internal("unknown MTProto proto tag in client init".to_owned())
    })?;

    let dc_abs = client_init.dc_id.unsigned_abs() as u8;
    debug!(dc = dc_abs, transport = ?client_init.transport, "MTProto WS relay starting");

    // Build target host + SNI for the outbound WebSocket connection.
    let (target_host, sni_host) = if cfg.cf_proxy_enabled {
        let sni = format!("kws{}.{}", dc_abs, cfg.cf_proxy_domain);
        (sni.clone(), sni)
    } else {
        let sni = format!("kws{}.web.telegram.org", dc_abs);
        let ip = dc_ip(client_init.dc_id)
            .ok_or_else(|| EngineError::Internal(format!("unknown Telegram DC {dc_abs}")))?;
        (ip.to_owned(), sni)
    };

    // Connect to the Telegram server via WSS.
    let mut server = connect_wss(&target_host, &sni_host).await?;

    // Generate a fresh 64-byte server init (padded intermediate, same DC).
    // An empty secret means no key derivation from a proxy secret on the server leg.
    let server_init_raw = make_server_init(client_init.dc_id);
    let server_init = parse_init(&server_init_raw, &[]).ok_or_else(|| {
        EngineError::Internal("self-generated MTProto server init has invalid proto tag".to_owned())
    })?;

    // Send the fresh init as the first WebSocket binary frame.
    let frame = ws_frame_masked(&server_init_raw);
    server.write_all(&frame).await.map_err(EngineError::Io)?;

    // Set up four AES-CTR cipher contexts — one per direction per leg.
    let mut client_cs = AesCtr::new(&client_init.cs_key, &client_init.cs_iv); // decrypt from client
    let mut client_sc = AesCtr::new(&client_init.sc_key, &client_init.sc_iv); // encrypt to client
    let mut server_cs = AesCtr::new(&server_init.cs_key, &server_init.cs_iv); // encrypt to server
    let mut server_sc = AesCtr::new(&server_init.sc_key, &server_init.sc_iv); // decrypt from server

    let transport = client_init.transport;

    let (mut client_r, mut client_w) = client.into_split();
    let (mut server_r, mut server_w) = tokio::io::split(server);

    let c2s = async {
        loop {
            let pkt = read_mtproto_packet(&mut client_r, transport, &mut client_cs).await?;
            let encrypted = server_cs.process(&pkt);
            let frame = ws_frame_masked(&encrypted);
            server_w.write_all(&frame).await.map_err(EngineError::Io)?;
        }
        #[allow(unreachable_code)]
        Ok::<(), EngineError>(())
    };

    let s2c = async {
        loop {
            let mut frame_payload = read_ws_frame(&mut server_r).await?;
            server_sc.apply(&mut frame_payload);
            let wrapped = wrap_for_client(transport, &frame_payload, &mut client_sc);
            client_w
                .write_all(&wrapped)
                .await
                .map_err(EngineError::Io)?;
        }
        #[allow(unreachable_code)]
        Ok::<(), EngineError>(())
    };

    tokio::select! {
        r = c2s => r,
        r = s2c => r,
    }
}

// ── MTProto packet I/O ────────────────────────────────────────────────────────

/// Read one MTProto packet from `r`, decrypting it with `cs`.
async fn read_mtproto_packet<R: AsyncRead + Unpin>(
    r: &mut R,
    transport: MtProtoTransport,
    cs: &mut AesCtr,
) -> Result<Vec<u8>> {
    match transport {
        MtProtoTransport::Abridged => {
            let mut b = [0u8; 1];
            r.read_exact(&mut b).await.map_err(EngineError::Io)?;
            cs.apply(&mut b);
            let len = if b[0] < 0x7F {
                b[0] as usize * 4
            } else {
                let mut ext = [0u8; 3];
                r.read_exact(&mut ext).await.map_err(EngineError::Io)?;
                cs.apply(&mut ext);
                (u32::from_le_bytes([ext[0], ext[1], ext[2], 0]) as usize) * 4
            };
            if len > MAX_FRAME_SIZE {
                return Err(EngineError::Internal(format!(
                    "MTProto abridged packet too large: {len} bytes (max {MAX_FRAME_SIZE})"
                )));
            }
            let mut data = vec![0u8; len];
            r.read_exact(&mut data).await.map_err(EngineError::Io)?;
            cs.apply(&mut data);
            Ok(data)
        }
        MtProtoTransport::Intermediate => {
            let mut hdr = [0u8; 4];
            r.read_exact(&mut hdr).await.map_err(EngineError::Io)?;
            cs.apply(&mut hdr);
            let len = u32::from_le_bytes(hdr) as usize;
            if len > MAX_FRAME_SIZE {
                return Err(EngineError::Internal(format!(
                    "MTProto intermediate packet too large: {len} bytes \
                     (max {MAX_FRAME_SIZE})"
                )));
            }
            let mut data = vec![0u8; len];
            r.read_exact(&mut data).await.map_err(EngineError::Io)?;
            cs.apply(&mut data);
            Ok(data)
        }
        MtProtoTransport::Padded => {
            let mut hdr = [0u8; 4];
            r.read_exact(&mut hdr).await.map_err(EngineError::Io)?;
            cs.apply(&mut hdr);
            let raw_len = u32::from_le_bytes(hdr);
            let has_padding = (raw_len & 0x8000_0000) != 0;
            let data_len = (raw_len & 0x7FFF_FFFF) as usize;
            if data_len > MAX_FRAME_SIZE {
                return Err(EngineError::Internal(format!(
                    "MTProto padded packet too large: {data_len} bytes \
                     (max {MAX_FRAME_SIZE})"
                )));
            }
            let mut data = vec![0u8; data_len];
            r.read_exact(&mut data).await.map_err(EngineError::Io)?;
            cs.apply(&mut data);
            // If the padding bit is set, the last byte indicates how many padding
            // bytes are appended; strip them so the upstream sees clean payload.
            if has_padding && data_len >= 1 {
                let pad_len = data[data_len - 1] as usize % 16;
                let real_len = data_len.saturating_sub(pad_len);
                data.truncate(real_len);
            }
            Ok(data)
        }
    }
}

/// Wrap a raw MTProto payload for the client transport, prepending the length
/// header and encrypting the whole output with `sc`.
fn wrap_for_client(transport: MtProtoTransport, payload: &[u8], sc: &mut AesCtr) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 8);
    match transport {
        MtProtoTransport::Abridged => {
            let words = payload.len() / 4;
            if words < 0x7F {
                let mut h = [words as u8];
                sc.apply(&mut h);
                out.extend_from_slice(&h);
            } else {
                let mut h = [
                    0x7Fu8,
                    (words & 0xFF) as u8,
                    ((words >> 8) & 0xFF) as u8,
                    ((words >> 16) & 0xFF) as u8,
                ];
                sc.apply(&mut h);
                out.extend_from_slice(&h);
            }
        }
        MtProtoTransport::Intermediate => {
            let mut hdr = (payload.len() as u32).to_le_bytes();
            sc.apply(&mut hdr);
            out.extend_from_slice(&hdr);
        }
        MtProtoTransport::Padded => {
            // Top bit = 0: no padding added when sending to client.
            let mut hdr = (payload.len() as u32).to_le_bytes();
            sc.apply(&mut hdr);
            out.extend_from_slice(&hdr);
        }
    }
    let mut enc_payload = payload.to_vec();
    sc.apply(&mut enc_payload);
    out.extend_from_slice(&enc_payload);
    out
}

// ── WebSocket frame I/O ───────────────────────────────────────────────────────

/// Encode `payload` as a masked WebSocket binary frame (client→server direction).
fn ws_frame_masked(payload: &[u8]) -> Vec<u8> {
    let mask_key: [u8; 4] = rand::thread_rng().gen();
    let len = payload.len();
    let mut out = Vec::with_capacity(len + 14);
    out.push(0x82); // FIN=1, opcode=2 (binary)
    if len < 126 {
        out.push(0x80 | len as u8); // MASK=1
    } else if len < 65536 {
        out.push(0xFE); // MASK=1, len=126
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0xFF); // MASK=1, len=127
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask_key);
    for (i, &b) in payload.iter().enumerate() {
        out.push(b ^ mask_key[i % 4]);
    }
    out
}

/// Read one WebSocket binary frame from the server stream (server frames are unmasked).
async fn read_ws_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr).await.map_err(EngineError::Io)?;
    let masked = (hdr[1] & 0x80) != 0;
    let len_field = (hdr[1] & 0x7F) as usize;
    let payload_len: usize = if len_field < 126 {
        len_field
    } else if len_field == 126 {
        let mut ext = [0u8; 2];
        r.read_exact(&mut ext).await.map_err(EngineError::Io)?;
        u16::from_be_bytes(ext) as usize
    } else {
        let mut ext = [0u8; 8];
        r.read_exact(&mut ext).await.map_err(EngineError::Io)?;
        u64::from_be_bytes(ext) as usize
    };
    if payload_len > MAX_FRAME_SIZE {
        return Err(EngineError::Internal(format!(
            "WS frame too large: {payload_len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }
    let mut mask_key = [0u8; 4];
    if masked {
        r.read_exact(&mut mask_key).await.map_err(EngineError::Io)?;
    }
    let mut payload = vec![0u8; payload_len];
    r.read_exact(&mut payload).await.map_err(EngineError::Io)?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask_key[i % 4];
        }
    }
    Ok(payload)
}

// ── Server connection ─────────────────────────────────────────────────────────

/// Open a TLS connection to `host:443` with SNI = `sni` and perform the
/// WebSocket upgrade handshake.
async fn connect_wss(host: &str, sni: &str) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let addr = tokio::net::lookup_host(format!("{host}:443"))
        .await
        .map_err(EngineError::Io)?
        .next()
        .ok_or_else(|| EngineError::Internal(format!("DNS: no address for {host}")))?;

    let tcp = tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| EngineError::Internal(format!("TCP connect to {addr} timed out after 10s")))?
    .map_err(EngineError::Io)?;

    let root_store = {
        let mut store = rustls::RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    };
    let tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_cfg));
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned())
        .map_err(|_| EngineError::Internal(format!("invalid TLS SNI: {sni}")))?;
    let mut tls = tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| EngineError::Internal(format!("TLS handshake with {sni} timed out after 10s")))?
    .map_err(EngineError::Io)?;

    // WebSocket upgrade — Telegram's WSS endpoint is at /apiws.
    let key_bytes: [u8; 16] = rand::thread_rng().gen();
    let ws_key = BASE64.encode(key_bytes);
    let request = format!(
        "GET /apiws HTTP/1.1\r\n\
         Host: {sni}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: binary\r\n\
         Origin: https://web.telegram.org\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\
         \r\n"
    );
    tls.write_all(request.as_bytes())
        .await
        .map_err(EngineError::Io)?;

    // Read HTTP response headers byte-by-byte until \r\n\r\n (with timeout).
    let response = tokio::time::timeout(tokio::time::Duration::from_secs(10), async {
        let mut resp = Vec::new();
        let mut b = [0u8; 1];
        loop {
            tls.read_exact(&mut b).await.map_err(EngineError::Io)?;
            resp.push(b[0]);
            if resp.ends_with(b"\r\n\r\n") {
                break;
            }
            if resp.len() > 4096 {
                return Err(EngineError::Internal(
                    "WS upgrade response exceeded 4 KiB".to_owned(),
                ));
            }
        }
        Ok::<Vec<u8>, EngineError>(resp)
    })
    .await
    .map_err(|_| EngineError::Internal("WS upgrade response timed out after 10s".to_owned()))??;
    let resp_str = String::from_utf8_lossy(&response);
    if !resp_str.contains("101") {
        return Err(EngineError::Internal(format!(
            "WS upgrade failed: {}",
            resp_str.lines().next().unwrap_or("")
        )));
    }

    Ok(tls)
}

/// Return the default IP string for a Telegram DC.
fn dc_ip(dc_id: i16) -> Option<&'static str> {
    let dc = dc_id.unsigned_abs() as i16;
    DC_IPS.iter().find(|(d, _)| *d == dc).map(|(_, ip)| *ip)
}

/// Generate a fresh 64-byte MTProto obfuscated init packet for the server leg.
///
/// Uses padded-intermediate transport and the provided DC ID.
fn make_server_init(dc_id: i16) -> [u8; 64] {
    let mut raw = [0u8; 64];
    rand::thread_rng().fill(&mut raw[..]);
    // Override proto tag and DC ID at their fixed offsets.
    raw[56..60].copy_from_slice(&MtProtoTransport::Padded.tag_bytes());
    raw[60..62].copy_from_slice(&dc_id.to_le_bytes());
    raw
}

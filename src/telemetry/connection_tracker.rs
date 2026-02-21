use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub struct ConnectionTracker {
    pub connections: Arc<RwLock<HashMap<u64, ConnectionInfo>>>,
    tx: broadcast::Sender<ConnectionInfo>,
    next_id: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: u64,
    pub url: String,
    pub status: ConnectionStatus,
    pub privacy_filtered: bool,
    pub blocked_by_privacy: bool,
    pub dns_info: Option<DnsInfo>,
    pub tls_info: Option<TlsInfo>,
    pub download_info: DownloadInfo,
    pub timestamps: Timestamps,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Queued,
    Resolving,
    Connecting,
    TlsHandshake,
    Sending,
    Receiving,
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub resolver_used: String,
    pub resolved_ip: String,
    pub resolution_time_ms: u64,
    pub chain: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub version: String,
    pub cipher_suite: String,
    pub ech_status: String,
    pub handshake_time_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DownloadInfo {
    pub bytes_downloaded: u64,
    pub total_bytes: Option<u64>,
    pub speed_bytes_per_sec: f64,
    pub avg_speed_bytes_per_sec: f64,
}

#[derive(Debug, Clone)]
pub struct Timestamps {
    pub queued_at: SystemTime,
    pub started_at: Option<SystemTime>,
    pub completed_at: Option<SystemTime>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            tx,
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn next_connection_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ConnectionInfo> {
        self.tx.subscribe()
    }

    pub fn begin(&self, id: u64, url: impl Into<String>) {
        let info = ConnectionInfo {
            id,
            url: url.into(),
            status: ConnectionStatus::Queued,
            privacy_filtered: false,
            blocked_by_privacy: false,
            dns_info: None,
            tls_info: None,
            download_info: DownloadInfo::default(),
            timestamps: Timestamps {
                queued_at: SystemTime::now(),
                started_at: Some(SystemTime::now()),
                completed_at: None,
            },
            error: None,
        };
        self.connections.write().insert(id, info.clone());
        let _ = self.tx.send(info);
    }

    pub fn update_status(&self, id: u64, status: ConnectionStatus) {
        if let Some(conn) = self.connections.write().get_mut(&id) {
            conn.status = status;
            if matches!(
                status,
                ConnectionStatus::Completed | ConnectionStatus::Failed
            ) {
                conn.timestamps.completed_at = Some(SystemTime::now());
            }
            let _ = self.tx.send(conn.clone());
        }
    }

    pub fn update_dns(&self, id: u64, dns: DnsInfo) {
        if let Some(conn) = self.connections.write().get_mut(&id) {
            conn.dns_info = Some(dns);
            let _ = self.tx.send(conn.clone());
        }
    }

    pub fn update_tls(&self, id: u64, tls: TlsInfo) {
        if let Some(conn) = self.connections.write().get_mut(&id) {
            conn.tls_info = Some(tls);
            let _ = self.tx.send(conn.clone());
        }
    }

    pub fn update_download(&self, id: u64, download: DownloadInfo) {
        if let Some(conn) = self.connections.write().get_mut(&id) {
            conn.download_info = download;
            let _ = self.tx.send(conn.clone());
        }
    }

    pub fn mark_privacy(&self, id: u64, blocked: bool) {
        if let Some(conn) = self.connections.write().get_mut(&id) {
            conn.privacy_filtered = true;
            if blocked {
                conn.blocked_by_privacy = true;
            }
            let _ = self.tx.send(conn.clone());
        }
    }

    pub fn fail(&self, id: u64, message: impl Into<String>) {
        if let Some(conn) = self.connections.write().get_mut(&id) {
            conn.status = ConnectionStatus::Failed;
            conn.error = Some(message.into());
            conn.timestamps.completed_at = Some(SystemTime::now());
            let _ = self.tx.send(conn.clone());
        }
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub static GLOBAL_CONNECTION_TRACKER: Lazy<ConnectionTracker> = Lazy::new(ConnectionTracker::new);

pub fn global_connection_tracker() -> ConnectionTracker {
    GLOBAL_CONNECTION_TRACKER.clone()
}

use dashmap::DashMap;
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{RwLock, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use std::sync::Arc;

use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use crate::blocklist::expand_tilde;
use crate::error::{EngineError, Result};
use crate::anticensorship::ResolverChain;
use crate::pt::{OutboundConnector, DynOutbound, BoxStream, TargetAddr, TargetEndpoint};

// use super::{BoxStream, DynOutbound, TargetAddr, TargetEndpoint};

pub const ROUTE_WINNER_TTL_SECS: u64 = 15 * 60;
pub const ROUTE_FAILS_BEFORE_WEAK: u8 = 2;
pub const ROUTE_WEAK_BASE_SECS: u64 = 45;
pub const ROUTE_WEAK_MAX_SECS: u64 = 300;
pub const ROUTE_SOFT_ZERO_REPLY_MIN_C2U: u64 = 256;
pub const ROUTE_SOFT_ZERO_REPLY_MIN_LIFETIME_MS: u64 = 2000;
pub const GLOBAL_BYPASS_HARD_WEAK_SCORE: i64 = -80;
pub const LEARNED_BYPASS_MIN_FAILURES_DOMAIN: u8 = 2;
pub const LEARNED_BYPASS_MIN_FAILURES_IP: u8 = 1;
pub const ROUTE_CAPABILITY_BYPASS_REP03_SECS: u64 = 120;
pub const ROUTE_RACE_MAX_CANDIDATES: usize = 4;
pub const ROUTE_RACE_BASE_DELAY_MS: u64 = 50;
pub const ROUTE_RACE_DIRECT_HEADSTART_MS: u64 = 0;
pub const ROUTE_RACE_BYPASS_EXTRA_DELAY_MS: u64 = 150;
pub const ROUTE_RACE_BYPASS_EXTRA_DELAY_BUILTIN_MS: u64 = 50;
pub const ROUTE_RACE_BYPASS_EXTRA_DELAY_LEARNED_MS: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockingSignal {
    Reset,
    Timeout,
    EarlyClose,
    BrokenPipe,
    SuspiciousZeroReply,
    SilentDrop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierStoreConfig {
    pub path: PathBuf,
    pub entry_ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClassifierSnapshotEntry {
    pub failures: u8,
    pub preferred_stage: u8,
    pub stats: DestinationClassifier,
    pub bypass_profile_idx: Option<u8>,
    pub bypass_profile_failures: u8,
    pub route_winner: Option<RouteWinner>,
    pub route_health: HashMap<String, RouteHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierSnapshot {
    pub version: u32,
    pub updated_at_unix: u64,
    pub entries: HashMap<String, ClassifierSnapshotEntry>,
    pub global_bypass_health: HashMap<String, BypassProfileHealth>,
}

pub struct UdpDestinationPolicy {
    pub padding_min: usize,
    pub padding_max: usize,
    pub block_quic: bool,
}

// Semantically grouped sections for SOCKS5 PT server.
#[path = "socks5_server_parts/state_and_startup.rs"]
mod state_and_startup;
#[path = "socks5_server_parts/route_connection.rs"]
mod route_connection;
#[path = "socks5_server_parts/protocol_handlers.rs"]
mod protocol_handlers;
#[path = "socks5_server_parts/protocol_socks4.rs"]
mod protocol_socks4;
#[path = "socks5_server_parts/route_scoring.rs"]
mod route_scoring;
#[path = "socks5_server_parts/classifier_and_persistence.rs"]
mod classifier_and_persistence;
#[path = "socks5_server_parts/relay_and_io_helpers.rs"]
mod relay_and_io_helpers;
#[cfg(test)]
#[path = "socks5_server_parts/evasion_tests.rs"]
mod evasion_tests;
#[cfg(test)]
#[path = "socks5_server_parts/tests.rs"]
mod tests;

use classifier_and_persistence::*;
use protocol_handlers::*;
use protocol_socks4::*;
use relay_and_io_helpers::*;
use route_connection::*;
use route_scoring::*;
use state_and_startup::*;

pub use state_and_startup::{RelayOptions, Socks5ServerGuard, start_socks5_server};

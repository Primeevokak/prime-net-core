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
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use crate::blocklist::expand_tilde;
use crate::error::{EngineError, Result};
use crate::anticensorship::ResolverChain;

use super::{BoxStream, DynOutbound, TargetAddr, TargetEndpoint};

// Semantically grouped sections for SOCKS5 PT server.
include!("socks5_server_parts/state_and_startup.rs");
include!("socks5_server_parts/route_connection.rs");
include!("socks5_server_parts/protocol_handlers.rs");
include!("socks5_server_parts/protocol_socks4.rs");
include!("socks5_server_parts/route_scoring.rs");
include!("socks5_server_parts/classifier_and_persistence.rs");
include!("socks5_server_parts/relay_and_io_helpers.rs");
include!("socks5_server_parts/evasion_tests.rs");
include!("socks5_server_parts/tests.rs");

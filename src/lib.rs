// Enforce "no unwrap/expect in production code" via clippy, while keeping tests ergonomic.
#![cfg_attr(all(not(test), clippy), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod adblock;
pub mod anticensorship;
pub mod blocklist;
pub mod config;
pub mod core;
pub mod dns;
pub mod engine;
pub mod error;
pub mod evasion;
pub mod ffi;
pub mod health;
pub mod observability;
pub mod pac;
pub mod platform;
pub mod privacy;
pub mod proxy;
pub mod pt;
pub mod sse;
pub mod telemetry;
pub mod tls;
pub mod tui;
pub mod udp_tunnel;
pub mod updater;
pub mod version;
pub mod websocket;

pub use config::{EngineConfig, TransportConfig};
pub use core::{DownloadOutcome, PrimeHttpClient, RequestData, ResponseData, ResponseStream};
pub use engine::PrimeEngine;
pub use error::{EngineError, Result};
pub use observability::{init_observability, ObservabilityConfig, ObservabilityGuard};
pub use sse::{SseConfig, SseEvent, SseStream};
pub use tls::{Ja3Fingerprint, TlsConfig, TlsVersion};
pub use udp_tunnel::{UdpDatagram, UdpOverTcpConfig, UdpOverTcpTunnel, UdpTargetAddr};
pub use websocket::{WebSocketClient, WsConfig, WsMessage};

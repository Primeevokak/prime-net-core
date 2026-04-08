use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::Result;

pub mod direct;
pub mod mtproto_ws;
pub mod shadowsocks;
pub mod socks5_server;
pub mod tor_client;
pub mod trojan;

pub trait AsyncStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncStream for T {}

pub type BoxStream = Box<dyn AsyncStream + Unpin + Send>;

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Ip(IpAddr),
    Domain(String),
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{}", ip),
            Self::Domain(domain) => write!(f, "{}", domain),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetEndpoint {
    pub addr: TargetAddr,
    pub port: u16,
}

impl std::fmt::Display for TargetEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.addr {
            TargetAddr::Ip(IpAddr::V6(ip)) => write!(f, "[{}]:{}", ip, self.port),
            _ => write!(f, "{}:{}", self.addr, self.port),
        }
    }
}

pub trait OutboundConnector: Send + Sync {
    fn connect<'a>(
        &'a self,
        target: TargetEndpoint,
    ) -> Pin<Box<dyn Future<Output = Result<BoxStream>> + Send + 'a>>;

    fn resolver(&self) -> Option<Arc<crate::anticensorship::ResolverChain>> {
        None
    }
}

pub type DynOutbound = Arc<dyn OutboundConnector>;

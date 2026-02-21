use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::Result;

pub mod direct;
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

#[derive(Debug, Clone)]
pub struct TargetEndpoint {
    pub addr: TargetAddr,
    pub port: u16,
}

pub trait OutboundConnector: Send + Sync {
    fn connect<'a>(
        &'a self,
        target: TargetEndpoint,
    ) -> Pin<Box<dyn Future<Output = Result<BoxStream>> + Send + 'a>>;
}

pub type DynOutbound = Arc<dyn OutboundConnector>;

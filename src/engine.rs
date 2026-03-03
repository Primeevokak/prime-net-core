use std::sync::Arc;

use crate::anticensorship::ResolverChain;
use crate::config::{EngineConfig, PluggableTransportKind, ProxyConfig, ProxyKind};
use crate::core::PrimeHttpClient;
use crate::error::{EngineError, Result};
use crate::pt::shadowsocks::ShadowsocksOutbound;
use crate::pt::socks5_server::{start_socks5_server, RelayOptions};
use crate::pt::tor_client::{start_tor_obfs4, start_tor_snowflake, TorClientGuard};
use crate::pt::trojan::TrojanOutbound;
use crate::pt::DynOutbound;

#[derive(Debug)]
pub struct PrimeEngine {
    client: Arc<PrimeHttpClient>,
    _pt_guard: Option<crate::pt::socks5_server::Socks5ServerGuard>,
    _tor_guard: Option<TorClientGuard>,
}

impl PrimeEngine {
    pub async fn new(config: EngineConfig) -> Result<Self> {
        config.validate()?;

        let Some(pt) = config.pt.clone() else {
            return Ok(Self {
                client: Arc::new(PrimeHttpClient::new(config)?),
                _pt_guard: None,
                _tor_guard: None,
            });
        };

        let resolver = Arc::new(ResolverChain::from_config(&config.anticensorship)?);

        let outbound: DynOutbound = match pt.kind {
            PluggableTransportKind::Trojan => {
                let t = pt.trojan.clone().ok_or_else(|| {
                    EngineError::Config("pt.kind=trojan requires pt.trojan".to_owned())
                })?;
                Arc::new(TrojanOutbound::new(resolver, t))
            }
            PluggableTransportKind::Shadowsocks => {
                let s = pt.shadowsocks.clone().ok_or_else(|| {
                    EngineError::Config("pt.kind=shadowsocks requires pt.shadowsocks".to_owned())
                })?;
                Arc::new(ShadowsocksOutbound::new(resolver, s).await?)
            }
            PluggableTransportKind::Obfs4 => {
                let o = pt.obfs4.clone().ok_or_else(|| {
                    EngineError::Config("pt.kind=obfs4 requires pt.obfs4".to_owned())
                })?;
                let tor = start_tor_obfs4(&pt.local_socks5_bind, &o).await?;
                let listen = tor.socks_addr();

                let mut cfg2 = config.clone();
                cfg2.pt = None;
                cfg2.proxy = Some(ProxyConfig {
                    kind: ProxyKind::Socks5,
                    address: listen.to_string(),
                });

                return Ok(Self {
                    client: Arc::new(PrimeHttpClient::new(cfg2)?),
                    _pt_guard: None,
                    _tor_guard: Some(tor),
                });
            }
            PluggableTransportKind::Snowflake => {
                let s = pt.snowflake.clone().ok_or_else(|| {
                    EngineError::Config("pt.kind=snowflake requires pt.snowflake".to_owned())
                })?;
                let tor = start_tor_snowflake(&pt.local_socks5_bind, &s).await?;
                let listen = tor.socks_addr();

                let mut cfg2 = config.clone();
                cfg2.pt = None;
                cfg2.proxy = Some(ProxyConfig {
                    kind: ProxyKind::Socks5,
                    address: listen.to_string(),
                });

                return Ok(Self {
                    client: Arc::new(PrimeHttpClient::new(cfg2)?),
                    _pt_guard: None,
                    _tor_guard: Some(tor),
                });
            }
        };

        let bind_addr: std::net::SocketAddr = pt.local_socks5_bind.parse().map_err(|e| EngineError::Config(format!("invalid bind address: {}", e)))?;
        let guard = start_socks5_server(
            bind_addr,
            outbound,
            Arc::new(config.clone()),
            pt.silent_drop,
            RelayOptions::default(),
        )
        .await?;
        let listen = guard.listen_addr();

        let mut cfg2 = config.clone();
        cfg2.pt = None; // internal wiring uses proxy to the local socks5 server.
        cfg2.proxy = Some(ProxyConfig {
            kind: ProxyKind::Socks5,
            address: listen.to_string(),
        });

        Ok(Self {
            client: Arc::new(PrimeHttpClient::new(cfg2)?),
            _pt_guard: Some(guard),
            _tor_guard: None,
        })
    }

    pub fn client(&self) -> Arc<PrimeHttpClient> {
        self.client.clone()
    }

    pub fn pt_socks5_addr(&self) -> Option<std::net::SocketAddr> {
        if let Some(g) = &self._pt_guard {
            return Some(g.listen_addr());
        }
        self._tor_guard.as_ref().map(|g| g.socks_addr())
    }
}

use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::anticensorship::ResolverChain;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
pub struct PrimeReqwestDnsResolver {
    chain: Arc<ResolverChain>,
}

impl PrimeReqwestDnsResolver {
    pub fn new(chain: Arc<ResolverChain>) -> Self {
        Self { chain }
    }
}

impl Resolve for PrimeReqwestDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let chain = self.chain.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let ips = chain
                .resolve(&host)
                .await
                .map_err(|e| Box::new(e) as BoxError)?;
            let addrs: Vec<SocketAddr> = ips.into_iter().map(|ip| SocketAddr::new(ip, 0)).collect();
            let addrs: Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

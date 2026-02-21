use crate::error::{EngineError, Result};

#[derive(Debug, Clone)]
pub struct Socks5ProxyConfig {
    pub address: String,
}

impl Socks5ProxyConfig {
    pub fn new(address: impl Into<String>) -> Result<Self> {
        let address = address.into();
        if address.trim().is_empty() {
            return Err(EngineError::InvalidInput(
                "SOCKS5 proxy address is empty".to_owned(),
            ));
        }
        Ok(Self { address })
    }
}

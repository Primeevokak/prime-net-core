use crate::error::{EngineError, Result};

#[derive(Debug, Clone)]
pub struct HttpProxyConfig {
    pub address: String,
}

impl HttpProxyConfig {
    pub fn new(address: impl Into<String>) -> Result<Self> {
        let address = address.into();
        if address.trim().is_empty() {
            return Err(EngineError::InvalidInput(
                "HTTP proxy address is empty".to_owned(),
            ));
        }
        Ok(Self { address })
    }
}

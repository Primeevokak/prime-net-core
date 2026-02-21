use serde::{Deserialize, Serialize};

use crate::error::{EngineError, Result};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum Ja3Fingerprint {
    /// Use the default rustls ClientHello (no attempt to match browser JA3).
    #[serde(rename = "rustls_default")]
    #[default]
    RustlsDefault,
    /// Best-effort rustls-based profile aiming to resemble Chrome (JA3-adjacent; not a full uTLS impersonation).
    #[serde(rename = "chrome_120")]
    Chrome120,
    /// Best-effort rustls-based profile aiming to resemble Firefox (JA3-adjacent; not a full uTLS impersonation).
    #[serde(rename = "firefox_121")]
    Firefox121,
    /// Randomize some ClientHello parameters (best-effort within rustls constraints).
    #[serde(rename = "random")]
    Random,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
    Tls1_0,
    Tls1_1,
    #[default]
    Tls1_2,
    Tls1_3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub min_version: TlsVersion,
    #[serde(default = "default_tls_max")]
    pub max_version: TlsVersion,
    #[serde(default = "default_alpn")]
    pub alpn_protocols: Vec<String>,
    #[serde(default)]
    pub ja3_fingerprint: Ja3Fingerprint,
}

fn default_tls_max() -> TlsVersion {
    TlsVersion::Tls1_3
}

fn default_alpn() -> Vec<String> {
    vec!["h2".to_owned(), "http/1.1".to_owned()]
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: TlsVersion::Tls1_2,
            max_version: TlsVersion::Tls1_3,
            alpn_protocols: default_alpn(),
            ja3_fingerprint: Ja3Fingerprint::default(),
        }
    }
}

impl TlsConfig {
    pub fn validate(&self) -> Result<()> {
        if version_rank(self.min_version) > version_rank(self.max_version) {
            return Err(EngineError::Config(
                "tls.min_version cannot be greater than tls.max_version".to_owned(),
            ));
        }
        Ok(())
    }
}

fn version_rank(v: TlsVersion) -> u8 {
    match v {
        TlsVersion::Tls1_0 => 10,
        TlsVersion::Tls1_1 => 11,
        TlsVersion::Tls1_2 => 12,
        TlsVersion::Tls1_3 => 13,
    }
}

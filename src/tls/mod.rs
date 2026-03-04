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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsRootStore {
    /// Use the bundled Mozilla roots (via webpki-roots). Good for portability.
    #[default]
    Webpki,
    /// Use the system's trust store. Required for corporate proxies or local certs.
    System,
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
    #[serde(default)]
    pub root_store: TlsRootStore,
    #[serde(default)]
    pub insecure_skip_verify: bool,
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
            root_store: TlsRootStore::default(),
            insecure_skip_verify: false,
        }
    }
}

impl TlsConfig {
    pub fn validate(&self) -> Result<()> {
        fn is_dev_mode() -> bool {
            std::env::var("PRIME_NET_DEV").is_ok()
        }

        if version_rank(self.min_version) < version_rank(TlsVersion::Tls1_2) && !is_dev_mode() {
            return Err(EngineError::Config(
                "TLS 1.0 and 1.1 are disabled in production for security reasons. Use TLS 1.2 or higher, or set PRIME_NET_DEV=1 for legacy testing."
                    .to_owned(),
            ));
        }

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

#[derive(Debug)]
pub struct InsecureSkipVerify;

impl rustls::client::danger::ServerCertVerifier for InsecureSkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

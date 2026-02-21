use crate::error::EngineError;
use crate::error::Result;

pub struct SignatureVerifier {
    public_key: &'static str,
}

impl SignatureVerifier {
    pub fn new() -> Self {
        Self {
            public_key: PRIME_NET_PUBLIC_KEY,
        }
    }

    fn ensure_public_key_configured(&self) -> Result<()> {
        if self
            .public_key
            .contains("REPLACE_WITH_REAL_RELEASE_SIGNING_KEY")
        {
            return Err(EngineError::Internal(
                "release signature verification is not configured: public key placeholder is still set"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "signature-verification")]
    pub fn verify_release(&self, binary: &[u8], signature: &[u8]) -> Result<bool> {
        use gpgme::{Context, Protocol};

        self.ensure_public_key_configured()?;

        let mut ctx = Context::from_protocol(Protocol::OpenPgp)
            .map_err(|e| EngineError::Internal(format!("failed to create GPG context: {e}")))?;
        let key_data = self.public_key.as_bytes();
        ctx.import(key_data)
            .map_err(|e| EngineError::Internal(format!("failed to import public key: {e}")))?;
        let result = ctx
            .verify_detached(signature, binary)
            .map_err(|e| EngineError::Internal(format!("signature verification failed: {e}")))?;
        Ok(result.signatures().any(|sig| sig.status().is_ok()))
    }

    #[cfg(not(feature = "signature-verification"))]
    pub fn verify_release(&self, _binary: &[u8], _signature: &[u8]) -> Result<bool> {
        self.ensure_public_key_configured()?;
        Err(EngineError::Internal(
            "signature verification is disabled in this build; recompile with feature 'signature-verification'"
                .to_owned(),
        ))
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

const PRIME_NET_PUBLIC_KEY: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----
REPLACE_WITH_REAL_RELEASE_SIGNING_KEY
-----END PGP PUBLIC KEY BLOCK-----"#;

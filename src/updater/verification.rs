use crate::error::EngineError;
use crate::error::Result;

pub struct SignatureVerifier {
    public_key: &'static str,
    public_key_fingerprint: &'static str,
}

impl SignatureVerifier {
    pub fn new() -> Self {
        Self {
            public_key: PRIME_NET_PUBLIC_KEY,
            public_key_fingerprint: PRIME_NET_PUBLIC_KEY_FINGERPRINT,
        }
    }

    fn ensure_public_key_configured(&self) -> Result<()> {
        if self
            .public_key
            .contains("REPLACE_WITH_REAL_RELEASE_SIGNING_KEY")
            || self
                .public_key_fingerprint
                .contains("REPLACE_WITH_REAL_RELEASE_SIGNING_FINGERPRINT")
            || self.public_key_fingerprint == "0123456789ABCDEF0123456789ABCDEF01234567"
            || self.public_key.contains("7E2X7E2X7E2X7E2X")
        {
            return Err(EngineError::Internal(
                "release signature verification is not configured: public key/fingerprint placeholders or dummy values are still set"
                    .to_owned(),
            ));
        }
        if normalize_fingerprint(self.public_key_fingerprint).is_none() {
            return Err(EngineError::Internal(
                "release signing fingerprint has invalid format".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "signature-verification")]
    pub fn verify_release(&self, binary: &[u8], signature: &[u8]) -> Result<bool> {
        use gpgme::{Context, Protocol};

        self.ensure_public_key_configured()?;

        let expected_fpr = normalize_fingerprint(self.public_key_fingerprint).ok_or_else(|| {
            EngineError::Internal("configured release signing fingerprint is invalid".to_owned())
        })?;

        // Isolate verifier keyring from user/system keychain to avoid trust poisoning.
        let gpg_home = tempfile::tempdir().map_err(|e| {
            EngineError::Internal(format!("failed to create temporary keyring directory: {e}"))
        })?;
        let gpg_home_path = gpg_home.path().to_string_lossy().to_string();

        let mut ctx = Context::from_protocol(Protocol::OpenPgp)
            .map_err(|e| EngineError::Internal(format!("failed to create GPG context: {e}")))?;
        ctx.set_engine_home_dir(gpg_home_path.as_str())
            .map_err(|e| {
                EngineError::Internal(format!("failed to set isolated GPG home dir: {e}"))
            })?;

        let key_data = self.public_key.as_bytes();
        ctx.import(key_data)
            .map_err(|e| EngineError::Internal(format!("failed to import public key: {e}")))?;
        let result = ctx
            .verify_detached(signature, binary)
            .map_err(|e| EngineError::Internal(format!("signature verification failed: {e}")))?;

        let has_expected_signature = result.signatures().any(|sig| {
            if sig.status().is_err() {
                return false;
            }
            let Ok(fpr) = sig.fingerprint() else {
                return false;
            };
            normalize_fingerprint(fpr).is_some_and(|f| f == expected_fpr)
        });

        Ok(has_expected_signature)
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

fn normalize_fingerprint(value: &str) -> Option<String> {
    let normalized: String = value
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalized.len() < 32 {
        return None;
    }
    Some(normalized)
}

const PRIME_NET_PUBLIC_KEY: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZpXzWhYJKwYBBAHaRw8BAQdA9A6xTj9E6N1U3W7Q4Q6P8H7A6S9K7D5G8F2U
H4I8J9K0F1ByaW1lIE5ldCBTaWduaW5nIEtleSAyMDI2IDxyZWxlYXNlQHByaW1l
bmV0LmV4YW1wbGUuY29tPoiQBBMWCAA4FiEE7E2X7E2X7E2X7E2X7E2X7E2X7E2X
BQJmlfNaAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEOxNl+xNl+xNl+xA
9A6xTj9E6N1U3W7Q4Q6P8H7A6S9K7D5G8F2UH4I8J9K0
-----END PGP PUBLIC KEY BLOCK-----"#;

const PRIME_NET_PUBLIC_KEY_FINGERPRINT: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

#[cfg(test)]
mod tests {
    use super::normalize_fingerprint;

    #[test]
    fn normalize_fingerprint_accepts_spaced_lowercase() {
        let got =
            normalize_fingerprint("ab cd ef 12 34 56 78 90 ab cd ef 12 34 56 78 90 ab cd ef 12")
                .expect("must normalize valid fingerprint");
        assert_eq!(got, "ABCDEF1234567890ABCDEF1234567890ABCDEF12");
    }

    #[test]
    fn normalize_fingerprint_rejects_too_short() {
        assert!(normalize_fingerprint("1234").is_none());
    }
}

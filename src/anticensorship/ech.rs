use std::collections::HashMap;
use std::sync::Arc;

use crate::anticensorship::resolver_chain::ResolverChain;
use crate::error::{EngineError, Result};

#[cfg(feature = "hickory-dns")]
use hickory_resolver::proto::rr::rdata::svcb::SvcParamValue;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::proto::rr::{RData, RecordType};
#[cfg(feature = "hickory-dns")]
use hickory_resolver::TokioResolver;

#[derive(Debug, Clone, Default)]
pub struct EchConfig {
    pub public_name: String,
    pub config_list: Vec<u8>,
    pub max_name_length: usize,
}

#[derive(Debug, Default)]
pub struct EchManager {
    pub enabled: bool,
    pub config_cache: HashMap<String, EchConfig>,
    /// When set, ECH config discovery uses this chain (DoH/DoT/DoQ) instead of
    /// the system resolver, which may return NXDOMAIN for HTTPS RRs on censored
    /// networks.
    pub resolver: Option<Arc<ResolverChain>>,
}

impl EchManager {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            config_cache: HashMap::new(),
            resolver: None,
        }
    }

    /// Attach a resolver chain so ECH discovery bypasses censored system DNS.
    pub fn with_resolver(mut self, resolver: Arc<ResolverChain>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Attach a resolver chain so ECH discovery bypasses censored system DNS.
    pub fn set_resolver(&mut self, resolver: Arc<ResolverChain>) {
        self.resolver = Some(resolver);
    }

    pub async fn refresh_domain_config(&mut self, domain: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            return Err(EngineError::InvalidInput("domain is empty".to_owned()));
        }

        // Fast path: use the anti-censorship resolver chain when available.
        // This works on networks where system DNS blocks HTTPS RR lookups.
        if let Some(chain) = &self.resolver {
            let chain = chain.clone();
            match chain.lookup_ech_config_list(&domain).await {
                Ok(Some(config_list)) => {
                    // ResolverChain does not return target_name, so we use the
                    // queried domain as the ECH outer SNI public_name.
                    self.config_cache.insert(
                        domain.clone(),
                        EchConfig {
                            public_name: domain.clone(),
                            config_list,
                            max_name_length: domain.len(),
                        },
                    );
                    return Ok(());
                }
                Ok(None) => {
                    self.config_cache.remove(&domain);
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        domain = %domain,
                        "ResolverChain ECH lookup failed; falling back to system DNS"
                    );
                    // Fall through to system DNS path below.
                }
            }
        }

        #[cfg(feature = "hickory-dns")]
        {
            let resolver = TokioResolver::builder_tokio()
                .map_err(|e| EngineError::Internal(format!("system resolver build failed: {e}")))?
                .build();

            let lookup = resolver
                .lookup(domain.as_str(), RecordType::HTTPS)
                .await
                .map_err(|e| {
                    EngineError::Internal(format!("HTTPS lookup failed for {domain}: {e}"))
                })?;

            // Pick the first HTTPS/SVCB record that contains an ECH config list.
            // If multiple are present, prefer the lowest SvcPriority.
            let mut best: Option<(u16, String, Vec<u8>)> = None;
            for r in lookup.iter() {
                let RData::HTTPS(https) = r else { continue };

                let prio = https.svc_priority();
                for (_, v) in https.svc_params() {
                    if let SvcParamValue::EchConfigList(ech) = v {
                        let target = https.target_name().to_utf8();
                        let public_name = target
                            .strip_suffix('.')
                            .unwrap_or(target.as_str())
                            .to_owned();
                        let value = (prio, public_name, ech.0.clone());
                        match &best {
                            None => best = Some(value),
                            Some((best_prio, _, _)) if prio < *best_prio => best = Some(value),
                            _ => {}
                        }
                    }
                }
            }

            if let Some((_prio, public_name, config_list)) = best {
                self.config_cache.insert(
                    domain.clone(),
                    EchConfig {
                        public_name,
                        config_list,
                        max_name_length: domain.len(),
                    },
                );
            } else {
                self.config_cache.remove(&domain);
            }

            Ok(())
        }

        #[cfg(not(feature = "hickory-dns"))]
        {
            Err(EngineError::Internal(
                "ECH refresh requires feature \"hickory-dns\"".to_owned(),
            ))
        }
    }
}

use std::collections::HashMap;

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
}

impl EchManager {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            config_cache: HashMap::new(),
        }
    }

    pub async fn refresh_domain_config(&mut self, domain: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(feature = "hickory-dns")]
        {
            let domain = domain.trim().to_ascii_lowercase();
            if domain.is_empty() {
                return Err(EngineError::InvalidInput("domain is empty".to_owned()));
            }

            // TODO: pass a ResolverChain reference here instead of using the system DNS.
            // On censored networks the system DNS returns NXDOMAIN for HTTPS RR lookups,
            // so ECH config discovery silently fails.  The ResolverChain (DoH/DoT/DoQ) must
            // be threaded through to this call site before ECH can work on blocked networks.
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

                // For ServiceMode records, svc_priority is > 0; we still accept 0 as "some record"
                // but keep the selection logic simple.
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
                // No ECH published for this domain; clear any stale entry.
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

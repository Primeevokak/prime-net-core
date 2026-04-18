//! Startup capability report for the desync engine.
//!
//! Analyses a [`TcpDesyncEngine`] and emits structured log messages describing
//! which profiles are fully operational and which have degraded because a
//! platform component (WinDivert, NFQueue, raw injector) is missing.

use tracing::{info, warn};

use crate::evasion::packet_intercept::raw_inject;
use crate::evasion::tcp_desync::{DesyncTechnique, FakeProbeStrategy, TcpDesyncEngine};

/// Reason why a profile operates in degraded mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DegradedReason {
    /// `TcpDisorder` needs a packet interceptor (WinDivert/NFQueue).
    /// Falls back to plain TCP segment split.
    TcpDisorderNoInterceptor,
    /// `SeqOverlap` needs the raw packet injector (WinDivert).
    /// Falls back to plain TLS record split.
    SeqOverlapNoInjector,
    /// Fake probe with `BadTimestamp`/`BadChecksum`/`BadSeq` needs the raw
    /// packet injector.  The probe is silently skipped; the split technique
    /// still runs but without the DPI state-poisoning effect.
    FakeProbeNoInjector,
}

/// One profile that will run in degraded mode.
#[derive(Debug, Clone)]
pub struct DegradedProfile {
    /// Profile name (e.g. `"tcp-disorder-15ms"`).
    pub name: String,
    /// Why it is degraded.
    pub reason: DegradedReason,
}

/// Summary of desync engine capabilities at startup.
///
/// Computed once after [`TcpDesyncEngine`] creation and logged so operators
/// can immediately see what is working and what is degraded.
#[derive(Debug)]
pub struct DesyncEngineReport {
    /// Total number of loaded profiles.
    pub total_profiles: usize,
    /// Whether a packet interceptor (WinDivert/NFQueue) is available.
    pub has_packet_interceptor: bool,
    /// Name of the packet interceptor backend, if available.
    pub interceptor_backend: Option<String>,
    /// Whether the raw packet injector (WinDivert send-only handle) is available.
    pub has_raw_injector: bool,
    /// Profiles that will operate in degraded mode.
    pub degraded: Vec<DegradedProfile>,
}

/// Analyse a [`TcpDesyncEngine`] and produce a startup capability report.
pub fn analyze_engine(engine: &TcpDesyncEngine) -> DesyncEngineReport {
    let has_interceptor = engine.packet_interceptor.is_some();
    let backend_name = engine
        .packet_interceptor
        .as_ref()
        .map(|i| i.backend_name().to_owned());
    let has_injector = raw_inject::is_injector_available();

    let mut degraded = Vec::new();

    for idx in 0..engine.profile_count() {
        let profile = engine.profile_at(idx);
        let name = profile.name.clone();

        // Check technique-level degradation.
        match &profile.technique {
            DesyncTechnique::TcpDisorder { .. } if !has_interceptor => {
                degraded.push(DegradedProfile {
                    name,
                    reason: DegradedReason::TcpDisorderNoInterceptor,
                });
                continue;
            }
            DesyncTechnique::SeqOverlap { .. } if !has_injector => {
                degraded.push(DegradedProfile {
                    name,
                    reason: DegradedReason::SeqOverlapNoInjector,
                });
                continue;
            }
            _ => {}
        }

        // Check fake-probe degradation (probe component is lost, but the
        // split technique itself still runs).
        if let Some(ref probe) = profile.fake_probe {
            let needs_injector = matches!(
                probe.fooling,
                Some(FakeProbeStrategy::BadTimestamp)
                    | Some(FakeProbeStrategy::BadChecksum)
                    | Some(FakeProbeStrategy::BadSeq)
            );
            if needs_injector && !has_injector {
                degraded.push(DegradedProfile {
                    name,
                    reason: DegradedReason::FakeProbeNoInjector,
                });
            }
        }
    }

    DesyncEngineReport {
        total_profiles: engine.profile_count(),
        has_packet_interceptor: has_interceptor,
        interceptor_backend: backend_name,
        has_raw_injector: has_injector,
        degraded,
    }
}

/// Emit structured log messages describing engine capabilities.
///
/// Uses INFO for available capabilities and WARN for missing components
/// with degraded profiles listed by name.
pub fn log_report(report: &DesyncEngineReport) {
    // ── Packet interceptor status ────────────────────────────────────────
    if let Some(ref backend) = report.interceptor_backend {
        info!(
            target: "desync",
            backend = backend.as_str(),
            "packet interceptor loaded (TCP disorder available)"
        );
    } else {
        let disorder_count = report
            .degraded
            .iter()
            .filter(|d| d.reason == DegradedReason::TcpDisorderNoInterceptor)
            .count();
        if disorder_count > 0 {
            let names: Vec<&str> = report
                .degraded
                .iter()
                .filter(|d| d.reason == DegradedReason::TcpDisorderNoInterceptor)
                .map(|d| d.name.as_str())
                .collect();
            warn!(
                target: "desync",
                degraded = disorder_count,
                profiles = ?names,
                "packet interceptor unavailable (install WinDivert on Windows \
                 or configure NFQueue on Linux) — {} profile(s) fall back to plain TCP split",
                disorder_count,
            );
        }
    }

    // ── Raw injector status ──────────────────────────────────────────────
    if report.has_raw_injector {
        info!(
            target: "desync",
            "raw packet injector available (SeqOverlap / fake probe injection active)"
        );
    } else {
        let seqovl_profiles: Vec<&str> = report
            .degraded
            .iter()
            .filter(|d| d.reason == DegradedReason::SeqOverlapNoInjector)
            .map(|d| d.name.as_str())
            .collect();
        let fake_profiles: Vec<&str> = report
            .degraded
            .iter()
            .filter(|d| d.reason == DegradedReason::FakeProbeNoInjector)
            .map(|d| d.name.as_str())
            .collect();

        if !seqovl_profiles.is_empty() {
            warn!(
                target: "desync",
                degraded = seqovl_profiles.len(),
                profiles = ?seqovl_profiles,
                "raw packet injector unavailable — {} SeqOverlap profile(s) \
                 fall back to plain TLS record split",
                seqovl_profiles.len(),
            );
        }
        if !fake_profiles.is_empty() {
            warn!(
                target: "desync",
                degraded = fake_profiles.len(),
                profiles = ?fake_profiles,
                "raw packet injector unavailable — {} profile(s) lose their \
                 fake-probe injection (split technique still runs, but DPI state-poisoning disabled)",
                fake_profiles.len(),
            );
        }
    }

    // ── Overall summary ──────────────────────────────────────────────────
    let ok_count = report.total_profiles - report.degraded.len();
    if report.total_profiles == 0 {
        warn!(
            target: "desync",
            "no desync profiles loaded — native bypass is effectively disabled"
        );
    } else if report.degraded.is_empty() {
        info!(
            target: "desync",
            total = report.total_profiles,
            "all {} desync profiles fully operational",
            report.total_profiles,
        );
    } else {
        warn!(
            target: "desync",
            total = report.total_profiles,
            operational = ok_count,
            degraded = report.degraded.len(),
            "{}/{} desync profiles operational, {} degraded \
             (install WinDivert to enable all profiles)",
            ok_count,
            report.total_profiles,
            report.degraded.len(),
        );
    }
}

#[cfg(test)]
mod startup_report_tests {
    use super::*;
    use crate::evasion::tcp_desync::{FakeProbe, NativeDesyncProfile, SplitAt, TcpDesyncEngine};

    fn make_profile(name: &str, technique: DesyncTechnique) -> NativeDesyncProfile {
        NativeDesyncProfile {
            name: name.to_owned(),
            technique,
            cloudflare_safe: true,
            fake_probe: None,
            randomize_sni_case: false,
            inter_fragment_delay_ms: None,
        }
    }

    #[test]
    fn detects_disorder_degradation_without_interceptor() {
        let profiles = vec![
            make_profile(
                "split-test",
                DesyncTechnique::TcpSegmentSplit {
                    at: SplitAt::IntoSni,
                },
            ),
            make_profile(
                "disorder-test",
                DesyncTechnique::TcpDisorder { delay_ms: 15 },
            ),
        ];
        let engine = TcpDesyncEngine::new(profiles);
        let report = analyze_engine(&engine);

        assert_eq!(report.total_profiles, 2);
        assert!(!report.has_packet_interceptor);
        assert_eq!(report.degraded.len(), 1);
        assert_eq!(report.degraded[0].name, "disorder-test");
        assert_eq!(
            report.degraded[0].reason,
            DegradedReason::TcpDisorderNoInterceptor
        );
    }

    #[test]
    fn detects_fake_probe_degradation() {
        let mut profile = make_profile(
            "fake-ts",
            DesyncTechnique::TlsRecordSplit {
                at: SplitAt::IntoSni,
            },
        );
        profile.fake_probe = Some(FakeProbe {
            ttl: 8,
            data_size: 0,
            fake_sni: Some("www.google.com".to_owned()),
            fooling: Some(FakeProbeStrategy::BadTimestamp),
        });

        let engine = TcpDesyncEngine::new(vec![profile]);
        let report = analyze_engine(&engine);

        // raw_inject::is_injector_available() is false in test env.
        let fake_degraded = report
            .degraded
            .iter()
            .filter(|d| d.reason == DegradedReason::FakeProbeNoInjector)
            .count();
        assert_eq!(fake_degraded, 1);
    }

    #[test]
    fn no_degradation_for_plain_split() {
        let profiles = vec![make_profile(
            "split",
            DesyncTechnique::TcpSegmentSplit {
                at: SplitAt::IntoSni,
            },
        )];
        let engine = TcpDesyncEngine::new(profiles);
        let report = analyze_engine(&engine);

        assert_eq!(report.degraded.len(), 0);
    }
}

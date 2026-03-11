// Semantically grouped packet-bypass sections.
include!("packet_bypass_parts/bootstrap_and_profiles.rs");
include!("packet_bypass_parts/download_and_permissions.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_asset_version_strips_v_and_leading_zero_major() {
        assert_eq!(release_asset_version("v0.17.3"), "17.3");
        assert_eq!(release_asset_version("0.13.1"), "13.1");
        assert_eq!(release_asset_version("v1.2.3"), "1.2.3");
    }

    #[test]
    fn release_asset_version_keeps_non_numeric_tags() {
        assert_eq!(
            release_asset_version("nightly-2025-10-01"),
            "nightly-2025-10-01"
        );
    }

    #[test]
    fn parse_env_packet_profiles_supports_multiple_entries() {
        let raw = "--disorder 1 --fake -1; --split 1+s --auto=torst";
        let parsed = parse_env_packet_profiles(raw);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "env-1");
        assert_eq!(parsed[1].name, "env-2");
        assert!(parsed[0].args.iter().any(|a| a == "--fake"));
        assert!(parsed[1].args.iter().any(|a| a == "--split"));
    }

    #[tokio::test]
    async fn resolve_packet_bypass_tag_uses_stable_by_default() {
        std::env::remove_var("PRIME_PACKET_BYPASS_TAG");
        std::env::remove_var("PRIME_PACKET_BYPASS_USE_LATEST");
        let tag = resolve_packet_bypass_tag().await;
        assert_eq!(tag, PACKET_BYPASS_STABLE_TAG);
    }

    #[tokio::test]
    async fn resolve_packet_bypass_tag_ignores_use_latest_in_strict_mode() {
        std::env::remove_var("PRIME_PACKET_BYPASS_TAG");
        std::env::set_var("PRIME_PACKET_BYPASS_USE_LATEST", "1");
        let tag = resolve_packet_bypass_tag().await;
        assert_eq!(tag, PACKET_BYPASS_STABLE_TAG);
        std::env::remove_var("PRIME_PACKET_BYPASS_USE_LATEST");
    }
}

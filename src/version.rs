/// Shared application version taken from Cargo package metadata.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version label used by the TUI header.
pub const PRIME_TUI_VERSION_LABEL: &str = concat!("prime-tui-version-", env!("CARGO_PKG_VERSION"));

/// Version label used by the engine CLI and logs.
pub const PRIME_NET_ENGINE_VERSION_LABEL: &str =
    concat!("prime-net-engine-version-", env!("CARGO_PKG_VERSION"));

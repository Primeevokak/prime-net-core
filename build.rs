use std::env;

fn env_truthy(name: &str) -> bool {
    env::var(name)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PRIME_WINDOWS_REQUIRE_ADMIN_MANIFEST");

    if env::var("CARGO_CFG_TARGET_OS").ok().as_deref() != Some("windows") {
        return;
    }
    if env::var("CARGO_CFG_TARGET_ENV").ok().as_deref() != Some("msvc") {
        return;
    }
    // Requiring elevation in test/dev builds breaks `cargo test` on Windows (os error 740).
    let is_release = env::var("PROFILE").ok().as_deref() == Some("release");
    if !is_release && !env_truthy("PRIME_WINDOWS_REQUIRE_ADMIN_MANIFEST") {
        return;
    }

    let bins = ["prime-net-engine", "prime-tui"];
    for bin in bins {
        println!("cargo:rustc-link-arg-bin={bin}=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bin={bin}=/MANIFESTUAC:level='asInvoker'");
    }
}

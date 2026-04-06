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

    if env::var("CARGO_CFG_TARGET_OS").ok().as_deref() == Some("windows") {
        // Only embed the VERSION resource when this package is the primary (root) package
        // being compiled.  When prime-net-engine is used as a library dependency of another
        // binary (e.g. prime-gui), the downstream build script handles its own resource; linking
        // our resource too causes a duplicate VERSION resource linker error (LNK1123/CVT1100).
        let is_primary = env::var("CARGO_PRIMARY_PACKAGE").ok().as_deref() == Some("1");
        if is_primary {
            let mut res = winres::WindowsResource::new();
            res.set_language(0x0409); // English (US)
            res.set("ProductName", "Prime Net Engine");
            res.set(
                "FileDescription",
                "High-performance anti-censorship network engine",
            );
            res.set("LegalCopyright", "Copyright (c) 2026");

            if let Err(e) = res.compile() {
                eprintln!("failed to compile winres: {e}");
            }
        }

        if env::var("CARGO_CFG_TARGET_ENV").ok().as_deref() == Some("msvc") {
            // Requiring elevation in test/dev builds breaks `cargo test` on Windows (os error 740).
            let is_release = env::var("PROFILE").ok().as_deref() == Some("release");
            if is_release || env_truthy("PRIME_WINDOWS_REQUIRE_ADMIN_MANIFEST") {
                let bins = ["prime-net-engine", "prime-tui"];
                for bin in bins {
                    println!("cargo:rustc-link-arg-bin={bin}=/MANIFEST:EMBED");
                    println!("cargo:rustc-link-arg-bin={bin}=/MANIFESTUAC:level='asInvoker'");
                }
            }
        }
    }
}

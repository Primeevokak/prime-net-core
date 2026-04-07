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

/// Downloads wintun.dll into OUT_DIR at build time so it can be embedded via `include_bytes!`.
/// Only runs when building for Windows with the `tun` feature enabled.
/// Uses PowerShell (always available on Windows 10+) — no extra build dependencies needed.
fn embed_wintun_if_needed() {
    if env::var("CARGO_FEATURE_TUN").is_err() {
        return;
    }

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set by Cargo");
    let dll_path = std::path::PathBuf::from(&out_dir).join("wintun.dll");

    if dll_path.exists() {
        // Already present from a cached build run — nothing to do.
        return;
    }

    let arch = match env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_default()
        .as_str()
    {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => "x86",
    };

    let zip_url = "https://www.wintun.net/builds/wintun-0.14.1.zip";
    let zip_path = std::path::PathBuf::from(&out_dir).join("wintun.zip");

    // Single PowerShell one-liner: download zip, open archive, copy matching entry to dll_path.
    let ps_script = format!(
        "$ProgressPreference='SilentlyContinue'; \
         Invoke-WebRequest -Uri '{url}' -OutFile '{zip}'; \
         Add-Type -Assembly System.IO.Compression.FileSystem; \
         $a=[IO.Compression.ZipFile]::OpenRead('{zip}'); \
         $e=$a.Entries|Where-Object{{$_.FullName -like '*{arch}/wintun.dll'}}; \
         $s=$e.Open(); $d=[System.IO.File]::Create('{dll}'); \
         $s.CopyTo($d); $d.Close(); $s.Close(); $a.Dispose()",
        url = zip_url,
        zip = zip_path.display(),
        arch = arch,
        dll = dll_path.display(),
    );

    let ok = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !ok {
        panic!(
            "build.rs: failed to download wintun.dll from {zip_url}.\n\
             Manual fix: place wintun.dll (amd64) at {dll}",
            zip_url = zip_url,
            dll = dll_path.display()
        );
    }

    println!("cargo:warning=wintun.dll ({arch}) downloaded and will be embedded in the binary");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PRIME_WINDOWS_REQUIRE_ADMIN_MANIFEST");

    if env::var("CARGO_CFG_TARGET_OS").ok().as_deref() == Some("windows") {
        embed_wintun_if_needed();
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

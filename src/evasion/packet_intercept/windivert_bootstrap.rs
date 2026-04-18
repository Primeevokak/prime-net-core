//! Auto-download of WinDivert 2.2 when it is not present alongside the engine binary.
//!
//! On first startup (or if the DLL is missing), downloads the official WinDivert
//! release ZIP from GitHub, extracts `WinDivert.dll` and `WinDivert64.sys`, and
//! writes them next to the current executable.  Subsequent startups find the DLL
//! in place and skip the download.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use tracing::info;

/// WinDivert release URL (official GitHub, version 2.2.2-A, x64).
const WINDIVERT_ZIP_URL: &str =
    "https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";

/// Maximum time for the HTTP download.
const DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Connect timeout for the HTTP client.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Files to extract from the ZIP archive (matched by `file_name()`, case-insensitive).
const REQUIRED_FILES: &[&str] = &["WinDivert.dll", "WinDivert64.sys"];

/// Errors that can occur during WinDivert auto-download.
#[derive(Debug)]
pub enum WinDivertBootstrapError {
    /// Could not determine the engine binary directory.
    ExePathUnknown(std::io::Error),
    /// HTTP download failed.
    Download(String),
    /// ZIP extraction failed.
    ZipExtract(String),
    /// Writing extracted files to disk failed.
    FileWrite(std::io::Error),
}

impl fmt::Display for WinDivertBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExePathUnknown(e) => write!(f, "cannot determine exe directory: {e}"),
            Self::Download(msg) => write!(f, "download failed: {msg}"),
            Self::ZipExtract(msg) => write!(f, "zip extraction failed: {msg}"),
            Self::FileWrite(e) => write!(f, "writing files to disk failed: {e}"),
        }
    }
}

impl std::error::Error for WinDivertBootstrapError {}

/// Return the directory containing the current engine binary.
fn engine_dir() -> Result<PathBuf, WinDivertBootstrapError> {
    std::env::current_exe()
        .and_then(|p| {
            p.parent()
                .map(|d| d.to_path_buf())
                .ok_or_else(|| std::io::Error::other("exe has no parent directory"))
        })
        .map_err(WinDivertBootstrapError::ExePathUnknown)
}

/// Ensure WinDivert DLL and kernel driver are present next to the engine binary.
///
/// If `WinDivert.dll` already exists alongside the current executable, returns
/// immediately with `Ok(false)`.  Otherwise downloads the WinDivert 2.2.2
/// release ZIP from GitHub, extracts `WinDivert.dll` and `WinDivert64.sys`,
/// and writes them next to the engine binary.
///
/// Returns `Ok(true)` if files were downloaded, `Ok(false)` if already present,
/// or `Err` on download/extraction failure.  Callers should treat errors as
/// non-fatal (log a warning and continue without WinDivert).
pub async fn ensure_windivert_available() -> Result<bool, WinDivertBootstrapError> {
    let dir = engine_dir()?;
    let dll_path = dir.join("WinDivert.dll");

    if dll_path.exists() {
        return Ok(false);
    }

    info!(
        target: "windivert",
        "WinDivert.dll not found — downloading from GitHub release"
    );

    let zip_bytes = download_zip().await?;
    let files = extract_files(&zip_bytes)?;

    for (name, data) in &files {
        let dest = dir.join(name);
        tokio::fs::write(&dest, data)
            .await
            .map_err(WinDivertBootstrapError::FileWrite)?;
        info!(
            target: "windivert",
            path = %dest.display(),
            size = data.len(),
            "extracted {name}"
        );
    }

    Ok(true)
}

/// Download the WinDivert release ZIP into memory.
async fn download_zip() -> Result<Vec<u8>, WinDivertBootstrapError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .map_err(|e| WinDivertBootstrapError::Download(e.to_string()))?;

    let resp = client
        .get(WINDIVERT_ZIP_URL)
        .send()
        .await
        .map_err(|e| WinDivertBootstrapError::Download(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(WinDivertBootstrapError::Download(format!(
            "HTTP {}",
            resp.status()
        )));
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| WinDivertBootstrapError::Download(e.to_string()))
}

/// Extract the required DLL and SYS files from the ZIP archive.
///
/// Matches files by their trailing filename component (case-insensitive) inside
/// the `x64` subdirectory of the archive.
fn extract_files(zip_bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, WinDivertBootstrapError> {
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| WinDivertBootstrapError::ZipExtract(format!("open: {e}")))?;

    let mut extracted: Vec<(String, Vec<u8>)> = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| WinDivertBootstrapError::ZipExtract(format!("entry {i}: {e}")))?;

        let entry_path = entry.name().to_owned();

        // Only extract from x64 subdirectory.
        if !entry_path.to_ascii_lowercase().contains("x64") {
            continue;
        }

        let file_name = Path::new(&entry_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let matched = REQUIRED_FILES
            .iter()
            .find(|&&req| req.eq_ignore_ascii_case(file_name));

        if let Some(&target_name) = matched {
            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut buf).map_err(|e| {
                WinDivertBootstrapError::ZipExtract(format!("read '{entry_path}': {e}"))
            })?;
            extracted.push((target_name.to_owned(), buf));
        }
    }

    if extracted.len() < REQUIRED_FILES.len() {
        let found: Vec<&str> = extracted.iter().map(|(n, _)| n.as_str()).collect();
        return Err(WinDivertBootstrapError::ZipExtract(format!(
            "expected {} files, found {} ({:?})",
            REQUIRED_FILES.len(),
            found.len(),
            found
        )));
    }

    Ok(extracted)
}

#[cfg(test)]
mod windivert_bootstrap_tests {
    use super::*;

    #[test]
    fn engine_dir_returns_path() {
        // Should not fail in a test environment.
        let dir = engine_dir();
        assert!(dir.is_ok(), "engine_dir() should succeed: {:?}", dir.err());
    }

    /// Build a minimal ZIP in memory with the expected WinDivert structure.
    fn build_test_zip() -> Vec<u8> {
        use std::io::Write;

        let buf = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(buf);

        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        // Write a fake DLL inside x64/
        zip.start_file("WinDivert-2.2.2-A/x64/WinDivert.dll", opts)
            .expect("start_file");
        zip.write_all(b"FAKE_DLL_DATA").expect("write");

        // Write a fake SYS inside x64/
        zip.start_file("WinDivert-2.2.2-A/x64/WinDivert64.sys", opts)
            .expect("start_file");
        zip.write_all(b"FAKE_SYS_DATA").expect("write");

        // Write a decoy in x86/
        zip.start_file("WinDivert-2.2.2-A/x86/WinDivert.dll", opts)
            .expect("start_file");
        zip.write_all(b"WRONG_ARCH").expect("write");

        zip.finish().expect("finish").into_inner()
    }

    #[test]
    fn extract_finds_x64_files() {
        let zip_data = build_test_zip();
        let files = extract_files(&zip_data).expect("should extract successfully");

        assert_eq!(files.len(), 2);

        let dll = files.iter().find(|(n, _)| n == "WinDivert.dll");
        assert!(dll.is_some(), "should find WinDivert.dll");
        assert_eq!(dll.unwrap().1, b"FAKE_DLL_DATA");

        let sys = files.iter().find(|(n, _)| n == "WinDivert64.sys");
        assert!(sys.is_some(), "should find WinDivert64.sys");
        assert_eq!(sys.unwrap().1, b"FAKE_SYS_DATA");
    }

    #[test]
    fn extract_fails_on_empty_zip() {
        let buf = std::io::Cursor::new(Vec::new());
        let zip = zip::ZipWriter::new(buf);
        let zip_data = zip.finish().expect("finish").into_inner();

        let result = extract_files(&zip_data);
        assert!(result.is_err());
    }
}

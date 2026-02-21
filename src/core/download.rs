use std::path::PathBuf;

#[derive(Debug, Clone)]
/// Result of a file download performed by the engine.
pub struct DownloadOutcome {
    /// HTTP status code of the "probe" response (HEAD or range probe). For ranged downloads this
    /// typically still ends up being `200` from a HEAD, even though the chunk GETs are `206`.
    pub status_code: u16,
    /// Response headers captured from the "probe" response.
    pub headers: Vec<(String, String)>,
    /// Total number of bytes written to the target file.
    pub bytes_written: u64,
    /// Whether the engine resumed from an existing partial download (best-effort).
    pub resumed: bool,
    /// Whether ranged / chunked downloading was used.
    pub chunked: bool,
    /// Final output file path.
    pub path: PathBuf,
}

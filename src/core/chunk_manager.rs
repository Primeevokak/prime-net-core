use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, RANGE};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::core::RequestData;
use crate::error::{EngineError, Result};

pub type ProgressHook = Arc<dyn Fn(u64, u64, f64) + Send + Sync + 'static>;

#[derive(Debug, Clone)]
pub struct DownloadStrategy {
    pub initial_concurrency: usize,
    pub max_concurrency: usize,
    pub chunk_size_bytes: usize,
    pub adaptive_threshold_mbps: f64,
    pub max_response_body_mb: usize,
}

impl Default for DownloadStrategy {
    fn default() -> Self {
        Self {
            initial_concurrency: 4,
            max_concurrency: 16,
            chunk_size_bytes: 4 * 1024 * 1024,
            adaptive_threshold_mbps: 25.0,
            max_response_body_mb: 100,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ChunkRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug)]
pub struct ChunkManager {
    strategy: DownloadStrategy,
    concurrent_chunks: AtomicUsize,
    adaptive_enabled: bool,
}

impl ChunkManager {
    pub fn new(strategy: DownloadStrategy, adaptive_enabled: bool) -> Self {
        Self {
            concurrent_chunks: AtomicUsize::new(strategy.initial_concurrency.max(1)),
            strategy,
            adaptive_enabled,
        }
    }

    pub fn calculate_chunks(&self, content_length: u64) -> Vec<ChunkRange> {
        if content_length == 0 {
            return Vec::new();
        }
        let chunk = self.strategy.chunk_size_bytes as u64;
        let mut chunks = Vec::new();
        let mut start = 0_u64;
        while start < content_length {
            let end = (start + chunk).saturating_sub(1).min(content_length - 1);
            chunks.push(ChunkRange { start, end });
            start = end + 1;
        }
        chunks
    }

    pub fn adjust_concurrency(&self, current_speed_mbps: f64) {
        if !self.adaptive_enabled {
            return;
        }
        let current = self.concurrent_chunks.load(Ordering::Relaxed);
        if current_speed_mbps > self.strategy.adaptive_threshold_mbps
            && current < self.strategy.max_concurrency
        {
            self.concurrent_chunks.fetch_add(1, Ordering::Relaxed);
        } else if current_speed_mbps <= self.strategy.adaptive_threshold_mbps && current > 1 {
            self.concurrent_chunks.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn current_concurrency(&self) -> usize {
        self.concurrent_chunks
            .load(Ordering::Relaxed)
            .min(self.strategy.max_concurrency)
            .max(1)
    }

    pub async fn download_chunked(
        &self,
        client: &reqwest::Client,
        request: &RequestData,
        content_length: u64,
        max_retries: usize,
        progress: Option<ProgressHook>,
    ) -> Result<Vec<u8>> {
        let max_bytes = (self.strategy.max_response_body_mb as u64) * 1024 * 1024;
        if content_length > max_bytes {
            return Err(EngineError::Internal(format!(
                "chunked download too large ({} bytes, limit is {} MB)",
                content_length, self.strategy.max_response_body_mb
            )));
        }

        if request.method != reqwest::Method::GET {
            return Err(EngineError::InvalidInput(
                "chunked download only supports GET requests".to_owned(),
            ));
        }
        let chunks = self.calculate_chunks(content_length);
        if chunks.is_empty() {
            return Ok(Vec::new());
        }
        let concurrency = self.current_concurrency();

        let semaphore = Arc::new(Semaphore::new(concurrency));
        let downloaded = Arc::new(AtomicU64::new(0));
        let started_at = Instant::now();

        let mut join_set = JoinSet::new();
        for (index, chunk) in chunks.iter().copied().enumerate() {
            let client = client.clone();
            let request = request.clone();
            let downloaded = downloaded.clone();
            let progress = progress.clone();
            let sem = semaphore.clone();

            join_set.spawn(async move {
                let _permit = sem
                    .acquire_owned()
                    .await
                    .map_err(|_| EngineError::Internal("semaphore closed".to_owned()))?;

                let bytes =
                    download_chunk_with_retry(&client, &request, chunk, max_retries).await?;
                let chunk_len = bytes.len() as u64;
                let total_downloaded =
                    downloaded.fetch_add(chunk_len, Ordering::Relaxed) + chunk_len;

                if let Some(cb) = progress {
                    let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
                    let speed_mbps = (total_downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
                    cb(total_downloaded, content_length, speed_mbps);
                }
                Ok::<(usize, Vec<u8>), EngineError>((index, bytes))
            });
        }

        let mut ordered_parts = vec![Vec::new(); chunks.len()];
        while let Some(result) = join_set.join_next().await {
            let (index, bytes) = result??;
            ordered_parts[index] = bytes;
        }

        let mut merged = Vec::with_capacity(content_length as usize);
        for part in ordered_parts {
            merged.extend_from_slice(&part);
        }

        let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
        let speed_mbps = (content_length as f64 * 8.0 / 1_000_000.0) / elapsed;
        self.adjust_concurrency(speed_mbps);
        Ok(merged)
    }

    pub async fn download_to_path(
        &self,
        client: &reqwest::Client,
        request: &RequestData,
        content_length: u64,
        max_retries: usize,
        path: &std::path::Path,
        progress: Option<ProgressHook>,
    ) -> Result<()> {
        use std::fs::OpenOptions;
        #[cfg(windows)]
        use std::os::windows::fs::FileExt;
        #[cfg(unix)]
        use std::os::unix::fs::FileExt;

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        if content_length > 0 {
            file.set_len(content_length)?;
        }
        let file = Arc::new(file);

        let chunks = self.calculate_chunks(content_length);
        let concurrency = self.current_concurrency();
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let downloaded = Arc::new(AtomicU64::new(0));
        let started_at = Instant::now();

        let mut join_set = JoinSet::new();
        for chunk in chunks {
            let client = client.clone();
            let request = request.clone();
            let downloaded = downloaded.clone();
            let progress = progress.clone();
            let sem = semaphore.clone();
            let file = file.clone();

            join_set.spawn(async move {
                let _permit = sem
                    .acquire_owned()
                    .await
                    .map_err(|_| EngineError::Internal("semaphore closed".to_owned()))?;

                let bytes =
                    download_chunk_with_retry(&client, &request, chunk, max_retries).await?;

                let chunk_len = bytes.len() as u64;
                let chunk_start = chunk.start;
                
                tokio::task::spawn_blocking(move || {
                    #[cfg(windows)]
                    file.seek_write(&bytes, chunk_start)?;
                    #[cfg(unix)]
                    file.write_at(&bytes, chunk_start)?;
                    Ok::<(), std::io::Error>(())
                })
                .await
                .map_err(|e| EngineError::Internal(format!("blocking write task failed: {e}")))??;

                let total_downloaded =
                    downloaded.fetch_add(chunk_len, Ordering::Relaxed) + chunk_len;

                if let Some(cb) = progress {
                    let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
                    let speed_mbps = (total_downloaded as f64 * 8.0 / 1_000_000.0) / elapsed;
                    cb(total_downloaded, content_length, speed_mbps);
                }
                Ok::<(), EngineError>(())
            });
        }

        while let Some(result) = join_set.join_next().await {
            result??;
        }

        let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
        let speed_mbps = (content_length as f64 * 8.0 / 1_000_000.0) / elapsed;
        self.adjust_concurrency(speed_mbps);
        Ok(())
    }
}

async fn download_chunk_with_retry(
    client: &reqwest::Client,
    request: &RequestData,
    chunk: ChunkRange,
    max_retries: usize,
) -> Result<Vec<u8>> {
    let mut last_error: Option<EngineError> = None;
    for attempt in 0..=max_retries {
        match download_range(client, request, chunk).await {
            Ok(data) => return Ok(data),
            Err(err) => {
                let retryable = is_retryable_chunk_error(&err);
                last_error = Some(err);
                if !retryable || attempt >= max_retries {
                    break;
                }
                tokio::time::sleep(chunk_retry_delay(attempt)).await;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| EngineError::Internal("chunk download failed".to_owned())))
}

fn is_retryable_chunk_error(err: &EngineError) -> bool {
    match err {
        EngineError::Http(e) => e.is_timeout() || e.is_connect() || e.is_request(),
        EngineError::Io(e) => matches!(
            e.kind(),
            std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::WouldBlock
        ),
        _ => false,
    }
}

fn chunk_retry_delay(attempt: usize) -> Duration {
    let exp = 1u64 << attempt.min(5);
    Duration::from_millis((100u64.saturating_mul(exp)).min(2_000))
}

use crate::core::request::parse_content_range_bounds;

async fn download_range(
    client: &reqwest::Client,
    request: &RequestData,
    chunk: ChunkRange,
) -> Result<Vec<u8>> {
    let range_value = format!("bytes={}-{}", chunk.start, chunk.end);
    let mut headers = HeaderMap::new();
    for (name, value) in &request.headers {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_str(value)?,
        );
    }
    headers.insert(RANGE, HeaderValue::from_str(&range_value)?);

    let response = client.get(&request.url).headers(headers).send().await?;

    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        return Err(EngineError::Internal(format!(
            "server did not return Partial Content (expected 206, got {})",
            response.status().as_u16()
        )));
    }

    let parsed = parse_content_range_bounds(response.headers()).ok_or_else(|| {
        EngineError::Internal("missing or invalid Content-Range for chunk response".to_owned())
    })?;
    if parsed.start != chunk.start || parsed.end != chunk.end {
        return Err(EngineError::Internal(format!(
            "Content-Range mismatch for chunk: requested {}-{}, got {}-{}",
            chunk.start, chunk.end, parsed.start, parsed.end
        )));
    }

    let bytes = response.bytes().await?.to_vec();
    let expected_len = chunk.end - chunk.start + 1;
    if bytes.len() as u64 != expected_len {
        return Err(EngineError::Internal(format!(
            "chunk size mismatch: expected {expected_len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::CONTENT_RANGE;

    #[test]
    fn parse_content_range_accepts_valid_bytes_range() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_RANGE, HeaderValue::from_static("bytes 10-19/100"));
        let parsed = parse_content_range_bounds(&headers).expect("valid content-range");
        assert_eq!(parsed.start, 10);
        assert_eq!(parsed.end, 19);
    }

    #[test]
    fn parse_content_range_rejects_invalid_header() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_RANGE, HeaderValue::from_static("items 10-19/100"));
        assert!(parse_content_range_bounds(&headers).is_none());
    }

    #[test]
    fn chunk_retry_delay_backoff_is_capped() {
        assert_eq!(chunk_retry_delay(0), Duration::from_millis(100));
        assert_eq!(chunk_retry_delay(1), Duration::from_millis(200));
        assert_eq!(chunk_retry_delay(5), Duration::from_millis(2_000));
        assert_eq!(chunk_retry_delay(10), Duration::from_millis(2_000));
    }

    #[test]
    fn retryable_chunk_error_detection_matches_transient_io() {
        let timeout_err =
            EngineError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
        let bad_input = EngineError::InvalidInput("bad".to_owned());
        assert!(is_retryable_chunk_error(&timeout_err));
        assert!(!is_retryable_chunk_error(&bad_input));
    }
}

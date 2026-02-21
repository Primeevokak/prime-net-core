use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

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
}

impl Default for DownloadStrategy {
    fn default() -> Self {
        Self {
            initial_concurrency: 4,
            max_concurrency: 16,
            chunk_size_bytes: 4 * 1024 * 1024,
            adaptive_threshold_mbps: 25.0,
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

    pub async fn download_chunked(
        &self,
        client: &reqwest::Client,
        request: &RequestData,
        content_length: u64,
        max_retries: usize,
        progress: Option<ProgressHook>,
    ) -> Result<Vec<u8>> {
        if request.method != reqwest::Method::GET {
            return Err(EngineError::InvalidInput(
                "chunked download only supports GET requests".to_owned(),
            ));
        }
        let chunks = self.calculate_chunks(content_length);
        if chunks.is_empty() {
            return Ok(Vec::new());
        }
        let concurrency = self
            .concurrent_chunks
            .load(Ordering::Relaxed)
            .min(self.strategy.max_concurrency)
            .max(1);

        let semaphore = Arc::new(Semaphore::new(concurrency));
        let downloaded = Arc::new(AtomicU64::new(0));
        let started_at = Instant::now();

        let mut join_set = JoinSet::new();
        for (index, chunk) in chunks.iter().copied().enumerate() {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| EngineError::Internal("semaphore closed".to_owned()))?;
            let client = client.clone();
            let request = request.clone();
            let downloaded = downloaded.clone();
            let progress = progress.clone();
            join_set.spawn(async move {
                let _permit = permit;
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
}

async fn download_chunk_with_retry(
    client: &reqwest::Client,
    request: &RequestData,
    chunk: ChunkRange,
    max_retries: usize,
) -> Result<Vec<u8>> {
    let mut last_error: Option<EngineError> = None;
    for _ in 0..=max_retries {
        match download_range(client, request, chunk).await {
            Ok(data) => return Ok(data),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| EngineError::Internal("chunk download failed".to_owned())))
}

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

    let response = client
        .get(&request.url)
        .headers(headers)
        .send()
        .await?
        .error_for_status()?;

    Ok(response.bytes().await?.to_vec())
}

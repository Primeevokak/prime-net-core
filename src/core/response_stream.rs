use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use tokio::io::AsyncRead;

/// Streaming HTTP response (body is not buffered in memory).
pub struct ResponseStream {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub stream: Box<dyn AsyncRead + Send + Unpin>,
}

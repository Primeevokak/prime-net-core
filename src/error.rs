use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("invalid config: {0}")]
    Config(String),
    #[error("null pointer: {0}")]
    NullPointer(&'static str),
    #[error("ffi error: {0}")]
    Ffi(String),
    #[error("http client error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("utf-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("header value error: {0}")]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),
    #[error("header name error: {0}")]
    InvalidHeaderName(#[from] http::header::InvalidHeaderName),
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("resolver not initialized")]
    ResolverMissing,
    #[error("bypass address not set for this route candidate")]
    BypassAddrMissing,
    #[error("internal error: {0}")]
    Internal(String),
    #[error("blocked by privacy policy: {0}")]
    BlockedByPrivacyPolicy(String),
}

pub type Result<T> = std::result::Result<T, EngineError>;

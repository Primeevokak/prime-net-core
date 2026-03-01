use reqwest::Method;

#[derive(Debug, Clone)]
/// High-level HTTP request representation used by the engine public API.
///
/// This is intentionally decoupled from `reqwest::Request` so it can be created and passed across FFI
/// boundaries and used consistently by different HTTP backends.
pub struct RequestData {
    /// Absolute URL (for example, `https://example.com/path`).
    pub url: String,
    /// HTTP method.
    pub method: Method,
    /// Request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Request body bytes.
    pub body: Vec<u8>,
}

impl RequestData {
    /// Creates a new request with empty headers and body.
    pub fn new(url: impl Into<String>, method: Method) -> Self {
        Self {
            url: url.into(),
            method,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Convenience constructor for a `GET` request.
    pub fn get(url: impl Into<String>) -> Self {
        Self::new(url, Method::GET)
    }

    /// Adds a header to the request.
    ///
    /// Note: header names are treated as case-insensitive by the HTTP stack.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets the request body.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }
}

#[derive(Debug, Clone)]
/// High-level HTTP response representation returned by the engine public API.
pub struct ResponseData {
    /// HTTP status code (e.g. `200`).
    pub status_code: u16,
    /// Response headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl ResponseData {
    /// Returns the first header value for `key` (case-insensitive).
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}

/// Parses a single `Header: value` line.
///
/// Returns `None` if the line does not contain `:` or if the header name is empty after trimming.
pub fn parse_header_line(line: &str) -> Option<(String, String)> {
    let (name, value) = line.split_once(':')?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_owned(), value.to_owned()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Bounds and total length extracted from a `Content-Range` header (RFC 9110).
pub struct ContentRangeBounds {
    /// Byte index where the range starts (inclusive).
    pub start: u64,
    /// Byte index where the range ends (inclusive).
    pub end: u64,
    /// Total size of the resource if known (`*` in header means None).
    pub total: Option<u64>,
}

/// Parses a `reqwest::header::HeaderMap` for `Content-Range`.
///
/// Returns `None` if the header is missing, malformed, or if the unit is not `bytes`.
pub fn parse_content_range_bounds(headers: &reqwest::header::HeaderMap) -> Option<ContentRangeBounds> {
    // Content-Range: bytes 0-0/12345
    let v = headers
        .get(reqwest::header::CONTENT_RANGE)?
        .to_str()
        .ok()?
        .trim();
    let (unit, rest) = v.split_once(' ')?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return None;
    }

    let (range_part, total_part) = rest.split_once('/')?;
    let (start_s, end_s) = range_part.split_once('-')?;
    let start = start_s.trim().parse::<u64>().ok()?;
    let end = end_s.trim().parse::<u64>().ok()?;
    if end < start {
        return None;
    }

    let total = if total_part.trim() == "*" {
        None
    } else {
        Some(total_part.trim().parse::<u64>().ok()?)
    };

    if let Some(t) = total {
        if t == 0 || start >= t || end >= t {
            return None;
        }
    }

    Some(ContentRangeBounds { start, end, total })
}

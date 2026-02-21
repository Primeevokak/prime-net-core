use std::path::PathBuf;

use prime_net_engine_core::core::parse_header_line;
use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::{EngineConfig, PrimeEngine, RequestData};
use reqwest::Method;
use tokio::io::{AsyncWriteExt, BufWriter};

#[derive(Debug, Clone)]
pub struct FetchOpts {
    pub url: String,
    pub method: String,
    pub headers: Vec<String>,
    pub body: Option<String>,
    pub body_file: Option<PathBuf>,
    pub out: Option<PathBuf>,
    pub print_headers: bool,
}

#[derive(Debug, Clone)]
pub struct DownloadOpts {
    pub url: String,
    pub out: PathBuf,
}

pub async fn run_fetch(cfg: EngineConfig, opts: &FetchOpts) -> Result<()> {
    let client = PrimeEngine::new(cfg).await?.client();

    let method = opts
        .method
        .parse::<Method>()
        .map_err(|e| EngineError::InvalidInput(e.to_string()))?;
    let mut req = RequestData::new(opts.url.clone(), method);

    for h in &opts.headers {
        let (k, v) = parse_header_line(h).ok_or_else(|| {
            EngineError::InvalidInput(format!("invalid header line (expected 'Key: Value'): {h}"))
        })?;
        req.headers.push((k, v));
    }

    if let Some(path) = &opts.body_file {
        req.body = tokio::fs::read(path).await?;
    } else if let Some(body) = &opts.body {
        req.body = body.as_bytes().to_vec();
    }

    let mut resp = client.fetch_stream(req).await?;

    if opts.print_headers {
        eprintln!("Status: {}", resp.status);
        for (k, v) in resp.headers.iter() {
            match v.to_str() {
                Ok(s) => eprintln!("{}: {}", k, s),
                Err(_) => eprintln!("{}: <binary>", k),
            }
        }
        eprintln!();
    }

    match &opts.out {
        Some(path) if path.as_os_str() == "-" => {
            let mut out = BufWriter::new(tokio::io::stdout());
            tokio::io::copy(&mut resp.stream, &mut out).await?;
            out.flush().await?;
        }
        Some(path) => {
            let f = tokio::fs::File::create(path).await?;
            let mut out = BufWriter::new(f);
            tokio::io::copy(&mut resp.stream, &mut out).await?;
            out.flush().await?;
        }
        None => {
            // Default: stream to stdout.
            let mut out = BufWriter::new(tokio::io::stdout());
            tokio::io::copy(&mut resp.stream, &mut out).await?;
            out.flush().await?;
        }
    }

    Ok(())
}

pub async fn run_download(cfg: EngineConfig, opts: &DownloadOpts) -> Result<()> {
    let client = PrimeEngine::new(cfg).await?.client();
    let outcome = client
        .download_to_path(RequestData::get(opts.url.clone()), &opts.out, None)
        .await?;

    eprintln!(
        "download: bytes_written={} resumed={} path={}",
        outcome.bytes_written,
        outcome.resumed,
        opts.out.display()
    );
    Ok(())
}

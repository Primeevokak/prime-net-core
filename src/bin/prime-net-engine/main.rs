mod blocklist_builtin;
mod blocklist_cmd;
mod blocklist_runtime;
mod config_check;
mod http_cmd;
mod logging;
mod packet_bypass;
mod preset;
mod proxy_cmd;
mod socks_cmd;
mod test_cmd;
mod tui_cmd;
#[cfg(feature = "tun")]
mod tun_cmd;
mod update_cmd;
mod wizard;

use std::path::PathBuf;

use prime_net_engine_core::error::{EngineError, Result};
use prime_net_engine_core::EngineConfig;
use tracing::{info, Level};

use crate::blocklist_cmd::{run_blocklist, BlocklistOpts};
use crate::config_check::{run_config_check, ConfigCheckOpts};
use crate::http_cmd::{run_download, run_fetch, DownloadOpts, FetchOpts};
use crate::logging::{init_logging, LogFormat, LogRotation, LoggingOpts};
use crate::preset::apply_preset;
use crate::proxy_cmd::{run_proxy, ProxyOpts};
use crate::socks_cmd::{run_socks, SocksOpts};
use crate::test_cmd::{run_test, TestOpts};
use crate::tui_cmd::{run_tui, TuiOpts};
use crate::update_cmd::{run_update, UpdateOpts};
use crate::wizard::{run_wizard, WizardOpts};

fn main() {
    let worker_threads = std::env::var("PRIME_WORKER_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        });

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads.max(1))
        .enable_all()
        // Aggressive I/O polling for lower latency in packet forwarding
        .global_queue_interval(31)
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to build tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    runtime.block_on(async {
        if let Err(e) = real_main().await {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    });
}

async fn real_main() -> Result<()> {
    // Aggressively prevent any library from using system proxy.
    std::env::set_var("http_proxy", "");
    std::env::set_var("https_proxy", "");
    std::env::set_var("all_proxy", "");
    std::env::remove_var("http_proxy");
    std::env::remove_var("https_proxy");
    std::env::remove_var("all_proxy");

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }

    if args.iter().any(|a| a == "-v" || a == "--version") {
        println!(
            "prime-net-engine {}",
            prime_net_engine_core::version::APP_VERSION
        );
        return Ok(());
    }

    let parsed = parse_cli(&args)?;

    init_logging(LoggingOpts {
        level: parsed.log_level,
        format: parsed.log_format,
        file: parsed.log_file.clone(),
        rotation: parsed.log_rotation,
    })
    .map_err(EngineError::Io)?;

    info!(
        version = prime_net_engine_core::version::APP_VERSION,
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
        build = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        "=== PRIME NET ENGINE STARTUP ==="
    );

    let cfg = match &parsed.config_path {
        Some(path) => EngineConfig::from_file(path)?,
        None => EngineConfig::default(),
    };

    let mut cfg = cfg;
    if let Some(name) = parsed.preset.as_deref() {
        let strict = parsed.config_path.is_some();
        apply_preset(&mut cfg, name, strict)?;
    }

    if parsed.config_check {
        let rep = run_config_check(
            &cfg,
            &ConfigCheckOpts {
                offline: parsed.offline,
                probe_domain: parsed.probe_domain.clone(),
            },
        )
        .await?;

        println!("config: OK");
        if !rep.doh_results.is_empty() {
            println!("doh:");
            for (name, ok, msg) in rep.doh_results {
                println!("  {name}: {} ({msg})", if ok { "OK" } else { "FAIL" });
            }
        }
        if !rep.fronting_results.is_empty() {
            println!("fronting:");
            for (label, ok, msg) in rep.fronting_results {
                println!("  {label}: {} ({msg})", if ok { "OK" } else { "FAIL" });
            }
        }
        return Ok(());
    }

    let config_path_for_tui = parsed.config_path.clone();

    match parsed.cmd {
        Some(Cmd::Fetch(opts)) => run_fetch(cfg, &opts).await?,
        Some(Cmd::Download(opts)) => run_download(cfg, &opts).await?,
        Some(Cmd::Socks(opts)) => run_socks(cfg, &opts).await?,
        Some(Cmd::Wizard(opts)) => run_wizard(&opts).await?,
        Some(Cmd::Tui(mut opts)) => {
            if opts.config.is_none() {
                opts.config = config_path_for_tui
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string());
            }
            run_tui(&opts)?
        }
        Some(Cmd::Proxy(opts)) => run_proxy(&opts, &cfg.system_proxy, &cfg.blocklist).await?,
        Some(Cmd::Blocklist(opts)) => run_blocklist(&opts, &cfg.blocklist).await?,
        Some(Cmd::Update(opts)) => run_update(&opts, &cfg.updater).await?,
        Some(Cmd::Test(opts)) => run_test(cfg, &opts).await?,
        #[cfg(feature = "tun")]
        Some(Cmd::Tun(opts)) => crate::tun_cmd::run_tun(cfg, &opts).await?,
        None => {
            print_help();
        }
    }

    Ok(())
}

#[derive(Debug)]
struct ParsedCli {
    config_path: Option<PathBuf>,
    preset: Option<String>,
    config_check: bool,
    offline: bool,
    probe_domain: String,
    log_level: Level,
    log_format: LogFormat,
    log_file: Option<PathBuf>,
    log_rotation: LogRotation,
    cmd: Option<Cmd>,
}

#[derive(Debug)]
enum Cmd {
    Fetch(FetchOpts),
    Download(DownloadOpts),
    Socks(SocksOpts),
    Wizard(WizardOpts),
    Tui(TuiOpts),
    Proxy(ProxyOpts),
    Blocklist(BlocklistOpts),
    Update(UpdateOpts),
    Test(TestOpts),
    #[cfg(feature = "tun")]
    Tun(crate::tun_cmd::TunOpts),
}

fn parse_cli(args: &[String]) -> Result<ParsedCli> {
    let mut i = 0usize;
    let mut out = ParsedCli {
        config_path: None,
        preset: None,
        config_check: false,
        offline: false,
        probe_domain: "example.com".to_owned(),
        log_level: Level::DEBUG,
        log_format: LogFormat::Text,
        log_file: None,
        log_rotation: LogRotation::Daily,
        cmd: None,
    };

    while i < args.len() {
        let a = &args[i];
        if !a.starts_with('-') {
            break;
        }

        match a.as_str() {
            "--config" => {
                i += 1;
                out.config_path = Some(PathBuf::from(arg_value(args, i, "--config")?));
            }
            "--preset" => {
                i += 1;
                out.preset = Some(arg_value(args, i, "--preset")?.to_owned());
            }
            "--config-check" => out.config_check = true,
            "--offline" => out.offline = true,
            "--probe-domain" => {
                i += 1;
                out.probe_domain = arg_value(args, i, "--probe-domain")?.to_owned();
            }
            "--log-level" => {
                i += 1;
                out.log_level = parse_level(arg_value(args, i, "--log-level")?)?;
            }
            "--log-format" => {
                i += 1;
                out.log_format = parse_log_format(arg_value(args, i, "--log-format")?)?;
            }
            "--log-file" => {
                i += 1;
                out.log_file = Some(PathBuf::from(arg_value(args, i, "--log-file")?));
            }
            "--log-rotation" => {
                i += 1;
                out.log_rotation = parse_log_rotation(arg_value(args, i, "--log-rotation")?)?;
            }
            _ => {
                return Err(EngineError::InvalidInput(format!("unknown flag: {a}")));
            }
        }

        i += 1;
    }

    if i >= args.len() {
        return Ok(out);
    }

    let cmd = args[i].as_str();
    let rest = &args[i + 1..];
    out.cmd = Some(match cmd {
        "fetch" => Cmd::Fetch(parse_fetch(rest)?),
        "download" => Cmd::Download(parse_download(rest)?),
        "socks" => Cmd::Socks(parse_socks(rest)?),
        "wizard" => Cmd::Wizard(parse_wizard(rest)?),
        "tui" => Cmd::Tui(parse_tui(rest)?),
        "proxy" => Cmd::Proxy(parse_proxy(rest)?),
        "blocklist" => Cmd::Blocklist(parse_blocklist(rest)?),
        "update" => Cmd::Update(parse_update(rest)?),
        "test" => Cmd::Test(parse_test(rest)?),
        #[cfg(feature = "tun")]
        "tun" => Cmd::Tun(parse_tun(rest)?),
        _ => {
            return Err(EngineError::InvalidInput(format!("unknown command: {cmd}")));
        }
    });

    Ok(out)
}

fn parse_fetch(args: &[String]) -> Result<FetchOpts> {
    if args.is_empty() {
        return Err(EngineError::InvalidInput("fetch: missing <url>".to_owned()));
    }
    let mut i = 0usize;
    let url = args[i].clone();
    i += 1;

    let mut method = "GET".to_owned();
    let mut headers = Vec::new();
    let mut body: Option<String> = None;
    let mut body_file: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut print_headers = false;

    while i < args.len() {
        match args[i].as_str() {
            "--method" => {
                i += 1;
                method = arg_value(args, i, "--method")?.to_owned();
            }
            "-H" | "--header" => {
                i += 1;
                headers.push(arg_value(args, i, "--header")?.to_owned());
            }
            "--body" => {
                i += 1;
                body = Some(arg_value(args, i, "--body")?.to_owned());
            }
            "--body-file" => {
                i += 1;
                body_file = Some(PathBuf::from(arg_value(args, i, "--body-file")?));
            }
            "--out" => {
                i += 1;
                out = Some(PathBuf::from(arg_value(args, i, "--out")?));
            }
            "--print-headers" => print_headers = true,
            v => {
                return Err(EngineError::InvalidInput(format!(
                    "fetch: unknown arg: {v}"
                )));
            }
        }
        i += 1;
    }

    Ok(FetchOpts {
        url,
        method,
        headers,
        body,
        body_file,
        out,
        print_headers,
    })
}

fn parse_download(args: &[String]) -> Result<DownloadOpts> {
    if args.is_empty() {
        return Err(EngineError::InvalidInput(
            "download: missing <url>".to_owned(),
        ));
    }
    let mut i = 0usize;
    let url = args[i].clone();
    i += 1;

    let mut out: Option<PathBuf> = None;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out = Some(PathBuf::from(arg_value(args, i, "--out")?));
            }
            v => {
                return Err(EngineError::InvalidInput(format!(
                    "download: unknown arg: {v}"
                )));
            }
        }
        i += 1;
    }

    let out =
        out.ok_or_else(|| EngineError::InvalidInput("download: --out is required".to_owned()))?;
    Ok(DownloadOpts { url, out })
}

fn parse_wizard(args: &[String]) -> Result<WizardOpts> {
    let mut out_path = PathBuf::from("prime-net-engine.toml");
    let mut force = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_path = PathBuf::from(arg_value(args, i, "--out")?);
            }
            "--force" => force = true,
            v => {
                return Err(EngineError::InvalidInput(format!(
                    "wizard: unknown arg: {v}"
                )));
            }
        }
        i += 1;
    }

    Ok(WizardOpts { out_path, force })
}

fn parse_socks(args: &[String]) -> Result<SocksOpts> {
    let mut bind = "127.0.0.1:1080".to_owned();
    let mut silent_drop = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                bind = arg_value(args, i, "--bind")?.to_owned();
            }
            "--silent-drop" => silent_drop = true,
            v => {
                return Err(EngineError::InvalidInput(format!(
                    "socks: unknown arg: {v}"
                )));
            }
        }
        i += 1;
    }

    Ok(SocksOpts { bind, silent_drop })
}

fn parse_tui(args: &[String]) -> Result<TuiOpts> {
    let mut config = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                config = Some(arg_value(args, i, "--config")?.to_owned());
            }
            v => {
                return Err(EngineError::InvalidInput(format!("tui: unknown arg: {v}")));
            }
        }
        i += 1;
    }
    Ok(TuiOpts { config })
}

fn parse_proxy(args: &[String]) -> Result<ProxyOpts> {
    use crate::proxy_cmd::ProxyAction;

    if args.is_empty() {
        return Err(EngineError::InvalidInput(
            "proxy: missing subcommand".to_owned(),
        ));
    }
    let sub = args[0].as_str();
    let rest = &args[1..];

    let action = match sub {
        "enable" => {
            let mut mode = "all".to_owned();
            let mut pac_url = None;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--mode" => {
                        i += 1;
                        mode = arg_value(rest, i, "--mode")?.to_owned();
                    }
                    "--pac-url" => {
                        i += 1;
                        pac_url = Some(arg_value(rest, i, "--pac-url")?.to_owned());
                    }
                    v => {
                        return Err(EngineError::InvalidInput(format!(
                            "proxy enable: unknown arg: {v}"
                        )));
                    }
                }
                i += 1;
            }
            ProxyAction::Enable {
                mode,
                custom_pac_url: pac_url,
            }
        }
        "disable" => ProxyAction::Disable,
        "status" => ProxyAction::Status,
        "generate-pac" => {
            let mut output = PathBuf::from("proxy.pac");
            let mut socks_endpoint = "127.0.0.1:1080".to_owned();
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--output" => {
                        i += 1;
                        output = PathBuf::from(arg_value(rest, i, "--output")?);
                    }
                    "--socks-endpoint" => {
                        i += 1;
                        socks_endpoint = arg_value(rest, i, "--socks-endpoint")?.to_owned();
                    }
                    v => {
                        return Err(EngineError::InvalidInput(format!(
                            "proxy generate-pac: unknown arg: {v}"
                        )));
                    }
                }
                i += 1;
            }
            ProxyAction::GeneratePac {
                output,
                socks_endpoint,
            }
        }
        "serve-pac" => {
            let mut port = 8888_u16;
            let mut socks_endpoint = "127.0.0.1:1080".to_owned();
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--port" => {
                        i += 1;
                        port = arg_value(rest, i, "--port")?.parse().map_err(|e| {
                            EngineError::InvalidInput(format!("invalid --port: {e}"))
                        })?;
                    }
                    "--socks-endpoint" => {
                        i += 1;
                        socks_endpoint = arg_value(rest, i, "--socks-endpoint")?.to_owned();
                    }
                    v => {
                        return Err(EngineError::InvalidInput(format!(
                            "proxy serve-pac: unknown arg: {v}"
                        )));
                    }
                }
                i += 1;
            }
            ProxyAction::ServePac {
                port,
                socks_endpoint,
            }
        }
        _ => {
            return Err(EngineError::InvalidInput(format!(
                "proxy: unknown subcommand: {sub}"
            )));
        }
    };

    Ok(ProxyOpts { action })
}

fn parse_blocklist(args: &[String]) -> Result<BlocklistOpts> {
    use crate::blocklist_cmd::BlocklistAction;
    if args.is_empty() {
        return Err(EngineError::InvalidInput(
            "blocklist: missing subcommand".to_owned(),
        ));
    }
    let mut source_override = None;
    let action = match args[0].as_str() {
        "update" => {
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--source" => {
                        i += 1;
                        source_override = Some(arg_value(args, i, "--source")?.to_owned());
                    }
                    v => {
                        return Err(EngineError::InvalidInput(format!(
                            "blocklist update: unknown arg: {v}"
                        )));
                    }
                }
                i += 1;
            }
            BlocklistAction::Update
        }
        "status" => BlocklistAction::Status,
        v => {
            return Err(EngineError::InvalidInput(format!(
                "blocklist: unknown subcommand: {v}"
            )));
        }
    };
    Ok(BlocklistOpts {
        action,
        source_override,
    })
}

fn parse_update(args: &[String]) -> Result<UpdateOpts> {
    use crate::update_cmd::UpdateAction;
    use prime_net_engine_core::config::UpdateChannel;
    if args.is_empty() {
        return Err(EngineError::InvalidInput(
            "update: missing subcommand".to_owned(),
        ));
    }
    let action = match args[0].as_str() {
        "check" => {
            let mut channel = None;
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--channel" => {
                        i += 1;
                        channel = Some(
                            match arg_value(args, i, "--channel")?
                                .trim()
                                .to_ascii_lowercase()
                                .as_str()
                            {
                                "stable" => UpdateChannel::Stable,
                                "beta" => UpdateChannel::Beta,
                                "nightly" => UpdateChannel::Nightly,
                                v => {
                                    return Err(EngineError::InvalidInput(format!(
                                        "update check: invalid --channel value: {v}"
                                    )));
                                }
                            },
                        );
                    }
                    v => {
                        return Err(EngineError::InvalidInput(format!(
                            "update check: unknown arg: {v}"
                        )));
                    }
                }
                i += 1;
            }
            UpdateAction::Check { channel }
        }
        "rollback" => UpdateAction::Rollback,
        "install" => {
            let mut version = None;
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--version" => {
                        i += 1;
                        version = Some(arg_value(args, i, "--version")?.to_owned());
                    }
                    v => {
                        return Err(EngineError::InvalidInput(format!(
                            "update install: unknown arg: {v}"
                        )));
                    }
                }
                i += 1;
            }
            UpdateAction::Install { version }
        }
        v => {
            return Err(EngineError::InvalidInput(format!(
                "update: unknown subcommand: {v}"
            )));
        }
    };
    Ok(UpdateOpts { action })
}

fn parse_test(args: &[String]) -> Result<TestOpts> {
    let mut url = "https://example.com".to_owned();
    let mut check_leaks = false;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--url" => {
                i += 1;
                url = arg_value(args, i, "--url")?.to_owned();
            }
            "--check-leaks" => check_leaks = true,
            v if !v.starts_with('-') && i == 0 => {
                url = v.to_owned();
            }
            v => {
                return Err(EngineError::InvalidInput(format!("test: unknown arg: {v}")));
            }
        }
        i += 1;
    }
    Ok(TestOpts { url, check_leaks })
}

fn arg_value<'a>(args: &'a [String], idx: usize, flag: &str) -> Result<&'a str> {
    args.get(idx)
        .map(|s| s.as_str())
        .ok_or_else(|| EngineError::InvalidInput(format!("{flag}: missing value")))
}

fn parse_level(s: &str) -> Result<Level> {
    match s.trim().to_ascii_lowercase().as_str() {
        "error" => Ok(Level::ERROR),
        "warn" | "warning" => Ok(Level::WARN),
        "info" => Ok(Level::INFO),
        "debug" => Ok(Level::DEBUG),
        "trace" => Ok(Level::TRACE),
        _ => Err(EngineError::InvalidInput(format!("invalid log level: {s}"))),
    }
}

fn parse_log_format(s: &str) -> Result<LogFormat> {
    match s.trim().to_ascii_lowercase().as_str() {
        "text" => Ok(LogFormat::Text),
        "json" => Ok(LogFormat::Json),
        _ => Err(EngineError::InvalidInput(format!(
            "invalid log format: {s} (expected text|json)"
        ))),
    }
}

fn parse_log_rotation(s: &str) -> Result<LogRotation> {
    match s.trim().to_ascii_lowercase().as_str() {
        "never" => Ok(LogRotation::Never),
        "daily" => Ok(LogRotation::Daily),
        "hourly" => Ok(LogRotation::Hourly),
        "minutely" => Ok(LogRotation::Minutely),
        _ => Err(EngineError::InvalidInput(format!(
            "invalid log rotation: {s} (expected never|daily|hourly|minutely)"
        ))),
    }
}

fn print_help() {
    println!(
        r#"prime-net-engine

USAGE:
  prime-net-engine [GLOBAL_OPTS] --config-check [--offline]
  prime-net-engine [GLOBAL_OPTS] fetch <url> [FETCH_OPTS]
  prime-net-engine [GLOBAL_OPTS] download <url> --out <path>
  prime-net-engine [GLOBAL_OPTS] socks [SOCKS_OPTS]
  prime-net-engine [GLOBAL_OPTS] wizard [--out <path>] [--force]
  prime-net-engine [GLOBAL_OPTS] tui [--config <path>]
  prime-net-engine [GLOBAL_OPTS] proxy <enable|disable|status|generate-pac|serve-pac> [OPTS]
  prime-net-engine [GLOBAL_OPTS] blocklist <update|status>
  prime-net-engine [GLOBAL_OPTS] update <check|install|rollback> [OPTS]
  prime-net-engine [GLOBAL_OPTS] test [--url <url>] [--check-leaks]
  prime-net-engine [GLOBAL_OPTS] tun [TUN_OPTS]   (requires --features tun)

GLOBAL_OPTS:
  -v, --version            Print version information
  --config <path>          Config file (TOML/JSON/YAML)
  --preset <name>          Apply a built-in preset (strict-privacy|balanced-privacy|max-compatibility|aggressive-evasion)
  --config-check           Validate config and probe DoH/fronting endpoints
  --offline                Skip network probes for --config-check
  --probe-domain <domain>  Domain used for DoH probe queries (default: example.com)
  --log-level <lvl>        error|warn|info|debug|trace (default: info)
  --log-format <fmt>       text|json (default: text)
  --log-file <path>        Write logs to file (optional)
  --log-rotation <rot>     never|daily|hourly|minutely (default: daily)

FETCH_OPTS:
  --method <METHOD>        Default: GET
  -H, --header <line>      Add header, repeatable, format: 'Key: Value'
  --body <string>          Request body as UTF-8
  --body-file <path>       Request body from file (binary)
  --out <path>             Output file path, or '-' for stdout (default: stdout)
  --print-headers          Print response status+headers to stderr

SOCKS_OPTS:
  --bind <host:port>       Listen address (default: 127.0.0.1:1080)
  --silent-drop            Be quiet on invalid handshakes (best-effort)

PROXY_OPTS:
  enable --mode <m>        all|pac|custom
  enable --pac-url <url>   Required for mode=custom
  generate-pac --output <path> [--socks-endpoint <host:port>]
  serve-pac --port <n> [--socks-endpoint <host:port>]

UPDATE_OPTS:
  check --channel <name>   stable|beta|nightly
  install --version <v>    Install a specific version tag (optional)

BLOCKLIST_OPTS:
  update --source <url>    Override blocklist source URL for this run

TUN_OPTS (feature = tun):
  --tun-name <name>        Interface name (default: prime0)
  --tun-addr <ip>          TUN interface IP (default: 10.88.0.1)
  --tun-prefix <n>         CIDR prefix length (default: 16)
  --socks-addr <host:port> SOCKS5 backend (default: 127.0.0.1:1080)
  --mtu <n>                MTU (default: 1500)
  --print-routes           Print routing setup commands and exit
"#
    );
}

#[cfg(feature = "tun")]
fn parse_tun(args: &[String]) -> Result<crate::tun_cmd::TunOpts> {
    let mut opts = crate::tun_cmd::TunOpts::default();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--tun-name" => {
                i += 1;
                opts.tun_name = arg_value(args, i, "--tun-name")?.to_owned();
            }
            "--tun-addr" => {
                i += 1;
                opts.tun_addr = arg_value(args, i, "--tun-addr")?
                    .parse()
                    .map_err(|_| EngineError::InvalidInput("tun: invalid --tun-addr".to_owned()))?;
            }
            "--tun-prefix" => {
                i += 1;
                opts.tun_prefix = arg_value(args, i, "--tun-prefix")?.parse().map_err(|_| {
                    EngineError::InvalidInput("tun: invalid --tun-prefix".to_owned())
                })?;
            }
            "--socks-addr" => {
                i += 1;
                opts.socks_addr = arg_value(args, i, "--socks-addr")?.parse().map_err(|_| {
                    EngineError::InvalidInput("tun: invalid --socks-addr".to_owned())
                })?;
            }
            "--mtu" => {
                i += 1;
                opts.mtu = arg_value(args, i, "--mtu")?
                    .parse()
                    .map_err(|_| EngineError::InvalidInput("tun: invalid --mtu".to_owned()))?;
            }
            "--print-routes" => opts.print_routes_only = true,
            v => {
                return Err(EngineError::InvalidInput(format!("tun: unknown arg: {v}")));
            }
        }
        i += 1;
    }
    Ok(opts)
}

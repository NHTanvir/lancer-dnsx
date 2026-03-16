//! lancer-dnsx — Phase 0: skeleton and A/AAAA resolve

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    error::ResolveErrorKind,
    TokioAsyncResolver,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Known multi-character long flags (without leading dashes).
/// Any `-flag` that appears in this list gets rewritten to `--flag`
/// so clap can handle it. This emulates Go-style single-dash long flags.
const SINGLE_DASH_LONG_FLAGS: &[&str] = &[
    "list",
    "aaaa",
    "threads",
    "timeout",
    "retry",
    "resp-only",
    "ro",
    "resp",
    "re",
    "silent",
    "no-color",
    "output",
    "version",
];

/// Rewrite single-dash long flags to double-dash so clap can parse them.
///
/// `-silent` → `--silent`
/// `-resp-only` → `--resp-only`
/// `-l foo` stays as `-l foo` (single char, handled natively)
fn normalize_args(args: impl Iterator<Item = String>) -> Vec<String> {
    args.map(|arg| {
        // Only touch things that start with exactly one '-' followed by 2+ chars
        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() >= 3 {
            let without_dash = &arg[1..];
            // Check if the base (before '=') matches a known long flag
            let base = without_dash.split('=').next().unwrap_or(without_dash);
            if SINGLE_DASH_LONG_FLAGS.contains(&base) {
                return format!("-{arg}"); // add one more '-'
            }
        }
        arg
    })
    .collect()
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// Rust clone of dnsx — fast and multi-purpose DNS toolkit
#[derive(Parser, Debug)]
#[command(
    name = "lancer-dnsx",
    version = VERSION,
    about = "Rust clone of dnsx — fast and multi-purpose DNS toolkit",
    long_about = None,
    disable_version_flag = true,
)]
struct Cli {
    // ---- input ----
    #[clap(next_help_heading = "Input")]
    /// Input file containing list of hosts/IPs, or comma-separated hosts
    #[arg(short = 'l', long = "list", value_name = "FILE_OR_HOSTS")]
    list: Option<String>,

    // ---- query type ----
    #[clap(next_help_heading = "Query")]
    /// Query A records (default)
    #[arg(short = 'a')]
    query_a: bool,

    /// Query AAAA records
    #[arg(long = "aaaa")]
    query_aaaa: bool,

    // ---- filter ----
    #[clap(next_help_heading = "Filter")]
    /// Number of concurrent workers
    #[arg(short = 't', long = "threads", default_value_t = 100)]
    threads: usize,

    // ---- output ----
    #[clap(next_help_heading = "Output")]
    /// Show full response value alongside host (format: "host TYPE value")
    #[arg(long = "resp", visible_alias = "re")]
    resp: bool,

    /// Show only the response value (IP address)
    #[arg(long = "resp-only", visible_alias = "ro")]
    resp_only: bool,

    /// Suppress banner and non-result output
    #[arg(long = "silent")]
    silent: bool,

    /// Disable ANSI color output
    /// Phase 0: output is plain text with no ANSI codes; this flag is wired
    /// through to format_result so future color output can be suppressed.
    #[arg(long = "no-color")]
    no_color: bool,

    /// Write output to file
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<String>,

    // ---- configurations ----
    #[clap(next_help_heading = "Configurations")]
    /// Per-query timeout in seconds
    #[arg(long = "timeout", default_value_t = 3)]
    timeout: u64,

    /// Number of retries on failure
    #[arg(long = "retry", default_value_t = 2)]
    retry: usize,

    // ---- debug ----
    #[clap(next_help_heading = "Debug")]
    /// Print version and exit
    #[arg(short = 'v', long = "version")]
    version: bool,
}

// ---------------------------------------------------------------------------
// Resolver pool
// ---------------------------------------------------------------------------

/// Build the default 8-resolver pool (Cloudflare, Google, Quad9, OpenDNS).
fn default_name_servers() -> Vec<NameServerConfig> {
    let addrs: &[&str] = &[
        "1.1.1.1:53",
        "1.0.0.1:53",
        "8.8.8.8:53",
        "8.8.4.4:53",
        "9.9.9.9:53",
        "149.112.112.112:53",
        "208.67.222.222:53",
        "208.67.220.220:53",
    ];
    addrs
        .iter()
        .map(|a| {
            let sa: SocketAddr = a.parse().expect("static addr");
            NameServerConfig::new(sa, Protocol::Udp)
        })
        .collect()
}

fn build_resolver(
    servers: &[NameServerConfig],
    timeout_secs: u64,
    retries: usize,
) -> Result<TokioAsyncResolver> {
    let mut config = ResolverConfig::new();
    for ns in servers {
        config.add_name_server(ns.clone());
    }

    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(timeout_secs);
    opts.attempts = retries;
    opts.num_concurrent_reqs = 1;

    let resolver = TokioAsyncResolver::tokio(config, opts);
    Ok(resolver)
}

// ---------------------------------------------------------------------------
// Resolution helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum RecordType {
    A,
    Aaaa,
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::Aaaa => write!(f, "AAAA"),
        }
    }
}

#[derive(Debug, Clone)]
struct DnsResult {
    host: String,
    record_type: RecordType,
    value: String,
}

async fn resolve_host(
    resolver: Arc<TokioAsyncResolver>,
    host: String,
    query_a: bool,
    query_aaaa: bool,
    silent: bool,
) -> Vec<DnsResult> {
    let mut results = Vec::new();

    // Determine which record types to query
    let do_a = query_a || !query_aaaa; // A is default unless only AAAA requested
    let do_aaaa = query_aaaa;

    if do_a {
        match resolver.ipv4_lookup(host.as_str()).await {
            Ok(response) => {
                for record in response.iter() {
                    results.push(DnsResult {
                        host: host.clone(),
                        record_type: RecordType::A,
                        value: record.to_string(),
                    });
                }
            }
            Err(e) => match e.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => {}
                _ => {
                    if !silent {
                        eprintln!("[WARN] {} A: {}", host, e);
                    }
                }
            },
        }
    }

    if do_aaaa {
        match resolver.ipv6_lookup(host.as_str()).await {
            Ok(response) => {
                for record in response.iter() {
                    results.push(DnsResult {
                        host: host.clone(),
                        record_type: RecordType::Aaaa,
                        value: record.to_string(),
                    });
                }
            }
            Err(e) => match e.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => {}
                _ => {
                    if !silent {
                        eprintln!("[WARN] {} AAAA: {}", host, e);
                    }
                }
            },
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Input collection
// ---------------------------------------------------------------------------

async fn collect_input(list: Option<&str>, silent: bool) -> Result<Vec<String>> {
    let mut hosts: Vec<String> = Vec::new();

    if let Some(arg) = list {
        // Check if it looks like a file path (no commas, and the file exists)
        if !arg.contains(',') {
            // Try to open as file
            match tokio::fs::File::open(arg).await {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    let mut lines = reader.lines();
                    while let Some(line) = lines.next_line().await? {
                        let trimmed = line.trim().to_string();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            hosts.push(trimmed);
                        }
                    }
                    return Ok(hosts);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Warn if it looks like a filename that should have existed
                    if arg.ends_with(".txt") || arg.ends_with(".lst") {
                        if !silent {
                            eprintln!("[WARN] File not found: {arg}, treating as hostname");
                        }
                    }
                    // Treat as a single hostname
                    hosts.push(arg.trim().to_string());
                    return Ok(hosts);
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Cannot open input file '{}': {}", arg, e));
                }
            }
        } else {
            // Comma-separated list
            for part in arg.split(',') {
                let trimmed = part.trim().to_string();
                if !trimmed.is_empty() {
                    hosts.push(trimmed);
                }
            }
            return Ok(hosts);
        }
    }

    // Fall back to stdin
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            hosts.push(trimmed);
        }
    }

    Ok(hosts)
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Format a single DNS result for output.
///
/// - Default (no `-resp`, no `-resp-only`): print just the hostname
/// - `-resp` / `-re`: print `host TYPE value`
/// - `-resp-only` / `-ro`: print just `value`
///
/// `no_color`: when true, suppress any ANSI escape codes. Phase 0 emits only
/// plain text, so this flag is a no-op today but is wired through so that
/// future color formatting can check it.
fn format_result(result: &DnsResult, resp: bool, resp_only: bool, _no_color: bool) -> String {
    if resp_only {
        result.value.clone()
    } else if resp {
        format!("{} {} {}", result.host, result.record_type, result.value)
    } else {
        result.host.clone()
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // Normalize Go-style single-dash long flags to double-dash for clap.
    let raw_args: Vec<String> = std::env::args().collect();
    let normalized = normalize_args(raw_args.into_iter());
    let cli = Cli::parse_from(normalized);

    // Handle --version early
    if cli.version {
        println!("lancer-dnsx v{VERSION}");
        return Ok(());
    }

    // Banner (suppressed by --silent)
    if !cli.silent {
        eprintln!(
            "lancer-dnsx v{VERSION} — Rust clone of dnsx\n\
             Use -silent to suppress this banner."
        );
    }

    // Build resolver using the shared name-server pool
    let servers = default_name_servers();
    let resolver = Arc::new(build_resolver(&servers, cli.timeout, cli.retry)?);

    // Collect input hosts
    let hosts = collect_input(cli.list.as_deref(), cli.silent).await?;

    if hosts.is_empty() {
        if !cli.silent {
            eprintln!("No input provided. Use -l <file> or pipe hostnames via stdin.");
        }
        return Ok(());
    }

    // Prepare optional output file (plain, no mutex needed — writes are single-threaded)
    let mut output_file: Option<tokio::fs::File> = if let Some(ref path) = cli.output {
        let f = tokio::fs::File::create(path).await?;
        Some(f)
    } else {
        None
    };

    // Worker pool via async-channel (MPMC — each worker clones the receiver directly)
    let (tx, rx) = async_channel::bounded::<String>(cli.threads * 2);

    // Output channel (tokio mpsc is fine here; workers send, main loop drains)
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<DnsResult>>(cli.threads * 2);

    // Spawn N worker tasks
    let num_workers = cli.threads.min(hosts.len()).max(1);
    let query_a = cli.query_a;
    let query_aaaa = cli.query_aaaa;
    let silent = cli.silent;

    let mut worker_handles = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let resolver_c = Arc::clone(&resolver);
        let rx_c = rx.clone();
        let out_tx_c = out_tx.clone();

        let handle = tokio::spawn(async move {
            while let Ok(host) = rx_c.recv().await {
                let results =
                    resolve_host(Arc::clone(&resolver_c), host, query_a, query_aaaa, silent).await;
                if !results.is_empty() {
                    let _ = out_tx_c.send(results).await;
                }
            }
        });
        worker_handles.push(handle);
    }
    drop(out_tx); // drop the sender clone held in main

    // Feed hosts into the worker channel
    let feed_handle = tokio::spawn(async move {
        for host in hosts {
            if tx.send(host).await.is_err() {
                break;
            }
        }
        // tx drops here, closing the channel
    });

    // Collect and print results
    let resp = cli.resp;
    let resp_only = cli.resp_only;
    let no_color = cli.no_color;

    // Deduplicate printed hosts when using default (hostname-only) output
    let mut printed_hosts: std::collections::HashSet<String> = std::collections::HashSet::new();

    while let Some(batch) = out_rx.recv().await {
        for result in &batch {
            let line = format_result(result, resp, resp_only, no_color);

            // In default mode, only print a hostname once (multiple A records → one line)
            if !resp && !resp_only {
                if !printed_hosts.insert(result.host.clone()) {
                    continue;
                }
            }

            println!("{line}");
            if let Some(ref mut fh) = output_file {
                if let Err(e) = fh.write_all(format!("{line}\n").as_bytes()).await {
                    eprintln!("[ERROR] Failed to write output: {e}");
                }
            }
        }
    }

    // Wait for all workers and feeder to finish
    feed_handle.await?;
    for h in worker_handles {
        h.await?;
    }

    Ok(())
}

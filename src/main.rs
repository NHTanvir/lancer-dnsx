//! lancer-dnsx — Phase 0: skeleton and A/AAAA resolve

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, RwLock};

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
    /// Input file containing list of hosts/IPs, or comma-separated hosts
    #[arg(short = 'l', long = "list", value_name = "FILE_OR_HOSTS")]
    list: Option<String>,

    // ---- query type ----
    /// Query A records (default)
    #[arg(short = 'a', long = "a", default_value_t = false)]
    query_a: bool,

    /// Query AAAA records
    #[arg(long = "aaaa", default_value_t = false)]
    query_aaaa: bool,

    // ---- rate-limit / concurrency ----
    /// Number of concurrent workers
    #[arg(short = 't', long = "threads", default_value_t = 100)]
    threads: usize,

    // ---- configurations ----
    /// Per-query timeout in seconds
    #[arg(long = "timeout", default_value_t = 3)]
    timeout: u64,

    /// Number of retries on failure
    #[arg(long = "retry", default_value_t = 2)]
    retry: usize,

    // ---- output ----
    /// Show full response value alongside host (format: "host TYPE value")
    #[arg(long = "resp", visible_alias = "re", default_value_t = false)]
    resp: bool,

    /// Show only the response value (IP address)
    #[arg(long = "resp-only", visible_alias = "ro", default_value_t = false)]
    resp_only: bool,

    /// Suppress banner and non-result output
    #[arg(long = "silent", default_value_t = false)]
    silent: bool,

    /// Disable ANSI color output
    #[arg(long = "no-color", default_value_t = false)]
    no_color: bool,

    /// Write output to file
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<String>,

    // ---- debug ----
    /// Print version and exit
    #[arg(short = 'v', long = "version", default_value_t = false)]
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

#[derive(Debug, Clone)]
struct DnsResult {
    host: String,
    record_type: String,
    value: String,
}

async fn resolve_host(
    resolver: Arc<TokioAsyncResolver>,
    host: String,
    query_a: bool,
    query_aaaa: bool,
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
                        record_type: "A".to_string(),
                        value: record.to_string(),
                    });
                }
            }
            Err(_) => {}
        }
    }

    if do_aaaa {
        match resolver.ipv6_lookup(host.as_str()).await {
            Ok(response) => {
                for record in response.iter() {
                    results.push(DnsResult {
                        host: host.clone(),
                        record_type: "AAAA".to_string(),
                        value: record.to_string(),
                    });
                }
            }
            Err(_) => {}
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Input collection
// ---------------------------------------------------------------------------

async fn collect_input(list: Option<&str>) -> Result<Vec<String>> {
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
                Err(_) => {
                    // Not a file — treat as a single hostname
                    hosts.push(arg.trim().to_string());
                    return Ok(hosts);
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

fn format_result(result: &DnsResult, resp: bool, resp_only: bool) -> String {
    if resp_only {
        result.value.clone()
    } else if resp {
        format!("{} {} [{}]", result.host, result.record_type, result.value)
    } else {
        format!("{} {} {}", result.host, result.record_type, result.value)
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
    let _servers_arc = Arc::new(RwLock::new(servers.clone()));
    let resolver = Arc::new(build_resolver(&servers, cli.timeout, cli.retry)?);

    // Collect input hosts
    let hosts = collect_input(cli.list.as_deref()).await?;

    if hosts.is_empty() {
        if !cli.silent {
            eprintln!("No input provided. Use -l <file> or pipe hostnames via stdin.");
        }
        return Ok(());
    }

    // Prepare optional output file
    let output_file: Option<Arc<tokio::sync::Mutex<tokio::fs::File>>> =
        if let Some(ref path) = cli.output {
            let f = tokio::fs::File::create(path).await?;
            Some(Arc::new(tokio::sync::Mutex::new(f)))
        } else {
            None
        };

    // Worker pool via bounded mpsc channel
    let (tx, rx) = mpsc::channel::<String>(cli.threads * 2);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));

    // Output channel
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<DnsResult>>(cli.threads * 2);

    // Spawn N worker tasks
    let num_workers = cli.threads.min(hosts.len()).max(1);
    let query_a = cli.query_a;
    let query_aaaa = cli.query_aaaa;

    let mut worker_handles = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let resolver_c = Arc::clone(&resolver);
        let rx_c = Arc::clone(&rx);
        let out_tx_c = out_tx.clone();

        let handle = tokio::spawn(async move {
            loop {
                let host = {
                    let mut guard = rx_c.lock().await;
                    guard.recv().await
                };
                match host {
                    None => break,
                    Some(h) => {
                        let results =
                            resolve_host(Arc::clone(&resolver_c), h, query_a, query_aaaa).await;
                        if !results.is_empty() {
                            let _ = out_tx_c.send(results).await;
                        }
                    }
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

    use tokio::io::AsyncWriteExt;
    while let Some(batch) = out_rx.recv().await {
        for result in &batch {
            let line = format_result(result, resp, resp_only);
            println!("{line}");
            if let Some(ref fh) = output_file {
                let mut guard = fh.lock().await;
                let _ = guard.write_all(format!("{line}\n").as_bytes()).await;
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

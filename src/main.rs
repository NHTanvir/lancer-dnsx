//! lancer-dnsx — Phase 1: all record types + JSON output

use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    error::ResolveErrorKind,
    proto::rr::RecordType as HickoryRecordType,
    TokioAsyncResolver,
};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Known multi-character long flags (without leading dashes).
/// Any `-flag` that appears in this list gets rewritten to `--flag`
/// so clap can handle it. This emulates Go-style single-dash long flags.
const SINGLE_DASH_LONG_FLAGS: &[&str] = &[
    "list",
    "aaaa",
    "cname",
    "mx",
    "txt",
    "ns",
    "ptr",
    "srv",
    "soa",
    "caa",
    "any",
    "axfr",
    "recon",
    "all",
    "exclude-type",
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
    "json",
    "omit-raw",
    "or",
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

    /// Query CNAME records
    #[arg(long = "cname")]
    cname: bool,

    /// Query MX records
    #[arg(long = "mx")]
    mx: bool,

    /// Query TXT records
    #[arg(long = "txt")]
    txt: bool,

    /// Query NS records
    #[arg(long = "ns")]
    ns: bool,

    /// Query PTR records
    #[arg(long = "ptr")]
    ptr: bool,

    /// Query SRV records
    #[arg(long = "srv")]
    srv: bool,

    /// Query SOA records
    #[arg(long = "soa")]
    soa: bool,

    /// Query CAA records
    #[arg(long = "caa")]
    caa: bool,

    /// Query ANY records
    #[arg(long = "any")]
    any: bool,

    /// Query AXFR (zone transfer stub — full impl in Phase 5)
    #[arg(long = "axfr")]
    axfr: bool,

    /// Query all record types (A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, SOA, CAA)
    #[arg(long = "recon", visible_alias = "all")]
    recon: bool,

    /// Exclude specific record types (comma-separated, e.g. cname,a)
    #[arg(short = 'e', long = "exclude-type", value_name = "TYPES")]
    exclude_type: Option<String>,

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

    /// Output as JSONL (one JSON object per host)
    #[arg(short = 'j', long = "json")]
    json: bool,

    /// Omit raw response field from JSON output (no-op in Phase 1 — no raw field exists)
    #[arg(long = "omit-raw", visible_alias = "or")]
    omit_raw: bool,

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
// Record types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Ptr,
    Srv,
    Soa,
    Caa,
    Any,
    Axfr,
}

impl RecordType {
    fn to_hickory(self) -> HickoryRecordType {
        match self {
            RecordType::A => HickoryRecordType::A,
            RecordType::Aaaa => HickoryRecordType::AAAA,
            RecordType::Cname => HickoryRecordType::CNAME,
            RecordType::Mx => HickoryRecordType::MX,
            RecordType::Txt => HickoryRecordType::TXT,
            RecordType::Ns => HickoryRecordType::NS,
            RecordType::Ptr => HickoryRecordType::PTR,
            RecordType::Srv => HickoryRecordType::SRV,
            RecordType::Soa => HickoryRecordType::SOA,
            RecordType::Caa => HickoryRecordType::CAA,
            RecordType::Any => HickoryRecordType::ANY,
            RecordType::Axfr => HickoryRecordType::AXFR,
        }
    }

    /// Parse a type name (case-insensitive) from a string.
    fn from_str_ci(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "a" => Some(RecordType::A),
            "aaaa" => Some(RecordType::Aaaa),
            "cname" => Some(RecordType::Cname),
            "mx" => Some(RecordType::Mx),
            "txt" => Some(RecordType::Txt),
            "ns" => Some(RecordType::Ns),
            "ptr" => Some(RecordType::Ptr),
            "srv" => Some(RecordType::Srv),
            "soa" => Some(RecordType::Soa),
            "caa" => Some(RecordType::Caa),
            "any" => Some(RecordType::Any),
            "axfr" => Some(RecordType::Axfr),
            _ => None,
        }
    }

    /// The JSON field name for this record type.
    #[allow(dead_code)]
    fn json_key(self) -> &'static str {
        match self {
            RecordType::A => "a",
            RecordType::Aaaa => "aaaa",
            RecordType::Cname => "cname",
            RecordType::Mx => "mx",
            RecordType::Txt => "txt",
            RecordType::Ns => "ns",
            RecordType::Ptr => "ptr",
            RecordType::Srv => "srv",
            RecordType::Soa => "soa",
            RecordType::Caa => "caa",
            RecordType::Any => "any",
            RecordType::Axfr => "axfr",
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::Aaaa => write!(f, "AAAA"),
            RecordType::Cname => write!(f, "CNAME"),
            RecordType::Mx => write!(f, "MX"),
            RecordType::Txt => write!(f, "TXT"),
            RecordType::Ns => write!(f, "NS"),
            RecordType::Ptr => write!(f, "PTR"),
            RecordType::Srv => write!(f, "SRV"),
            RecordType::Soa => write!(f, "SOA"),
            RecordType::Caa => write!(f, "CAA"),
            RecordType::Any => write!(f, "ANY"),
            RecordType::Axfr => write!(f, "AXFR"),
        }
    }
}

// ---------------------------------------------------------------------------
// Active query type selection
// ---------------------------------------------------------------------------

/// Returns true if the user set any explicit record-type flag (other than recon).
fn any_explicit_type_flag(cli: &Cli) -> bool {
    cli.query_a
        || cli.query_aaaa
        || cli.cname
        || cli.mx
        || cli.txt
        || cli.ns
        || cli.ptr
        || cli.srv
        || cli.soa
        || cli.caa
        || cli.any
        || cli.axfr
}

/// Parse a comma-separated type list into RecordType values.
fn parse_type_list(s: &str) -> Vec<RecordType> {
    s.split(',')
        .filter_map(|t| RecordType::from_str_ci(t.trim()))
        .collect()
}

/// Determine which record types to query based on CLI flags.
fn active_query_types(cli: &Cli) -> Vec<RecordType> {
    if cli.recon {
        // -recon queries all common types (skip AXFR/ANY by default)
        return vec![
            RecordType::A,
            RecordType::Aaaa,
            RecordType::Cname,
            RecordType::Mx,
            RecordType::Txt,
            RecordType::Ns,
            RecordType::Ptr,
            RecordType::Srv,
            RecordType::Soa,
            RecordType::Caa,
        ];
    }

    let mut types = vec![];

    // A is the default unless the user explicitly asked for other types
    if cli.query_a || !any_explicit_type_flag(cli) {
        types.push(RecordType::A);
    }
    if cli.query_aaaa {
        types.push(RecordType::Aaaa);
    }
    if cli.cname {
        types.push(RecordType::Cname);
    }
    if cli.mx {
        types.push(RecordType::Mx);
    }
    if cli.txt {
        types.push(RecordType::Txt);
    }
    if cli.ns {
        types.push(RecordType::Ns);
    }
    if cli.ptr {
        types.push(RecordType::Ptr);
    }
    if cli.srv {
        types.push(RecordType::Srv);
    }
    if cli.soa {
        types.push(RecordType::Soa);
    }
    if cli.caa {
        types.push(RecordType::Caa);
    }
    if cli.any {
        types.push(RecordType::Any);
    }
    if cli.axfr {
        types.push(RecordType::Axfr);
    }

    // Apply -exclude-type filter
    if let Some(ref excl) = cli.exclude_type {
        let excluded = parse_type_list(excl);
        types.retain(|t| !excluded.contains(t));
    }

    types
}

// ---------------------------------------------------------------------------
// Resolution helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DnsResult {
    host: String,
    record_type: RecordType,
    value: String,
}

/// Perform a single record-type lookup and append results to `out`.
async fn lookup_type(
    resolver: &TokioAsyncResolver,
    host: &str,
    rtype: RecordType,
    silent: bool,
    out: &mut Vec<DnsResult>,
) {
    match rtype {
        RecordType::A => match resolver.ipv4_lookup(host).await {
            Ok(resp) => {
                for r in resp.iter() {
                    out.push(DnsResult {
                        host: host.to_string(),
                        record_type: rtype,
                        value: r.to_string(),
                    });
                }
            }
            Err(e) => handle_lookup_error(host, rtype, &e, silent),
        },

        RecordType::Aaaa => match resolver.ipv6_lookup(host).await {
            Ok(resp) => {
                for r in resp.iter() {
                    out.push(DnsResult {
                        host: host.to_string(),
                        record_type: rtype,
                        value: r.to_string(),
                    });
                }
            }
            Err(e) => handle_lookup_error(host, rtype, &e, silent),
        },

        RecordType::Mx => match resolver.mx_lookup(host).await {
            Ok(resp) => {
                for r in resp.iter() {
                    out.push(DnsResult {
                        host: host.to_string(),
                        record_type: rtype,
                        value: format!("{} {}", r.preference(), r.exchange()),
                    });
                }
            }
            Err(e) => handle_lookup_error(host, rtype, &e, silent),
        },

        RecordType::Txt => match resolver.txt_lookup(host).await {
            Ok(resp) => {
                for r in resp.iter() {
                    let txt = r
                        .iter()
                        .map(|d| String::from_utf8_lossy(d).to_string())
                        .collect::<Vec<_>>()
                        .join("");
                    out.push(DnsResult {
                        host: host.to_string(),
                        record_type: rtype,
                        value: txt,
                    });
                }
            }
            Err(e) => handle_lookup_error(host, rtype, &e, silent),
        },

        RecordType::Ns => match resolver.ns_lookup(host).await {
            Ok(resp) => {
                for r in resp.iter() {
                    out.push(DnsResult {
                        host: host.to_string(),
                        record_type: rtype,
                        value: r.to_string(),
                    });
                }
            }
            Err(e) => handle_lookup_error(host, rtype, &e, silent),
        },

        // Generic lookup for CNAME, PTR, SRV, SOA, CAA, ANY
        RecordType::Cname
        | RecordType::Ptr
        | RecordType::Srv
        | RecordType::Soa
        | RecordType::Caa
        | RecordType::Any => {
            match resolver.lookup(host, rtype.to_hickory()).await {
                Ok(resp) => {
                    for record in resp.records() {
                        let value = record.data().map(|d| d.to_string()).unwrap_or_default();
                        if !value.is_empty() {
                            out.push(DnsResult {
                                host: host.to_string(),
                                record_type: rtype,
                                value,
                            });
                        }
                    }
                }
                Err(e) => handle_lookup_error(host, rtype, &e, silent),
            }
        }

        // Full AXFR implementation in Phase 5
        RecordType::Axfr => {
            match resolver.lookup(host, HickoryRecordType::AXFR).await {
                Ok(resp) => {
                    for record in resp.records() {
                        let value = record.data().map(|d| d.to_string()).unwrap_or_default();
                        if !value.is_empty() {
                            out.push(DnsResult {
                                host: host.to_string(),
                                record_type: rtype,
                                value,
                            });
                        }
                    }
                }
                Err(e) => handle_lookup_error(host, rtype, &e, silent),
            }
        }
    }
}

fn handle_lookup_error(
    host: &str,
    rtype: RecordType,
    e: &hickory_resolver::error::ResolveError,
    silent: bool,
) {
    match e.kind() {
        ResolveErrorKind::NoRecordsFound { .. } => {}
        _ => {
            if !silent {
                eprintln!("[WARN] {} {}: {}", host, rtype, e);
            }
        }
    }
}

async fn resolve_host(
    resolver: Arc<TokioAsyncResolver>,
    host: String,
    query_types: Vec<RecordType>,
    silent: bool,
) -> Vec<DnsResult> {
    let mut results = Vec::new();
    for rtype in query_types {
        lookup_type(&resolver, &host, rtype, silent, &mut results).await;
    }
    results
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

#[derive(Serialize, Default)]
struct HostRecord {
    host: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    a: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    aaaa: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cname: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mx: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ns: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    txt: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ptr: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    srv: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    soa: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    caa: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    any: Vec<String>,
    timestamp: String,
}

impl HostRecord {
    fn from_results(host: &str, results: &[DnsResult]) -> Self {
        let mut rec = HostRecord {
            host: host.to_string(),
            timestamp: chrono_now(),
            ..Default::default()
        };
        for r in results {
            match r.record_type {
                RecordType::A => rec.a.push(r.value.clone()),
                RecordType::Aaaa => rec.aaaa.push(r.value.clone()),
                RecordType::Cname => rec.cname.push(r.value.clone()),
                RecordType::Mx => rec.mx.push(r.value.clone()),
                RecordType::Ns => rec.ns.push(r.value.clone()),
                RecordType::Txt => rec.txt.push(r.value.clone()),
                RecordType::Ptr => rec.ptr.push(r.value.clone()),
                RecordType::Srv => rec.srv.push(r.value.clone()),
                RecordType::Soa => rec.soa.push(r.value.clone()),
                RecordType::Caa => rec.caa.push(r.value.clone()),
                RecordType::Any => rec.any.push(r.value.clone()),
                RecordType::Axfr => {} // AXFR results not included in JSON record in Phase 1
            }
        }
        rec
    }
}

/// Return a UTC timestamp string in RFC 3339 format without depending on chrono.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Manual RFC 3339 from UNIX seconds (good enough for Phase 1)
    let s = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86400; // days since 1970-01-01

    // Compute year/month/day from days
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Gregorian calendar calculation
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
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
// Worker message type
// ---------------------------------------------------------------------------

/// The payload sent from workers to the output loop.
struct WorkerOutput {
    host: String,
    results: Vec<DnsResult>,
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

    // Determine which record types to query (computed once, shared via Arc)
    let query_types: Arc<Vec<RecordType>> = Arc::new(active_query_types(&cli));

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
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<WorkerOutput>(cli.threads * 2);

    // Spawn N worker tasks
    let num_workers = cli.threads.min(hosts.len()).max(1);
    let silent = cli.silent;

    let mut worker_handles = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let resolver_c = Arc::clone(&resolver);
        let rx_c = rx.clone();
        let out_tx_c = out_tx.clone();
        let qtypes_c = Arc::clone(&query_types);

        let handle = tokio::spawn(async move {
            while let Ok(host) = rx_c.recv().await {
                let results = resolve_host(
                    Arc::clone(&resolver_c),
                    host.clone(),
                    (*qtypes_c).clone(),
                    silent,
                )
                .await;
                // Always send even if empty — JSON output needs the host entry
                let _ = out_tx_c.send(WorkerOutput { host, results }).await;
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
    let json_output = cli.json;

    // Deduplicate printed hosts when using default (hostname-only) output
    let mut printed_hosts: HashSet<String> = HashSet::new();

    while let Some(wo) = out_rx.recv().await {
        if json_output {
            // Only emit JSON if there are any results (skip hosts with no records)
            if !wo.results.is_empty() {
                let rec = HostRecord::from_results(&wo.host, &wo.results);
                let line = serde_json::to_string(&rec)?;
                println!("{line}");
                if let Some(ref mut fh) = output_file {
                    if let Err(e) = fh.write_all(format!("{line}\n").as_bytes()).await {
                        eprintln!("[ERROR] Failed to write output: {e}");
                    }
                }
            }
        } else {
            for result in &wo.results {
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
    }

    // Wait for all workers and feeder to finish
    feed_handle.await?;
    for h in worker_handles {
        h.await?;
    }

    Ok(())
}

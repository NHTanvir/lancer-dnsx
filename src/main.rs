//! lancer-dnsx -- Phase 2: custom resolver pool and DoH/DoT support

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use clap::Parser;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    error::{ResolveError, ResolveErrorKind},
    lookup::Lookup,
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
    "resolver",
    "resolver-list",
    "resolvers-file",
    "rL",
];

/// Rewrite single-dash long flags to double-dash so clap can parse them.
///
/// `-silent` -> `--silent`
/// `-resp-only` -> `--resp-only`
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

/// Rust clone of dnsx -- fast and multi-purpose DNS toolkit
#[derive(Parser, Debug)]
#[command(
    name = "lancer-dnsx",
    version = VERSION,
    about = "Rust clone of dnsx -- fast and multi-purpose DNS toolkit",
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

    /// Query AXFR (zone transfer stub -- full impl in Phase 5)
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

    /// Omit raw response field from JSON output
    #[arg(long = "omit-raw", visible_alias = "or")]
    omit_raw: bool,

    /// Suppress banner and non-result output
    #[arg(long = "silent")]
    silent: bool,

    /// Disable ANSI color output
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

    /// Custom resolvers, comma-separated (e.g. 1.1.1.1,doh:https://cloudflare-dns.com/dns-query)
    #[arg(short = 'r', long = "resolver", value_name = "RESOLVERS")]
    resolver: Option<String>,

    /// File containing resolvers, one per line
    #[arg(
        long = "resolvers-file",
        value_name = "FILE",
        visible_aliases = ["rL", "resolver-list"]
    )]
    resolver_list: Option<String>,

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

/// Format a `NameServerConfig` as a human-readable resolver URL.
///
/// For encrypted protocols with a TLS hostname the format is:
///   `scheme://hostname (addr:port)`
/// For plain protocols (or encrypted without a known hostname):
///   `scheme://addr:port`
fn describe_resolver(ns: &NameServerConfig) -> String {
    // hickory's Protocol implements Display ("udp"/"tcp"/"tls"/"https"/...)
    let scheme = ns.protocol.to_string();
    match &ns.tls_dns_name {
        Some(host) => format!("{}://{} ({})", scheme, host, ns.socket_addr),
        None => format!("{}://{}", scheme, ns.socket_addr),
    }
}

/// Build a single `TokioAsyncResolver` configured with a single `NameServerConfig`.
fn build_single_resolver(
    ns: &NameServerConfig,
    timeout_secs: u64,
    retries: usize,
) -> TokioAsyncResolver {
    let mut config = ResolverConfig::new();
    config.add_name_server(ns.clone());

    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(timeout_secs);
    opts.attempts = retries;
    opts.num_concurrent_reqs = 1;
    // Don't shuffle within the single-resolver: we own the ordering at the pool layer
    opts.rotate = false;

    TokioAsyncResolver::tokio(config, opts)
}

// ---------------------------------------------------------------------------
// Resolver string parser
// ---------------------------------------------------------------------------

/// Parse a resolver string into a `NameServerConfig`.
///
/// Supported formats:
///   - `1.1.1.1` or `1.1.1.1:53`                  -> UDP, port 53
///   - `udp:1.1.1.1` or `udp:1.1.1.1:53`          -> UDP, port 53
///   - `tcp:1.1.1.1` or `tcp:1.1.1.1:53`          -> TCP, port 53
///   - `tls:1.1.1.1` or `tls:1.1.1.1:853`         -> DoT, port 853
///   - `doh:https://example.com/dns-query`         -> DoH (Protocol::Https), port 443
///   - `quic:1.1.1.1`                              -> DoQ (unsupported; returns an error)
fn parse_resolver_string(s: &str) -> Result<NameServerConfig> {
    let s = s.trim();

    // DoH: prefix doh: followed by a URL
    if let Some(url) = s.strip_prefix("doh:") {
        return parse_doh_resolver(url);
    }

    // quic: prefix -- DoQ feature is not enabled in this build
    if s.starts_with("quic:") {
        return Err(anyhow!(
            "DoQ (quic:) is not supported in this build. Rebuild with the \
             `dns-over-quic` feature on hickory-resolver, or use udp/tcp/tls/doh."
        ));
    }

    // tls: prefix
    if let Some(rest) = s.strip_prefix("tls:") {
        let (ip, port) = parse_ip_port(rest, 853)?;
        let addr = SocketAddr::new(ip, port);
        let mut ns = NameServerConfig::new(addr, Protocol::Tls);
        // Map well-known IPs to their proper TLS hostnames (SNI). For unknown
        // IPs, fall back to the IP string -- DoT servers will reject this in
        // most cases but it's better than nothing if the user knows what
        // they're doing. They can override SNI by using `doh:` syntax with the
        // domain name instead.
        ns.tls_dns_name = Some(well_known_tls_hostname(&ip).unwrap_or_else(|| ip.to_string()));
        return Ok(ns);
    }

    // tcp: prefix
    if let Some(rest) = s.strip_prefix("tcp:") {
        let (ip, port) = parse_ip_port(rest, 53)?;
        let addr = SocketAddr::new(ip, port);
        return Ok(NameServerConfig::new(addr, Protocol::Tcp));
    }

    // udp: prefix
    if let Some(rest) = s.strip_prefix("udp:") {
        let (ip, port) = parse_ip_port(rest, 53)?;
        let addr = SocketAddr::new(ip, port);
        return Ok(NameServerConfig::new(addr, Protocol::Udp));
    }

    // Plain IP (no scheme) -- treat as UDP
    let (ip, port) = parse_ip_port(s, 53)?;
    let addr = SocketAddr::new(ip, port);
    Ok(NameServerConfig::new(addr, Protocol::Udp))
}

/// Parse a DoH URL into a `NameServerConfig` using `Protocol::Https`.
///
/// Well-known providers are resolved to their IPs so no pre-existing DNS is
/// required. Unknown hostnames that aren't bare IPs return an error.
fn parse_doh_resolver(url: &str) -> Result<NameServerConfig> {
    // Must start with https://
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("DoH URL must start with https://: {url}"))?;

    // Extract hostname (everything before the first '/')
    let host = rest.split('/').next().unwrap_or(rest);

    // Well-known DoH providers -> hardcoded IPs
    let ip: IpAddr = match host {
        "cloudflare-dns.com" | "1dot1dot1dot1.cloudflare-dns.com" => {
            "1.1.1.1".parse().unwrap()
        }
        "dns.google" | "dns64.dns.google" => "8.8.8.8".parse().unwrap(),
        "dns.quad9.net" | "dns9.quad9.net" | "dns11.quad9.net" => {
            "9.9.9.9".parse().unwrap()
        }
        "doh.opendns.com" => "208.67.222.222".parse().unwrap(),
        "doh.familyshield.opendns.com" => "208.67.222.123".parse().unwrap(),
        other => {
            // Allow bare IP in URL (e.g. doh:https://1.1.1.1/dns-query)
            other.parse::<IpAddr>().map_err(|_| {
                anyhow!(
                    "Unknown DoH host '{other}'. Use a well-known provider or \
                     provide the IP directly (e.g. doh:https://1.1.1.1/dns-query)"
                )
            })?
        }
    };

    let addr = SocketAddr::new(ip, 443);
    let mut ns = NameServerConfig::new(addr, Protocol::Https);
    ns.tls_dns_name = Some(host.to_string());
    Ok(ns)
}

/// Map a well-known DoT/DoH provider IP back to its SNI hostname.
fn well_known_tls_hostname(ip: &IpAddr) -> Option<String> {
    let s = ip.to_string();
    match s.as_str() {
        "1.1.1.1" | "1.0.0.1" => Some("one.one.one.one".to_string()),
        "8.8.8.8" | "8.8.4.4" => Some("dns.google".to_string()),
        "9.9.9.9" | "149.112.112.112" => Some("dns.quad9.net".to_string()),
        "208.67.222.222" | "208.67.220.220" => Some("doh.opendns.com".to_string()),
        _ => None,
    }
}

/// Parse `addr` as a bare IP or `IP:port`, returning `(IpAddr, port)`.
///
/// The two branches here are sufficient:
///   1. `IpAddr::parse` handles bare IPv4 and IPv6 addresses.
///   2. `SocketAddr::parse` handles `IPv4:port` and `[IPv6]:port`.
///
/// Any other form (e.g. hostnames) is an error.
fn parse_ip_port(s: &str, default_port: u16) -> Result<(IpAddr, u16)> {
    // Bare IPv4 or IPv6
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip, default_port));
    }
    // Full SocketAddr (handles [IPv6]:port and IPv4:port)
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok((sa.ip(), sa.port()));
    }
    Err(anyhow!("Cannot parse resolver address: '{s}'"))
}

/// Load the resolver list from CLI flags, or return the built-in defaults.
async fn load_resolvers(cli: &Cli) -> Result<Vec<NameServerConfig>> {
    if cli.resolver.is_none() && cli.resolver_list.is_none() {
        return Ok(default_name_servers());
    }

    let mut servers: Vec<NameServerConfig> = Vec::new();

    // -r / --resolver: comma-separated
    if let Some(ref r) = cli.resolver {
        for part in r.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match parse_resolver_string(part) {
                Ok(ns) => servers.push(ns),
                Err(e) => eprintln!("[WARN] Skipping resolver '{part}': {e}"),
            }
        }
    }

    // -rL / --resolver-list: file, one resolver per line
    if let Some(ref path) = cli.resolver_list {
        match tokio::fs::read_to_string(path).await {
            Ok(content) => {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    match parse_resolver_string(line) {
                        Ok(ns) => servers.push(ns),
                        Err(e) => eprintln!("[WARN] Skipping resolver '{line}': {e}"),
                    }
                }
            }
            Err(e) => {
                return Err(anyhow!("Cannot read resolver list '{}': {}", path, e));
            }
        }
    }

    if servers.is_empty() {
        eprintln!(
            "[WARN] No valid resolvers parsed from -r/-rL; falling back to defaults."
        );
        return Ok(default_name_servers());
    }

    Ok(servers)
}

// ---------------------------------------------------------------------------
// Per-resolver health tracking and resolver pool
// ---------------------------------------------------------------------------

/// Maximum number of outcomes retained in the per-resolver sliding window.
const HEALTH_WINDOW: usize = 100;

/// Minimum sample count before we'll consider evicting a resolver.
const HEALTH_MIN_SAMPLES: usize = 20;

/// Error-rate threshold above which a resolver is evicted from the pool.
const HEALTH_EVICT_RATE: f64 = 0.5;

/// Sliding window of the last `HEALTH_WINDOW` query outcomes for one resolver.
struct RingBuffer {
    outcomes: VecDeque<bool>, // true = success, false = error
    capacity: usize,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            outcomes: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, success: bool) {
        if self.outcomes.len() >= self.capacity {
            self.outcomes.pop_front();
        }
        self.outcomes.push_back(success);
    }

    fn error_rate(&self) -> f64 {
        if self.outcomes.is_empty() {
            return 0.0;
        }
        let errors = self.outcomes.iter().filter(|&&s| !s).count();
        errors as f64 / self.outcomes.len() as f64
    }

    fn len(&self) -> usize {
        self.outcomes.len()
    }
}

/// One resolver in the pool, with its own health window and eviction flag.
struct TrackedResolver {
    name: String,
    resolver: TokioAsyncResolver,
    stats: Mutex<RingBuffer>,
    evicted: AtomicBool,
}

impl TrackedResolver {
    fn new(name: String, resolver: TokioAsyncResolver) -> Self {
        Self {
            name,
            resolver,
            stats: Mutex::new(RingBuffer::new(HEALTH_WINDOW)),
            evicted: AtomicBool::new(false),
        }
    }

    fn is_evicted(&self) -> bool {
        self.evicted.load(Ordering::Acquire)
    }

    /// Record a query outcome. Evicts the resolver if the error rate over the
    /// sliding window (with at least `HEALTH_MIN_SAMPLES` samples) exceeds
    /// `HEALTH_EVICT_RATE`. Emits a one-time warning on eviction unless silent.
    fn record_outcome(&self, success: bool, silent: bool) {
        let (should_evict, rate, len) = {
            let mut buf = self.stats.lock().unwrap_or_else(|p| p.into_inner());
            buf.push(success);
            if buf.len() >= HEALTH_MIN_SAMPLES {
                let rate = buf.error_rate();
                let len = buf.len();
                let evict = rate > HEALTH_EVICT_RATE
                    && self
                        .evicted
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok();
                (evict, rate, len)
            } else {
                (false, 0.0, 0)
            }
        }; // MutexGuard dropped here
        if should_evict && !silent {
            eprintln!(
                "[WARN] Evicted resolver {} (error rate: {:.0}%, {} samples)",
                self.name,
                rate * 100.0,
                len
            );
        }
    }
}

/// Pool of resolvers with round-robin selection and per-resolver health tracking.
struct ResolverPool {
    resolvers: Vec<TrackedResolver>,
    next_idx: AtomicUsize,
    silent: bool,
}

impl ResolverPool {
    fn new(resolvers: Vec<TrackedResolver>, silent: bool) -> Self {
        Self {
            resolvers,
            next_idx: AtomicUsize::new(0),
            silent,
        }
    }

    /// Number of resolvers in the pool (evicted or not).
    fn len(&self) -> usize {
        self.resolvers.len()
    }

    /// True if the pool was constructed empty (shouldn't happen via `build`).
    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }

    /// Build a pool of one tracked resolver per name-server config.
    fn build(
        servers: &[NameServerConfig],
        timeout_secs: u64,
        retries: usize,
        silent: bool,
    ) -> Result<Self> {
        if servers.is_empty() {
            return Err(anyhow!("Cannot build resolver pool with zero name servers"));
        }
        let mut tracked = Vec::with_capacity(servers.len());
        for ns in servers {
            let resolver = build_single_resolver(ns, timeout_secs, retries);
            tracked.push(TrackedResolver::new(describe_resolver(ns), resolver));
        }
        Ok(Self::new(tracked, silent))
    }

    /// Round-robin pick of the next non-evicted resolver.
    /// Returns `(index, resolver)` so the caller can later report the outcome
    /// back to the right slot.
    fn pick(&self) -> Option<(usize, &TrackedResolver)> {
        let n = self.resolvers.len();
        if n == 0 {
            return None;
        }
        let start = self.next_idx.fetch_add(1, Ordering::Relaxed) % n;
        for offset in 0..n {
            let idx = (start + offset) % n;
            let r = &self.resolvers[idx];
            if !r.is_evicted() {
                return Some((idx, r));
            }
        }
        None
    }

    /// Record an outcome against the resolver at `idx`.
    fn record(&self, idx: usize, success: bool) {
        if let Some(r) = self.resolvers.get(idx) {
            r.record_outcome(success, self.silent);
        }
    }

    /// Are all resolvers in the pool evicted?
    fn all_evicted(&self) -> bool {
        self.resolvers.iter().all(|r| r.is_evicted())
    }
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
    let mut types: Vec<RecordType> = if cli.recon {
        // -recon queries all common types (skip AXFR/ANY by default)
        vec![
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
        ]
    } else {
        let mut t = vec![];

        // A is the default unless the user explicitly asked for other types
        if cli.query_a || !any_explicit_type_flag(cli) {
            t.push(RecordType::A);
        }
        if cli.query_aaaa {
            t.push(RecordType::Aaaa);
        }
        if cli.cname {
            t.push(RecordType::Cname);
        }
        if cli.mx {
            t.push(RecordType::Mx);
        }
        if cli.txt {
            t.push(RecordType::Txt);
        }
        if cli.ns {
            t.push(RecordType::Ns);
        }
        if cli.ptr {
            t.push(RecordType::Ptr);
        }
        if cli.srv {
            t.push(RecordType::Srv);
        }
        if cli.soa {
            t.push(RecordType::Soa);
        }
        if cli.caa {
            t.push(RecordType::Caa);
        }
        if cli.any {
            t.push(RecordType::Any);
        }
        if cli.axfr {
            t.push(RecordType::Axfr);
        }

        t
    };

    // Apply -exclude-type filter (runs for BOTH recon and non-recon paths)
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

/// Perform a single record-type lookup against the pool. Picks one resolver
/// via round-robin, records the outcome for health tracking, and appends any
/// records to `out`.
async fn lookup_type(
    pool: &ResolverPool,
    host: &str,
    rtype: RecordType,
    silent: bool,
    out: &mut Vec<DnsResult>,
) {
    let Some((idx, tracked)) = pool.pick() else {
        if !silent {
            eprintln!(
                "[WARN] All resolvers evicted -- dropping query for {} {}",
                host, rtype
            );
        }
        return;
    };
    let resolver = &tracked.resolver;

    let mut outcome_ok = true;
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
            Err(e) => {
                outcome_ok = !is_transport_error(&e);
                handle_lookup_error(host, rtype, &e, silent);
            }
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
            Err(e) => {
                outcome_ok = !is_transport_error(&e);
                handle_lookup_error(host, rtype, &e, silent);
            }
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
            Err(e) => {
                outcome_ok = !is_transport_error(&e);
                handle_lookup_error(host, rtype, &e, silent);
            }
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
            Err(e) => {
                outcome_ok = !is_transport_error(&e);
                handle_lookup_error(host, rtype, &e, silent);
            }
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
            Err(e) => {
                outcome_ok = !is_transport_error(&e);
                handle_lookup_error(host, rtype, &e, silent);
            }
        },

        // Generic lookup for CNAME, PTR, SRV, SOA, CAA, ANY, AXFR
        RecordType::Cname
        | RecordType::Ptr
        | RecordType::Srv
        | RecordType::Soa
        | RecordType::Caa
        | RecordType::Any
        | RecordType::Axfr => {
            let result: Result<Lookup, ResolveError> =
                resolver.lookup(host, rtype.to_hickory()).await;
            match result {
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
                Err(e) => {
                    outcome_ok = !is_transport_error(&e);
                    handle_lookup_error(host, rtype, &e, silent);
                }
            }
        }
    }

    pool.record(idx, outcome_ok);
}

/// Returns true if this error is a transport / network failure (timeout,
/// connection refused, no connections available, etc.) -- one that should
/// count as a resolver health hit. NXDOMAIN, "no records", malformed
/// responses (Proto), and internal message errors do NOT count.
fn is_transport_error(e: &ResolveError) -> bool {
    matches!(
        e.kind(),
        ResolveErrorKind::Io(_) | ResolveErrorKind::Timeout | ResolveErrorKind::NoConnections
    )
}

/// Emit a warning line for a non-NXDOMAIN lookup error.
fn handle_lookup_error(host: &str, rtype: RecordType, e: &ResolveError, silent: bool) {
    if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
        return;
    }
    if !silent {
        eprintln!("[WARN] {} {}: {}", host, rtype, e);
    }
}

async fn resolve_host(
    pool: &ResolverPool,
    host: String,
    query_types: Vec<RecordType>,
    silent: bool,
) -> Vec<DnsResult> {
    let mut results = Vec::new();
    for rtype in query_types {
        lookup_type(pool, &host, rtype, silent, &mut results).await;
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
                RecordType::Axfr => {} // AXFR results not included in JSON record
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

    let s = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86400; // days since 1970-01-01

    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
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
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
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
                    if (arg.ends_with(".txt") || arg.ends_with(".lst")) && !silent {
                        eprintln!("[WARN] File not found: {arg}, treating as hostname");
                    }
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
            "lancer-dnsx v{VERSION} -- Rust clone of dnsx\n\
             Use -silent to suppress this banner."
        );
    }

    // Load resolvers from -r/-rL or fall back to defaults
    let servers = load_resolvers(&cli).await?;

    if !cli.silent {
        eprintln!("[INFO] Using {} resolver(s)", servers.len());
    }

    // Build the resolver pool (one TokioAsyncResolver per name server, with
    // per-resolver health tracking and round-robin selection).
    let pool = Arc::new(ResolverPool::build(
        &servers,
        cli.timeout,
        cli.retry,
        cli.silent,
    )?);

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

    // Prepare optional output file
    let mut output_file: Option<tokio::fs::File> = if let Some(ref path) = cli.output {
        let f = tokio::fs::File::create(path).await?;
        Some(f)
    } else {
        None
    };

    // Worker pool via async-channel (MPMC)
    let (tx, rx) = async_channel::bounded::<String>(cli.threads * 2);

    // Output channel
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<WorkerOutput>(cli.threads * 2);

    // Spawn N worker tasks
    let num_workers = cli.threads.min(hosts.len()).max(1);
    let silent = cli.silent;

    let mut worker_handles = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let pool_c = Arc::clone(&pool);
        let rx_c = rx.clone();
        let out_tx_c = out_tx.clone();
        let qtypes_c = Arc::clone(&query_types);

        let handle = tokio::spawn(async move {
            while let Ok(host) = rx_c.recv().await {
                let results = resolve_host(
                    &pool_c,
                    host.clone(),
                    (*qtypes_c).clone(),
                    silent,
                )
                .await;
                if !results.is_empty() {
                    let _ = out_tx_c.send(WorkerOutput { host, results }).await;
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
    let json_output = cli.json;
    let _omit_raw = cli.omit_raw; // TODO: wire through HostRecord serialization when "raw" field is added

    // Deduplicate printed hosts when using default (hostname-only) output
    let mut printed_hosts: HashSet<String> = HashSet::new();

    while let Some(wo) = out_rx.recv().await {
        if json_output {
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

                // In default mode, only print a hostname once (multiple A records -> one line)
                if !resp && !resp_only && !printed_hosts.insert(result.host.clone()) {
                    continue;
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

    // Warn if the pool ended fully evicted
    if !cli.silent && pool.all_evicted() {
        eprintln!(
            "[WARN] All {} resolver(s) were evicted due to high error rates. \
             Consider supplying -r with reliable resolvers.",
            pool.len()
        );
    }

    Ok(())
}

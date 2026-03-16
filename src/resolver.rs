//! Custom resolver pool with health tracking and DoH/DoT support.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use anyhow::{anyhow, Result};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    error::{ResolveError, ResolveErrorKind},
    lookup::Lookup,
    TokioAsyncResolver,
};

use crate::cli::Cli;
use crate::record::{DnsResult, RecordType};

// ---------------------------------------------------------------------------
// Default resolvers / builders
// ---------------------------------------------------------------------------

/// Build the default 8-resolver pool (Cloudflare, Google, Quad9, OpenDNS).
pub(crate) fn default_name_servers() -> Vec<NameServerConfig> {
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
pub(crate) fn describe_resolver(ns: &NameServerConfig) -> String {
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
pub(crate) fn parse_resolver_string(s: &str) -> Result<NameServerConfig> {
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
pub(crate) fn parse_ip_port(s: &str, default_port: u16) -> Result<(IpAddr, u16)> {
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
pub(crate) async fn load_resolvers(cli: &Cli) -> Result<Vec<NameServerConfig>> {
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
pub(crate) struct TrackedResolver {
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
pub(crate) struct ResolverPool {
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
    pub(crate) fn len(&self) -> usize {
        self.resolvers.len()
    }

    /// True if the pool was constructed empty (shouldn't happen via `build`).
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }

    /// Build a pool of one tracked resolver per name-server config.
    pub(crate) fn build(
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
    pub(crate) fn all_evicted(&self) -> bool {
        self.resolvers.iter().all(|r| r.is_evicted())
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

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

pub(crate) async fn resolve_host(
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

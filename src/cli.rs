//! CLI definition and Go-style single-dash flag normalization.

use clap::Parser;

/// Known multi-character long flags (without leading dashes).
/// Any `-flag` that appears in this list gets rewritten to `--flag`
/// so clap can handle it. This emulates Go-style single-dash long flags.
const SINGLE_DASH_LONG_FLAGS: &[&str] = &[
    "list",
    "domain",
    "wordlist",
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
    "wildcard-domain",
    "wd",
    "auto-wildcard",
    "wildcard-threshold",
    "wt",
    "response-code",
    "rcode",
    "rc",
    "response-type-filter",
    "rtf",
    "match-regex",
    "mr",
    "exclude-regex",
    "er",
    "stream",
    "trace",
    "trace-max-recursion",
    "cdn",
    "asn",
    "stats",
    "resume",
    "hc",
    "health-check",
];

/// Rewrite single-dash long flags to double-dash so clap can parse them.
///
/// `-silent` -> `--silent`
/// `-resp-only` -> `--resp-only`
/// `-l foo` stays as `-l foo` (single char, handled natively)
pub fn normalize_args(args: impl Iterator<Item = String>) -> Vec<String> {
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

/// Rust clone of dnsx -- fast and multi-purpose DNS toolkit
#[derive(Parser, Debug)]
#[command(
    name = "lancer-dnsx",
    version = VERSION,
    about = "Rust clone of dnsx -- fast and multi-purpose DNS toolkit",
    long_about = None,
    disable_version_flag = true,
)]
pub struct Cli {
    // ---- input ----
    #[clap(next_help_heading = "Input")]
    /// Input file containing list of hosts/IPs, or comma-separated hosts
    #[arg(short = 'l', long = "list", value_name = "FILE_OR_HOSTS")]
    pub list: Option<String>,

    /// Target domain(s) to brute-force (comma-separated)
    #[arg(short = 'd', long = "domain", value_name = "DOMAIN")]
    pub domain: Option<String>,

    /// Wordlist file (one subdomain label per line)
    #[arg(short = 'w', long = "wordlist", value_name = "FILE")]
    pub wordlist: Option<String>,

    // ---- query type ----
    #[clap(next_help_heading = "Query")]
    /// Query A records (default)
    #[arg(short = 'a')]
    pub query_a: bool,

    /// Query AAAA records
    #[arg(long = "aaaa")]
    pub query_aaaa: bool,

    /// Query CNAME records
    #[arg(long = "cname")]
    pub cname: bool,

    /// Query MX records
    #[arg(long = "mx")]
    pub mx: bool,

    /// Query TXT records
    #[arg(long = "txt")]
    pub txt: bool,

    /// Query NS records
    #[arg(long = "ns")]
    pub ns: bool,

    /// Query PTR records
    #[arg(long = "ptr")]
    pub ptr: bool,

    /// Query SRV records
    #[arg(long = "srv")]
    pub srv: bool,

    /// Query SOA records
    #[arg(long = "soa")]
    pub soa: bool,

    /// Query CAA records
    #[arg(long = "caa")]
    pub caa: bool,

    /// Query ANY records
    #[arg(long = "any")]
    pub any: bool,

    /// Query AXFR (zone transfer stub -- full impl in Phase 5)
    #[arg(long = "axfr")]
    pub axfr: bool,

    /// Query all record types (A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, SOA, CAA)
    #[arg(long = "recon", visible_alias = "all")]
    pub recon: bool,

    /// Exclude specific record types (comma-separated, e.g. cname,a)
    #[arg(short = 'e', long = "exclude-type", value_name = "TYPES")]
    pub exclude_type: Option<String>,

    // ---- filter ----
    #[clap(next_help_heading = "Filter")]
    /// Number of concurrent workers
    #[arg(short = 't', long = "threads", default_value_t = 100)]
    pub threads: usize,

    /// Filter by DNS response code (comma-separated: noerror, nxdomain, servfail, refused, formerr, notimp)
    #[arg(
        long = "response-code",
        visible_aliases = ["rcode", "rc"],
        value_name = "CODES"
    )]
    pub response_code: Option<String>,

    /// Drop hosts that have any record of these types (comma-separated, e.g. cname,a)
    #[arg(
        long = "response-type-filter",
        visible_alias = "rtf",
        value_name = "TYPES"
    )]
    pub response_type_filter: Option<String>,

    /// Only include results whose resolved value matches this regex
    #[arg(long = "match-regex", visible_alias = "mr", value_name = "REGEX")]
    pub match_regex: Option<String>,

    /// Exclude results whose resolved value matches this regex
    #[arg(long = "exclude-regex", visible_alias = "er", value_name = "REGEX")]
    pub exclude_regex: Option<String>,

    /// Stream mode: disable wildcard detection, stats, and resume for low-latency / low-memory operation
    #[arg(long = "stream")]
    pub stream: bool,

    // ---- wildcard ----
    #[clap(next_help_heading = "Wildcard")]
    /// Manual wildcard probe target; IPs from <random>.<this> are treated as wildcards
    #[arg(long = "wildcard-domain", visible_alias = "wd", value_name = "DOMAIN")]
    pub wildcard_domain: Option<String>,

    /// Auto-detect wildcard zones by walking up from each host
    #[arg(long = "auto-wildcard")]
    pub auto_wildcard: bool,

    /// Number of random probes per wildcard level (default 5)
    #[arg(
        long = "wildcard-threshold",
        visible_alias = "wt",
        default_value_t = 5,
        value_name = "N"
    )]
    pub wildcard_threshold: usize,

    // ---- output ----
    #[clap(next_help_heading = "Output")]
    /// Show full response value alongside host (format: "host TYPE value")
    #[arg(long = "resp", visible_alias = "re")]
    pub resp: bool,

    /// Show only the response value (IP address)
    #[arg(long = "resp-only", visible_alias = "ro")]
    pub resp_only: bool,

    /// Output as JSONL (one JSON object per host)
    #[arg(short = 'j', long = "json")]
    pub json: bool,

    /// Omit raw response field from JSON output
    #[arg(long = "omit-raw", visible_alias = "or")]
    pub omit_raw: bool,

    /// Suppress banner and non-result output
    #[arg(long = "silent")]
    pub silent: bool,

    /// Disable ANSI color output
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Write output to file
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<String>,

    /// Display CDN name for IPs behind known CDNs
    #[arg(long = "cdn")]
    pub cdn: bool,

    /// Display ASN information for resolved IPs (uses BGPView API)
    #[arg(long = "asn")]
    pub asn: bool,

    // ---- configurations ----
    #[clap(next_help_heading = "Configurations")]
    /// Per-query timeout in seconds
    #[arg(long = "timeout", default_value_t = 3)]
    pub timeout: u64,

    /// Number of retries on failure
    #[arg(long = "retry", default_value_t = 2)]
    pub retry: usize,

    /// Custom resolvers, comma-separated (e.g. 1.1.1.1,doh:https://cloudflare-dns.com/dns-query)
    #[arg(short = 'r', long = "resolver", value_name = "RESOLVERS")]
    pub resolver: Option<String>,

    /// File containing resolvers, one per line
    #[arg(
        long = "resolvers-file",
        value_name = "FILE",
        visible_aliases = ["rL", "resolver-list"]
    )]
    pub resolver_list: Option<String>,

    // ---- probe ----
    #[clap(next_help_heading = "Probe")]
    /// DNS trace mode (recursive root-to-authoritative walk per host)
    #[arg(long = "trace")]
    pub trace: bool,

    /// Maximum recursion depth for -trace
    #[arg(long = "trace-max-recursion", default_value_t = 255)]
    pub trace_max_recursion: u32,

    // ---- optimization ----
    #[clap(next_help_heading = "Optimization")]
    /// Show a live progress bar with QPS, errors, and drop counters
    #[arg(long = "stats")]
    pub stats: bool,

    /// Resume from a previous run by skipping hosts listed in resume.cfg
    #[arg(long = "resume")]
    pub resume: bool,

    // ---- debug ----
    #[clap(next_help_heading = "Debug")]
    /// Print version and exit
    #[arg(short = 'v', long = "version")]
    pub version: bool,

    /// Run resolver / hostsfile / disk healthcheck and exit
    #[arg(long = "hc", visible_alias = "health-check")]
    pub hc: bool,
}

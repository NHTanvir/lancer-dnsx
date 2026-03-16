//! lancer-dnsx -- Rust clone of dnsx.
//!
//! This crate is primarily a CLI tool (`lancer-dnsx`) but exposes a small
//! library API so it can be embedded into other Rust projects.
//!
//! # Quick example
//!
//! ```no_run
//! use lancer_dnsx::{default_name_servers, resolve_host, RecordType, ResolverPool};
//!
//! # async fn run() -> anyhow::Result<()> {
//! // Build a resolver pool from the built-in defaults (Cloudflare, Google,
//! // Quad9, OpenDNS) with a 3s timeout and 2 retries.
//! let servers = default_name_servers();
//! let pool = ResolverPool::build(&servers, 3, 2, true)?;
//!
//! // Resolve A + AAAA for a host. `silent = true` suppresses log lines.
//! let resolution = resolve_host(
//!     &pool,
//!     "example.com".to_string(),
//!     vec![RecordType::A, RecordType::Aaaa],
//!     true,
//! )
//! .await;
//!
//! for r in &resolution.results {
//!     println!("{} {} {}", r.host, r.record_type, r.value);
//! }
//! # Ok(())
//! # }
//! ```

// Internal modules used by both the binary and the library. They are
// declared `pub` here so the binary (which sees the crate via `extern
// crate`-style `use lancer_dnsx::...`) and external library users get the
// same view. Items within these modules that should remain crate-private
// are still gated by `pub(crate)`.
pub mod asn;
pub mod axfr;
pub mod brute;
pub mod cdn;
pub mod cli;
pub mod filter;
pub mod healthcheck;
pub mod hybrid_map;
pub mod input;
pub mod output;
pub mod record;
pub mod resolver;
pub mod resume;
pub mod stats;
pub mod trace;
pub mod wildcard;

// ---- Public library API (re-exports) -----------------------------------
//
// Keep this surface minimal. Anything not re-exported here is considered
// internal and may change without a semver bump.

pub use record::{DnsResult, HostRecord, HostResolution, RecordType, ResponseCode};
pub use resolver::{default_name_servers, parse_resolver_string, resolve_host, ResolverPool};
pub use wildcard::WildcardCache;

//! Phase 8: `-hc` healthcheck.
//!
//! Verifies that:
//!   * each default resolver can answer an `A` lookup for `google.com`
//!     within ~3s
//!   * the system hostsfile (`/etc/hosts` on Unix, `C:\Windows\System32\drivers\etc\hosts`
//!     on Windows) is readable
//!   * the temp directory is writable
//!
//! Results are printed to stdout in the same format as the dnsx
//! reference: per-line `name ... OK (Nms)` or `name ... FAIL (reason)`.
//! Returns `Ok(true)` if everything passed, `Ok(false)` otherwise (the
//! caller decides the exit code).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

/// Probe target -- short, well-known, low-latency.
const PROBE_HOST: &str = "google.com";
const PROBE_TIMEOUT_SECS: u64 = 3;

/// Default resolver pool tested by `-hc`. Kept minimal (2 entries) so the
/// command stays snappy.
fn hc_resolvers() -> Vec<&'static str> {
    vec!["1.1.1.1:53", "8.8.8.8:53"]
}

fn hostsfile_path() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

async fn probe_resolver(addr: &str) -> Result<Duration, String> {
    let sa: SocketAddr = addr.parse().map_err(|e| format!("bad addr: {e}"))?;
    let ns = NameServerConfig::new(sa, Protocol::Udp);
    let mut config = ResolverConfig::new();
    config.add_name_server(ns);
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(PROBE_TIMEOUT_SECS);
    opts.attempts = 1;
    opts.num_concurrent_reqs = 1;
    let resolver = TokioAsyncResolver::tokio(config, opts);

    let start = Instant::now();
    let fut = resolver.ipv4_lookup(PROBE_HOST);
    match tokio::time::timeout(Duration::from_secs(PROBE_TIMEOUT_SECS + 1), fut).await {
        Ok(Ok(_)) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(format!("{e}")),
        Err(_) => Err(format!("timeout after {}s", PROBE_TIMEOUT_SECS + 1)),
    }
}

/// Run the full healthcheck, printing each step to stdout. Returns whether
/// all checks passed.
pub(crate) async fn run(version: &str) -> Result<bool> {
    println!("lancer-dnsx healthcheck v{version}\n");
    let mut all_ok = true;

    // ---- Resolvers ----
    println!("Resolvers:");
    for addr in hc_resolvers() {
        match probe_resolver(addr).await {
            Ok(elapsed) => {
                println!("  {addr} ... OK ({}ms)", elapsed.as_millis());
            }
            Err(e) => {
                println!("  {addr} ... FAIL ({e})");
                all_ok = false;
            }
        }
    }

    // ---- Hostsfile ----
    println!("\nHostsfile:");
    let hf = hostsfile_path();
    let readable = std::fs::File::open(&hf).is_ok();
    let writable = {
        let mut opts = std::fs::OpenOptions::new();
        opts.append(true).open(&hf).is_ok()
    };
    if readable {
        println!(
            "  {} ... OK (writable: {}, readable: yes)",
            hf.display(),
            if writable { "yes" } else { "no" }
        );
    } else {
        println!("  {} ... FAIL (not readable)", hf.display());
        all_ok = false;
    }

    // ---- Disk write ----
    println!("\nDisk:");
    let tmp = std::env::temp_dir().join(format!("lancer-dnsx-hc-{}.tmp", std::process::id()));
    match std::fs::write(&tmp, b"ok") {
        Ok(_) => {
            println!("  Temp write at {} ... OK", tmp.display());
            let _ = std::fs::remove_file(&tmp);
        }
        Err(e) => {
            println!("  Temp write at {} ... FAIL ({e})", tmp.display());
            all_ok = false;
        }
    }

    Ok(all_ok)
}

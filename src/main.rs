//! lancer-dnsx -- Phase 4: filters (rcode, rtf, regex, stream)

mod cli;
mod filter;
mod input;
mod output;
mod record;
mod resolver;
mod wildcard;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::io::AsyncWriteExt;

use crate::cli::{normalize_args, Cli};
use crate::filter::Filters;
use crate::input::collect_input;
use crate::output::{format_result, WorkerOutput};
use crate::record::{HostRecord, RecordType};
use crate::resolver::{load_resolvers, resolve_host, ResolverPool};
use crate::wildcard::WildcardCache;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

/// Validate the value of `--wildcard-domain`. Returns Ok(()) if it looks like
/// a domain name (e.g. `target.com`), otherwise an error suitable for
/// surfacing directly to the user.
fn validate_wildcard_domain(value: &str) -> Result<()> {
    let trimmed = value.trim();
    let invalid = trimmed.is_empty()
        || !trimmed.contains('.')
        || trimmed.starts_with('.')
        || trimmed.ends_with('.')
        || trimmed.chars().any(char::is_whitespace);
    if invalid {
        anyhow::bail!(
            "--wildcard-domain must be a domain name (e.g., target.com), got: {value}"
        );
    }
    Ok(())
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

    // Validate --wildcard-domain looks like a domain name (not a URL, IP, or
    // bare label). We do this early so a typo fails fast before any
    // resolvers are loaded.
    if let Some(ref value) = cli.wildcard_domain {
        validate_wildcard_domain(value)?;
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

    // Build filters from CLI flags (rcode, rtf, regex). Errors here are
    // user-facing — bail out before any resolution begins.
    let filters = Arc::new(Filters::build(&cli)?);

    // Build the wildcard cache if either wildcard mode is enabled. Shared
    // across all workers; interior `RwLock` lets workers populate the cache
    // collaboratively (each level is probed at most once).
    //
    // Stream mode (-stream) short-circuits wildcard detection: in low-latency
    // / low-memory mode the user explicitly opts out of these features.
    let wildcard_cache: Option<Arc<WildcardCache>> = if cli.stream {
        if !cli.silent && (cli.wildcard_domain.is_some() || cli.auto_wildcard) {
            eprintln!("[INFO] -stream is set; wildcard detection disabled");
        }
        None
    } else if cli.wildcard_domain.is_some() || cli.auto_wildcard {
        Some(Arc::new(WildcardCache::new(
            cli.wildcard_threshold,
            cli.silent,
        )))
    } else {
        None
    };

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
    let auto_wildcard = cli.auto_wildcard;
    let wildcard_domain: Option<Arc<String>> = cli.wildcard_domain.clone().map(Arc::new);

    let mut worker_handles = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let pool_c = Arc::clone(&pool);
        let rx_c = rx.clone();
        let out_tx_c = out_tx.clone();
        let qtypes_c = Arc::clone(&query_types);
        let wildcard_c = wildcard_cache.as_ref().map(Arc::clone);
        let wd_c = wildcard_domain.clone();
        let filters_c = Arc::clone(&filters);

        let handle = tokio::spawn(async move {
            while let Ok(host) = rx_c.recv().await {
                let resolution = resolve_host(
                    &pool_c,
                    host.clone(),
                    (*qtypes_c).clone(),
                    silent,
                )
                .await;

                // Wildcard filtering: drop results when every A/AAAA IP for
                // this host is a member of an applicable wildcard set.
                if let Some(cache) = &wildcard_c {
                    let host_ips: Vec<IpAddr> = resolution
                        .results
                        .iter()
                        .filter_map(|r| match r.record_type {
                            RecordType::A | RecordType::Aaaa => r.value.parse::<IpAddr>().ok(),
                            _ => None,
                        })
                        .collect();

                    if !host_ips.is_empty() {
                        let is_wildcard = cache
                            .is_wildcard_match(
                                &pool_c,
                                &host,
                                &host_ips,
                                auto_wildcard,
                                wd_c.as_deref().map(String::as_str),
                            )
                            .await;
                        if is_wildcard {
                            if !silent {
                                eprintln!("[INFO] Dropping wildcard match: {host}");
                            }
                            continue;
                        }
                    }
                }

                // Apply rcode / rtf / regex filters. Fast path when no
                // filters are configured: take the results as-is.
                let (results, matched_rcode) = if filters_c.is_empty() {
                    (resolution.results, None)
                } else {
                    // Compute the matched rcode BEFORE apply consumes the
                    // resolution — needed so the output layer can surface
                    // hosts that matched a code filter but produced no
                    // records (e.g. NXDOMAIN under `-rcode nxdomain`).
                    let matched = filters_c.matched_rcode(&resolution);
                    match filters_c.apply(resolution) {
                        Some(r) => (r, matched),
                        None => continue,
                    }
                };

                // Forward when we have records OR when an rcode filter
                // matched a record-less response (e.g. NXDOMAIN). The
                // latter is the whole point of `-rcode nxdomain`.
                if !results.is_empty() || matched_rcode.is_some() {
                    let _ = out_tx_c
                        .send(WorkerOutput {
                            host,
                            results,
                            matched_rcode,
                        })
                        .await;
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
        } else if wo.results.is_empty() {
            // Host matched an `-rcode` filter but produced no records
            // (e.g. NXDOMAIN). Surface the host with the matched code so
            // the user actually sees the result they filtered for.
            if let Some(code) = wo.matched_rcode {
                let line = if resp || resp_only {
                    format!("{} [{}]", wo.host, code)
                } else if printed_hosts.insert(wo.host.clone()) {
                    wo.host.clone()
                } else {
                    continue;
                };
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

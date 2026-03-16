//! lancer-dnsx -- Phase 5: DNS trace and AXFR

mod asn;
mod axfr;
mod brute;
mod cdn;
mod cli;
mod filter;
mod input;
mod output;
mod record;
mod resolver;
mod trace;
mod wildcard;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::io::AsyncWriteExt;

use crate::asn::AsnLookup;
use crate::cdn::CdnMatcher;
use crate::cli::{normalize_args, Cli};
use crate::filter::Filters;
use crate::input::collect_input;
use crate::output::{append_annotations, format_result, WorkerOutput};
use crate::record::{AsnAnnotation, CdnAnnotation, HostRecord, RecordType};
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

/// True if any record-type flag other than -axfr is set. Used to decide
/// whether `-axfr` should route through the dedicated Phase 5 AXFR
/// implementation (alone) or be folded into the regular lookup pipeline
/// alongside e.g. `-a -axfr`.
fn any_non_axfr_type_flag(cli: &Cli) -> bool {
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
// Helpers
// ---------------------------------------------------------------------------

/// Write a line (with a trailing newline) to an optional output file.
/// Errors are logged to stderr and swallowed so a single write failure does
/// not abort the entire run.
async fn write_line(fh: &mut Option<tokio::fs::File>, line: &str) {
    if let Some(ref mut f) = fh {
        if let Err(e) = f.write_all(format!("{line}\n").as_bytes()).await {
            eprintln!("[ERROR] Failed to write output: {e}");
        }
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
    let mut cli = Cli::parse_from(normalized);

    // Brute mode (`-d/--domain`) forces auto-wildcard on. A wordlist probe
    // against a wildcard zone produces enormous false-positive floods, so
    // dnsx convention is to always run wildcard detection in this mode --
    // even when the user passes `-stream` (we emit a warning but still
    // honor the wildcard enable).
    let brute_mode = cli.domain.is_some();
    if brute_mode {
        if cli.stream && !cli.silent {
            eprintln!(
                "[WARN] -stream + -d: wildcard detection cannot be disabled \
                 in brute mode; forcing wildcard on"
            );
        }
        if cli.list.is_some() && !cli.silent {
            eprintln!("[WARN] -l is ignored when -d is set (brute-force mode)");
        }
        cli.auto_wildcard = true;
    }

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
    let wildcard_cache: Option<Arc<WildcardCache>> = if cli.stream && !brute_mode {
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

    // Collect input hosts. Brute mode (`-d`) generates `word.domain` pairs
    // from a wordlist; otherwise fall back to the usual stdin / file / `-l`
    // collection path.
    let hosts = if brute_mode {
        let domain_arg = cli
            .domain
            .as_deref()
            .expect("brute_mode implies cli.domain is Some");
        brute::generate_brute_input(domain_arg, cli.wordlist.as_deref(), cli.silent).await?
    } else {
        collect_input(cli.list.as_deref(), cli.silent).await?
    };

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

    // ---- Phase 5: standalone probe modes -------------------------------
    // -trace short-circuits normal resolution.
    if cli.trace {
        let (work_tx, work_rx) = async_channel::bounded::<String>(cli.threads * 2);
        // Output channel so workers can send formatted text to a single drain
        // task, guaranteeing non-interleaved output lines.
        let (out_tx5, mut out_rx5) =
            tokio::sync::mpsc::channel::<(String, Option<String>)>(cli.threads * 2);

        let num_workers = cli.threads.min(hosts.len()).max(1);
        let max_rec = cli.trace_max_recursion;
        let silent5 = cli.silent;
        let mut trace_handles = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let rx_c = work_rx.clone();
            let out_c = out_tx5.clone();
            let handle = tokio::spawn(async move {
                while let Ok(host) = rx_c.recv().await {
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(60),
                        trace::trace_host(&host, max_rec),
                    )
                    .await;
                    match result {
                        Ok(Ok(steps)) => {
                            let text = trace::format_trace_text(&host, &steps);
                            let _ = out_c.send((text, None)).await;
                        }
                        Ok(Err(e)) => {
                            if !silent5 {
                                let _ = out_c
                                    .send((
                                        String::new(),
                                        Some(format!("[ERROR] trace {} failed: {}", host, e)),
                                    ))
                                    .await;
                            }
                        }
                        Err(_) => {
                            let _ = out_c
                                .send((
                                    String::new(),
                                    Some(format!(
                                        "[ERROR] trace {} timed out after 60s",
                                        host
                                    )),
                                ))
                                .await;
                        }
                    }
                }
            });
            trace_handles.push(handle);
        }
        drop(out_tx5);

        // Feed hosts
        for host in hosts {
            let _ = work_tx.send(host).await;
        }
        drop(work_tx);

        // Drain output (single task → serialized writes)
        while let Some((text, err)) = out_rx5.recv().await {
            if let Some(msg) = err {
                eprintln!("{msg}");
            } else if !text.is_empty() {
                print!("{text}");
                write_line(&mut output_file, text.trim_end()).await;
            }
        }

        for h in trace_handles {
            let _ = h.await;
        }
        return Ok(());
    }

    // -axfr (when set alone, or as the only active record type) routes to
    // the dedicated AXFR implementation instead of the regular lookup path.
    if cli.axfr && !cli.recon && !any_non_axfr_type_flag(&cli) {
        let (work_tx, work_rx) = async_channel::bounded::<String>(cli.threads * 2);
        let (out_tx5, mut out_rx5) =
            tokio::sync::mpsc::channel::<(String, Option<String>)>(cli.threads * 2);

        let num_workers = cli.threads.min(hosts.len()).max(1);
        let silent5 = cli.silent;
        let mut axfr_handles = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let rx_c = work_rx.clone();
            let out_c = out_tx5.clone();
            let pool_c = Arc::clone(&pool);
            let handle = tokio::spawn(async move {
                while let Ok(host) = rx_c.recv().await {
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        axfr::axfr_host(&host, &pool_c),
                    )
                    .await;
                    match result {
                        Ok(Ok(report)) => {
                            let text = axfr::format_axfr_text(&report);
                            let _ = out_c.send((text, None)).await;
                        }
                        Ok(Err(e)) => {
                            if !silent5 {
                                let _ = out_c
                                    .send((
                                        String::new(),
                                        Some(format!("[ERROR] axfr {} failed: {}", host, e)),
                                    ))
                                    .await;
                            }
                        }
                        Err(_) => {
                            let _ = out_c
                                .send((
                                    String::new(),
                                    Some(format!(
                                        "[ERROR] axfr {} timed out after 30s",
                                        host
                                    )),
                                ))
                                .await;
                        }
                    }
                }
            });
            axfr_handles.push(handle);
        }
        drop(out_tx5);

        // Feed hosts
        for host in hosts {
            let _ = work_tx.send(host).await;
        }
        drop(work_tx);

        // Drain output
        while let Some((text, err)) = out_rx5.recv().await {
            if let Some(msg) = err {
                eprintln!("{msg}");
            } else if !text.is_empty() {
                print!("{text}");
                write_line(&mut output_file, text.trim_end()).await;
            }
        }

        for h in axfr_handles {
            let _ = h.await;
        }
        return Ok(());
    }
    // -------------------------------------------------------------------

    // Worker pool via async-channel (MPMC)
    let (tx, rx) = async_channel::bounded::<String>(cli.threads * 2);

    // Output channel
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<WorkerOutput>(cli.threads * 2);

    // Spawn N worker tasks
    let num_workers = cli.threads.min(hosts.len()).max(1);
    let silent = cli.silent;
    let auto_wildcard = cli.auto_wildcard;
    let wildcard_domain: Option<Arc<String>> = cli.wildcard_domain.clone().map(Arc::new);

    // Phase 7: CDN/ASN matchers, shared across workers. Constructed only
    // when the relevant flag is set so we don't pay for the static range
    // table or HTTP client in the common case.
    let cdn_matcher: Option<Arc<CdnMatcher>> = if cli.cdn {
        Some(Arc::new(CdnMatcher::new()))
    } else {
        None
    };
    let asn_lookup: Option<Arc<AsnLookup>> = if cli.asn {
        Some(Arc::new(AsnLookup::new(cli.silent)))
    } else {
        None
    };

    let mut worker_handles = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let pool_c = Arc::clone(&pool);
        let rx_c = rx.clone();
        let out_tx_c = out_tx.clone();
        let qtypes_c = Arc::clone(&query_types);
        let wildcard_c = wildcard_cache.as_ref().map(Arc::clone);
        let wd_c = wildcard_domain.clone();
        let filters_c = Arc::clone(&filters);
        let cdn_c = cdn_matcher.as_ref().map(Arc::clone);
        let asn_c = asn_lookup.as_ref().map(Arc::clone);

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

                // Phase 7: CDN/ASN annotations. Walk surviving A/AAAA
                // results and attach matches by IP. ASN is async (HTTP
                // call into BGPView with an in-memory cache) so unique
                // IPs are deduplicated before issuing lookups.
                let mut cdn_annotations: Vec<CdnAnnotation> = Vec::new();
                let mut asn_annotations: Vec<AsnAnnotation> = Vec::new();
                if cdn_c.is_some() || asn_c.is_some() {
                    let mut seen_ips: HashSet<String> = HashSet::new();
                    for r in &results {
                        if !matches!(r.record_type, RecordType::A | RecordType::Aaaa) {
                            continue;
                        }
                        if !seen_ips.insert(r.value.clone()) {
                            continue;
                        }
                        let Ok(ip) = r.value.parse::<IpAddr>() else {
                            continue;
                        };
                        if let Some(m) = &cdn_c {
                            if let Some(info) = m.lookup(ip) {
                                cdn_annotations.push(CdnAnnotation {
                                    ip: r.value.clone(),
                                    name: info.name.to_string(),
                                    cdn_type: info.cdn_type.to_string(),
                                });
                            }
                        }
                        if let Some(a) = &asn_c {
                            if let Some(info) = a.lookup(ip).await {
                                asn_annotations
                                    .push(AsnAnnotation::from_info(r.value.clone(), &info));
                            }
                        }
                    }
                }

                // Forward when we have records OR when an rcode filter
                // matched a record-less response (e.g. NXDOMAIN). The
                // latter is the whole point of `-rcode nxdomain`.
                if !results.is_empty() || matched_rcode.is_some() {
                    let _ = out_tx_c
                        .send(WorkerOutput {
                            host,
                            results,
                            matched_rcode,
                            cdn: cdn_annotations,
                            asn: asn_annotations,
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
                let mut rec = HostRecord::from_results(&wo.host, &wo.results);
                rec.cdn = wo.cdn.clone();
                rec.asn = wo.asn.clone();
                let line = serde_json::to_string(&rec)?;
                println!("{line}");
                write_line(&mut output_file, &line).await;
            } else if let Some(code) = wo.matched_rcode {
                // Host matched an `-rcode` filter but returned no records
                // (e.g. NXDOMAIN under `-rcode nxdomain -json`). Emit a
                // minimal JSON object so the caller sees the result.
                let rec = HostRecord::empty_with_rcode(&wo.host, code);
                let line = serde_json::to_string(&rec)?;
                println!("{line}");
                write_line(&mut output_file, &line).await;
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
                write_line(&mut output_file, &line).await;
            }
        } else {
            for result in &wo.results {
                let mut line = format_result(result, resp, resp_only, no_color);

                // In default mode, only print a hostname once (multiple A records -> one line)
                if !resp && !resp_only && !printed_hosts.insert(result.host.clone()) {
                    continue;
                }

                // Phase 7: append CDN/ASN annotations to the IP that
                // produced them. Only meaningful for A/AAAA records.
                if (!wo.cdn.is_empty() || !wo.asn.is_empty())
                    && matches!(result.record_type, RecordType::A | RecordType::Aaaa)
                {
                    append_annotations(&mut line, &result.value, &wo.cdn, &wo.asn);
                }

                println!("{line}");
                write_line(&mut output_file, &line).await;
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

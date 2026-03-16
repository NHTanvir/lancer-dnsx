//! AXFR (DNS zone transfer) attempts.
//!
//! For each input host we:
//!   1. Query the resolver pool for NS records (the host's authoritative
//!      nameservers).
//!   2. Resolve each NS to an IPv4 address (glue/A lookup).
//!   3. Open a TCP DNS connection to that NS:53 and request an AXFR.
//!   4. Stream answer records until the trailing SOA marks the end.
//!
//! Almost every public server refuses AXFR — `refused` is the expected
//! outcome. Output reports per-NS status so the user sees which (if any)
//! allowed the transfer.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use futures_util::StreamExt;
use hickory_client::client::{AsyncClient, ClientHandle};
use hickory_proto::iocompat::AsyncIoTokioAsStd;
use hickory_proto::rr::Name;
use hickory_proto::tcp::TcpClientStream;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time::timeout;

use crate::resolver::ResolverPool;

/// Hard timeout for any individual NS connection / AXFR exchange.
const AXFR_TIMEOUT: Duration = Duration::from_secs(8);

/// One line of AXFR output per host: which NS we tried and what happened.
pub struct AxfrReport {
    pub host: String,
    pub per_ns: Vec<AxfrNsResult>,
}

pub struct AxfrNsResult {
    pub ns_name: String,
    pub ns_ip: Option<std::net::IpAddr>,
    pub outcome: AxfrOutcome,
}

pub enum AxfrOutcome {
    /// Transfer succeeded — list of stringified records.
    Records(Vec<String>),
    /// Transfer failed (refused, timeout, network error, malformed reply, …).
    Error(String),
}

/// Resolve NS records for `host` to a list of (ns_name, ns_ipv4) pairs by
/// going through the resolver pool. Names that have no A record (or fail to
/// resolve) are still returned with `None` IP so the caller can show the
/// attempt.
async fn resolve_ns_targets(
    pool: &ResolverPool,
    host: &str,
) -> Vec<(String, Option<std::net::IpAddr>)> {
    let Some((idx, tracked)) = pool.pick() else {
        return Vec::new();
    };
    let resolver = tracked.resolver();
    let ns_resp = resolver.ns_lookup(host).await;
    pool.record(idx, ns_resp.is_ok());
    let mut ns_names: Vec<String> = match ns_resp {
        Ok(resp) => resp
            .iter()
            .map(|n| n.to_utf8().trim_end_matches('.').to_string())
            .collect(),
        Err(_) => Vec::new(),
    };
    ns_names.sort();
    ns_names.dedup();

    let mut out = Vec::with_capacity(ns_names.len());
    for ns_name in ns_names {
        let ip = if let Some((idx2, tracked2)) = pool.pick() {
            let r2 = tracked2.resolver();
            let res = r2.ipv4_lookup(&ns_name).await;
            pool.record(idx2, res.is_ok());
            res.ok().and_then(|resp| {
                resp.iter()
                    .next()
                    .map(|a| std::net::IpAddr::V4(a.0))
            })
        } else {
            None
        };
        out.push((ns_name, ip));
    }
    out
}

/// Attempt an AXFR transfer of `zone` from `ns_ip:53` over TCP. Returns the
/// list of stringified records on success, or a human-readable error string
/// on failure.
async fn try_axfr_one(zone: &str, ns_ip: std::net::IpAddr) -> Result<Vec<String>, String> {
    let zone_name = match Name::from_str(zone) {
        Ok(n) => n,
        Err(e) => return Err(format!("invalid zone name: {e}")),
    };
    let addr: SocketAddr = SocketAddr::new(ns_ip, 53);

    // Build a TCP client connection.
    let (stream, sender) =
        TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(addr);
    let client_future = AsyncClient::new(stream, sender, None);

    let (mut client, bg) = match timeout(AXFR_TIMEOUT, client_future).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(format!("tcp connect error: {e}")),
        Err(_) => return Err("tcp connect timeout".to_string()),
    };
    tokio::spawn(bg);

    // Issue an AXFR via the dedicated zone_transfer API. This returns a
    // Stream of DnsResponse messages that ends when the trailing SOA marks
    // the close of the transfer (or when the server replies with a single
    // error message).
    let mut xfr = client.zone_transfer(zone_name, None);

    let mut records: Vec<String> = Vec::new();
    let mut got_any = false;
    loop {
        let next = timeout(AXFR_TIMEOUT, xfr.next()).await;
        match next {
            Ok(Some(Ok(msg))) => {
                got_any = true;
                // Refused / ServFail / NotAuth → bail out with the rcode.
                let rcode = msg.response_code();
                if rcode != hickory_proto::op::ResponseCode::NoError {
                    return Err(format!("server returned {}", rcode));
                }
                for r in msg.answers() {
                    let rtype = r.record_type();
                    let value = r
                        .data()
                        .map(|d| d.to_string())
                        .unwrap_or_default();
                    records.push(format!(
                        "{} {} {} {}",
                        r.name().to_utf8().trim_end_matches('.'),
                        r.ttl(),
                        rtype,
                        value,
                    ));
                }
            }
            Ok(Some(Err(e))) => return Err(format!("axfr error: {e}")),
            Ok(None) => break,
            Err(_) => return Err("axfr timeout".to_string()),
        }
    }

    if !got_any {
        return Err("no response from server".to_string());
    }
    if records.is_empty() {
        return Err("server returned NoError with no records".to_string());
    }
    Ok(records)
}

/// Attempt AXFR against every NS for `host` and return the per-NS report.
pub async fn axfr_host(host: &str, pool: &ResolverPool) -> Result<AxfrReport> {
    let ns_targets = resolve_ns_targets(pool, host).await;
    let mut per_ns = Vec::with_capacity(ns_targets.len());
    for (ns_name, ns_ip) in ns_targets {
        let outcome = match ns_ip {
            Some(ip) => match try_axfr_one(host, ip).await {
                Ok(records) => AxfrOutcome::Records(records),
                Err(e) => AxfrOutcome::Error(e),
            },
            None => AxfrOutcome::Error("could not resolve NS to IP".to_string()),
        };
        per_ns.push(AxfrNsResult {
            ns_name,
            ns_ip,
            outcome,
        });
    }
    Ok(AxfrReport {
        host: host.to_string(),
        per_ns,
    })
}

/// Pretty-print an `AxfrReport` to plain text.
pub fn format_axfr_text(report: &AxfrReport) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    writeln!(out, "AXFR {}", report.host).unwrap();
    if report.per_ns.is_empty() {
        out.push_str("  (no NS records found)\n");
        return out;
    }
    for ns in &report.per_ns {
        let ip_str = ns
            .ns_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "?".to_string());
        match &ns.outcome {
            AxfrOutcome::Records(records) => {
                writeln!(
                    out,
                    "  {} ({}) -> SUCCESS ({} records)",
                    ns.ns_name,
                    ip_str,
                    records.len()
                )
                .unwrap();
                for r in records {
                    writeln!(out, "    {r}").unwrap();
                }
            }
            AxfrOutcome::Error(msg) => {
                writeln!(
                    out,
                    "  {} ({}) -> FAILED: {}",
                    ns.ns_name, ip_str, msg
                )
                .unwrap();
            }
        }
    }
    out
}

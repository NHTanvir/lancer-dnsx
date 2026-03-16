//! DNS trace: recursive lookup from root NS down to authoritative server.
//!
//! For each input host we send non-recursive (RD=0) DNS queries starting at a
//! root server (a.root-servers.net …), follow the NS delegations in the
//! authority section until we get an authoritative answer (or hit the
//! recursion cap / a dead end).

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Hard-coded IANA root server addresses. We try them in order until one
/// responds.
pub(crate) const ROOT_SERVERS: &[(&str, &str)] = &[
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "199.9.14.201"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
];

/// One step of the trace walk.
pub(crate) struct TraceStep {
    pub(crate) step: usize,
    pub(crate) server: String,
    pub(crate) server_ip: IpAddr,
    /// The queried hostname for this hop. Kept on every step so a future
    /// JSON-output mode (or debugger) can show "what we asked at hop N".
    #[allow(dead_code)]
    pub(crate) question: String,
    pub(crate) response_kind: TraceResponseKind,
}

pub(crate) enum TraceResponseKind {
    /// Authority section returned NS records: list of NS names.
    Delegation(Vec<String>),
    /// Authoritative answer records (typed string forms).
    Answer(Vec<String>),
    /// Step failed (timeout / parse / refused / ...).
    Error(String),
}

/// Per-query timeout for individual trace hops.
const HOP_TIMEOUT: Duration = Duration::from_secs(3);

/// Send a single non-recursive A query for `qname` to `server_ip:53` over UDP
/// and parse the response into a hickory `Message`.
async fn query_one(server_ip: IpAddr, qname: &Name) -> Result<Message> {
    // Build the query message: RD=0, single A question.
    let mut msg = Message::new();
    msg.set_id(rand::random::<u16>())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false);
    let mut q = Query::new();
    q.set_name(qname.clone())
        .set_query_type(RecordType::A)
        .set_query_class(DNSClass::IN);
    msg.add_query(q);
    let bytes = msg.to_vec()?;

    // Bind a local socket (v4 or v6 to match remote family).
    let bind_addr: SocketAddr = match server_ip {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    let remote = SocketAddr::new(server_ip, 53);
    sock.connect(remote).await?;

    timeout(HOP_TIMEOUT, sock.send(&bytes))
        .await
        .map_err(|_| anyhow!("send timeout"))??;

    let mut buf = vec![0u8; 4096];
    let n = timeout(HOP_TIMEOUT, sock.recv(&mut buf))
        .await
        .map_err(|_| anyhow!("recv timeout"))??;
    buf.truncate(n);

    let resp = Message::from_bytes(&buf)?;
    Ok(resp)
}

/// Extract NS names from a record slice. Only considers NS records whose
/// owner name is a proper ancestor of `qname` (i.e. an actual delegation
/// from the current server to a sub-zone). This skips "hint"-style NS
/// records that some servers emit for the root zone when they can't
/// delegate.
fn extract_ns_names_for(records: &[Record], qname: &Name) -> Vec<String> {
    let qname_lower = qname.to_utf8().trim_end_matches('.').to_lowercase();
    records
        .iter()
        .filter(|r| r.record_type() == RecordType::NS)
        .filter(|r| {
            let owner = r.name().to_utf8().trim_end_matches('.').to_lowercase();
            // Owner must be qname itself or a parent label of qname.
            owner.is_empty()
                || qname_lower == owner
                || qname_lower.ends_with(&format!(".{owner}"))
        })
        .filter_map(|r| match r.data() {
            Some(RData::NS(ns)) => Some(ns.0.to_utf8().trim_end_matches('.').to_string()),
            _ => None,
        })
        .collect()
}

/// Return the most-specific delegation owner name in `records` relative to
/// `qname`. Used so we don't accept a delegation that doesn't progress
/// toward the answer (e.g. root re-advertising "." NS).
fn deepest_owner(records: &[Record], qname: &Name) -> Option<String> {
    let qname_lower = qname.to_utf8().trim_end_matches('.').to_lowercase();
    records
        .iter()
        .filter(|r| r.record_type() == RecordType::NS)
        .map(|r| r.name().to_utf8().trim_end_matches('.').to_lowercase())
        .filter(|owner| {
            owner.is_empty()
                || qname_lower == *owner
                || qname_lower.ends_with(&format!(".{owner}"))
        })
        .max_by_key(|owner| owner.split('.').filter(|s| !s.is_empty()).count())
}

/// Pull glue A/AAAA records out of the additional section, keyed by owner
/// name (trimmed of trailing dot, lowercased).
fn extract_glue(records: &[Record]) -> Vec<(String, IpAddr)> {
    let mut glue = Vec::new();
    for r in records {
        let owner = r.name().to_utf8().trim_end_matches('.').to_lowercase();
        match (r.record_type(), r.data()) {
            (RecordType::A, Some(RData::A(a))) => glue.push((owner, IpAddr::V4(a.0))),
            (RecordType::AAAA, Some(RData::AAAA(a))) => glue.push((owner, IpAddr::V6(a.0))),
            _ => {}
        }
    }
    glue
}

/// Resolve an NS hostname to an IPv4 address, preferring glue records from
/// `glue` and falling back to a one-shot lookup against the system resolver
/// pool of root servers (we just iterate roots → tld → … typically glue is
/// present so this fallback rarely fires).
async fn resolve_ns_ip(ns_name: &str, glue: &[(String, IpAddr)]) -> Option<IpAddr> {
    let key = ns_name.trim_end_matches('.').to_lowercase();
    if let Some((_, ip)) = glue.iter().find(|(o, _)| *o == key) {
        return Some(*ip);
    }
    // Fallback: do a basic UDP A query against one of the public roots via
    // the system to find this NS. We can't use the resolver pool from here
    // without a circular dep, so just do a recursive query via 1.1.1.1.
    let name = Name::from_ascii(ns_name).ok()?;
    let mut msg = Message::new();
    msg.set_id(rand::random::<u16>())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(name)
        .set_query_type(RecordType::A)
        .set_query_class(DNSClass::IN);
    msg.add_query(q);
    let bytes = msg.to_vec().ok()?;
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let remote: SocketAddr = "1.1.1.1:53".parse().unwrap();
    sock.connect(remote).await.ok()?;
    timeout(HOP_TIMEOUT, sock.send(&bytes)).await.ok()?.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(HOP_TIMEOUT, sock.recv(&mut buf)).await.ok()?.ok()?;
    buf.truncate(n);
    let resp = Message::from_bytes(&buf).ok()?;
    for r in resp.answers() {
        if let Some(RData::A(a)) = r.data() {
            return Some(IpAddr::V4(a.0));
        }
    }
    None
}

/// Stringify a record into "TYPE value" form for trace output.
fn record_to_string(r: &Record) -> String {
    let rtype = r.record_type();
    let value = r.data().map(|d| d.to_string()).unwrap_or_default();
    format!("{rtype} {value}")
}

/// Trace `host` recursively from a root server down to the authoritative
/// answer. Bounded by `max_recursion` hops. Best-effort: if a root times out
/// we try the next one; if delegation chain breaks we record an `Error` step
/// and stop.
pub(crate) async fn trace_host(host: &str, max_recursion: u32) -> Result<Vec<TraceStep>> {
    let qname = Name::from_str(host)
        .map_err(|e| anyhow!("invalid host {host}: {e}"))?;

    let mut steps: Vec<TraceStep> = Vec::new();

    // Pick an initial root server. Try each in order until one responds.
    let mut current_server_name: String;
    let mut current_server_ip: IpAddr;
    let mut first_resp: Option<Message> = None;
    let mut chosen_root: Option<(&str, IpAddr)> = None;
    for (name, ip_str) in ROOT_SERVERS {
        let ip: IpAddr = ip_str.parse().expect("static");
        match query_one(ip, &qname).await {
            Ok(resp) => {
                chosen_root = Some((name, ip));
                first_resp = Some(resp);
                break;
            }
            Err(_) => continue,
        }
    }
    let (root_name, root_ip) = match chosen_root {
        Some(v) => v,
        None => {
            steps.push(TraceStep {
                step: 1,
                server: "root".to_string(),
                server_ip: ROOT_SERVERS[0].1.parse().unwrap(),
                question: host.to_string(),
                response_kind: TraceResponseKind::Error("all root servers unreachable".into()),
            });
            return Ok(steps);
        }
    };
    current_server_name = root_name.to_string();
    current_server_ip = root_ip;

    let mut step_no: usize = 1;
    let mut response = first_resp.expect("we just set it above");

    // Track the deepest delegation we've seen so far; we refuse to "step"
    // sideways or backwards into a same-or-shallower zone, which is what
    // happens when an upstream resolver returns the root NS hints in
    // response to a name we have no path to.
    let mut last_owner_depth: usize = 0;

    // Process each response (starting with the root's response) and follow
    // delegations up to max_recursion follow-up queries. We use a helper
    // macro to avoid duplicating the process-response block. The root
    // response is always processed unconditionally (step 0 of the loop
    // below, with no preceding query) so that max_recursion=0 still
    // surfaces the root's reply rather than discarding it.
    //
    // Loop: iteration 0 → process root response (already in `response`).
    //       iterations 1..=max_recursion → follow one delegation per turn.
    for hop in 0..=max_recursion {
        // Did we get an authoritative answer?
        if !response.answers().is_empty() {
            let answers: Vec<String> =
                response.answers().iter().map(record_to_string).collect();
            steps.push(TraceStep {
                step: step_no,
                server: current_server_name.clone(),
                server_ip: current_server_ip,
                question: host.to_string(),
                response_kind: TraceResponseKind::Answer(answers),
            });
            return Ok(steps);
        }

        // No answer → look for NS delegation in authority.
        let ns_names = extract_ns_names_for(response.name_servers(), &qname);
        let owner = deepest_owner(response.name_servers(), &qname).unwrap_or_default();
        let owner_depth = owner.split('.').filter(|s| !s.is_empty()).count();
        let glue = extract_glue(response.additionals());

        steps.push(TraceStep {
            step: step_no,
            server: current_server_name.clone(),
            server_ip: current_server_ip,
            question: host.to_string(),
            response_kind: TraceResponseKind::Delegation(ns_names.clone()),
        });

        if ns_names.is_empty() {
            steps.push(TraceStep {
                step: step_no + 1,
                server: current_server_name.clone(),
                server_ip: current_server_ip,
                question: host.to_string(),
                response_kind: TraceResponseKind::Error(
                    "no delegation and no answer".into(),
                ),
            });
            return Ok(steps);
        }

        // Refuse to "follow" a delegation that doesn't get us closer to
        // qname. Otherwise an upstream that keeps returning root hints
        // would send us in circles forever.
        if owner_depth <= last_owner_depth && step_no > 1 {
            steps.push(TraceStep {
                step: step_no + 1,
                server: current_server_name.clone(),
                server_ip: current_server_ip,
                question: host.to_string(),
                response_kind: TraceResponseKind::Error(format!(
                    "server stopped delegating toward target (owner '{owner}')"
                )),
            });
            return Ok(steps);
        }
        last_owner_depth = owner_depth;

        // We have consumed this hop's delegation; if we have reached the
        // follow-up cap we must stop before issuing another query.
        if hop == max_recursion {
            break;
        }

        // Pick the first NS we can resolve (glue first, then fallback).
        let mut next_server: Option<(String, IpAddr)> = None;
        for ns in &ns_names {
            if let Some(ip) = resolve_ns_ip(ns, &glue).await {
                next_server = Some((ns.clone(), ip));
                break;
            }
        }
        let (ns_name, ns_ip) = match next_server {
            Some(v) => v,
            None => {
                steps.push(TraceStep {
                    step: step_no + 1,
                    server: current_server_name.clone(),
                    server_ip: current_server_ip,
                    question: host.to_string(),
                    response_kind: TraceResponseKind::Error(
                        "could not resolve any NS to an IP".into(),
                    ),
                });
                return Ok(steps);
            }
        };

        step_no += 1;
        current_server_name = ns_name;
        current_server_ip = ns_ip;
        match query_one(current_server_ip, &qname).await {
            Ok(resp) => response = resp,
            Err(e) => {
                steps.push(TraceStep {
                    step: step_no,
                    server: current_server_name.clone(),
                    server_ip: current_server_ip,
                    question: host.to_string(),
                    response_kind: TraceResponseKind::Error(e.to_string()),
                });
                return Ok(steps);
            }
        }
    }

    steps.push(TraceStep {
        step: step_no,
        server: current_server_name,
        server_ip: current_server_ip,
        question: host.to_string(),
        response_kind: TraceResponseKind::Error(format!(
            "max recursion depth ({max_recursion}) reached"
        )),
    });
    Ok(steps)
}

/// Pretty-print a trace result as plain text.
pub(crate) fn format_trace_text(host: &str, steps: &[TraceStep]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    writeln!(out, "TRACE {host}").unwrap();
    for s in steps {
        match &s.response_kind {
            TraceResponseKind::Delegation(ns_list) => {
                let joined = if ns_list.is_empty() {
                    "(none)".to_string()
                } else {
                    ns_list.join(", ")
                };
                writeln!(
                    out,
                    "  [{}] {} ({}) -> NS ({})",
                    s.step, s.server, s.server_ip, joined
                )
                .unwrap();
            }
            TraceResponseKind::Answer(records) => {
                if records.is_empty() {
                    writeln!(
                        out,
                        "  [{}] {} ({}) -> (empty answer)",
                        s.step, s.server, s.server_ip
                    )
                    .unwrap();
                } else {
                    writeln!(
                        out,
                        "  [{}] {} ({}) -> {}",
                        s.step,
                        s.server,
                        s.server_ip,
                        records.join(", ")
                    )
                    .unwrap();
                }
            }
            TraceResponseKind::Error(msg) => {
                writeln!(
                    out,
                    "  [{}] {} ({}) -> ERROR: {}",
                    s.step, s.server, s.server_ip, msg
                )
                .unwrap();
            }
        }
    }
    out
}

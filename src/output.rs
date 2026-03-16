//! Output formatting and the worker -> output channel payload type.

use crate::record::{AsnAnnotation, CdnAnnotation, DnsResult, ResponseCode};

/// Format a single DNS result for output.
///
/// - Default (no `-resp`, no `-resp-only`): print just the hostname
/// - `-resp` / `-re`: print `host TYPE value`
/// - `-resp-only` / `-ro`: print just `value`
pub(crate) fn format_result(
    result: &DnsResult,
    resp: bool,
    resp_only: bool,
    _no_color: bool,
) -> String {
    if resp_only {
        result.value.clone()
    } else if resp {
        format!("{} {} {}", result.host, result.record_type, result.value)
    } else {
        result.host.clone()
    }
}

/// Append CDN/ASN annotations to a result line. Looks up by IP value so the
/// annotation only attaches to the matching A/AAAA line.
pub(crate) fn append_annotations(
    line: &mut String,
    ip: &str,
    cdns: &[CdnAnnotation],
    asns: &[AsnAnnotation],
) {
    for c in cdns.iter().filter(|c| c.ip == ip) {
        line.push_str(&format!(" [cdn:{}]", c.name));
    }
    for a in asns.iter().filter(|a| a.ip == ip) {
        line.push_str(&format!(" [asn:{} {} {}]", a.asn, a.name, a.country));
    }
}

/// The payload sent from workers to the output loop.
///
/// `matched_rcode` is set when the host produced no records but matched an
/// `-rcode` filter (e.g. NXDOMAIN for a non-existent name): we still surface
/// the host so the user sees the result they explicitly asked for.
pub(crate) struct WorkerOutput {
    pub(crate) host: String,
    pub(crate) results: Vec<DnsResult>,
    pub(crate) matched_rcode: Option<ResponseCode>,
    pub(crate) cdn: Vec<CdnAnnotation>,
    pub(crate) asn: Vec<AsnAnnotation>,
}

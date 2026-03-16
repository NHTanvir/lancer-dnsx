//! Post-resolution filters: response-code, response-type, and value regex.
//!
//! All filters operate on a fully populated `HostResolution` (results +
//! per-record-type response codes). The pipeline is:
//!
//! 1. `-rcode` — drop the host unless at least one queried record type
//!    returned a response code in the user-supplied set.
//! 2. `-rtf` (response-type-filter) — drop the host if it has ANY record of
//!    the listed types. Useful for finding dangling CNAMEs where the
//!    CNAME target failed to resolve (host kept ONLY if it has no CNAME
//!    record at all). This is the inverse of `-exclude-type`.
//! 3. `-mr` / `-er` — per-record value regex match / exclude. Applied
//!    AFTER the host-level filters; an empty result set after this step
//!    drops the host entirely.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use regex::Regex;

use crate::cli::Cli;
use crate::record::{DnsResult, HostResolution, RecordType, ResponseCode};

pub(crate) struct Filters {
    rcode: Option<HashSet<ResponseCode>>,
    response_type_filter: Option<Vec<RecordType>>,
    match_regex: Option<Regex>,
    exclude_regex: Option<Regex>,
}

impl Filters {
    /// Build the filter set from CLI flags. Returns an error if any filter
    /// argument cannot be parsed.
    pub(crate) fn build(cli: &Cli) -> Result<Self> {
        let rcode = match &cli.response_code {
            Some(s) => Some(parse_rcode_list(s)?),
            None => None,
        };

        let response_type_filter = match &cli.response_type_filter {
            Some(s) => Some(parse_type_list(s)?),
            None => None,
        };

        let match_regex = match &cli.match_regex {
            Some(s) => Some(
                Regex::new(s).map_err(|e| anyhow!("invalid --match-regex '{s}': {e}"))?,
            ),
            None => None,
        };

        let exclude_regex = match &cli.exclude_regex {
            Some(s) => Some(
                Regex::new(s).map_err(|e| anyhow!("invalid --exclude-regex '{s}': {e}"))?,
            ),
            None => None,
        };

        Ok(Filters {
            rcode,
            response_type_filter,
            match_regex,
            exclude_regex,
        })
    }

    /// True if no filters are active (fast-path the worker loop can use to
    /// skip the apply step entirely).
    pub(crate) fn is_empty(&self) -> bool {
        self.rcode.is_none()
            && self.response_type_filter.is_none()
            && self.match_regex.is_none()
            && self.exclude_regex.is_none()
    }

    /// Find the first response code on this resolution that matches the
    /// configured `-rcode` set, if any. Used by the output layer to surface
    /// hosts that matched a code filter but produced no records (e.g.
    /// NXDOMAIN), so `-rcode nxdomain` actually prints those hosts.
    pub(crate) fn matched_rcode(&self, resolution: &HostResolution) -> Option<ResponseCode> {
        let wanted = self.rcode.as_ref()?;
        resolution
            .codes
            .values()
            .filter_map(|c| c.as_ref())
            .find(|c| wanted.contains(c))
            .copied()
    }

    /// Apply all filters to a host's resolution. Returns the (possibly
    /// reduced) result list when the host passes, or `None` when the host
    /// is dropped.
    pub(crate) fn apply(&self, resolution: HostResolution) -> Option<Vec<DnsResult>> {
        // 1. Host-level: response-code filter. A host passes when ANY of
        //    its queried record types returned a code in the configured
        //    set. Codes that are None (transport failure) never match.
        if let Some(ref wanted) = self.rcode {
            let any_match = resolution
                .codes
                .values()
                .filter_map(|c| c.as_ref())
                .any(|c| wanted.contains(c));
            if !any_match {
                return None;
            }
        }

        // 2. Host-level: response-type filter. Drop the host if it has
        //    ANY record of one of the listed types.
        if let Some(ref blocked_types) = self.response_type_filter {
            let has_blocked = resolution
                .results
                .iter()
                .any(|r| blocked_types.contains(&r.record_type));
            if has_blocked {
                return None;
            }
        }

        // 3. Per-record: value regex filters.
        let mut results = resolution.results;
        if let Some(ref mr) = self.match_regex {
            results.retain(|r| mr.is_match(&r.value));
        }
        if let Some(ref er) = self.exclude_regex {
            results.retain(|r| !er.is_match(&r.value));
        }

        // Drop the host entirely if the regex filters removed every record.
        // (If the user didn't set any regex filter, this still correctly
        // returns the empty list as-is — the caller decides whether an
        // empty list is interesting.)
        if results.is_empty() && (self.match_regex.is_some() || self.exclude_regex.is_some()) {
            return None;
        }

        Some(results)
    }
}

/// Parse a comma-separated list of response-code names. Unknown names are
/// rejected loudly so a typo doesn't silently behave as "no filter".
fn parse_rcode_list(s: &str) -> Result<HashSet<ResponseCode>> {
    let mut out = HashSet::new();
    for part in s.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let code = ResponseCode::from_str_ci(trimmed)
            .ok_or_else(|| anyhow!("unknown response code '{trimmed}' (valid: noerror, nxdomain, servfail, refused, formerr, notimp)"))?;
        out.insert(code);
    }
    if out.is_empty() {
        return Err(anyhow!(
            "--response-code given but no valid codes parsed from '{s}'"
        ));
    }
    Ok(out)
}

/// Parse a comma-separated list of record-type names. Unknown names are
/// rejected loudly (same rationale as `parse_rcode_list`).
fn parse_type_list(s: &str) -> Result<Vec<RecordType>> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let t = RecordType::from_str_ci(trimmed)
            .ok_or_else(|| anyhow!("unknown record type '{trimmed}'"))?;
        out.push(t);
    }
    if out.is_empty() {
        return Err(anyhow!(
            "--response-type-filter given but no valid types parsed from '{s}'"
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn dns_result(host: &str, rtype: RecordType, value: &str) -> DnsResult {
        DnsResult {
            host: host.to_string(),
            record_type: rtype,
            value: value.to_string(),
        }
    }

    fn host_resolution(
        results: Vec<DnsResult>,
        codes: Vec<(RecordType, Option<ResponseCode>)>,
    ) -> HostResolution {
        let mut map: HashMap<RecordType, Option<ResponseCode>> = HashMap::new();
        for (t, c) in codes {
            map.insert(t, c);
        }
        HostResolution {
            results,
            codes: map,
        }
    }

    #[test]
    fn parses_rcode_list() {
        let v = parse_rcode_list("noerror,nxdomain,SERVFAIL").unwrap();
        assert_eq!(
            v,
            HashSet::from([
                ResponseCode::NoError,
                ResponseCode::NxDomain,
                ResponseCode::ServFail,
            ])
        );
    }

    #[test]
    fn rejects_unknown_rcode() {
        assert!(parse_rcode_list("noerror,bogus").is_err());
    }

    #[test]
    fn rcode_filter_passes_matching_host() {
        let filters = Filters {
            rcode: Some(HashSet::from([ResponseCode::NxDomain])),
            response_type_filter: None,
            match_regex: None,
            exclude_regex: None,
        };
        let res = host_resolution(
            vec![],
            vec![(RecordType::A, Some(ResponseCode::NxDomain))],
        );
        assert!(filters.apply(res).is_some());
    }

    #[test]
    fn rcode_filter_drops_non_matching_host() {
        let filters = Filters {
            rcode: Some(HashSet::from([ResponseCode::NxDomain])),
            response_type_filter: None,
            match_regex: None,
            exclude_regex: None,
        };
        let res = host_resolution(
            vec![dns_result("x", RecordType::A, "1.2.3.4")],
            vec![(RecordType::A, Some(ResponseCode::NoError))],
        );
        assert!(filters.apply(res).is_none());
    }

    #[test]
    fn rtf_drops_host_with_blocked_type() {
        let filters = Filters {
            rcode: None,
            response_type_filter: Some(vec![RecordType::Cname]),
            match_regex: None,
            exclude_regex: None,
        };
        let res = host_resolution(
            vec![
                dns_result("x", RecordType::A, "1.2.3.4"),
                dns_result("x", RecordType::Cname, "target.example.com."),
            ],
            vec![],
        );
        assert!(filters.apply(res).is_none());
    }

    #[test]
    fn rtf_keeps_host_without_blocked_type() {
        let filters = Filters {
            rcode: None,
            response_type_filter: Some(vec![RecordType::Cname]),
            match_regex: None,
            exclude_regex: None,
        };
        let res = host_resolution(
            vec![dns_result("x", RecordType::A, "1.2.3.4")],
            vec![],
        );
        let out = filters.apply(res).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn match_regex_keeps_matching_values() {
        let filters = Filters {
            rcode: None,
            response_type_filter: None,
            match_regex: Some(Regex::new(r"^142\.").unwrap()),
            exclude_regex: None,
        };
        let res = host_resolution(
            vec![
                dns_result("x", RecordType::A, "142.250.1.1"),
                dns_result("x", RecordType::A, "172.217.1.1"),
            ],
            vec![],
        );
        let out = filters.apply(res).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].value, "142.250.1.1");
    }

    #[test]
    fn exclude_regex_removes_matching_values() {
        let filters = Filters {
            rcode: None,
            response_type_filter: None,
            match_regex: None,
            exclude_regex: Some(Regex::new(r"^142\.").unwrap()),
        };
        let res = host_resolution(
            vec![
                dns_result("x", RecordType::A, "142.250.1.1"),
                dns_result("x", RecordType::A, "172.217.1.1"),
            ],
            vec![],
        );
        let out = filters.apply(res).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].value, "172.217.1.1");
    }

    #[test]
    fn regex_dropping_everything_drops_host() {
        let filters = Filters {
            rcode: None,
            response_type_filter: None,
            match_regex: Some(Regex::new(r"^nope$").unwrap()),
            exclude_regex: None,
        };
        let res = host_resolution(
            vec![dns_result("x", RecordType::A, "1.2.3.4")],
            vec![],
        );
        assert!(filters.apply(res).is_none());
    }

    #[test]
    fn empty_filters_pass_through() {
        let filters = Filters {
            rcode: None,
            response_type_filter: None,
            match_regex: None,
            exclude_regex: None,
        };
        assert!(filters.is_empty());
        let res = host_resolution(
            vec![dns_result("x", RecordType::A, "1.2.3.4")],
            vec![],
        );
        let out = filters.apply(res).unwrap();
        assert_eq!(out.len(), 1);
    }
}

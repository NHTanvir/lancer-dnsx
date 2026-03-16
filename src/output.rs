//! Output formatting and the worker -> output channel payload type.

use crate::record::DnsResult;

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

/// The payload sent from workers to the output loop.
pub(crate) struct WorkerOutput {
    pub(crate) host: String,
    pub(crate) results: Vec<DnsResult>,
}

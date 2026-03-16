//! DNS record types, query results, and JSON serialization.

use std::collections::HashMap;
use std::fmt;

use hickory_resolver::proto::op::ResponseCode as HickoryResponseCode;
use hickory_resolver::proto::rr::RecordType as HickoryRecordType;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Ptr,
    Srv,
    Soa,
    Caa,
    Any,
    Axfr,
}

impl RecordType {
    pub(crate) fn to_hickory(self) -> HickoryRecordType {
        match self {
            RecordType::A => HickoryRecordType::A,
            RecordType::Aaaa => HickoryRecordType::AAAA,
            RecordType::Cname => HickoryRecordType::CNAME,
            RecordType::Mx => HickoryRecordType::MX,
            RecordType::Txt => HickoryRecordType::TXT,
            RecordType::Ns => HickoryRecordType::NS,
            RecordType::Ptr => HickoryRecordType::PTR,
            RecordType::Srv => HickoryRecordType::SRV,
            RecordType::Soa => HickoryRecordType::SOA,
            RecordType::Caa => HickoryRecordType::CAA,
            RecordType::Any => HickoryRecordType::ANY,
            RecordType::Axfr => HickoryRecordType::AXFR,
        }
    }

    /// Parse a type name (case-insensitive) from a string.
    pub(crate) fn from_str_ci(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "a" => Some(RecordType::A),
            "aaaa" => Some(RecordType::Aaaa),
            "cname" => Some(RecordType::Cname),
            "mx" => Some(RecordType::Mx),
            "txt" => Some(RecordType::Txt),
            "ns" => Some(RecordType::Ns),
            "ptr" => Some(RecordType::Ptr),
            "srv" => Some(RecordType::Srv),
            "soa" => Some(RecordType::Soa),
            "caa" => Some(RecordType::Caa),
            "any" => Some(RecordType::Any),
            "axfr" => Some(RecordType::Axfr),
            _ => None,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::Aaaa => write!(f, "AAAA"),
            RecordType::Cname => write!(f, "CNAME"),
            RecordType::Mx => write!(f, "MX"),
            RecordType::Txt => write!(f, "TXT"),
            RecordType::Ns => write!(f, "NS"),
            RecordType::Ptr => write!(f, "PTR"),
            RecordType::Srv => write!(f, "SRV"),
            RecordType::Soa => write!(f, "SOA"),
            RecordType::Caa => write!(f, "CAA"),
            RecordType::Any => write!(f, "ANY"),
            RecordType::Axfr => write!(f, "AXFR"),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DnsResult {
    pub(crate) host: String,
    pub(crate) record_type: RecordType,
    pub(crate) value: String,
}

/// Local mirror of the DNS response codes we filter on. Mapped from
/// hickory's `ResponseCode` via `from_hickory`. Codes we don't recognize
/// (e.g. NotZone, BADVERS, …) are folded into `Other` so filtering still
/// works coherently — a user can only request the codes listed here, and
/// any unknown code never matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ResponseCode {
    NoError,
    NxDomain,
    ServFail,
    Refused,
    FormErr,
    NotImp,
    Other,
}

impl ResponseCode {
    /// Parse a code name (case-insensitive). Returns None for unknown names.
    pub(crate) fn from_str_ci(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "noerror" | "no-error" => Some(ResponseCode::NoError),
            "nxdomain" | "nx-domain" => Some(ResponseCode::NxDomain),
            "servfail" | "serv-fail" => Some(ResponseCode::ServFail),
            "refused" => Some(ResponseCode::Refused),
            "formerr" | "form-err" => Some(ResponseCode::FormErr),
            "notimp" | "not-imp" | "notimpl" => Some(ResponseCode::NotImp),
            _ => None,
        }
    }

    /// Map a hickory `ResponseCode` into our local enum.
    pub(crate) fn from_hickory(rc: HickoryResponseCode) -> Self {
        match rc {
            HickoryResponseCode::NoError => ResponseCode::NoError,
            HickoryResponseCode::NXDomain => ResponseCode::NxDomain,
            HickoryResponseCode::ServFail => ResponseCode::ServFail,
            HickoryResponseCode::Refused => ResponseCode::Refused,
            HickoryResponseCode::FormErr => ResponseCode::FormErr,
            HickoryResponseCode::NotImp => ResponseCode::NotImp,
            _ => ResponseCode::Other,
        }
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseCode::NoError => write!(f, "NOERROR"),
            ResponseCode::NxDomain => write!(f, "NXDOMAIN"),
            ResponseCode::ServFail => write!(f, "SERVFAIL"),
            ResponseCode::Refused => write!(f, "REFUSED"),
            ResponseCode::FormErr => write!(f, "FORMERR"),
            ResponseCode::NotImp => write!(f, "NOTIMP"),
            ResponseCode::Other => write!(f, "OTHER"),
        }
    }
}

/// Aggregate result of resolving all requested record types for a single
/// host. `codes` maps each queried record type to the DNS response code
/// observed (or `None` if the query failed with a transport error rather
/// than a structured DNS response).
#[derive(Debug, Clone, Default)]
pub(crate) struct HostResolution {
    pub(crate) results: Vec<DnsResult>,
    pub(crate) codes: HashMap<RecordType, Option<ResponseCode>>,
}

#[derive(Serialize, Default)]
pub(crate) struct HostRecord {
    pub(crate) host: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) a: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) aaaa: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) cname: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) mx: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) ns: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) txt: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) ptr: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) srv: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) soa: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) caa: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) any: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) response_code: Option<String>,
    pub(crate) timestamp: String,
}

impl HostRecord {
    pub(crate) fn from_results(host: &str, results: &[DnsResult]) -> Self {
        let mut rec = HostRecord {
            host: host.to_string(),
            timestamp: chrono_now(),
            ..Default::default()
        };
        for r in results {
            match r.record_type {
                RecordType::A => rec.a.push(r.value.clone()),
                RecordType::Aaaa => rec.aaaa.push(r.value.clone()),
                RecordType::Cname => rec.cname.push(r.value.clone()),
                RecordType::Mx => rec.mx.push(r.value.clone()),
                RecordType::Ns => rec.ns.push(r.value.clone()),
                RecordType::Txt => rec.txt.push(r.value.clone()),
                RecordType::Ptr => rec.ptr.push(r.value.clone()),
                RecordType::Srv => rec.srv.push(r.value.clone()),
                RecordType::Soa => rec.soa.push(r.value.clone()),
                RecordType::Caa => rec.caa.push(r.value.clone()),
                RecordType::Any => rec.any.push(r.value.clone()),
                RecordType::Axfr => {} // AXFR results not included in JSON record
            }
        }
        rec
    }

    /// Create a minimal record for a host that matched an rcode filter but
    /// returned no DNS records (e.g. NXDOMAIN under `-rcode nxdomain`).
    pub(crate) fn empty_with_rcode(host: &str, code: ResponseCode) -> Self {
        HostRecord {
            host: host.to_string(),
            response_code: Some(code.to_string().to_lowercase()),
            timestamp: chrono_now(),
            ..Default::default()
        }
    }
}

/// Return a UTC timestamp string in RFC 3339 format without depending on chrono.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let s = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86400; // days since 1970-01-01

    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

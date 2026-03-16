//! Integration tests exercising the public library API surface.
//!
//! These tests don't hit the network -- they only verify that the documented
//! `pub use` re-exports in `lib.rs` are reachable and have the expected
//! shape. Catches accidental breakage of the public API.

use lancer_dnsx::{
    default_name_servers, parse_resolver_string, DnsResult, HostRecord, HostResolution,
    RecordType, ResolverPool, ResponseCode, WildcardCache,
};

#[test]
fn default_name_servers_returns_some_servers() {
    let servers = default_name_servers();
    assert!(
        !servers.is_empty(),
        "default_name_servers must produce at least one config"
    );
}

#[test]
fn parse_resolver_string_handles_plain_ip() {
    let ns = parse_resolver_string("1.1.1.1").expect("parse 1.1.1.1");
    assert_eq!(ns.socket_addr.port(), 53);
}

#[test]
fn parse_resolver_string_handles_doh() {
    let ns = parse_resolver_string("doh:https://cloudflare-dns.com/dns-query")
        .expect("parse DoH");
    assert_eq!(ns.socket_addr.port(), 443);
    assert!(ns.tls_dns_name.is_some());
}

#[test]
fn resolver_pool_build_yields_non_empty_pool() {
    let servers = default_name_servers();
    let pool = ResolverPool::build(&servers, 3, 2, true).expect("build pool");
    assert!(!pool.is_empty());
    assert_eq!(pool.len(), servers.len());
}

#[test]
fn resolver_pool_build_rejects_empty_input() {
    let result = ResolverPool::build(&[], 3, 2, true);
    assert!(result.is_err(), "empty input should error");
}

#[test]
fn record_type_round_trip_via_str() {
    assert_eq!(RecordType::from_str_ci("a"), Some(RecordType::A));
    assert_eq!(RecordType::from_str_ci("AAAA"), Some(RecordType::Aaaa));
    assert_eq!(RecordType::from_str_ci("nope"), None);
}

#[test]
fn response_code_parses_known_codes() {
    assert_eq!(
        ResponseCode::from_str_ci("nxdomain"),
        Some(ResponseCode::NxDomain)
    );
    assert_eq!(
        ResponseCode::from_str_ci("NOERROR"),
        Some(ResponseCode::NoError)
    );
}

#[test]
fn host_record_from_results_buckets_by_type() {
    let results = vec![
        DnsResult {
            host: "example.com".to_string(),
            record_type: RecordType::A,
            value: "93.184.216.34".to_string(),
        },
        DnsResult {
            host: "example.com".to_string(),
            record_type: RecordType::Aaaa,
            value: "2606:2800:220:1:248:1893:25c8:1946".to_string(),
        },
    ];
    let rec = HostRecord::from_results("example.com", &results);
    assert_eq!(rec.host, "example.com");
    assert_eq!(rec.a.len(), 1);
    assert_eq!(rec.aaaa.len(), 1);
    assert!(rec.cname.is_empty());
}

#[test]
fn host_resolution_default_is_empty() {
    let r = HostResolution::default();
    assert!(r.results.is_empty());
    assert!(r.codes.is_empty());
}

#[test]
fn wildcard_cache_constructs() {
    // Just verify the constructor is reachable from the public surface.
    // The cache won't actually probe unless given a pool + level.
    let _cache = WildcardCache::new(5, true);
}

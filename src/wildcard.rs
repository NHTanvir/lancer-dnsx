//! Wildcard DNS detection.
//!
//! Wildcard DNS is the #1 cause of false positives during subdomain
//! enumeration: many zones publish `*.target.com` records that return the
//! same IP for ANY non-existent subdomain. Without filtering, brute-force
//! discovery floods results with hundreds of duplicate "live" hosts.
//!
//! This module provides two filtering modes:
//!
//! 1. **Manual mode** (`--wildcard-domain target.com`) -- probe a single
//!    configured domain up front. Any A/AAAA result whose host ends in
//!    `.target.com` and whose IPs are a subset of the probed wildcard set is
//!    dropped.
//!
//! 2. **Auto mode** (`--auto-wildcard`) -- for each incoming host, walk up
//!    from the immediate parent to the apex, probing each level on first
//!    encounter. Results are dropped if their IPs match the wildcard set at
//!    any level.
//!
//! Both modes cache positive and negative probe results so each level is
//! probed only once across the entire run.
//!
//! Probing emits `<random>.<level>` queries via the shared `ResolverPool`
//! (round-robin), so wildcard detection respects the same health tracking
//! as primary resolution.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use rand::distributions::Alphanumeric;
use rand::Rng;
use tokio::sync::RwLock;

use crate::resolver::{is_transport_error, ResolverPool};

/// Length of the random label prepended to a wildcard probe.
const RANDOM_LABEL_LEN: usize = 12;

/// Cache of wildcard IPs keyed by zone level.
pub struct WildcardCache {
    /// Map from level (e.g. `target.com`) to its observed wildcard IP set.
    /// An empty `ips` set is the cached negative result.
    levels: RwLock<HashMap<String, LevelInfo>>,
    /// Number of random probes per level.
    probes: usize,
    /// Suppress informational log lines when true.
    silent: bool,
}

struct LevelInfo {
    ips: HashSet<IpAddr>,
}

/// Outcome of probing a single level.
struct ProbeOutcome {
    /// Union of A and AAAA IPs observed across all probes.
    ips: HashSet<IpAddr>,
    /// True if at least one probe completed successfully or returned NXDOMAIN.
    /// False only if every probe failed with a transport error -- in which
    /// case the caller should NOT cache the empty result.
    any_probe_succeeded: bool,
}

impl WildcardCache {
    /// Build a wildcard cache.
    ///
    /// `probes` is the number of random `<random>.<level>` queries issued per
    /// level. It is clamped to a minimum of 1 so callers cannot accidentally
    /// disable probing entirely.
    ///
    /// `silent` suppresses both `[INFO]` (wildcard detected) and `[WARN]`
    /// (all probes failed) log lines emitted by the cache.
    pub fn new(probes: usize, silent: bool) -> Self {
        // Clamp to a sensible minimum so users can't accidentally disable probing.
        let probes = probes.max(1);
        Self {
            levels: RwLock::new(HashMap::new()),
            probes,
            silent,
        }
    }

    /// Probe a level by querying `<random>.<level>` `self.probes` times.
    ///
    /// Returns a `ProbeOutcome` that distinguishes "no wildcard" (all probes
    /// completed but no IPs returned) from "all probes failed" (network down /
    /// every resolver timed out) so the caller can decide whether to cache.
    async fn probe_level(&self, pool: &ResolverPool, level: &str) -> ProbeOutcome {
        let mut all_ips: HashSet<IpAddr> = HashSet::new();
        let mut any_probe_succeeded = false;

        for _ in 0..self.probes {
            let candidate = format!("{}.{}", generate_random_label(), level);

            // Probe A
            if let Some((idx, tracked)) = pool.pick() {
                let outcome = tracked.resolver().ipv4_lookup(&candidate).await;
                let ok = is_health_ok(&outcome);
                pool.record(idx, ok);
                if ok {
                    any_probe_succeeded = true;
                }
                if let Ok(response) = outcome {
                    for record in response.iter() {
                        all_ips.insert(IpAddr::V4(record.0));
                    }
                }
            }

            // Probe AAAA
            if let Some((idx, tracked)) = pool.pick() {
                let outcome = tracked.resolver().ipv6_lookup(&candidate).await;
                let ok = is_health_ok(&outcome);
                pool.record(idx, ok);
                if ok {
                    any_probe_succeeded = true;
                }
                if let Ok(response) = outcome {
                    for record in response.iter() {
                        all_ips.insert(IpAddr::V6(record.0));
                    }
                }
            }
        }

        ProbeOutcome {
            ips: all_ips,
            any_probe_succeeded,
        }
    }

    /// Return the wildcard IP set for `level`, probing on first miss.
    ///
    /// If every probe failed with a transport error, the level is left
    /// uncached so a later worker may retry. An empty set is returned in that
    /// case so the current call doesn't block, but no negative-result entry
    /// is written.
    pub async fn get_or_probe(
        &self,
        pool: &ResolverPool,
        level: &str,
    ) -> HashSet<IpAddr> {
        // Fast path: cache hit
        {
            let r = self.levels.read().await;
            if let Some(info) = r.get(level) {
                return info.ips.clone();
            }
        }

        // Cache miss -- probe
        let outcome = self.probe_level(pool, level).await;

        // If every probe transport-failed, don't pollute the cache with a
        // false-negative entry. Warn (unless silent) and bail out -- a future
        // worker can retry the level.
        if !outcome.any_probe_succeeded {
            if !self.silent {
                eprintln!(
                    "[WARN] All wildcard probes failed for *.{level}; leaving level \
                     uncached for retry"
                );
            }
            return outcome.ips;
        }

        // Insert into cache. If a concurrent worker raced us here, prefer the
        // already-cached entry (its result is just as valid) to avoid logging
        // twice.
        let mut w = self.levels.write().await;
        if let Some(existing) = w.get(level) {
            return existing.ips.clone();
        }
        if !self.silent && !outcome.ips.is_empty() {
            eprintln!(
                "[INFO] Detected wildcard at *.{}: {} IP(s)",
                level,
                outcome.ips.len()
            );
        }
        let ips = outcome.ips.clone();
        w.insert(level.to_string(), LevelInfo { ips: outcome.ips });
        ips
    }

    /// True if `host_ips` are a (non-empty) subset of the wildcard IPs for any
    /// candidate level.
    ///
    /// `manual_target` and `walk_up` are independent and additive: if both are
    /// supplied, the level list is the union of the manual target (when it
    /// matches the host) and the walk-up parents. Either flag alone behaves
    /// as before.
    ///
    /// * `manual_target` -- if set and `host` equals or is a subdomain of it,
    ///   the target is checked.
    /// * `walk_up` -- if true, walk up from the immediate parent of `host`
    ///   to its apex, checking each level.
    pub async fn is_wildcard_match(
        &self,
        pool: &ResolverPool,
        host: &str,
        host_ips: &[IpAddr],
        walk_up: bool,
        manual_target: Option<&str>,
    ) -> bool {
        if host_ips.is_empty() {
            return false;
        }

        let levels: Vec<String> = {
            let mut v = Vec::new();
            if let Some(target) = manual_target {
                let suffix = format!(".{target}");
                if host == target || host.ends_with(&suffix) {
                    v.push(target.to_string());
                }
            }
            if walk_up {
                for lvl in levels_walking_up(host) {
                    if !v.contains(&lvl) {
                        v.push(lvl);
                    }
                }
            }
            v
        };

        for level in &levels {
            let wildcard_ips = self.get_or_probe(pool, level).await;
            if wildcard_ips.is_empty() {
                continue;
            }
            if host_ips.iter().all(|ip| wildcard_ips.contains(ip)) {
                return true;
            }
        }
        false
    }
}

/// True if a lookup result counts as "the resolver is healthy" -- either an
/// `Ok` response or NXDOMAIN. Transport errors (timeouts, IO, no
/// connections) count as failures.
fn is_health_ok<T>(
    outcome: &Result<T, hickory_resolver::error::ResolveError>,
) -> bool {
    match outcome {
        Ok(_) => true,
        Err(e) => !is_transport_error(e),
    }
}

/// Generate a random lowercase alphanumeric label of `RANDOM_LABEL_LEN` chars.
fn generate_random_label() -> String {
    let mut rng = rand::thread_rng();
    let mut s = String::with_capacity(RANDOM_LABEL_LEN);
    for _ in 0..RANDOM_LABEL_LEN {
        let b: u8 = rng.sample(Alphanumeric);
        // Alphanumeric yields 0-9, A-Z, a-z. Lowercase the uppercase letters.
        let c = (b as char).to_ascii_lowercase();
        s.push(c);
    }
    s
}

/// True if the input parses as a bare IPv4 address (and therefore should not
/// be walked up for wildcard levels).
fn looks_like_ipv4(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Return the candidate parent levels of `host`, from immediate parent up to
/// the apex (skipping the TLD).
///
/// `sub.foo.target.com` -> [`foo.target.com`, `target.com`]
/// `target.com`         -> []
/// `co.uk`              -> []
/// `1.2.3.4`            -> []
///
/// Note: this is a heuristic that treats the final label as a TLD. It will
/// over-trim for ccTLD-plus-SLD zones (e.g. `*.example.co.uk` won't have
/// `co.uk` probed, which is the correct behavior anyway). It will not probe
/// the host itself, which is also intentional -- the host's resolution is
/// what we're trying to validate. IPv4 inputs short-circuit to an empty
/// result so we don't issue probes against e.g. `3.4.1.2.in-addr.arpa`.
fn levels_walking_up(host: &str) -> Vec<String> {
    // IPv4 addresses look like 4 numeric labels separated by dots -- the
    // walk-up logic would otherwise treat them as a domain. Skip those.
    if looks_like_ipv4(host) {
        return Vec::new();
    }
    let parts: Vec<&str> = host.split('.').filter(|p| !p.is_empty()).collect();
    let mut levels = Vec::new();
    if parts.len() < 3 {
        return levels;
    }
    // Start from index 1 (the immediate parent) and stop before the TLD
    // (index parts.len() - 1). That means the highest level considered is
    // parts[parts.len() - 2..] which is `apex.tld`.
    for i in 1..(parts.len() - 1) {
        levels.push(parts[i..].join("."));
    }
    levels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_label_is_lowercase_alphanumeric() {
        for _ in 0..32 {
            let s = generate_random_label();
            assert_eq!(s.len(), RANDOM_LABEL_LEN);
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        }
    }

    #[test]
    fn levels_for_deep_subdomain() {
        let v = levels_walking_up("sub.foo.target.com");
        assert_eq!(v, vec!["foo.target.com", "target.com"]);
    }

    #[test]
    fn levels_for_apex_only() {
        // apex itself should not be probed
        assert!(levels_walking_up("target.com").is_empty());
    }

    #[test]
    fn levels_for_single_label() {
        assert!(levels_walking_up("localhost").is_empty());
    }

    #[test]
    fn levels_for_simple_subdomain() {
        let v = levels_walking_up("www.example.com");
        assert_eq!(v, vec!["example.com"]);
    }

    #[test]
    fn levels_strip_empty_labels() {
        // Trailing dot or doubled dots shouldn't produce empty levels
        let v = levels_walking_up("www.example.com.");
        assert_eq!(v, vec!["example.com"]);
    }

    #[test]
    fn levels_skip_ipv4_address() {
        // Bare IPv4 inputs must not be walked as if they were domains.
        assert!(levels_walking_up("1.2.3.4").is_empty());
        assert!(levels_walking_up("192.168.1.1").is_empty());
    }
}

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

use crate::resolver::ResolverPool;

/// Length of the random label prepended to a wildcard probe.
const RANDOM_LABEL_LEN: usize = 12;

/// Cache of wildcard IPs keyed by zone level.
pub(crate) struct WildcardCache {
    /// Map from level (e.g. `target.com`) to its observed wildcard IP set.
    /// An empty `ips` set with `confirmed_no_wildcard == true` is the cached
    /// negative result.
    levels: RwLock<HashMap<String, LevelInfo>>,
    /// Number of random probes per level.
    probes: usize,
    /// Suppress informational log lines when true.
    silent: bool,
}

struct LevelInfo {
    ips: HashSet<IpAddr>,
    #[allow(dead_code)]
    confirmed_no_wildcard: bool,
}

impl WildcardCache {
    pub(crate) fn new(probes: usize, silent: bool) -> Self {
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
    /// Returns the union of A and AAAA IPs observed across all probes.
    async fn probe_level(&self, pool: &ResolverPool, level: &str) -> HashSet<IpAddr> {
        let mut all_ips: HashSet<IpAddr> = HashSet::new();
        for _ in 0..self.probes {
            let candidate = format!("{}.{}", generate_random_label(), level);

            // Probe A
            if let Some((_idx, tracked)) = pool.pick() {
                if let Ok(response) = tracked.resolver().ipv4_lookup(&candidate).await {
                    for record in response.iter() {
                        all_ips.insert(IpAddr::V4(record.0));
                    }
                }
            }

            // Probe AAAA
            if let Some((_idx, tracked)) = pool.pick() {
                if let Ok(response) = tracked.resolver().ipv6_lookup(&candidate).await {
                    for record in response.iter() {
                        all_ips.insert(IpAddr::V6(record.0));
                    }
                }
            }
        }
        all_ips
    }

    /// Return the wildcard IP set for `level`, probing on first miss.
    pub(crate) async fn get_or_probe(
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
        let ips = self.probe_level(pool, level).await;

        // Insert into cache. If a concurrent worker raced us here, prefer the
        // already-cached entry (its result is just as valid) to avoid logging
        // twice.
        let mut w = self.levels.write().await;
        if let Some(existing) = w.get(level) {
            return existing.ips.clone();
        }
        let confirmed_no_wildcard = ips.is_empty();
        if !self.silent && !ips.is_empty() {
            eprintln!(
                "[INFO] Detected wildcard at *.{}: {} IP(s)",
                level,
                ips.len()
            );
        }
        w.insert(
            level.to_string(),
            LevelInfo {
                ips: ips.clone(),
                confirmed_no_wildcard,
            },
        );
        ips
    }

    /// True if `host_ips` are a (non-empty) subset of the wildcard IPs for any
    /// candidate level.
    ///
    /// * `manual_target` -- if set, only the configured target is checked
    ///   (host must equal it or be a subdomain).
    /// * `walk_up` -- if true and `manual_target` is None, walk up from the
    ///   immediate parent of `host` to its apex, checking each level.
    pub(crate) async fn is_wildcard_match(
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

        let levels: Vec<String> = if let Some(target) = manual_target {
            let suffix = format!(".{target}");
            if host == target || host.ends_with(&suffix) {
                vec![target.to_string()]
            } else {
                Vec::new()
            }
        } else if walk_up {
            levels_walking_up(host)
        } else {
            Vec::new()
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

/// Return the candidate parent levels of `host`, from immediate parent up to
/// the apex (skipping the TLD).
///
/// `sub.foo.target.com` -> [`foo.target.com`, `target.com`]
/// `target.com`         -> []
/// `co.uk`              -> []
///
/// Note: this is a heuristic that treats the final label as a TLD. It will
/// over-trim for ccTLD-plus-SLD zones (e.g. `*.example.co.uk` won't have
/// `co.uk` probed, which is the correct behavior anyway). It will not probe
/// the host itself, which is also intentional -- the host's resolution is
/// what we're trying to validate.
fn levels_walking_up(host: &str) -> Vec<String> {
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
}

//! Inline CDN matcher.
//!
//! Matches resolved A/AAAA IPs against a static set of well-known CDN/cloud
//! IPv4 CIDR ranges. This is a Phase 7 in-tree stand-in for the future
//! "LancerCDN" sibling crate: zero-network, fully offline, and good enough to
//! flag the major edge providers (Cloudflare, CloudFront, Fastly, Akamai,
//! Google Cloud, Netlify, Vercel).

use std::net::IpAddr;

use ipnet::IpNet;

#[derive(Debug, Clone, Copy)]
pub(crate) struct CdnInfo {
    pub name: &'static str,     // "cloudflare", "cloudfront", etc.
    pub cdn_type: &'static str, // "cdn", "waf", "cloud-host"
}

pub(crate) struct CdnMatcher {
    ranges: Vec<(IpNet, CdnInfo)>,
}

impl CdnMatcher {
    pub fn new() -> Self {
        // (CIDR, name, type)
        let ranges: &[(&str, &str, &str)] = &[
            // Cloudflare IPv4
            ("173.245.48.0/20", "cloudflare", "cdn"),
            ("103.21.244.0/22", "cloudflare", "cdn"),
            ("103.22.200.0/22", "cloudflare", "cdn"),
            ("103.31.4.0/22", "cloudflare", "cdn"),
            ("141.101.64.0/18", "cloudflare", "cdn"),
            ("108.162.192.0/18", "cloudflare", "cdn"),
            ("190.93.240.0/20", "cloudflare", "cdn"),
            ("188.114.96.0/20", "cloudflare", "cdn"),
            ("197.234.240.0/22", "cloudflare", "cdn"),
            ("198.41.128.0/17", "cloudflare", "cdn"),
            ("162.158.0.0/15", "cloudflare", "cdn"),
            ("104.16.0.0/13", "cloudflare", "cdn"),
            ("104.24.0.0/14", "cloudflare", "cdn"),
            ("172.64.0.0/13", "cloudflare", "cdn"),
            ("131.0.72.0/22", "cloudflare", "cdn"),
            // AWS CloudFront IPv4 (subset)
            ("52.84.0.0/15", "cloudfront", "cdn"),
            ("54.182.0.0/16", "cloudfront", "cdn"),
            ("54.192.0.0/16", "cloudfront", "cdn"),
            ("54.230.0.0/15", "cloudfront", "cdn"),
            ("13.32.0.0/15", "cloudfront", "cdn"),
            ("13.224.0.0/14", "cloudfront", "cdn"),
            ("204.246.164.0/22", "cloudfront", "cdn"),
            ("204.246.168.0/22", "cloudfront", "cdn"),
            ("204.246.174.0/23", "cloudfront", "cdn"),
            ("64.252.64.0/18", "cloudfront", "cdn"),
            ("99.86.0.0/16", "cloudfront", "cdn"),
            ("130.176.0.0/16", "cloudfront", "cdn"),
            ("3.5.140.0/22", "cloudfront", "cdn"),
            ("18.244.0.0/15", "cloudfront", "cdn"),
            // Fastly
            ("23.235.32.0/20", "fastly", "cdn"),
            ("43.249.72.0/22", "fastly", "cdn"),
            ("103.244.50.0/24", "fastly", "cdn"),
            ("103.245.222.0/23", "fastly", "cdn"),
            ("103.245.224.0/24", "fastly", "cdn"),
            ("104.156.80.0/20", "fastly", "cdn"),
            ("140.248.64.0/18", "fastly", "cdn"),
            ("140.248.128.0/17", "fastly", "cdn"),
            ("146.75.0.0/17", "fastly", "cdn"),
            ("151.101.0.0/16", "fastly", "cdn"),
            ("157.52.64.0/18", "fastly", "cdn"),
            ("167.82.0.0/17", "fastly", "cdn"),
            ("167.82.128.0/20", "fastly", "cdn"),
            ("167.82.160.0/20", "fastly", "cdn"),
            ("167.82.224.0/20", "fastly", "cdn"),
            ("172.111.64.0/18", "fastly", "cdn"),
            ("185.31.16.0/22", "fastly", "cdn"),
            ("199.27.72.0/21", "fastly", "cdn"),
            ("199.232.0.0/16", "fastly", "cdn"),
            // Akamai (subset of edge IPs — full list is huge)
            ("23.32.0.0/11", "akamai", "cdn"),
            ("23.64.0.0/14", "akamai", "cdn"),
            ("23.72.0.0/13", "akamai", "cdn"),
            ("96.6.0.0/15", "akamai", "cdn"),
            ("96.16.0.0/15", "akamai", "cdn"),
            ("104.64.0.0/10", "akamai", "cdn"),
            ("184.24.0.0/13", "akamai", "cdn"),
            ("184.50.0.0/15", "akamai", "cdn"),
            ("184.84.0.0/14", "akamai", "cdn"),
            // Google Cloud
            ("34.96.0.0/12", "google-cloud", "cloud-host"),
            ("35.190.0.0/15", "google-cloud", "cloud-host"),
            ("35.192.0.0/13", "google-cloud", "cloud-host"),
            // Netlify
            ("104.198.14.52/32", "netlify", "cdn"),
            ("75.2.60.5/32", "netlify", "cdn"),
            ("99.83.190.102/32", "netlify", "cdn"),
            // Vercel
            ("76.76.21.0/24", "vercel", "cdn"),
            ("76.223.126.0/24", "vercel", "cdn"),
            ("64.252.83.0/24", "vercel", "cdn"),
        ];

        let parsed: Vec<(IpNet, CdnInfo)> = ranges
            .iter()
            .map(|(cidr, name, cdn_type)| {
                (
                    cidr.parse().expect("static CIDR must parse"),
                    CdnInfo {
                        name,
                        cdn_type,
                    },
                )
            })
            .collect();

        Self { ranges: parsed }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<CdnInfo> {
        self.ranges
            .iter()
            .find(|(net, _)| net.contains(&ip))
            .map(|(_, info)| *info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_cloudflare() {
        let m = CdnMatcher::new();
        let ip: IpAddr = "104.16.132.229".parse().unwrap();
        let info = m.lookup(ip).expect("cloudflare range");
        assert_eq!(info.name, "cloudflare");
        assert_eq!(info.cdn_type, "cdn");
    }

    #[test]
    fn no_match_for_unknown() {
        let m = CdnMatcher::new();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(m.lookup(ip).is_none());
    }
}

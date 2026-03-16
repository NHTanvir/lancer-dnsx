//! ASN lookup via the BGPView REST API, with in-memory caching.
//!
//! Per Phase 7: best-effort enrichment of resolved IPs with ASN, AS name,
//! country, and prefix. Network failures degrade silently (lookup returns
//! `None`) so the rest of the pipeline keeps running.
//!
//! Caching: each unique IP is fetched at most once per process. The full
//! result (including the `None` case) is memoised so failed lookups aren't
//! retried — this is intentional to stay under BGPView's free-tier rate
//! limits when scanning lists with many hosts but few unique IPs.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AsnInfo {
    pub asn: u32,
    pub name: String,
    pub country: String,
    pub prefix: String,
}

pub struct AsnLookup {
    cache: RwLock<HashMap<IpAddr, Option<AsnInfo>>>,
    client: Client,
    #[allow(dead_code)]
    silent: bool,
}

impl AsnLookup {
    pub fn new(silent: bool) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent(concat!("lancer-dnsx/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            cache: RwLock::new(HashMap::new()),
            client,
            silent,
        }
    }

    pub async fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        {
            let r = self.cache.read().await;
            if let Some(cached) = r.get(&ip) {
                return cached.clone();
            }
        }

        let result = self.fetch_asn(ip).await;
        let mut w = self.cache.write().await;
        w.insert(ip, result.clone());
        result
    }

    async fn fetch_asn(&self, ip: IpAddr) -> Option<AsnInfo> {
        // BGPView API: https://api.bgpview.io/ip/{ip}
        let url = format!("https://api.bgpview.io/ip/{ip}");
        let resp = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                if !self.silent {
                    eprintln!("[WARN] asn lookup {ip} failed: {e}");
                }
                return None;
            }
        };
        let body = match resp.json::<BgpViewResponse>().await {
            Ok(b) => b,
            Err(e) => {
                if !self.silent {
                    eprintln!("[WARN] asn lookup {ip} parse failed: {e}");
                }
                return None;
            }
        };
        if body.status != "ok" {
            return None;
        }
        let prefix = body.data.prefixes.into_iter().next()?;
        Some(AsnInfo {
            asn: prefix.asn.asn,
            name: prefix.asn.name.unwrap_or_default(),
            country: prefix.asn.country_code.unwrap_or_default(),
            prefix: prefix.prefix,
        })
    }
}

#[derive(Deserialize)]
struct BgpViewResponse {
    status: String,
    data: BgpViewData,
}

#[derive(Deserialize)]
struct BgpViewData {
    prefixes: Vec<BgpPrefix>,
}

#[derive(Deserialize)]
struct BgpPrefix {
    prefix: String,
    asn: BgpAsn,
}

#[derive(Deserialize)]
struct BgpAsn {
    asn: u32,
    name: Option<String>,
    country_code: Option<String>,
}

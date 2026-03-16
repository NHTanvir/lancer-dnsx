# RESEARCH DOSSIER: dnsx

> Part of the Lancer ecosystem. A Rust clone of ProjectDiscovery's dnsx, the fast bulk DNS toolkit. Build with Claude Code.
> Upstream: github.com/projectdiscovery/dnsx (Go, v1.2.3 Dec 2025, ~2.4k stars). Default branch: `dev`.

## Feature Parity Mandate

**`lancer-dnsx` MUST ship with 100% feature parity to the upstream `dnsx` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `dnsx --help` (and the long-form man page / docs) must work in `lancer-dnsx --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-dnsx` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-dnsx --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does (1-paragraph)
dnsx is a tokio-equivalent worker-pool DNS resolver designed for *bulk* operation (millions of hosts/min). It reads hostnames from stdin/file, sends them to N workers (default 100), each worker queries a configurable resolver pool (default Cloudflare/Google/Quad9/OpenDNS over UDP, with TCP fallback) for one or more record types (A/AAAA/CNAME/MX/TXT/NS/PTR/SRV/SOA/CAA/AXFR/ANY), and emits results either as plain `host TYPE value` lines or as JSONL. Critically it implements **wildcard DNS detection** (manual `-wd target.com` or `-auto-wildcard` since Mar 2026) — the #1 source of subfinder false-positives. Other key modes: subdomain brute-force (`-d target.com -w wordlist.txt`), DNS trace (`-trace`), zone-transfer attempt (`-axfr`), `cdncheck` integration (`-cdn`), ASN lookup (`-asn`), response filtering by rcode (`-rcode noerror,nxdomain`). It sits between subfinder and httpx in the recon pipe.

## Internal architecture (file-level, dev branch as of May 2026)

- **`cmd/dnsx/dnsx.go`** — entrypoint.
- **`internal/runner/`** — orchestration.
  - `options.go` — `goflags` parser; `Options` struct with ~50 fields. Question-type enum (a/aaaa/cname/ns/txt/srv/ptr/mx/soa/axfr/caa/any). Default resolver auth via PDCP. Default timeout 3s, threads 100, retries 2.
  - `runner.go` — `Runner` holds `*dnsx.DNSX`, multiple wait-groups (output worker, resolve workers, wildcard worker), three channels (`workerchan`, `outputchan`, `wildcardworkerchan`), wildcard A/AAAA resolvers, `*hybrid.HybridMap` (in-memory + on-disk dedupe), `*ratelimit.Limiter`, `*clistats.StatisticsClient`. Workers consume `workerchan`, run `dnsx.QueryMultiple`, push results to `outputchan` or `wildcardworkerchan` based on flags. Wildcard handling has its own worker pool.
  - `wildcard.go` — auto-wildcard logic. Uses `projectdiscovery/utils/dns/wildcard.Resolver` for the recursive "for each host, query random siblings, drop if matches" loop. Stores wildcard IPs in `*mapsutil.SyncLockMap`. Two adapters (one for A, one for AAAA) so the same logic works on v4 and v6.
  - `wildcard_test.go` — extensive test corpus (`*.github.io`, etc.).
  - `healthcheck.go` — `-hc` diagnostic.
  - `resume.go` — `resume.cfg` JSON.
  - `util.go`, `doc.go`, `banner.go`.
- **`libs/dnsx/`** — the public library API (used by httpx, subfinder, naabu, etc.).
  - `dnsx.go` (~250 LOC) — `DNSX` wraps `*retryabledns.Client`. Methods: `Lookup`, `QueryOne`, `QueryMultiple`, `Trace`, `AXFR`. `DefaultOptions { MaxRetries: 5, QuestionTypes: [TypeA], TraceMaxRecursion: 255, Hostsfile: true, Timeout: 3s }`. `DefaultResolvers` is the 8-resolver Cloudflare/Google/Quad9/OpenDNS list (all `udp:`).
  - `cdn.go` — integrates `cdncheck` (`OutputCDN` flag) — annotates each result with cdn-name + cdn-type.
  - `util.go` — `prepareResolver()` normalizes resolver strings (`8.8.8.8` → `udp:8.8.8.8:53`, `tcp:1.1.1.1` → `tcp:1.1.1.1:53`, `https://cloudflare-dns.com/dns-query` → `doh:...`).
- **`internal/runner/runner.go` worker loop.** Each worker: read a hostname from `workerchan` → call `dnsx.QueryMultiple(host)` (which loops over question types) → apply `responseTypeFilterMap` (drop if entry has any of the filtered types) → check wildcard if applicable → write to `outputchan`. Output worker formats per `JSON|RAW|TXT` and writes to `os.Stdout` or `OutputFile`.
- **Concurrency model.** Three goroutine pools: N=`-t 100` resolve workers (default), 1 output worker (serialized so writes are atomic), N wildcard workers (sized to wildcard-job count). Communication via three buffered channels. `*hybrid.HybridMap` is the dedup cache: in-RAM until full, spills to disk (lmdb-style).
- **Underlying DNS library.** `projectdiscovery/retryabledns` (separate repo) is the *actual* DNS client. dnsx is a thin wrapper. retryabledns supports:
  - **UDP, TCP, DoH (HTTPS), DoT (TLS)** transports — resolver strings `udp:host:port`, `tcp:host:port`, `doh:URL`, `tls:host:port`.
  - **Retry with backoff** on SERVFAIL/timeout/REFUSED.
  - **TCP fallback** on TC=1 truncated UDP response.
  - **Hostsfile** support (reads `/etc/hosts`).
  - **DNS trace** (recursive root → TLD → authoritative).
  - **AXFR** zone transfer attempt.
  - **DNSSEC** validation toggle.
- **Total LOC.** Counting `internal/runner` + `libs/dnsx` ≈ 2500 Go LOC. Most complexity is in `retryabledns` (a few thousand LOC).
- **2024-2026 trends in commits.**
  - **Mar 2026:** `-auto-wildcard` flag landed (PR #966, addresses #924). Comma-separated `-l` input. Query-time tracking. CDN-check with both domain and DNS-response.
  - **2025:** answer-section-only filtering, omit-raw flag for JSON.
  - **May 2026:** aurora v2→v4 migration; deps bumped.

## Granular feature list

1. `-list hosts.txt` (`-l`) — file/stdin/comma-separated hostnames to resolve.
2. `-domain target.com` (`-d`) — domain(s) to brute-force (with `-w wordlist`).
3. `-wordlist words.txt` (`-w`) — wordlist for brute mode.
4. `-a`, `-aaaa`, `-cname`, `-ns`, `-txt`, `-srv`, `-ptr`, `-mx`, `-soa`, `-any`, `-axfr`, `-caa` — record types.
5. `-recon` (`-all`) — query *all* record types at once.
6. `-exclude-type a,cname` (`-e`) — exclude specific types.
7. `-resp` (`-re`) — display the DNS response value (not just hostname).
8. `-resp-only` (`-ro`) — display *only* the response value (e.g., the IP).
9. `-rcode noerror,servfail,refused,nxdomain` (`-rc`) — filter by response code.
10. `-response-type-filter a,cname` (`-rtf`) — return only entries with **no records** for these types (useful for finding dangling CNAMEs).
11. `-cdn` — display CDN name via cdncheck.
12. `-asn` — display ASN data (`-asn` triggers asnmap lookup).
13. `-threads 100` (`-t`) — worker count.
14. `-rate-limit -1` (`-rl`) — rate limit req/sec (default -1 = unlimited).
15. `-resolver 1.1.1.1,udp:8.8.8.8,tcp:1.1.1.1,doh:https://cloudflare-dns.com/dns-query,tls:1.1.1.1` (`-r`) — resolver list with transport prefix.
16. `-wildcard-threshold 5` (`-wt`) — # subdomains pointing same IP before suspicion.
17. `-auto-wildcard` — auto-detect wildcard domains for filtering.
18. `-wildcard-domain target.com` (`-wd`) — manual wildcard probe target.
19. `-trace` + `-trace-max-recursion 255` — DNS trace mode (recursive root→authoritative).
20. `-hostsfile` (`-hf`) — use system `/etc/hosts`.
21. `-retry 2` — retry count.
22. `-timeout 3s` — per-query timeout.
23. `-output out.txt` (`-o`) — output file.
24. `-json` (`-j`) / `-debug raw` — JSONL or raw DNS-response output.
25. `-or` (`-omit-raw`) — drop raw DNS response from JSON.
26. `-stats` — display per-second stats.
27. `-stream` — stream mode (disables wildcard, wordlist, stats, resume).
28. `-resume` — resume from `resume.cfg`.
29. `-proxy socks5://127.0.0.1:8080` — proxy.
30. `-silent` / `-verbose` / `-debug raw` / `-no-color` / `-version` / `-hc` (`-health-check`) — display + self-diagnostic.
31. `-auth pdcp_key` — PDCP cloud auth (required for `-asn` since asnmap moved to authenticated API).
32. `-up` / `-update` — self-update binary (pulls latest release).
33. `-duc` / `-disable-update-check` — skip auto-update check at startup.
34. `-proxy socks5://...` — supports **DNS-over-SOCKS5** since v1.2.2 (privacy-preserving resolution path).
35. **`FUZZ` placeholder in brute wordlist** (`-w wordlist_with_FUZZ.txt -d acme.com`) — replaces FUZZ token with each line, enabling `dev-FUZZ-api.acme.com`-style permutations (since v1.1.2).
36. **Answer-section-only filtering** (2025) — JSON output structures the `answer` array distinctly from `authority` / `additional` so downstream tools can filter to records the resolver actually returned in the ANSWER section (vs glue / SOA-in-authority).
37. **Response-type filter inverse semantics** — `-rtf` excludes hosts that HAVE the listed record types (i.e., returns the "negative" set), key for finding dangling-CNAME chains.

**Hidden features.**
- **`-recon` mode** queries ALL record types in a single dnsx run — useful for one-shot enum.
- **`-axfr` zone transfer attempt** — most misconfig today is internal DNS not external, but a clean `-axfr github.com` is still a fun test.
- **`-response-type-filter cname`** with `-cname` — surfaces hosts that have a CNAME *record* but the CNAME doesn't resolve → likely dangling CNAME → subdomain takeover candidate.
- **Resolver round-robin is implicit in retryabledns.** Different resolvers may return different results (e.g., GeoDNS-based answers); querying all 8 defaults catches more.
- **`-asn` exposes BGP routing data.** Helps prioritize: if 100 subs all in AS13335 (Cloudflare) → skip; if 5 in unique ASNs → those are interesting.
- **`-cdn` per-record annotation.** Output includes `cdn`, `cdn-name`, `cdn-type` fields.
- **Hybrid map disk-spill.** Means dnsx can resolve *millions* of hosts without OOM — RAM cap is configurable in `hmap` defaults.
- **FUZZ placeholder permutations** — `dev-FUZZ-api.acme.com` with a wordlist of `prod, stage, qa` yields three permuted queries. The placeholder can appear anywhere in the target template, not just as a leading subdomain.
- **DNS-over-SOCKS5** — `-proxy socks5://...` routes UDP/TCP DNS through SOCKS5; combined with `-r doh:` you get DoH-over-SOCKS5 (red-team egress evasion).
- **Self-update** — `-up`/`-update` pulls the latest release binary in place; `-duc` disables the startup check (useful in CI / air-gapped).
- **Authoritative section parsing** — the JSONL `answer` / `authority` / `additional` arrays are emitted separately, so tooling can filter to actual ANSWER section records (NXDOMAIN-with-SOA-in-authority distinguishable from NOERROR-with-empty-answer).

## Engineering hard parts

1. **Wildcard detection is the killer feature.** Naive: query `<sha1>.target.com` once. Real: that subdomain may itself be wildcard at multiple levels (`*.foo.target.com`, `*.bar.foo.target.com`). dnsx walks UP from candidate to apex, probing at each level, building an IP set per level, and dropping candidates whose IP set is a subset. Multiple wildcard IPs per target are normal (load-balanced wildcards). `-wt` (default 5) prevents over-eager flagging when there's a legit small group.
2. **DoH/DoT is slower per-query than UDP.** ~200ms HTTPS handshake vs ~20ms UDP. But DoH bypasses corporate firewalls blocking port 53 — bug bounty hunters increasingly need this for testing from restricted networks.
3. **Retry on UDP is tricky.** UDP queries can be silently dropped by the network. Retryabledns uses ~3 retries with backoff (1s, 2s, 4s). Too aggressive → flooded by your own resolvers; too lazy → false negatives.
4. **TCP fallback on TC=1.** Long DNS responses (TXT SPF records, NS lists) get truncated; resolver sets TC=1 in flags. Must auto-fallback to TCP and re-query.
5. **Resolver health.** Public resolvers go down. dnsx doesn't actively health-check; you should track per-resolver error rate and evict failing resolvers.
6. **Concurrency vs rate-limit interplay.** 100 workers × 8 resolvers × 1 req each = 800 simultaneous req. Cloudflare 1.1.1.1 caps you at ~150 req/sec from a single IP. Solution: cap rate (`-rl 100`) OR diversify resolvers (run your own pi-hole/unbound, add to `-r`).
7. **Hybrid map is finicky.** `projectdiscovery/hmap` defaults can fail on Windows or under restricted disk perms; clear `~/.config/dnsx/hmap-state` if dnsx mysteriously hangs.
8. **CAA records are RFC 8659 + many flag interpretations.** Rust DNS libs (hickory) handle this well; rolling your own bit parser is bug-prone.
9. **DNSSEC validation is rarely needed for bug bounty.** But if you set it, expect a 30% slowdown and some valid hosts to fail (chains broken at TLD level).
10. **Idempotency vs. cache poisoning concerns.** Resolving `<random>.target.com` 1000 times in a sec from one IP is detectable cache-busting behavior — Cloudflare will rate-limit you. Diversify resolvers + randomize subdomain probe seeds.

## Rust library mapping

| Original Go component | Recommended Rust crate | Version | Notes |
| --- | --- | --- | --- |
| `goflags` | `clap` (derive) | 4.5.x | Group with `next_help_heading`. |
| `gologger` | `tracing` + `tracing-subscriber` | 0.1 / 0.3 | — |
| `miekg/dns` + `retryabledns` (DNS protocol) | **`hickory-resolver`** + **`hickory-proto`** | 0.24.x | Pure Rust, async (`tokio`), supports UDP, TCP, DoH, DoT, **DoQ (DNS-over-QUIC)** since 0.24, DNSSEC. The de facto Rust DNS stack. Configure via `ResolverConfig` with `NameServerConfig` entries (one per resolver, per protocol). |
| Resolver pool | `hickory_resolver::config::ResolverConfig::add_name_server` with multiple `NameServerConfig` | — | hickory does round-robin automatically; configure `LookupIpStrategy::Ipv4AndIpv6`. |
| DoH | `hickory_resolver` with `Protocol::Https`, requires `rustls-platform-verifier` | 0.24 | URL like `https://cloudflare-dns.com/dns-query`. |
| DoT | `hickory_resolver` with `Protocol::Tls` | 0.24 | — |
| DoQ | `hickory_resolver` with `Protocol::Quic` (feature `dns-over-quic`) | 0.24 | Brand new, ~5 servers globally support it (Cloudflare, NextDNS, AdGuard). |
| AXFR | `hickory_proto::rr::Record` + manual TCP send (hickory does AXFR via its server crate, client side requires lower-level work) | 0.24 | Use `hickory-client` directly for AXFR streaming. |
| DNS trace (recursive root→authoritative) | hand-roll on top of `hickory_proto` | — | Not a single-crate feature; needs custom recursion with explicit NS following. |
| Wildcard detection | hand-roll: `<random>.target.com` probe + level-walking logic | — | Use `rand::distr::Alphanumeric` + `sha1` for probe naming. |
| `projectdiscovery/ratelimit` | `governor` | 0.6 | `RateLimiter::direct(Quota::per_second(NonZero::new(N)))`. |
| `projectdiscovery/hmap` (hybrid) | `dashmap` + `redb` (or `sled`) | 6.x / 2.x | RAM-first map; spill cold entries to embedded KV store. |
| `projectdiscovery/clistats` | `indicatif` + `prometheus` (if exposing metrics) | 0.17 / 0.13 | Live stats; per-second QPS, error rate. |
| `projectdiscovery/cdncheck` | LancerCDN crate (sibling) | — | Same data, Rust impl. |
| `projectdiscovery/asnmap` | call `https://api.bgpview.io/ip/{ip}` via `reqwest`, or use `ip-api` / `team-cymru-whois` lib | — | No mature Rust crate covers ASN→IP; net REST is fine for low QPS. |
| `jsoniter` JSON | `serde_json` | 1.0 | — |
| stdin streaming | `tokio::io::BufReader::new(stdin()).lines()` | — | — |
| Resolver string parser (`udp:`/`tcp:`/`doh:`/`tls:`) | small custom parser | — | Trivial. |
| Resume `resume.cfg` JSON | `serde_json` | 1.0 | Just persist `processed: HashSet<String>`. |
| `pdcp/auth` | call `https://api.projectdiscovery.io/v1/user` REST | — | Skip if not building PDCP-equivalent. |
| `prediction` model (not in dnsx) | — | — | N/A. |

## Data sources (the DNS endpoints)

| Resolver | Protocol | Endpoint | Notes |
| --- | --- | --- | --- |
| **Cloudflare** | UDP/TCP | `1.1.1.1:53`, `1.0.0.1:53` | Fastest globally; ~10ms RTT in NA/EU. |
| **Cloudflare** | DoH | `https://cloudflare-dns.com/dns-query`, `https://one.one.one.one/dns-query` | TLS overhead but bypasses port-53 filters. |
| **Cloudflare** | DoT | `tls:1.1.1.1:853` | — |
| **Cloudflare** | DoQ | `quic://1.1.1.1:853` | Experimental. |
| **Google** | UDP/TCP | `8.8.8.8:53`, `8.8.4.4:53` | Aggressive ECS (EDNS Client Subnet) — different answers per region. |
| **Google** | DoH | `https://dns.google/dns-query` | — |
| **Google** | DoT | `tls:8.8.8.8:853` | — |
| **Quad9** | UDP/TCP | `9.9.9.9:53`, `149.112.112.112:53` | Threat-blocking filter — returns NXDOMAIN for known malware C2. Use the `9.9.9.10` IP for *unfiltered* version. |
| **Quad9** | DoH | `https://dns.quad9.net/dns-query` | — |
| **OpenDNS (Cisco)** | UDP/TCP | `208.67.222.222:53`, `208.67.220.220:53` | Family-filter enabled on some IPs. |
| **AdGuard** | UDP/DoH/DoT/DoQ | `94.140.14.14:53`, `https://dns.adguard-dns.com/dns-query`, `quic://dns.adguard-dns.com:853` | — |
| **NextDNS** | DoH/DoT/DoQ | `https://dns.nextdns.io/<config_id>`, `tls:<id>.dns.nextdns.io:853` | Configurable filters per-account. |
| **dnscrypt-proxy** local | UDP `127.0.0.1:5353` | — | If user runs their own. |
| **Hostsfile** | `/etc/hosts` (Linux/macOS), `C:\Windows\System32\drivers\etc\hosts` (Windows) | dnsx reads this when `-hf`. |
| **DoH endpoints (community)** | https://github.com/curl/curl/wiki/DNS-over-HTTPS lists ~30 public DoH servers (use for diversity). |
| **Root hints (for `-trace`)** | `a.root-servers.net` (`198.41.0.4`) through `m.root-servers.net` (`202.12.27.33`) | RFC 8806; embedded data. |
| **TLD authoritative (per TLD)** | discovered via root NS query | — | Standard DNS trace. |

## 2024-2026 state

- **`-auto-wildcard`** landed Mar 2026 (was a long-requested feature, issue #924, addresses PureDNS gap).
- **hickory-dns** completed the trust-dns→hickory rebrand in 2024; v0.24 added DoQ, rustls 0.23. The Rust DNS stack is now production-ready and being adopted by Mozilla (Firefox NSS-free DoH) and several CDN edge platforms.
- **Forks / alternatives:**
  - **shuffledns** (ProjectDiscovery) — older sibling that does *brute force* enum (massive wordlist) with wildcard handling. dnsx absorbed most features.
  - **puredns** (d3mondev) — Go; pioneered the "trusted resolver pool" pattern. dnsx's auto-wildcard mode is the response.
  - **massdns** (blechschmidt) — C, the OG mass-resolver; still the fastest pure resolver. dnsx is comparable but easier to use.
  - **zdns** (academic, U.Mich) — Go; fast and rigorous; less recon-friendly output.
- **Performance benchmarks (community-reported).** dnsx resolves 1M hostnames in ~5 min on a 100Mbps line with default settings (100 threads, 8 resolvers). massdns is ~2x faster but harder to set up. puredns is comparable.
- **Community sentiment.** "If you only use one DNS tool, use dnsx." Universal in 2025-2026 recon methodologies. Common complaint: hybrid-map state files getting corrupted on Windows.

### Deep-research note — 2026-05-30

Re-verified upstream state (README, releases, docs.projectdiscovery.io, PDCP blog) on 2026-05-30. Confirmed and added the following to the plan:

- **Auto-wildcard PR (#966 / issue #924) is now the official approach** — `-auto-wildcard` walks UP from each candidate to the apex, building per-level wildcard IP sets; replaces the manual `-wd` workflow for mixed-domain input. Lancer `Phase 4` already captures this; no spec changes needed.
- **`-asn` flag now requires PDCP API key upstream** (asnmap moved to an authenticated API). Lancer divergence: default to unauthenticated BGPView; `-asn-key` opt-in for PDCP-compatible tier. Captured in the new `## Integrations` table.
- **FUZZ-placeholder bruteforcing** (since v1.1.2) was missing from the granular flag list — now added as item 35.
- **DNS-over-SOCKS5** (since v1.2.2) and self-update flags (`-up`, `-duc`) were missing — now added as items 32-34.
- **`-omit-raw` / `-or`** and the answer/authority/additional JSONL split (2025 release) are now explicit in the hidden-features section.
- **Historical DNS** is a published ProjectDiscovery pattern (PDCP blog) but NOT a built-in upstream flag — Lancer ships it as a first-class `-historical` / `-hist-store` / `-hist-diff` trio backed by `redb` (no cloud, no MongoDB/Redis dependency).
- **Censys + Shodan enrichment** are Lancer-only net-new integrations — added to the integration matrix. These complement `-cdn` + `-asn` and surface port/service/cert data for each resolved IP without a separate naabu/httpx hop.
- **DoQ (DNS-over-QUIC)** confirmed available via `hickory-resolver` 0.24 — already in the library mapping; flagged as `quic://` resolver prefix in `Phase 2`.
- **No new record types** introduced upstream in 2025-2026 (the 12-type set A/AAAA/CNAME/PTR/NS/MX/TXT/SRV/SOA/ANY/AXFR/CAA remains canonical). DNSSEC (DNSKEY/DS/RRSIG/NSEC/NSEC3) is still off the upstream flag surface but is exposed by retryabledns — Lancer can surface these in `-recon` JSON output as a divergence-allowed extension.
- **Output formats** — upstream emits plain-text + JSONL only. Lancer adds CSV + SARIF (for CI security gates) without breaking the parity contract since they're additive.

No deletions made — only additions. Net new lines: ~40. Plan now reflects upstream as of v1.2.3 + dev branch May 2026.

## Real-world pipeline patterns

```bash
# Canonical: subfinder → dnsx → httpx
subfinder -d acme.com -all -silent | dnsx -silent -a -resp-only \
  | httpx -silent -title -tech-detect

# Resolve + drop wildcards
subfinder -d acme.com -silent | dnsx -silent -auto-wildcard -a -resp-only

# Find live hosts only (any record)
cat hosts.txt | dnsx -silent -resp-only

# Get all records (one-shot enum)
cat hosts.txt | dnsx -silent -recon -json -o dnsx.json

# Brute-force subdomains with wordlist
dnsx -d acme.com -w /path/to/dns-wordlist.txt -silent -resp-only

# Find dangling CNAMEs (subdomain takeover candidates)
cat hosts.txt | dnsx -silent -cname -resp-only \
  | awk '{print $NF}' | dnsx -silent -rcode nxdomain -resp-only

# Zone transfer test (rare success but easy try)
echo target.com | dnsx -axfr -resp-only

# Find hosts NOT behind a CDN (origin candidates)
cat hosts.txt | dnsx -silent -cdn -json | jq -r 'select(.cdn==null) | .host'

# Trace resolution path
echo www.acme.com | dnsx -trace -silent

# Bulk resolution with custom resolvers (faster, your own pi-hole)
cat hosts.txt | dnsx -r 192.168.1.2,udp:1.1.1.1 -t 200 -silent
```

**Failure modes:**

- **Wildcard target without `-auto-wildcard` floods output.** `cat 1M_random_subs.txt | dnsx` on `*.appspot.com` returns 1M positive results.
- **Resolver pool exhaustion.** All 8 default resolvers rate-limit you → falls into retry loop → resolutions time out. Solution: lower `-t`, raise `-rl`, or use your own resolvers.
- **Hostsfile masking.** `/etc/hosts` overrides may mask real-world DNS state. `-hf=false` to disable.
- **DoH-only environments.** UDP port 53 blocked → use `-r doh:https://cloudflare-dns.com/dns-query`.
- **Hybrid map state corruption.** `~/.config/dnsx/hmap-state/` → delete to recover.

## Bug bounty value + AI augmentation ideas

**Why a hunter cares in 2026.**

dnsx is the **filter and amplifier** between subfinder and httpx. It:
- **Drops dead subdomains** so you don't waste httpx time on NXDOMAIN.
- **Surfaces takeover candidates** via dangling CNAMEs (`-cname` + `-rcode nxdomain` on the CNAME target).
- **Reveals zone-transfer misconfigs** (`-axfr`) — when one works, you get a Pulitzer.
- **Identifies origin IPs behind CDN** (when subfinder finds `direct.acme.com` and dnsx resolves to non-Cloudflare → that's the WAF bypass jackpot).
- **Drives wordlist-based brute-force** (`-d -w wordlist.txt`) — finds hosts public sources didn't index.

**Bug classes its output enables:**
- **Subdomain takeover** (CNAME → unregistered SaaS instance).
- **CDN-bypass / origin-IP discovery** (host that resolves to non-CDN IP while siblings sit behind CDN).
- **DNS rebinding** (TXT/CNAME games for SSRF).
- **DNSSEC misconfiguration** (DNSSEC enabled but key rotation failing → resolution breaks → user gets NXDOMAIN for legit subs).
- **Internal-name leak** in TXT/SOA records (`internal-cluster-prod.acme.local`).

**AI augmentation opportunities (Lancer differentiator):**

1. **Takeover candidate triage.** Feed dangling-CNAME list + the SaaS provider (extracted from CNAME suffix like `*.s3.amazonaws.com`, `*.github.io`, `*.herokudns.com`) to Claude — it returns: "This CNAME pointing to `dead-bucket.s3.amazonaws.com` is a high-confidence S3 takeover, register the bucket name. This one pointing to `removed-team.netlify.app` is medium-confidence — try registering the slug." Output: an action plan, not just a list.
2. **TXT record secret extraction.** TXT records sometimes contain API keys, validation tokens, SPF whitelists. AI scans the corpus for: AWS keys, Stripe keys, internal CIDR mentions, internal hostnames.
3. **Wildcard-set fingerprinting.** When wildcards detected → AI infers WAF/CDN from the IP set (e.g., 104.21.X.X / 172.67.X.X → Cloudflare; 13.32.X.X → CloudFront).
4. **ASN clustering.** Cluster subs by ASN; outliers (1 sub in obscure ASN) are usually the bug.
5. **DNS-Trace correlation with takeover.** `-trace` reveals authoritative NS; if NS itself is dangling (e.g., points to deleted Route53 hosted zone), entire subdomain tree is takeover-vulnerable.
6. **Wordlist generation.** AI generates per-target wordlists from discovered patterns (`api-v1`, `api-v2` exist → suggest `api-v3`, `api-internal`, `api-test`).

## Integrations (third-party data sources — net-new for Lancer)

Upstream dnsx ships with `cdncheck` + `asnmap` integrations. Lancer extends this with a richer integration matrix to enrich resolved records at scan time:

| Source | Trigger flag | Data added per record | Notes |
| --- | --- | --- | --- |
| **LancerCDN** (cdncheck port) | `-cdn` | `cdn`, `cdn-name`, `cdn-type` | Bundled. |
| **BGPView / Team-Cymru** (asnmap port) | `-asn` | `asn`, `as-name`, `as-country`, `as-range` | Upstream now requires PDCP API key — Lancer uses unauthenticated BGPView by default, with optional `-asn-key` for premium tier. |
| **Censys Hosts API** | `-censys` (`-cen`) | `services[]`, `cert-fingerprint`, `port-list`, `last-updated` | Lancer-only. Enriches each resolved IP. Requires `CENSYS_API_ID` + `CENSYS_API_SECRET` env vars. |
| **Shodan Host API** | `-shodan` (`-sh`) | `ports`, `vulns`, `hostnames`, `org`, `tags` | Lancer-only. `SHODAN_API_KEY`. Caches per IP for 24h to stay under quota. |
| **ProjectDiscovery Chaos** | `-chaos` | imports passive subdomain corpus before resolution | Optional; useful when you don't have a subfinder pre-step. |
| **PDCP Historical DNS** | `-historical` (`-hist`) | `history[]` array of past A/AAAA per host with `first-seen` / `last-seen` | Pattern from ProjectDiscovery blog — Lancer ships local MongoDB+Redis-style historical store via `redb`, no cloud required. |
| **Internal historical store** | `-hist-store path/` | persists every resolution to `redb` with timestamp | Enables `-hist-diff scan1.db scan2.db` to surface IP-changes between scans (CDN drift, origin moves). |

## Implementation phases (10-week plan)

### Phase 0 — Skeleton & A/AAAA resolve (Week 1)
- `cargo new lancerdns`. `clap` derive with groups (input/query/filter/probe/rate-limit/output/optimization/configurations/debug).
- `hickory-resolver` setup with default 8-resolver pool (UDP).
- stdin/file/comma-separated input parser.
- Worker pool: `tokio::sync::mpsc::channel` + N `tokio::spawn` tasks (default 100).
- Output: `host A 1.2.3.4` per line; `-resp-only` mode.
- Deliverable: `cat hosts.txt | lancerdns -silent` resolves 10k hosts in <30 sec.

### Phase 1 — All record types (Week 2)
- Add CNAME, MX, TXT, NS, PTR, SRV, SOA, CAA, ANY, AXFR.
- `-recon` (`-all`) queries all types.
- `-exclude-type` to skip specific types.
- `-resp` (full response display) vs `-resp-only` (value only).
- Multi-record output (one line per record).
- JSON output (`-json`) with nested structure; `-omit-raw` strips raw response.
- Deliverable: `echo google.com | lancerdns -recon -json` returns full record set.

### Phase 2 — Resolver pool & DoH/DoT (Week 3)
- Resolver-string parser: `udp:`, `tcp:`, `doh:`, `tls:`, `quic:` prefixes.
- `-r host:port,...` and `-rL resolvers.txt`.
- Per-resolver health: track error rate (last 100 queries), evict if >50% errors.
- Custom resolver pool with hickory `NameServerConfig` per entry.
- Deliverable: `lancerdns -r doh:https://cloudflare-dns.com/dns-query -silent` works through DNS-blocking firewall.

### Phase 3 — Wildcard detection (the killer feature) (Week 4-5)
- Manual mode (`-wd target.com`): probe `<sha1>.target.com` 3 times, capture wildcard IP set, drop matching answers.
- Auto mode (`-auto-wildcard`): walk-up: probe `<random>.host.target.com`, then `<random>.target.com`, build per-level wildcard IP sets.
- Wildcard worker pool (sized to job count).
- `-wt 5` threshold.
- Per-target cache (re-use wildcard probe data across input lines).
- Tests against known-wildcard targets: `*.github.io`, `*.herokuapp.com`, `*.cloudfront.net`, `*.appspot.com`.
- Deliverable: `cat 1M_random_subs.txt | lancerdns -auto-wildcard -silent` returns ≈0 hits (vs 1M without).

### Phase 4 — Filters, response-codes, response-type (Week 6)
- `-rcode noerror,nxdomain,servfail,refused` filter.
- `-rtf a,cname` (response-type-filter: only hosts with NO record of these types) — dangling-CNAME hunt.
- Match/exclude regex over resolved values.
- `-stream` mode (disable wildcard/wordlist/stats).
- Deliverable: `lancerdns -cname -rtf cname -silent` surfaces dangling-CNAME candidates.

### Phase 5 — DNS Trace + AXFR (Week 7)
- `-trace` mode: query root NS, walk down TLD → SLD → authoritative; print each step. `hickory-client` for raw query/response.
- `-axfr`: attempt AXFR against each NS in NS-record; print transfer if open.
- `-trace-max-recursion 255` cap.
- Deliverable: `echo wiki.acme.com | lancerdns -trace` prints recursive resolution path.

### Phase 6 — Brute-force mode (-d -w) (Week 7)
- `-d target.com -w wordlist.txt` → for each word, query `word.target.com`.
- Auto-wildcard always on in brute mode.
- Embed top-1000 / top-100k DNS wordlists via `include_str!` (or load from disk).
- Deliverable: `lancerdns -d acme.com -w wordlist.txt -silent` returns valid subs.

### Phase 7 — CDN/ASN integration (Week 8)
- `-cdn` integrate LancerCDN (sibling): annotate JSON with `cdn-name`, `cdn-type`, `cdn` bool.
- `-asn` — call BGPView/RIPEstat REST per resolved IP; annotate with AS number, name, country, range.
- Deliverable: `lancerdns -cdn -asn -json` outputs enriched records.

### Phase 8 — Stats, resume, hybrid map (Week 9)
- `dashmap` + `redb` hybrid map: in-RAM first, spill to disk when >N entries.
- `-stats` live counters (QPS, errors, drops) via `indicatif::ProgressBar` template.
- `-resume`: persist seen-set + in-flight to `resume.cfg`.
- Healthcheck command: resolver reachability, hostsfile readable, disk-write OK.
- Deliverable: 1M-host resolution doesn't OOM; `-resume` works.

### Phase 9 — Lancer library API + polish (Week 10)
- Library API: `Resolver::new(opts).resolve_stream(hosts).await -> impl Stream<Item=Resolution>`.
- Lancer §37 Bulk Probe calls this between LancerSub and LancerProbe (httpx).
- Cross-platform binary release.
- AI augmentation: `--ai-rank` flag on dangling-CNAME / interesting-TXT batches via shared `lancer-ai` crate.
- Deliverable: `cargo install lancerdns` works; library imports clean.

## CLAUDE.md to seed in the clone repo
```
This project = a dnsx clone in Rust ("lancerdns").
- hickory-resolver for ALL DNS protocol work — do NOT roll a custom resolver.
- Async tokio; worker pool reading from a mpsc channel (default 100 workers).
- Three resolver protocol flavors first-class: UDP, TCP, DoH (mandatory — bypasses corp filters), DoT/DoQ as bonus.
- Default resolver list: Cloudflare/Google/Quad9/OpenDNS (8 entries), all UDP.
- Wildcard detection (the killer feature): manual (-wd) and auto (-auto-wildcard). Walk UP from candidate to apex, probe <sha1>.<level> 3 times each, drop final answers whose IPs are a subset of any level's wildcard set.
- -wt threshold default 5 to avoid over-aggressive wildcarding.
- Output is sorted: <host> <type> <value>.
- JSON output via serde; -omit-raw strips redundant raw response.
- Hybrid map (dashmap + redb) for dedup at scale (1M+ hosts) without OOM.
- Resolver health: track last-100 error rate, evict failing resolvers.
- ENABLE_TLS_DETECTION etc. — N/A here, that's naabu.
- Library crate (lib.rs) exposes Resolver::resolve_stream; Lancer §37 imports.
```

---

## GUI (Lancer-standard pattern)

`lancer-dnsx` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-dnsx-cli` companion binary), but the **plain `lancer-dnsx` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-dnsx/`, `%APPDATA%\lancer-dnsx\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-dnsx-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-dnsx.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-dnsx.exe` (double-click opens the GUI window).
- Linux: `build/lancer-dnsx` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-dnsx` (bundled into `lancer-dnsx.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-dnsx/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-dnsx.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-dnsx-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-dnsx
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-dnsx.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-dnsx-windows-x86_64\bin\lancer-dnsx.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-dnsx`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.

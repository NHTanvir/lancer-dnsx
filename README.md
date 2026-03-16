# lancer-dnsx

Rust clone of `dnsx`. Part of the Lancer ecosystem — a complete 2026 AI-era bug bounty toolkit.

🚧 **In development.**

## Build

### Windows
Double-click `build.bat` or run from cmd:
```
build.bat
```
Output: `build\lancer-dnsx.exe`

For a packaged dist build:
```
build-windows.bat
```
Output: `dist\lancer-dnsx-windows-x86_64\bin\lancer-dnsx.exe`

### Linux / macOS
```bash
./build-linux.sh
```
Output: `build/lancer-dnsx`

### Requirements
- [Rust / Cargo](https://rustup.rs)
- (Windows) Visual C++ Build Tools 2019/2022

## Features

- All record types: A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, SOA, CAA, ANY, AXFR
- Custom resolvers via UDP / TCP / DoT (`tls:`) / DoH (`doh:`)
- Per-resolver health tracking with eviction of unhealthy resolvers
- Wildcard DNS detection (manual `--wildcard-domain` and auto walk-up)
- Response-code, response-type, and regex filters (`-rcode`, `-rtf`, `-mr`, `-er`)
- CDN matching (`-cdn`) and ASN lookups via BGPView (`-asn`)
- Subdomain brute-force (`-d` + `-w`)
- Recursive DNS trace (`-trace`) and AXFR zone transfer (`-axfr`)
- JSON Lines output (`-json`)
- Live progress bar (`-stats`) and resume-from-checkpoint (`-resume`)
- Hybrid in-memory + on-disk dedup for very large inputs
- Stream mode (`-stream`) for low-latency / low-memory operation (disables
  wildcard / stats / resume)
- Healthcheck mode (`-hc`)

## Library usage

`lancer-dnsx` is published both as a CLI binary and as a Rust library. To use
it as a dependency:

```toml
[dependencies]
lancer-dnsx = { git = "https://github.com/NHTanvir/lancer-dnsx" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

```rust
use lancer_dnsx::{default_name_servers, resolve_host, RecordType, ResolverPool};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let servers = default_name_servers();
    let pool = ResolverPool::build(&servers, 3, 2, true)?;

    let resolution = resolve_host(
        &pool,
        "example.com".to_string(),
        vec![RecordType::A, RecordType::Aaaa],
        true,
    )
    .await;

    for r in &resolution.results {
        println!("{} {} {}", r.host, r.record_type, r.value);
    }
    Ok(())
}
```

The library API surface is intentionally small. The currently re-exported
items are `ResolverPool`, `resolve_host`, `default_name_servers`,
`parse_resolver_string`, `RecordType`, `ResponseCode`, `DnsResult`,
`HostResolution`, `HostRecord`, and `WildcardCache`.

## Status

Phase 9 (library API + final polish) -- feature-complete dnsx clone.

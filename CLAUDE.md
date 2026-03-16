# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-dnsx` — a Rust clone of `dnsx`, part of the Lancer ecosystem — a complete 2026 AI-era bug bounty toolkit. It functions as both a CLI binary and a Rust library, providing high-performance DNS resolution with support for all major record types, custom resolvers (UDP/TCP/DoT/DoH), wildcard detection, CDN matching, ASN lookups, and subdomain brute-force capabilities.

## Architecture

- `src/lib.rs` — library crate root; exposes the public API for use as a dependency
- `src/main.rs` — binary entry point; CLI argument parsing and top-level orchestration
- `tests/` — integration tests
- `wordlists/` — bundled wordlists for subdomain brute-force (`-d` + `-w`)
- `build.bat` — Windows build script → `build\lancer-dnsx.exe`
- `build-windows.bat` — Windows packaged dist build → `dist\lancer-dnsx-windows-x86_64\bin\lancer-dnsx.exe`
- `build-linux.sh` — Linux/macOS build script → `build/lancer-dnsx`
- `Cargo.toml` — package manifest; DNS resolution via `hickory-resolver` with DoH/DoT features

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- GUI gated behind the default `gui` feature; `--no-default-features` builds headless CLI.
- Library code in `src/lib.rs`; binary entry point in `src/main.rs`.
- DNS resolution is async throughout (tokio runtime); all resolver I/O goes through `hickory-resolver`/`hickory-client`.
- Filters (`-rcode`, `-rtf`, `-mr`, `-er`) are applied post-resolution; add new filter types in the filter layer, not inside the resolver loop.

## Build / test / run

```
build.bat                   # Windows → build\lancer-dnsx.exe
./build-linux.sh            # Linux/macOS
cargo build --release       # standard release build
cargo test                  # run tests
```

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.

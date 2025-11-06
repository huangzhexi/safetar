# safetar

[![CI](https://github.com/your-org/safetar/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/safetar/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Crates.io](https://img.shields.io/crates/v/safetar.svg?label=crates.io&logo=rust)](https://crates.io/crates/safetar)

safetar is a secure-by-default tar-compatible archiver and library written in Rust. It enables path sanitisation, resource quotas, and link confinement out of the box while remaining largely compatible with GNU tar and bsdtar for everyday workflows.

## Why safetar?

- **Default safety**: Rejects absolute paths, `..` traversal, and links that escape the extraction root.
- **Configurable quotas**: Limit file counts, aggregate size, per-file size, and directory depth to tame archive bombs.
- **Modern ergonomics**: Rich CLI with dry-run plans, JSON listings, manifest hashing, and progress indicators.
- **Embeddable library**: Clean APIs for create/extract/list so other tools can reuse the safety primitives.

## Feature Matrix

| Capability | GNU tar | bsdtar | safetar |
| --- | --- | --- | --- |
| Create/extract/list (`c/x/t`) | ✅ | ✅ | ✅ |
| `-C` change directory | ✅ | ✅ | ✅ |
| Compression (`gzip`, `xz`, `zstd`) | ✅ (`zstd` via plugin) | ✅ (`zstd` via libarchive) | ✅ (built-in) |
| Glob excludes (`--exclude`, `--exclude-from`) | ✅ | ✅ | ✅ |
| Dry run / plan output | ❌ | ❌ | ✅ (`--print-plan`) |
| Manifest hashing & verification | ❌ | ❌ | ✅ |
| Default-on safety policies | ❌ | ⚠️ partial | ✅ |
| JSON listing | ❌ | ❌ | ✅ |

## Quick Start

```bash
# Build from source
cargo install --git https://github.com/your-org/safetar safetar

# Create a secure archive
safetar create -f backup.tar.zst -zstd ./data

# Extract with strict validation
safetar extract -f backup.tar.zst -C ./restore --manifest backup.manifest.json --strict

# Inspect contents as JSON
safetar list -f backup.tar.zst --json
```

## Common Workflows

- Generate a manifest alongside an archive:
  ```bash
  safetar create -f pkg.tar --manifest-out pkg.manifest.json ./pkg
  ```
- Run a dry plan to audit what would be captured:
  ```bash
  safetar create -f pkg.tar --print-plan ./pkg
  ```
- Relax manifest verification to allow new files:
  ```bash
  safetar extract -f pkg.tar --manifest pkg.manifest.json --manifest-relaxed
  ```

## Safety & Threat Model

safetar assumes archives may be untrusted. The security policy enforces:

- Path normalisation with rejection of absolute paths and parent traversal.
- Symlink/hardlink targets constrained to the extraction root.
- Resource quotas (default: 200k entries, 8 GiB total, 2 GiB per file, depth ≤ 64).
- Deterministic manifest hashing (SHA-256) for both creation and verification.

Apply `--strict` when you prefer immediate aborts on policy violations; otherwise safetar still fails the operation but keeps error classification explicit (exit code 3).

## Performance Notes

- Streaming tar IO with buffered readers/writers and zero-copy piping for compressors.
- Parallel SHA-256 manifest hashing with Rayon.
- Optional `cargo nextest` integration for high-throughput test runs.

## Roadmap

- [ ] Incremental hashing for very large files.
- [ ] Extended attributes and ACL preservation.
- [ ] Native Windows long-path support.
- [ ] Pluggable policy profiles for sandboxed environments.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide, coding style, and CI expectations. TL;DR:

```bash
make ci              # fmt + clippy + nextest + audit
cargo fmt            # format
cargo clippy -D warnings
cargo nextest run    # fast test harness
cargo audit          # dependency health
```

## Threat Report / Security

Report vulnerabilities privately per [SECURITY.md](SECURITY.md). Supported release branches and disclosure process are documented there.

## Acknowledgements

Built on top of the Rust ecosystem: `tar`, `camino`, `rayon`, `indicatif`, and many others that make secure tooling viable.

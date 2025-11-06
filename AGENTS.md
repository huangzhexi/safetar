# Repository Guidelines

## Project Structure & Module Organization
The CLI entry point sits in `src/main.rs`; shared logic should move into `src/lib.rs` and feature-focused submodules (`cli/`, `archive/`, `io/`, `policy/`, `manifest/`). Keep integration and property suites in `tests/` (`cli_smoke.rs`, `policy_e2e.rs`, `manifest_test.rs`) so they share fixtures and nextest config. Store reusable archives, manifests, and quotas-related fixtures under `tests/data/`.

## Build, Test, and Development Commands
- `cargo fmt` — reformat before every branch or commit.
- `cargo clippy -D warnings` — lint with warnings promoted to errors; the tree must stay unsafe-free.
- `cargo nextest run` — preferred runner for unit, integration, and property suites.
- `cargo audit` — check advisories on every PR; either upgrade or justify.
- `cargo run -- --help` — spot-check CLI surfacing of manifest and safety flags.

## Coding Style & Naming Conventions
Stick to Rust 2021 defaults: 4-space indentation, `snake_case` for items, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants. Use `//!` module headers and rustdoc comments on public APIs. Prefer `anyhow::Context` and `thiserror` for layered errors, avoid `unwrap()` outside tests, and keep each module scoped to one concern (policy, archive flow, manifest hashing).

## Testing Guidelines
Co-locate unit tests with modules and stage scenarios in `tests/`. Use `assert_cmd` for CLI flows, `insta` for manifest and plan snapshots, and `proptest` for fuzzable surfaces (path normalization, quotas). Cover path traversal, link escape, resource ceilings, manifest mismatches, and compression autodetection. Prefer fixtures that mirror GNU/bsdtar interoperability and exercise Unix plus Windows path handling.

## Commit & Pull Request Guidelines
Follow Conventional Commits (`feat(policy): enforce link targets`) so changelogs stay machine-readable. Keep commits independently buildable and tested. PRs should explain motivation, call out safety impact, link issues, and paste recent results from `cargo fmt`, `cargo clippy -D warnings`, `cargo nextest run`, and `cargo audit`. Add screenshots or transcripts when user-facing CLI output changes, and document any intentional deviation from the default security posture.

## Security & Configuration Expectations
Default to strict mode: keep path normalization, link confinement, and resource quotas enabled unless the user flips them off. Document new knobs in help text and the library API. When editing compression paths, confirm magic-byte detection and continue to route I/O through `io::dec` and `io::enc`. Maintain deterministic manifest hashing (`rayon`, `sha2`, `hex`), and audit new dependencies before merging.

# Contributing to safetar

Thanks for helping build a safer tar! This document explains how to collaborate effectively.

## Branches & Workflow

- `main` – release-ready. Protected; merges only via reviewed PRs.
- `dev` – default integration branch for day-to-day work.
- `release/*` – tagged release preparation (e.g. `release/v0.1.0`).

Create topic branches from `dev` (e.g. `feature/policy-boundary`) and open pull requests back to `dev`. Maintainers promote batches from `dev` to `main` via release PRs.

## Conventional Commits

All commits must follow [Conventional Commits](https://www.conventionalcommits.org/). Examples:

- `feat(policy): reject symlinks escaping root`
- `fix(manifest): normalise file ordering`
- `docs: clarify threat model`
- `test(cli): cover --print-plan`

Squash merges should keep a Conventional Commit summary.

## Coding Standards

- Rust 2021 edition, 4-space indentation, `snake_case` for items, `PascalCase` for types.
- `//!` module docs and rustdoc for public APIs.
- No `unsafe` in production code; prefer expressive error handling with `anyhow::Context` and `thiserror`.
- Keep modules focused (CLI, archive, policy, manifest, IO). Add comments only where flow is non-obvious.

## Tooling & Tests

Use the bundled `Makefile` helpers:

```bash
make fmt           # cargo fmt
make lint          # cargo clippy -- -D warnings
make test          # cargo test --workspace
make nextest       # cargo nextest run --workspace
make audit         # cargo audit
make ci            # fmt + lint + nextest + audit
```

Before sending a PR:

1. `make ci`
2. Ensure `cargo fmt` produces no diff.
3. Run `cargo nextest run --workspace` (preferred harness) or `cargo test` if nextest is unavailable.
4. Run `cargo clippy --all-targets --workspace -- -D warnings`.
5. Run `cargo audit` and address advisories or document false positives.

## Writing Tests

- Keep unit tests next to modules (`mod tests { ... }`) for focused behaviours.
- Use `tests/` for integration scenarios (CLI smoke, policy E2E, manifest validation, compression matrix).
- Property tests (`proptest`) belong in modules where non-trivial invariants exist (e.g. path normalisation).
- Prefer deterministic fixtures under `tests/data/` when binary assets are required.
- For large scenarios, build archives on the fly to avoid bloating the repo.

## Benchmarks

Benchmarks live under `benches/` (not yet populated). Use `cargo bench` and guard with `#[cfg(feature = "bench")]` if extra deps are needed.

## Pull Request Checklist

- [ ] Conventional Commit title
- [ ] Updated docs/examples if behaviour changed
- [ ] Added/updated tests (unit + integration)
- [ ] `make ci` passes locally
- [ ] Linked issue(s) or explained motivation
- [ ] Added changelog entry (once the changelog exists)

## Issue & PR Templates

GitHub templates under `.github/` help frame bug reports, feature requests, and pull requests. Please fill out all required sections.

## Communication

- Discussions: GitHub Discussions (`#ideas`, `#security` channels) once enabled.
- Security-sensitive reports: follow [SECURITY.md](SECURITY.md).
- Real-time chat: TBD (`Matrix` room planned for GA).

Thanks again for contributing!

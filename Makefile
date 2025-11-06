.PHONY: fmt lint test nextest audit ci

fmt:
	cargo fmt

lint:
	cargo clippy --all-targets --workspace -- -D warnings

test:
	cargo test --workspace

nextest:
	cargo nextest run --workspace

audit:
	cargo audit

ci: fmt lint nextest audit

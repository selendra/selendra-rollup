# Mirrors .github/workflows/ci.yml so the same checks run locally.
.PHONY: ci fmt clippy test deny audit udeps upstream-diff

ci: fmt clippy test deny audit

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
	cargo test --workspace --all-features --locked

deny:
	cargo deny check advisories bans licenses sources

audit:
	cargo audit --deny warnings

udeps:
	cargo +nightly udeps --workspace --all-targets --all-features --locked

upstream-diff:
	scripts/upstream-diff.sh

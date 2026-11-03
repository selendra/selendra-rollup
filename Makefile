# Mirrors .github/workflows/ci.yml so the same checks run locally (`udeps` and `fuzz` need nightly).
.PHONY: ci fmt clippy guest test test32 deny audit udeps fuzz upstream-diff

ci: fmt clippy guest test test32 deny audit udeps fuzz

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# The zk guest configuration (no `native`): lint it, and fail if OS randomness reaches it.
guest:
	cargo clippy -p selendra-interface --no-default-features --locked -- -D warnings
	cargo clippy -p selendra-primitives --no-default-features --locked -- -D warnings
	! cargo tree -p selendra-interface -p selendra-primitives --no-default-features -e normal --locked | grep getrandom

test:
	cargo test --workspace --all-features --locked

# Tests with a 32-bit `usize`, like the SP1 guest (musl: no 32-bit system libraries needed).
test32:
	rustup target add i686-unknown-linux-musl
	cargo test --workspace --all-features --locked --target i686-unknown-linux-musl

deny:
	cargo deny check advisories bans licenses sources

audit:
	cargo audit --deny warnings

udeps:
	RUSTFLAGS="" cargo +nightly udeps --workspace --all-targets --all-features --locked

# Fuzz every target for FUZZ_SECS seconds (needs nightly + cargo-fuzz).
FUZZ_SECS ?= 60
fuzz:
	cd fuzz && export RUSTFLAGS="" && for t in $$(cargo +nightly fuzz list); do cargo +nightly fuzz run $$t -- -max_total_time=$(FUZZ_SECS) || exit 1; done

upstream-diff:
	scripts/upstream-diff.sh

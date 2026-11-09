# Mirrors .github/workflows/ci.yml so the same checks run locally (`udeps` and `fuzz` need nightly).
.PHONY: ci fmt clippy guest test test32 deny audit udeps fuzz upstream-diff

ci: fmt clippy guest test test32 deny audit udeps fuzz

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# The zk guest configuration (no `native`): lint it, and fail if OS randomness reaches it.
# `selendra-state` has no self dev-dependency turning `native` on, so its tests (witness replay,
# checkpoint, cache) also build and run in the guest configuration.
guest:
	cargo clippy -p selendra-interface --no-default-features --locked -- -D warnings
	cargo clippy -p selendra-primitives --no-default-features --locked -- -D warnings
	cargo clippy -p selendra-state --no-default-features --all-targets --locked -- -D warnings
	cargo test -p selendra-state --no-default-features --locked
	! cargo tree -p selendra-interface -p selendra-primitives -p selendra-state --no-default-features -e normal --locked | grep getrandom

test:
	cargo test --workspace --all-features --locked

# Tests with a 32-bit `usize`, like the SP1 guest (musl: no 32-bit system libraries needed).
# Every feature except the node's storage stack (RocksDB and NOMT are not built for 32-bit
# targets): the `rockbound` and `selendra-db` crates and `selendra-state/rockbound` are left out.
TEST32_FEATURES := selendra-interface/native,selendra-interface/arbitrary,selendra-primitives/native,selendra-state/native,selendra-state/arbitrary
test32:
	rustup target add i686-unknown-linux-musl
	cargo test --workspace --exclude rockbound --exclude selendra-db --features $(TEST32_FEATURES) --locked --target i686-unknown-linux-musl
	cargo test -p selendra-state --no-default-features --locked --target i686-unknown-linux-musl

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

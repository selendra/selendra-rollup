# Mirrors .github/workflows/ci.yml so the same checks run locally (`doctest-codes`, `udeps` and
# `fuzz` need nightly).
.PHONY: ci fmt clippy guest test test32 doctest-codes deny audit udeps fuzz upstream-diff

ci: fmt clippy guest test test32 doctest-codes deny audit udeps fuzz

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# `$(call tree_lacks,<cargo tree arguments>,<extended regex>)`: fails if `cargo tree` fails or its
# output matches the regex (a bare `! cargo tree ... | grep ...` passes when `cargo tree` fails).
tree_lacks = tree="$$(cargo tree $(1))" && ! printf '%s\n' "$$tree" | grep -E '$(2)'

# The zk guest configuration (no `native`): lint it, and fail if OS randomness reaches it.
# `selendra-state` and the mock adapters have no self dev-dependency turning `native` on, and
# `selendra-modules-api`'s turns on only `test-utils`, so their tests (witness replay,
# checkpoint, cache, the known-answer vectors of the state hasher; the mock types, proofs and
# hints; gas, specs, ids; the derives' state layouts and module ids) also build and run in the
# guest configuration (`selendra-macros`, proc macros, runs on the host only). One line per
# crate: a shared invocation would unify dev-dependency features across the crates. State is
# hashed with SHA-256 only (`StateHasher`): fail if another hash crate reaches the state crate
# (on any target), or if nomt-core's built-in hashers get enabled anywhere (under any workspace
# feature, on any target).
guest:
	cargo clippy -p selendra-interface --no-default-features --locked -- -D warnings
	cargo clippy -p selendra-primitives --no-default-features --locked -- -D warnings
	cargo clippy -p selendra-state --no-default-features --all-targets --locked -- -D warnings
	cargo test -p selendra-state --no-default-features --locked
	cargo clippy -p selendra-mock-da --no-default-features --all-targets --locked -- -D warnings
	cargo test -p selendra-mock-da --no-default-features --locked
	cargo clippy -p selendra-mock-zkvm --no-default-features --all-targets --locked -- -D warnings
	cargo test -p selendra-mock-zkvm --no-default-features --locked
	cargo clippy -p selendra-modules-api --no-default-features --all-targets --locked -- -D warnings
	cargo test -p selendra-modules-api --no-default-features --locked
	$(call tree_lacks,-p selendra-interface -p selendra-primitives -p selendra-state -p selendra-mock-da -p selendra-mock-zkvm -p selendra-modules-api --no-default-features -e normal --locked,getrandom)
	$(call tree_lacks,-p selendra-state --no-default-features -e normal --target all --locked,(blake3|sha3) v)
	$(call tree_lacks,-e features -i nomt-core --all-features --target all --locked,sha2-hasher|blake3-hasher)

test:
	cargo test --workspace --all-features --locked

# Tests with a 32-bit `usize`, like the SP1 guest (musl: no 32-bit system libraries needed).
# Every feature except the node's storage stack (RocksDB and NOMT are not built for 32-bit
# targets): the `rockbound` and `selendra-db` crates and `selendra-state/rockbound` are left out.
# `selendra-interface/native` makes each crate's `native` mandatory (its `__if_native!` guard).
# Cargo builds proc-macro crates for the host, so `selendra-macros`' tests build and run on the
# host here; what its derives generate is tested 32-bit by `selendra-modules-api`'s tests.
TEST32_FEATURES := selendra-interface/native,selendra-interface/arbitrary,selendra-primitives/native,selendra-state/native,selendra-state/arbitrary,selendra-mock-da/native,selendra-mock-zkvm/native,selendra-modules-api/native,selendra-modules-api/arbitrary
test32:
	rustup target add i686-unknown-linux-musl
	cargo test --workspace --exclude rockbound --exclude selendra-db --features $(TEST32_FEATURES) --locked --target i686-unknown-linux-musl
	cargo test -p selendra-state --no-default-features --locked --target i686-unknown-linux-musl
	cargo test -p selendra-mock-da --no-default-features --locked --target i686-unknown-linux-musl
	cargo test -p selendra-mock-zkvm --no-default-features --locked --target i686-unknown-linux-musl
	cargo test -p selendra-modules-api --no-default-features --locked --target i686-unknown-linux-musl

# `compile_fail` doctests pin the error they fail with (```compile_fail,E0277). Stable rustdoc
# only checks that compilation fails, so a doctest broken by a typo or a missing import would
# still pass; nightly rustdoc also checks the code. Every `compile_fail` doctest must name one
# (the grep: `compile_fail` anywhere in a fence's info string, e.g. ```rust,compile_fail, must
# be followed in it by an `E####` code), and every doctest runs on nightly in both
# configurations `make test` and `make guest` run doctests in (all features; `selendra-state`,
# the mock adapters and `selendra-modules-api` without default features, one line per crate as
# in `make guest`).
# `RUSTFLAGS=""`: nightly may add warnings unrelated to the doctests.
doctest-codes:
	! grep -rnE --include='*.rs' '```[^`]*compile_fail' crates | grep -vE '```[^`]*compile_fail[^`]*E[0-9]{4}'
	RUSTFLAGS="" cargo +nightly test --doc --workspace --all-features --locked --no-fail-fast
	RUSTFLAGS="" cargo +nightly test --doc -p selendra-state --no-default-features --locked
	RUSTFLAGS="" cargo +nightly test --doc -p selendra-mock-da --no-default-features --locked
	RUSTFLAGS="" cargo +nightly test --doc -p selendra-mock-zkvm --no-default-features --locked
	RUSTFLAGS="" cargo +nightly test --doc -p selendra-modules-api --no-default-features --locked

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

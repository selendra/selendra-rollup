# Selendra — Build TODO

Own chain, own workspace, own crate names (`selendra-*`). No dependency on `sov-*` crates.
Sovereign SDK code (commit `c7046e2`, local copy `~/Projects/sovereign-sdk`, see `docs/sovereign-sdk-architecture.md`) is **copied in and adapted** where it saves time or is security-critical.

Legend: 🔁 = copy & adapt from Sovereign · ✍️ = write ourselves · ⚠️ = security-critical, needs review + tests before merge

---

## Decisions (locked)

| Topic | Decision | Notes |
|---|---|---|
| Chain type | **zk rollup on external DA** | No own consensus/validators; reuse Sovereign architecture |
| DA layer | **Avail** | Chosen for KZG validity proofs + DAS. Sovereign adapter is a stub → we finish it (Phase 9) |
| EVM | **Enabled by default** (`sov-evm`, revm) | Ethereum JSON-RPC + MetaMask/Foundry support from day one |
| Address type | **`MultiAddressEvm`** = `Standard` (28-byte, bech32m) or `Vm` (20-byte `0x…`) | Standard prefix **`sel`** instead of `sov` |
| Address prefix | `ADDRESS_PREFIX = "sel"` — Rust constant in `selendra-primitives::address` (not overridable config) | Must be set **before genesis**; e.g. `sel16adfsqvzky9t042tlmfujeq88g8wzuhnm2nzxfd0qgdxsudeldf` |
| Keys | ed25519 (`sel1…`) + secp256k1 (`0x…`, EIP-712 / Ethereum txs) | |
| zkVM | SP1 (only adapter with proof aggregation) | Has BLS12-381, keccak, ed25519 precompiles |
| Sequencing | **Preferred sequencer, 1 s soft blocks, lazy DA posting** | Post to Avail when `max_txs` reached OR `max_age` elapsed; **never post when empty** |
| Sequencing params | **On-chain, no hard-coded limits, changeable by governance at runtime** | `block_time_ms`, `max_txs`, `max_bytes`, `max_age_secs`, `deferred_slots_count` stored in kernel state (Phase 11) |
| Operating mode | **`Operator` at launch → `Zk` for mainnet; skip `Optimistic`** | Sovereign sets mode only at genesis → we add a governance switch (Phase 6) |
| Governance | **Testing: single admin key, no multisig, no timelock** → before public testnet/mainnet: multisig + `timelock` → token governance (SEL) | Admin controls: sequencing params, operating mode, SEL mint/burn, fee-token list & rates. Admin address is config, not hard-coded |
| Genesis allocation (testing) | **All 300,000,000 SEL to team test accounts**:<br>`sel1fs6stajfuu65eavsgujjx2slhydhk7xakzlqum35cs72ydqpl45` (ed25519) → 150,000,000 SEL<br>`0x02f9647E14d07ac4c76295ed34eBa30a47b626A3` (secp256k1, MetaMask) → 150,000,000 SEL | Random **test-only** keys in `keys/*.key` (gitignored). Same accounts act as admin. Replace with real addresses via genesis config before any public network |
| EVM chain ID | **1961** (Selendra; configurable in genesis) | Registered in `ethereum-lists/chains` as "Selendra Network Mainnet" (`eip155-1961.json`, symbol SEL, 18 decimals); 1953 = Selendra Network Testnet. ⚠️ The existing Selendra mainnet uses 1961 too: while both chains are live, an EIP-155 tx signed for one is valid on the other (same keys, same `0x` accounts) → decide migration/shutdown of the old chain, or use a different ID for testnets |
| Gas / native token | **Name `Selendra`, symbol `SEL`, 18 decimals, genesis supply 300,000,000 SEL** | = 300,000,000 × 10¹⁸ = 3 × 10²⁶ base units (fits `Amount(u128)`). Supply changeable later by governance mint/burn. Same token is EVM native currency (1:1, no scaling) |
| Multi-token gas | **SEL = default fee token; other fee tokens priced by price oracle** | Admin approves which tokens are allowed; their SEL rate comes from the oracle (`token/USD ÷ SEL/USD`). Native txs may pay in any allowed token; EVM txs pay in SEL. Not in Sovereign → new `fee-tokens` + `price-oracle` modules (Phase 6) |
| Sponsored fees | **Any account (dApp) can pay fees for a list of accounts**, limited to its own contracts, with per-tx / per-account / total budget limits and expiry | Many sponsorships at once (Sovereign `paymaster` allows only one payer per sequencer) → new `fee-sponsor` module (Phase 6) |
| State-root hash | **SHA-256** (NOMT trees + `global_root`) | 128-bit collision security, most-studied hash, SP1 precompile. Alternatives (SHA3/Keccak equal; BLAKE3/Poseidon less margin; SHA-512 variants no precompile) don't add real security. EVM still uses Keccak-256 internally (Ethereum standard) |
| Fee model | **EIP-1559 base fee (2 gas dimensions) + optional tip; on-chain params changeable by admin at runtime** | Base fee → 10% burned / 90% provers; tip → sequencer. Params in `fee-params` state (Phase 6), not compile-time `constants.toml` |
| Fee genesis values | `initial_base_fee_per_gas = [1 gwei, 1 gwei]` (10⁹ base units of SEL)<br>`base_fee_max_change_denominator = 48` (≈ 2 %/s with 1 s blocks)<br>`elasticity_multiplier = 2` (target 50 % full)<br>`percent_base_fee_to_burn = 10`<br>`min_base_fee_per_gas = [0.1 gwei, 0.1 gwei]` (floor)<br>`block_gas_limit = [1e11, 1e11]` (Sovereign default, **devnet only** → set from SP1 benchmark)<br>`max_tx_gas = [1e9, 1e9]`, `max_forced_tx_gas = [5e5, 5e5]`<br>`max_batch_size_bytes` = Avail per-extrinsic limit | Rule for `block_gas_limit`: a full 1 s block must be provable in < 1 s on the prover setup |
| Genesis values | `block_time_ms = 1000` (1 s blocks)<br>`max_txs = 1000` (post when ≥ 1000 txs buffered)<br>`max_age_secs = 3600` (post at least every 1 h **if** any tx)<br>`skip_if_empty = true` (no txs → no DA submission)<br>`deferred_slots_count = 240` (~80 min on Avail; must stay > 180 slots = 1 h) | `max_bytes` set from Avail's per-extrinsic data limit (check current value) |

## Phase 0 — Remaining decisions

- [ ] Before public testnet: real genesis allocation (team, treasury, sequencer bond, prover rewards, faucet…)
- [ ] Before public testnet: multisig signers + threshold (e.g. 3-of-5) and timelock delay (e.g. 48 h)
- [x] EVM chain ID: 1961 (already registered to Selendra Network Mainnet)
- [ ] Before public testnet: replay plan vs the existing Selendra mainnet (also 1961) — migrate/retire old chain, or give testnets their own ID (1953 is the existing Selendra testnet; update the `ethereum-lists/chains` entry's RPC/explorer when the rollup goes live). Same for native txs: `SELENDRA_CHAIN_ID` (signed-bytes header) is a const today → per-network genesis config, distinct on every non-mainnet network, or devnet/testnet txs signed with the team test keys replay on mainnet (Phase 5 authenticator item)
- [ ] First extra fee tokens (e.g. bridged USDC/USDT?)
- [ ] Oracle provider: Pyth (pull model, Wormhole-signed, works on any chain — recommended) vs RedStone vs Chainlink (needs deployment)
- [ ] SEL/USD source while SEL has no market: admin-set price → later on-chain DEX TWAP (SEL/USDC) with bounds
- [x] Write the Selendra overview: `README.md` (was `docs/selendra.md`); the locked decisions are the table above (keep both in sync when decisions change)

## Phase 1 — Repo & tooling

- [x] `git init`, Cargo workspace, `rust-toolchain.toml` (pin version), `rustfmt.toml`, `clippy.toml` — Rust 1.93.0 (same as upstream), edition 2024
- [ ] Crate layout: `crates/{primitives,interface,state,modules-api,macros,stf,kernel,modules/*,node,sequencer,db,adapters/{avail,mock-da,sp1,mock-zkvm},evm,cli}` — created one at a time when its code is written: add to `members` in `Cargo.toml`, use `[lints] workspace = true`, `#![forbid(unsafe_code)]` in the crate root
- [x] CI: fmt, clippy `-D warnings`, guest build (no `native`, no `getrandom`; `selendra-state` tests run there too), test, 32-bit test (`usize` like the SP1 guest), `cargo deny` (licenses/advisories), `cargo audit`, `cargo udeps`, fuzz (60 s per push, 30 min nightly) — `.github/workflows/ci.yml`, same checks via `make ci`
- [x] `#![forbid(unsafe_code)]` everywhere except where justified — workspace lint + attribute in every crate root
- [x] Track copied code: `docs/provenance.md` — file → upstream path + commit + what changed (needed for future upstream security patches)
- [x] Script to diff our copied files against upstream for security fixes — `scripts/upstream-diff.sh`

## Phase 2 — Core interface (the traits) 🔁

From `crates/rollup-interface`:
- [x] 🔁 `DaSpec`, `DaVerifier`, `BlobReaderTrait`, `DaService` → `selendra-interface::da` (state machine) + `::node::da` (native only)
- [x] 🔁 `StateTransitionFunction`, `ApplySlotOutput`, `ExecutionContext`, tx receipts/outcomes → `::stf` (optimistic-mode parts stripped; incl. `StateTransitionVerifier`, native-only `ProofSender`)
- [x] 🔁 `Zkvm`, `ZkvmHost`, `ZkvmGuest`, `ZkVerifier`, `OuterZkvmHost` → `::zk` (public outputs borsh-only; `CryptoSpec` comes with Phase 3; aggregation `circuit` with Phase 12)
- [x] 🔁 `StateTransitionPublicData` (proof public outputs) ⚠️ — copied, borsh-encoded; ⚠️ review still open (Phase 14)
- [x] ✍️ Strip what we don't need (Risc0, Celestia-specific bits, unused generics) — never copied Risc0/Celestia/optimistic/light client; removed dead `StateTransitionConfig` markers + `CheckedMath`; upstream wording → Selendra/Avail
- Selendra `Spec` moved to Phase 5 (needs the `Spec` trait, `MultiAddressEvm` from Phase 3, Avail + SP1 from Phase 9)

## Phase 3 — Crypto, primitives & addresses ⚠️

- [x] 🔁 Crypto spec, key types, signature verify wrappers (audited crates: `ed25519-consensus`, `k256`, `sha2`); re-add `ZkVerifier::CryptoSpec` (removed in Phase 2, without `sovereign_admin_pubkey`) — traits in `selendra-interface::crypto`, ed25519 + `Ed25519CryptoSpec` in `selendra-primitives`; `sha2 =0.10.9` / `ed25519-consensus =2.1.0` pinned for SP1 patches; secp256k1 (`k256`) comes with `EthereumPublicKey` below
- [x] 🔁 `Address` (28-byte, bech32m) from `sov-modules-api/src/common/address.rs` — `selendra-primitives::Address`; strict canonical decoding (upstream accepted extra padding symbols / non-zero padding bits); `Base58Address` dropped
- [x] ✍️ Set `ADDRESS_PREFIX = "sel"` in `constants.toml`; rename `sov` in schemas, JSON schema pattern, CLI, docs, TS clients — Rust const instead of `constants.toml`; JSON schema `^sel1[bech32 charset]{51}$`; docs already `sel1`; CLI + TS clients don't exist yet (Phase 13 must use `sel`)
- [x] ✍️ Update test vectors: `[1..=28]` → `sel1…`, `[11; 28]` → `sel1…`; add the RFC 8032 key vector — cross-checked with an independent BIP-350 encoder; plus a test for the team genesis address
- [x] ✍️ Reject `sov1…` addresses (wrong HRP) — test it
- [x] 🔁 `MultiAddress<EthereumAddress>` + `EthereumAddress` + `EthereumPublicKey` from `sov-address` (feature `evm`) — in `selendra-primitives`, always on; no `From<CredentialId>` (keys own accounts); canonical secp256k1 keys/low-S signatures; `k256` 0.14 (advisory)
- [x] ✍️ Test `Standard`/`Vm` parsing: 28 bytes vs 20 bytes, `sel` prefix vs `0x` — plus team genesis accounts (`sel1fs6…`, `0x02f9…`) pinned in tests
- [x] ✍️ Chain ID + domain separation in every signed message (prevent cross-chain replay) — `selendra_primitives::signing`: signs `0xB5 "SELENDRA" | version | domain | chain_id (u64 LE) | payload`, `SigningDomain::{Transaction, SequencerBlob, OffchainMessage}`, `SELENDRA_CHAIN_ID = 1961`; replaces upstream's `chain_hash`; first byte can't start an Ethereum tx or EIP-191/712 message. Ethereum txs keep EIP-155 (Phase 7)
- [x] 🔁 Borsh serialization conventions; ✍️ fuzz all decoders (`cargo fuzz`) — rules in `docs/serialization.md`; `fuzz/` targets `addresses`, `keys`, `tx_decoding` (no panic + canonical round-trip), in CI + `make fuzz`. Fuzzing found: `k256` accepted SEC1 compact (`0x05`) keys as a 2nd encoding → only `0x02/0x03/0x04` accepted, borsh decode rejects non-canonical bytes. Add a target for every new decoder
- [x] ✍️ No-panic review of all parsing code — fixed: `FullyBakedTx` accepted any non-zero `Option` tag (now only 0/1) and `data_len + seq_len` could overflow on the 32-bit zk guest; `BlobReaderTrait::full_data` slicing now saturates; bech32 payload size bounded at compile time. An independent audit (4 reviewers + adversarial verification) then found and we fixed: ed25519 public keys accepted small-order points (anyone can sign) and non-canonical encodings; hex strings accepted a missing `0x` and any case; `FullyBakedTx`/`RawTx` JSON accepted unpadded base64, unknown fields and the array form (last one found by the fuzzer's new JSON round-trip check); slot numbers parsed `+5`/`005`. The Sovereign comparison audit (our code vs upstream `c7046e2`, each risk checked by 2 skeptics) then found and we fixed: ⚠️ ed25519 signatures accepted non-canonical `R` (`y ≥ p`, sign bit on `x = 0`) and `s ≥ l` — `y ≥ p` was a native/guest split that upstream has too (native dalek-ng decodes it under ZIP-215, SP1's patched dalek-ng rejects it: a key holder could sign a tx nodes accept and the prover cannot prove) → byte checks in every constructor (`from_bytes`/borsh/serde/`FromStr`), `verify` re-checks, no public `From<ed25519_consensus::Signature>`; private key `as_hex()` returned hex without `0x` (now `0x` form = JSON). Re-review each new decoder (Phases 4–9)

## Phase 4 — State & storage ⚠️

From `sov-state`, `sov-db`:
- [x] 🔁 State containers: `StateValue/Map/Vec` + Kernel + Accessory namespaces — new crate `selendra-state`: namespaces, `Prefix`/`SlotKey`/`SlotValue`, `BorshCodec`/`EncodeLike`, `StateReader`/`StateWriter` per namespace (no gas yet), containers + `Borrowed`/`BorrowedMut`. Fixed: `StateVec` stored elements at item `+128` (panicked for item ≥ 128, collided with that item) → elements at `prefix ‖ u64 LE index`, layout pinned in `docs/serialization.md`; vec iterator's `ExactSizeIterator` panicked on 32-bit (`try_into().unwrap()`) and retried errors forever; `SlotKey::from_slice` panicked on < 2 bytes (now fallible `try_from_bytes`); `Namespace` JSON accepted `{"user":null}`; `BorrowedMut` drop guard needed `unsafe` (now `#[must_use]` + a debug-build panic when a modified borrow is dropped unsaved). `SlotKey` is one `Arc<[u8]>` (no inline/heap dual form). `vec.remove` shifts raw bytes. Fuzz target `state_keys`. Review fixes: vec ops order writes so a failed write (out of gas) never leaves a hole in `0..len` (upstream `clear`/`pop`/`set_all` could) and `vec.get` checks `len` (returned leftovers past `len`); container ops are not atomic → caller must revert on `Err` (Phase 5); decode-panic message capped at 32 bytes (hex-dumped whole values); write-only accessory access pinned by `compile_fail` doctests. Decode failure of stored bytes still panics — causes documented on `StateReader::get_decoded`: stored type breaks the round-trip precondition (`decode(encode(v))` must succeed; debug-asserted on every write), prefix collision/corruption, or an invalid witness in the guest (must stay a panic) — ⚠️ review in Phase 14. Deferred: raw/proof APIs (done with the Storage item below), `TxState`/gas/events and `push_accessory` (Phase 5), `BcsCodec` (Phase 6/7 encoding item), `VersionedStateValue` (Phase 8)
- [x] 🔁 `Storage` trait, `StateCheckpoint`, witness (`ArrayWitness`) — also port the deferred container APIs that need it: `get_with_proof`/`verify_proof` (value, map), native raw APIs (`get_raw`/`set_raw`/`remove_raw`, map `iter_raw`/`iter_raw_from_keys`, vec `push_raw`/`pop_raw`/`iter_raw`), `arbitrary_state_map` — all in `selendra-state` (features `native`, `arbitrary`): `Storage`/`NativeStorage`/`StateRoot`/`StorageProof`/`NodeLeaf` + `val_hash_and_size` (`storage.rs`), `Witness`/`ArrayWitness`, `ProvableStorageCache`/`StateAccesses`, `StateCheckpoint<St: Storage>` (no kernel/version fields) with `AccessoryDelta`/`AccessoryStateCheckpoint`, `ProvenStateAccessor`. Fixed: map `verify_proof` never checked the key's prefix → another container's entry was accepted as this map's (now prefix + canonical key re-encoding checked); witness hints ignored trailing bytes (`from_slice` now); accessory delete on the checkpoint dropped the pending write instead of recording it (deleting a committed value did nothing); `pop_raw` deleted before shrinking `len` (hole on a failed write); `SlotValue::size` panicked over `u32::MAX` (now saturating, unreachable in the 32-bit guest); `StorageProof` JSON non-canonical (missing `value`, array form); poisoned witness lock `unwrap`ped. Design: `StateCheckpoint` has no `StateReader<Accessory>` (STF writes accessory state, never reads it; `compile_fail` doctests), `get_accessory` moved to `NativeStorage`, leaf hints are bare `Option<NodeLeaf>`, `verify_proof` generic over `St: Storage` and not native-only, `ProvenStateAccessor` needs only `StateReader`, `arbitrary_state_map` takes any infallible writer, `materialize_update` panics on `compute_state_update` errors (guest: invalid witness → no proof), caches are `BTreeMap`s (a simplicity/performance trade, not a determinism fix: upstream sorted its writes at freeze; native lookups ~3× slower → Phase 11 benchmark). ⚠️ documented: `discard_revertable_storage_cache` drops reads from verification while their hints stay in the witness → sequencer-only (Phase 8). Test storage (prover/verifier modes, SHA-256 root) + replay proptest (prover vs witness-only verifier: same results, accesses, root) + tamper proptest (changing any byte of any hint must make the verifier panic or the state update fail: catches a cache that stops verifying a class of reads, which the honest replay cannot) + lying leaf/kernel/absent hint tests; the crate has no self dev-dependency enabling `native`, so its tests also run in the guest configuration (`make guest`, and 32-bit in `make test32`). Upstream's cache `get_or_fetch_historical`/`get_size_or_fetch_historical` dropped (never called upstream; they put another version's value into the verified read set and served it to later current reads) — historical reads go to `NativeStorage` directly (documented there). Fuzz target `state_witness` (`ArrayWitness`, hints, `NodeLeaf`, `StorageProof`). Deferred: `StateGetter`/`MaybePresentValue`/uncommitted-changes overlay (Phase 11), `StorageRoot` (two-root item), version fields/`TempCache`/gas/metrics (Phase 5), `ApiStateAccessor` (Phase 13), witness-consumed check in the guest STF (Phase 8)
- [ ] 🔁 NOMT backend: `NomtProverStorage` (native) + `NomtVerifierStorage` (guest) — guest reads return unverified witness hints, so a stored value that fails to decode means an invalid witness: `decode_unwrap` must keep panicking there (never a recoverable error); pin `nomt` 1.0.5; implement `selendra_state::Storage`/`NativeStorage` (leaf helpers `NodeLeaf`, `val_hash_and_size`, `SlotValue::combine_val_hash_and_size` and the saturating `SlotValue::size` already exist); follow the witness protocol on `Storage` with leaf hints as `Option<NodeLeaf>` (upstream: `NodeLeafAndMaybeValue` + an asserted `ReadType` tag); verify every read in `compute_state_update` (upstream's verifier does; keep the multi-proof hint per accessed namespace); leftover hints are rejected by the guest STF, not the storage (`Witness::ensure_consumed` after `materialize_update`, Phase 8; upstream asserts `witness.is_empty()` in `sov-modules-stf-blueprint`, and its `prover_storage.rs` tests check it too); `maybe_iter_*` in ascending key order (now documented on `NativeStorage`); port the `prover_storage.rs` tests (stale storage, proofs). Progress — guest half done in `selendra-state` (`nomt-core` =1.0.5, no `std`, in the guest): `StorageRoot<S>` (64 raw bytes / one hex string; `global_root` = `H("SELENDRA/state-root/v1" ‖ user ‖ kernel)`, tagged because upstream's untagged 64-byte preimage is a NOMT internal node), `NomtProof` (canonical `MultiProof`: decoding rejects non-canonical terminator positions, depth > 256, unsorted/prefix paths, wrong sibling count, non-canonical bytes — upstream's `MultiProof` was malleable and made verification panic), `verify_storage_proof`, `verify_namespace` (every read confirmed; also rejects proof paths no access needs), `namespace_needs_proof`, `NomtVerifierStorage`; tests against real NOMT sessions (test-only mini prover, 64-bit Unix): replay, tamper, lying hints, stale root, untouched namespace, proofs; fuzzed in `state_witness`. Found: NOMT 1.0.5 panics committing a session whose only value changes are deletes of absent keys into an empty database (underflow in `beatree/ops/update/leaf_stage.rs`, with our `overflow-checks` also in release) → the prover must turn such deletes into `Read(None)` (the test prover does). Remaining: `NomtProverStorage` + `NativeStorage` impl in a node-only db crate (blocked: RocksDB needs libclang, missing here), vendored rockbound (B1–B3 fixes), the `prover_storage.rs` test ports
- [ ] 🔁 Two-root commitment `user_root || kernel_root` → `global_root()` — port `StorageRoot<S: MerkleProofSpec>` (`sov-state/src/storage_internals.rs`, deferred from the Storage item) implementing `selendra_state::StateRoot`; `PRE_GENESIS_ROOT` from NOMT's terminator. Progress: ported in full (`crates/state/src/storage_root.rs`, tagged `global_root`, `StorageRoot::PRE_GENESIS`; see the NOMT item above) — nothing left to port; tick with that item's guest half
- [ ] 🔁 `rockbound` (RocksDB wrapper) or plain `rocksdb` — rockbound's `VersionedSchemaKeyMarker`/`HasPrefix` impls for `SlotKey` must live in `selendra-state` (orphan rule, E0117): optional `rockbound` dependency under `native`, not a newtype key
- [ ] 🔁 `NomtStorageManager` (fork-aware overlays, finalize, pruning)
- [ ] 🔁 Ledger DB schema (slots, batches, txs, events, proofs, state roots, STF infos)
- [ ] ✍️ Drop legacy `user_jmt_values` column-family names (fresh chain, no compat needed)
- [ ] ✍️ Property tests: native root == guest root for random read/write sets. Progress: `nomt::tests::verifier_replays_the_nomt_prover` checks it for the guest verifier against the real-NOMT test prover; re-run it on the real `NomtProverStorage`
- [ ] ✍️ Hash = SHA-256 everywhere in state (`sha2` with SP1-patched precompile in guest); single `Hasher` type in `Spec`, no mixing
- [ ] ✍️ Verify Merkle domain separation: leaf vs internal node prefixes in NOMT; user vs kernel root combination in `global_root()` ⚠️
- [ ] ✍️ Verify keys are hashed before tree insertion (`H(key)`) — attacker can't choose tree positions. Progress: the guest verifier does (`H(whole SlotKey)`), pinned by known-answer vectors (`nomt/vectors.rs`); check the real prover

## Phase 5 — Module system

From `sov-modules-api`, `sov-modules-macros`:
- [ ] 🔁 `Module` trait, `ModuleInfo`, `Context`, `TxState`, events, errors — accessors on `selendra-state`'s `StateReader`/`StateWriter` (`TxState`, `GenesisState`, `StateAccessor`, `VersionReader`, `PerBlockCache`, `EventContainer`/`TypeErasedEvent`); `ModuleInfo` assigns unique `Prefix`es
  - ⚠️ Any accessor `Err` (out of gas) must revert **all** of the transaction's writes: container ops are not atomic (`selendra-state` docs); modules must not catch the error and keep going with the writes kept
  - `StateCheckpoint` (Storage item) has no version fields, `TempCache`/`PerBlockCache`, gas or metrics yet: add the visible slot number + rollup height with `VersionReader` (read from the kernel when the checkpoint is created; upstream `BootstrapWorkingSet`, no `unimplemented!()` writer) — ⚠️ the kernel reads must run on the new checkpoint itself (e.g. `StateCheckpoint::new_with(storage, witness, |cp| …)`), so they are first reads verified against the root in the same order natively and in the guest; values passed in from outside (another checkpoint, storage) are unverified in the guest. Replay test: the bootstrap reads appear in the ordered reads; `type SpecCheckpoint<S> = StateCheckpoint<<S as Spec>::Storage>` keeps the port mechanical; `TempCache`/`BorshSerializedSize`, `RevertableWriter`/`TxScratchpad` (upstream `internals.rs`), metrics. Gas: the metering hook trait must never be implemented for `StateCheckpoint` itself (its concrete `StateReader`/`StateWriter` impls would overlap the blanket impls); metered `get_size` goes through `StateCheckpoint::get_size`
  - Bound state value sizes (gas per written byte, or an explicit maximum): `SlotValue::size` saturates at `u32::MAX`, and a value the 32-bit guest cannot hold makes the block unprovable
  - `push_accessory` (upstream: append to an `AccessoryStateVec` with a write-only accessory accessor, reading the length through the sealed `UniversalStateAccessor` that `selendra-state` dropped): needs a new capability, e.g. an unmetered accessory-length read implemented only by `TxState` that does **not** grant `StateReader<Accessory>` (that would let the STF read non-provable state → native/zk divergence). Upstream has no callers: drop it unless a module needs it
  - Orphan rule: upstream's metering blanket impls (`impl<T: ProvableStateReader<User>> StateReader<User> for T`, same for `Kernel`/`Accessory`/writers) can't be written outside `selendra-state` (E0210: trait and namespace markers are foreign). Plan: add a metering hook trait to `selendra-state` (e.g. `MeteredAccess<N>` with raw get/set/delete + charge hooks) with the blanket `StateReader`/`StateWriter` impls next to the traits, so every accessor is metered in one place; fallback: a local `Metered<T>` newtype. Not per-type hand-written impls (easy to forget charging gas). ⚠️ The hook's raw get/set/delete must be unreachable from module code (upstream: sealed `UniversalStateAccessor`): sealed trait or an unforgeable capability, plus a `compile_fail` doctest; `UnmeteredStateWrapper`/`to_unmetered` (EVM) only behind an `evm`/`test-utils` feature like upstream
  - State value types: no floats, infallible `BorshSerialize`, and the round-trip precondition (`decode(encode(v))` succeeds for every constructible `v`) — have the module derive macros reject float fields; fix `RawTx`/`FullyBakedTx` (private fields + fallible constructor bounded by `MAX_RAW_TX_SIZE`/`MAX_FULLY_BAKED_TX_SIZE`, or a size check in `BorshSerialize`) before any module stores them
- [ ] 🔁 `SafeVec` (`common/safe_vec.rs` + its `HexString<SafeVec<u8, N>>` JSON schema) into `selendra-interface` before porting modules, with a provenance row ⚠️ — 53 upstream files use it as a decode-time length cap on call messages (EVM allowlist, hyperlane bodies); swapping in `Vec` drops the caps
- [ ] 🔁 `Spec` trait (`sov-modules-api/src/module/spec.rs`) — ⚠️ upstream bound `Address: From<CredentialId>` (~58 sites: tx `default_address`, sov-accounts, simulate, sov-cli, test utils) → key-aware mapping instead (`for<'a> From<&'a PublicKey>` or a `CanonicalAddress` trait that knows the key kind). Never add `From<CredentialId>` for `MultiAddress` (an EVM key's account would become a `sel1…` nobody funds — upstream's bug); sov-accounts' canonical fallback = the authenticator's `default_address`, not `cred.into()`; sov-cli derives the address from the public key; test that an EVM key resolves to `Vm(0x…)` on every path; consider making `Address::from(CredentialId)` `pub(crate)` or renaming it
- [ ] ✍️ Selendra `Spec`: generic `SelendraSpec<Da, InnerZkvm, OuterZkvm>` with `Address = MultiAddressEvm`, `CryptoSpec`; mock DA + mock zkVM instance for M1; `Da = AvailDaSpec`, `InnerZkvm/OuterZkvm = SP1` instance in Phase 9
- [ ] 🔁 Derive macros: `ModuleInfo`, `Genesis`, `DispatchCall`, `Event`, `Hooks`, `MessageCodec`
- [ ] 🔁 Hooks: pre/post dispatch tx, begin/end block, finalize
- [ ] 🔁 Gas metering (`SlotGasMeter`, per-tx gas, base fee) — metered accessors override `StateReader::get_decoded` to charge for decoding (in the one blanket impl; test: metered `get_decoded` of an N-byte value costs N × the per-byte borsh rate more than `get`). `StateVec::get` reads `len` + element (upstream: one read) → double read gas; loops should use `iter()` (reads `len` once)
- [ ] 🔁 Capabilities traits: `GasEnforcer`, `TransactionAuthenticator`, `TransactionAuthorizer`, `SequencerAuthorization`, `SequencerRemuneration`, `ProofProcessor` ⚠️
- [ ] 🔁 Authenticator that accepts both native (ed25519) and Ethereum (secp256k1 RLP / EIP-712) txs — native txs verify via `selendra_primitives::signing` with `SigningDomain::Transaction` (not upstream's `chain_hash`); Ethereum txs via EIP-155 with chain ID 1961
  - ⚠️ Runtime binding: upstream's `chain_hash` also commits to the runtime schema, so after an upgrade a held-back tx can't decode as a different call. Add a runtime version or schema hash to the signed bytes, with an accepted-versions grace window like upstream's. Chain ID from genesis config per network (const `SELENDRA_CHAIN_ID` today; Phase 0 replay item)
  - ⚠️ Type-enforced domain separation: `Signature::verify`/`PrivateKey::sign` take any bytes, so a port that drops the wrapper still passes every test. Newtype that only `signing::signing_bytes` can build, taken by the authenticator and `Transaction::sign`/verify; regression test: a signature over the bare payload is rejected by the authenticator
  - EIP-712/EIP-155 txs are the exception to the `0xB5` header (documented in `signing.rs`): build the EIP-712 domain (chain ID, name, version, salt carrying the runtime commitment) in the authenticator. Native secp256k1 txs and `OffchainMessage` are software-key only (browser/hardware wallets can't sign `0xB5…` bytes); MetaMask users go through EIP-712, login via EIP-4361/`personal_sign`
- [ ] ✍️ Rename/re-namespace everything; remove `sov-revenue-share` coupling
- [ ] Later: `UniversalWallet`, `RuntimeRestApi`, `CliWallet` derives — orphan rule: `UniversalWallet` impls for `CredentialId`, `HexString`, `SlotNumber`, `Time`, keys/signatures and the `BasicAddress`/`PublicKey`/`Signature` bounds can only be added inside `selendra-interface`/`selendra-primitives` → optional `universal-wallet` feature with `cfg_attr` derives there (else module call messages fail with E0277); the schema's hex parsing must match our serde rules; clear-signing display shows/prepends the `0xB5 "SELENDRA"` header (`signing.rs` module doc), not just the payload

## Phase 6 — Core modules ⚠️

- [ ] 🔁 `accounts` (credential → address) — canonical fallback via the authenticator's `default_address`, not `cred.into()` (Phase 5 `Spec` item)
- [ ] 🔁 `bank` (tokens, gas token, mint/burn auth) — highest-risk module, extra tests

### Native token SEL ⚠️
- [ ] ✍️ `constants.toml`: `GAS_TOKEN_DECIMALS = 18` (Sovereign default is 6); generate new Selendra `GAS_TOKEN_ID`
- [ ] ✍️ Bank genesis `gas_token_config`: `token_name = "Selendra"`, `token_decimals = 18`, balances = team test accounts (150,000,000 × 10¹⁸ = 1.5 × 10²⁶ each), `admins = [admin]` (→ timelock later)
- [ ] ✍️ Add `symbol` to token metadata (Sovereign bank has **no symbol field**) → `SEL`; expose via `/modules/bank/tokens/{id}/metadata`
- [ ] ✍️ Supply changes only via governance `mint` / `burn` (through timelock); emit events; track `total_supply`
- [ ] ✍️ Overflow tests at 18 decimals (u128 max ≈ 3.4 × 10³⁸ base units ≈ 3.4 × 10²⁰ SEL — plenty, but test mint paths)
- [ ] ✍️ EVM native balance = bank SEL balance, 1:1 (both 18 decimals); MetaMask `nativeCurrency { name: "Selendra", symbol: "SEL", decimals: 18 }`

### Multi-token gas (new, not in Sovereign) ⚠️
- [ ] ✍️ `fee-tokens` module: admin-managed list `{token_id, oracle_feed_id, enabled, fee_margin_bps}`; SEL is always enabled and the default
- [ ] ✍️ `price-oracle` module (kernel/user state): latest `{feed_id, price, conf, expo, publish_time}` per feed
- [ ] ✍️ Pyth integration: sequencer fetches signed updates (Hermes API) and posts an `update_prices` tx at the start of a block when prices move or get old
- [ ] ✍️ STF verifies updates on-chain: Wormhole VAA guardian signatures (secp256k1, ≥ 13/19) + Merkle proof of price in the update; reject older `publish_time` ⚠️
- [ ] ✍️ Track Wormhole guardian-set upgrades (governance VAAs) — wrong guardian set = forged prices ⚠️
- [ ] ✍️ Rate = `token_usd / sel_usd`; SEL/USD from admin-set price until a liquid market exists, then DEX TWAP
- [ ] ✍️ Safety checks before using a price: **staleness** (e.g. > 60 s old → token disabled for fees), **confidence** (conf/price > threshold → disabled), **max change per update**, circuit breaker; fall back to SEL-only
- [ ] ✍️ Charge with `fee_margin_bps` safety margin; use the price least favourable to the payer (price − conf); refund unused gas at the same rate
- [ ] ✍️ Benchmark: Wormhole signature checks inside SP1 (secp256k1 precompile) per price update
- [ ] ✍️ Tx field `fee_token` for native txs (default SEL); include it in signed bytes
- [ ] ✍️ Modify `GasEnforcer` capability: reserve gas in chosen token at `sel_rate` (+ safety margin), refund unused in same token
- [ ] ✍️ Sequencer: accept/reject per fee token; `minimum_profit_per_tx` per token
- [ ] ✍️ Where fee-token fees go: sequencer / prover rewards / treasury (decide split)
- [ ] ✍️ EVM txs pay gas in SEL only; optional later: `paymaster` to sponsor EVM gas paid in other tokens
- [ ] ✍️ Tests: rate change mid-block, disabled token, rounding (always round against payer), insufficient balance, refund

### Sponsored fees / fee payer (new design; Sovereign `paymaster` is one payer per sequencer) ⚠️
- [ ] 🔁 Study `sov-paymaster` (`policies.rs`: `PayeePolicy` max_fee / max_gas_price / gas_limit / transaction_limit) and reuse the policy checks
- [ ] ✍️ `fee-sponsor` module: many concurrent sponsorships, each `{owner, managers, payees (list | all), allowed_targets (contracts/modules), per_tx {max_fee, max_gas_price, gas_limit}, per_account {max_txs, max_fee} per period, budget deposit (SEL or fee token), expiry, paused}`
- [ ] ✍️ Calls: `create_sponsorship`, `add_payees` / `remove_payees`, `update_limits`, `deposit`, `withdraw` (remaining budget), `pause` / `resume`, `close`
- [ ] ✍️ Payer selection: native + EIP-712 txs carry `fee_payer` (inside signed bytes); EVM raw txs auto-matched by `(sender, tx.to)` → sponsorship; deterministic rule if several match (explicit > target match > oldest)
- [ ] ✍️ Modify `GasEnforcer`: reserve gas from sponsorship deposit, refund unused to payer, fall back to sender if not covered (or reject if `fee_payer` named but not covered)
- [ ] ✍️ Sponsored EVM txs: skip sender-balance check for gas only (value transfers still need sender balance)
- [ ] ✍️ Verify MetaMask behaviour for 0-balance sponsored EVM txs; recommend EIP-712 path for dApps if MetaMask blocks it
- [ ] ✍️ Sequencer mempool: count sponsored txs against sponsorship limits too (DoS: spam of failing sponsored txs)
- [ ] ✍️ Events + REST: sponsorship status, remaining budget, per-account usage (for dApp dashboards)
- [ ] ✍️ TS SDK helper: `sendSponsored(tx, payer)`
- [ ] ✍️ Tests: budget exhaustion mid-block, expiry, removed payee, target not allowed, failing tx charged to payer within limits, several sponsorships for one user, withdraw while txs pending

### Fee model (EIP-1559, runtime-configurable) ⚠️
- [ ] 🔁 Base fee logic from Sovereign (`BLOCK_GAS_LIMIT`, `INITIAL_BASE_FEE_PER_GAS`, `BASE_FEE_MAX_CHANGE_DENOMINATOR`, `ELASTICITY_MULTIPLIER`, `PERCENT_BASE_FEE_TO_BURN` in `constants.toml:179–194`)
- [ ] ✍️ Move those constants into a `fee-params` kernel-state module; read from state instead of `config_value!`
- [ ] ✍️ `set_fee_params(new, activate_at_height)` — admin only; validation: denominator > 0, elasticity ≥ 1, burn ≤ 100, `max_tx_gas` ≤ `block_gas_limit`, `min_base_fee` ≤ current base fee
- [ ] ✍️ Add `min_base_fee_per_gas` floor (not in Sovereign) so fees never decay to ~0 during idle periods (anti-spam)
- [ ] ✍️ Confirm what the 2 gas dimensions are (expected: native execution vs zk proving; `crates/bench/sp1-microbenches`) and document
- [ ] ✍️ Re-calibrate gas constants for 18-decimal SEL and SP1 (port `sp1-microbenches`): per-byte, per-read, hash, signature, EVM gas mapping (`DEFAULT_GAS_TO_CHARGE_PER_EVM_GAS`)
- [ ] ✍️ **Benchmark → set `block_gas_limit`**: full 1 s block provable in < 1 s (incl. EVM-heavy blocks) so provers never fall behind
- [ ] ✍️ Fee split: 10 % of base fee burned, 90 % to provers (operator address in `Operator` mode); tip → sequencer
- [ ] ✍️ EVM RPC: `eth_gasPrice`, `eth_feeHistory`, `eth_maxPriorityFeePerGas`, block `baseFeePerGas` reflect Selendra base fee in SEL
- [ ] ✍️ Sequencer `minimum_profit_per_tx` covers Avail DA cost per tx (amortized over lazy batches)
- [ ] ✍️ Tests: fee spike/decay at 1 s blocks, floor, param change at activation height, burn accounting vs total supply

### Governance
- [ ] ✍️ Testing: single `admin` address in genesis config (`MultiAddressEvm`, any of the team test accounts); admin calls execute immediately
- [ ] ✍️ `set_admin(new)` call so admin can later be handed to multisig/timelock **without a new genesis**
- [ ] 🔁 Later: `timelock` module; admin multisig account as its proposer
- [ ] ✍️ Governance-gated calls: `sequencing_params.set_params`, `fee_params.set_fee_params`, `chain_state.set_operating_mode`, `bank.mint/burn` (SEL), `fee_tokens.*`
- [ ] ✍️ **Operating-mode switch** (Sovereign: genesis-only, `sov-chain-state/src/genesis.rs:73`): `set_operating_mode(Zk, activate_at_height)`; at activation switch incentive module (`operator-incentives` → `prover-incentives`), settle pending operator rewards, require ≥ 1 registered prover
- [ ] ✍️ Block switching back Zk → Operator (or require long timelock) — prevents silent security downgrade
- [ ] Later: SEL token governance (proposals, voting, quorum) replacing the multisig
- [ ] 🔁 `uniqueness` (nonce / replay protection, incl. Ethereum nonces)
- [ ] 🔁 `chain-state` (slot, heights, roots, gas price) — `slots`/code commitments use `BcsCodec` upstream (see the Phase 7 state-encoding item, needed here first)
- [ ] 🔁 `blob-storage` (deferred blobs) — only if soft confirmations
- [ ] 🔁 `sequencer-registry` (register, bond, slash) — DA address = `AvailAddress`. ⚠️ ed25519 keys may be mixed-order (`A + T`, `T` torsion): one private key gives up to 8 valid keys/credentials (documented on `Ed25519PublicKey`), so "one key, one registration" needs a prime-order check (one scalar multiplication) or must not be relied on
- [ ] 🔁 Incentives: `operator-incentives` (launch) + `prover-incentives` (zk); ❌ skip `attester-incentives`
- [ ] ✍️ ❌ Do **not** copy `sov-revenue-share`
- [ ] ✍️ Selendra-specific modules (your app logic): ____________
- [ ] Optional: `paymaster`, Hyperlane (bridging)

## Phase 7 — EVM (enabled by default) ⚠️

From `sov-evm`, `sov-ethereum`, `sov-address` (feature `evm`):
- [ ] 🔁 `sov-evm` module (revm) → `selendra-evm`; include in `Runtime<S>` by default — use `EthereumAddress` instead of `HexString<[u8; 20]>` (e.g. `ContractCreationPolicyUpdate::Allowlist`: strict hex rejects the EIP-55 addresses wallets print, which `EthereumAddress` accepts); same for hyperlane
- [ ] 🔁 State encoding for `BcsCodec` items (Phase 6 + 7; `selendra-state` dropped `BcsCodec`). Upstream users: Phase 6 `sov-chain-state` (`slots`, `inner_code_commitment`, `outer_code_commitment`), `sov-blob-storage` (`deferred_blobs`), `sov-prover-incentives` (`admin_upgrades`), `sov-bank`'s `EncodeLike<TokenHolderRef, TokenHolder> for BcsCodec` impl (drop it) → `BorshCodec` (no live chain, no migration) and a round-trip test (proptest/fuzz) per stored type, so `decode_unwrap` can't panic on a type without canonical borsh. Phase 7: every `sov-evm` `#[state]` item (`lib.rs:106-207`) — provable: `accounts`, `account_storage` incl. `EncodeLike<(&Address, &U256), AccountStorageKey>`, `code`, `block_hashes`, `pending_transactions`, `admin`, `contract_creation_allowlist`, `cfg`, `block_env`, `head`, `disable_max_fee_check`, `enabled_custom_precompiles`; accessory: `pending_head`, `block_numbers`, `blocks`, `transactions`, `receipts`, `block_hash_to_number`, `transaction_hashes`, `receipt_fees` → port `BcsCodec` (canonical decoding: reject trailing bytes, non-canonical ULEB128 lengths) or give the revm/alloy types borsh encodings; either way document the layout in `docs/serialization.md` and add a fuzz target
- [ ] ✍️ Gas token = EVM native balance (single SEL balance via `bank`, 18 decimals both sides, no dual accounts)
- [ ] ✍️ EVM chain ID in genesis config (`1961`); EIP-155 replay protection
- [ ] ✍️ Pin revm version; plan for Ethereum hard-fork upgrades (Cancun/Prague opcodes)
- [ ] ✍️ Check how Solidity ↔ native module calls work (precompiles?) before relying on it
- [ ] ✍️ Slot gas limit + max batch size in genesis/config (controls block capacity)
- [ ] ✍️ Price `SSTORE` / contract deploy to limit state growth
- [ ] ✍️ Verify where Ethereum blocks/receipts/logs are stored (expected: accessory state, not in state root); prune on non-archive nodes
- [ ] ✍️ **Benchmark SP1 proving cost** per tx type: native transfer, ETH transfer, ERC-20 transfer, swap → sets fees
- [ ] ✍️ EVM test suite: Ethereum state tests (`ethereum/tests`) subset, Foundry deploy/call tests

## Phase 8 — STF & kernel ⚠️

From `sov-modules-stf-blueprint`, `sov-kernels`, `sov-capabilities`:
- [ ] 🔁 `StfBlueprint::apply_slot` flow (checkpoint → sync kernel → select blobs → user space → batches → close block → materialize)
- [ ] 🔁 Registered vs unregistered (emergency/force-inclusion) batch paths — keep for censorship resistance
- [ ] 🔁 Proof blob processing (`proof_processing.rs`)
- [ ] 🔁 Kernel: start with `BasicKernel`; then `SoftConfirmationsKernel` — with `VersionedStateValue` (deferred from Phase 4: needs kernel accessors / `PrivilegedKernelAccessor`)
- [ ] 🔁 Standard capabilities struct wired to our modules
- [ ] ✍️ `Runtime<S>` for Selendra (core modules + EVM)
- [ ] ✍️ Genesis config format + `genesis.json` for devnet (`sel1…` and `0x…` balances); hex inputs parsed leniently (Phase 13 REST item)
- [ ] ✍️ Determinism checks: no `HashMap` iteration, no floats, no time/rand in STF
- [ ] ✍️ Guest path: after `materialize_update`, call `witness.ensure_consumed()` and panic on `Err` (port of upstream's `assert!(witness.is_empty(), "Non-native execution must completely consume the witness!…")` in `sov-modules-stf-blueprint`: leftover hints make the witness malleable) ⚠️
- [ ] ✍️ Never call `StateCheckpoint::discard_revertable_storage_cache` on a path the zk guest executes: discarded reads are not verified against the root (upstream discards only when `is_sequencer()`). The check above only catches a prover/guest mismatch (prover did not discard, guest did); a discard both run consumes every hint and leaves the dropped reads unverified, so not calling it is the only defence; `add_read_if_not_present` is sequencer warm-up only ⚠️
- [ ] 🔁 Kernel bits of `StateCheckpoint` deferred from Phase 4 (start-of-block kernel reads run on the checkpoint itself: Phase 5 `StateCheckpoint` note ⚠️): `get_rollup_height_of_underlying_storage`, `KernelStateAccessor` (true slot number, `PrivilegedKernelAccessor`, native `read_from_storage_at_slot_number`: read `NativeStorage::get_historical`/`get_leaf_historical`/`get_accessory_historical` directly with a throwaway witness, bypassing the checkpoint caches like upstream — never on a checkpoint that is materialized or proven: a historical value in the provable cache is verified against the previous root and shadows current state for the rest of the block ⚠️)

## Phase 9 — Adapters

### Mock (first, for all testing)
- [ ] 🔁 Mock DA (in-memory + sqlite)
- [ ] 🔁 Mock zkVM

### Avail DA ⚠️ (finish Sovereign stub `crates/adapters/avail`, 652 lines)
- [ ] ✍️ Register two Avail `app_id`s (`create_application_key`): **batches** and **proofs**
- [ ] 🔁/✍️ `AvailDaSpec`: `SlotHash` (blake2), `BlockHeader` (+ extension: `app_lookup`, row KZG commitments, `data_root`), `BlobTransaction`, `InclusionMultiProof`, `CompletenessProof`
- [ ] ✍️ `get_block_at`: read **GRANDPA-finalized** blocks only; one slot = one Avail block (~20 s)
- [ ] ✍️ Blob extraction: `app_lookup` → Selendra cell range → `kate_queryRows` → decode with `kate-recovery` / `avail-core` (don't reimplement encoding)
- [ ] ✍️ `send_transaction` / `send_proof` via `avail-rust` (`submitData` with app_id); split batches over per-extrinsic data limit (check current limit)
- [ ] ✍️ `get_proofs_at` (proofs app_id)
- [ ] ✍️ **Self-signed blobs**: blob = `{sequencer_pubkey, signature, payload}`; sign incl. Avail block number/nonce (anti re-post) via `selendra_primitives::signing` with `SigningDomain::SequencerBlob`; `sender()` = pubkey — Avail matrix has no signer info. Sign a fixed-size digest (`sha256(blob) ‖ avail_block ‖ nonce`), not the whole blob: ed25519 hashes the message with SHA-512, which SP1 doesn't accelerate (multi-MB in software per blob); rule documented on `SigningDomain::SequencerBlob`
- [ ] ✍️ **`AvailDaVerifier` in SP1 guest**:
  - [ ] Header hash (blake2-256, SCALE) == slot hash; `prev_hash` linkage
  - [ ] Completeness: every row covering Selendra's `app_lookup` range is supplied
  - [ ] Row data vs KZG row commitments: evaluate at random point + opening proof, **batched into one BLS12-381 pairing per slot**
  - [ ] Decode cells → blobs; verify blob signatures
- [ ] ✍️ **Prototype + benchmark batched KZG check in SP1 first** (riskiest part, sets proving cost)
- [ ] ✍️ Blob sender: Substrate nonce handling, AVAIL fee balance + alerts
- [ ] Optional: verify GRANDPA finality in guest — adapt `sp1-vector` (Avail↔Ethereum zk bridge)
- [ ] Optional: embed `avail-light` client in Selendra nodes (own DAS check)
- [ ] ✍️ Check Avail node pruning policy; set up archive source for sync-from-genesis
- [ ] ✍️ Adversarial tests: missing row, skipped blob, reordered blob, forged sender, wrong app_id
- [ ] ✍️ Integration tests against Avail local dev chain / Turing testnet

### SP1
- [ ] 🔁 SP1 adapter + guest program (`zk/sp1-guest`) ⚠️ — decode the proof envelope with borsh `from_slice` (upstream `strict_bincode_deserialize`, not copied); never plain `bincode::deserialize` (ignores trailing bytes → several encodings per proof)
- [ ] ✍️ Re-check SP1 patches vs our pins: `k256` 0.14 (SP1 secp256k1 patch targets 0.13.4, which has RUSTSEC-2026-0387; upstream's SP1 guests don't patch `k256` either, so software verify is no regression — benchmark it; if patched, verify with the same patched version natively and in the guest, never guest-only (edge cases would split); alloy brings `k256` 0.13.4 back in Phase 7 → two copies), `sha2 =0.10.9` + 0.9.9 (via `ed25519-consensus`), `ed25519-consensus =2.1.0`, `tiny-keccak` (alloy keccak, selected by the `tiny-keccak` feature); `getrandom` is kept out of the guest (`k256` without `std`, `curve25519-dalek-ng` without `std`; `make guest` checks it)
- [ ] ✍️ Run the ed25519 key **and** signature vectors inside the SP1 guest (patched dalek-ng decompresses via syscall; only tested natively so far): non-canonical + small-order public keys, the `x = 0` sign-bit encodings on the public-key path, non-canonical `R`/`s` (`crafted_non_canonical_r_signatures_are_rejected`-style inputs) → native and guest must agree end to end, on the error variant too (not just accept/reject: e.g. `y >= p` keys must be `NonCanonical` in both, now a byte check before decompress) ⚠️
- [ ] ✍️ Guest crypto benchmarks: ed25519 key checks as byte checks (`y < p` + table of the 8 small-order encodings, then one decompress in `VerificationKey::try_from`) instead of decompress + compress (field inversion) + cofactor mult per tx; `EthereumPublicKey` keeps the parsed key or derived address next to its canonical bytes (now ~3 square roots per secp256k1 tx: decode, credential/address, verify)
- [ ] ✍️ Verify guest uses identical STF/runtime as native (same crate, feature-gated)

## Phase 10 — Full node

From `sov-stf-runner`, `sov-modules-rollup-blueprint`:
- [ ] 🔁 `StateTransitionRunner` (fetch blocks, reorg check, apply_slot, persist)
- [ ] 🔁 STF info manager (witness persistence + back-pressure)
- [ ] 🔁 Node blueprint (wire DA + storage + ledger + runner + APIs)
- [ ] ✍️ TOML config (`[da]` Avail RPC URL, key file, batch/proof app_ids; `[storage] [runner] [sequencer] [proof_manager] [monitoring]`)
- [ ] ✍️ `selendra-node` binary with `--da-layer {mock,avail}` / `--zk-vm {mock,sp1}`
- [ ] ✍️ Graceful shutdown, crash-recovery tests (kill -9 mid-slot)

## Phase 11 — Sequencer

From `sov-sequencer`, `sov-blob-sender`:
- [ ] 🔁 Standard mempool sequencer (start here); accepts native + Ethereum txs
- [ ] ✍️ Sign batches before posting (self-signed blob format, Phase 9; `SigningDomain::SequencerBlob`)
- [ ] ✍️ Zeroize private keys before the sequencer key is used: `EthereumPrivateKey` drops its extra `bytes: [u8; 32]` copy (read bytes back from `SigningKey`); both `Ed25519PrivateKey` and `EthereumPrivateKey` wipe the secret on drop (`zeroize`; check what `k256` / `ed25519-consensus` already wipe); consider removing `Clone` so secret copies can't spread ⚠️
- [ ] 🔁 Blob sender with retries + in-flight tracking
- [ ] 🔁 Preferred sequencer + soft confirmations (speculative execution, state-root cross-check)
- [ ] 🔁 Sequencer state overlay deferred from Phase 4 (Storage item): `StateGetter` + `MaybePresentValue` + `sequencer_state.rs` (`RawStateChanges`), `StateCheckpoint` `uncommitted_changes`/`new_with_uncommitted_changes`/`replace_storage`/`clone_with_empty_witness_dropping_temp_cache`/`to_raw_state_changes`/`ChangeSet`/`changes()`/`apply_changes`/`apply_tx_changes`/`advance_visible_slot_number`, cache `get_from_cache`/`get_leaf_from_cache`; `ConcurrentStateCheckpoint`. Benchmark the `BTreeMap` caches here (audit bench: ~3× slower lookups than `HashMap` natively; every read hits two `CacheLog`s × each uncommitted layer on the mutex-held path); if it matters, a `HashMap` with a fixed seedless hasher (foldhash/FxHash) natively + sort at freeze, `BTreeMap` in the guest
- [ ] ✍️ Mempool DoS limits: size caps, per-sender rate limits, min fee ⚠️
- [ ] Later: HA (Postgres leader election, replicas)

### 1 s soft blocks + lazy DA posting (runtime-configurable) ⚠️
- [ ] ✍️ New kernel module `sequencing-params` (kernel state, provable) holding `SequencingParams { block_time_ms, max_txs, max_bytes, max_age_secs, deferred_slots_count }`
- [ ] ✍️ Genesis config for initial values; **no hard-coded upper limits**
- [ ] ✍️ Call `set_params(new, activate_at_height)` — only callable by governance (admin multisig via `timelock` first)
- [ ] ✍️ Changes take effect at a **future activation height** (sequencer + all nodes switch at the same block; no restart)
- [ ] ✍️ Validation in setter (correctness only, not policy limits): values non-zero; `deferred_slots_count` > `max_age_secs / avail_slot_secs` + margin, else forced blocks break unposted soft confirmations
- [ ] ✍️ Shrinking `deferred_slots_count`: apply only after currently deferred blobs drain (no blob dropped/invalidated by the change)
- [ ] ✍️ Move `DEFERRED_SLOTS_COUNT` from compile-time `constants.toml` (`config_value!`) to `sequencing-params` state; update `sov-blob-storage` capabilities to read it from state
- [ ] ✍️ Sequencer: 1 s block timer reading `block_time_ms` from state; seal soft block (height, timestamp, txs, root)
- [ ] ✍️ Sequencer flush policy reading params from state: flush when `txs ≥ max_txs` OR `bytes ≥ max_bytes` OR `oldest_age ≥ max_age_secs`; skip if no txs
- [ ] ✍️ Multi-block blob format `Vec<SoftBlock>`; empty blocks encoded as a compact range marker (or omitted)
- [ ] ✍️ STF: replay multi-block blobs; enforce block heights contiguous, timestamps monotonic and bounded vs Avail header time
- [ ] ✍️ STF: reject preferred blobs that violate the **active** params (e.g. older than `max_age`)
- [ ] ✍️ Sequencer write-ahead log of unposted blocks + replication (soft-confirmed txs must survive a crash)
- [ ] ✍️ Events + RPC: expose current/pending params and "last posted block" so wallets/bridges know hard-finality lag
- [ ] ✍️ Tests: param change mid-buffer, activation height, crash before flush, empty periods, max_age boundary, forced inclusion after deferral

## Phase 12 — Proving

- [ ] 🔁 `ZkProofManager` + `ParallelProverService`
- [ ] 🔁 Proof aggregation (outer zkVM, SP1)
- [ ] 🔁 Proof sender → Avail (proofs app_id)
- [ ] 🔁 Optimistic mode: `AttestationsManager`, challenge flow (if chosen)
- [ ] ✍️ Benchmark: proving cost per slot (EVM txs + Avail KZG verification), cycles per tx type

## Phase 13 — APIs & clients

- [ ] 🔁 REST: `/sequencer`, `/ledger`, `/rollup`, `/modules/*` (axum) — hex inputs: our `HexString`/`HexHash`/`TxHash`/`CredentialId` parsing is strict (`0x` + lowercase) while upstream tools send other forms (TS SDK `dedup` sends credential ids without `0x`; hashes pasted in uppercase; upstream hyperlane test parses an unprefixed hash). Parse leniently (optional `0x`, any case) only at input boundaries (REST path/query, CLI, genesis); output and everything signed/hashed (borsh) stay canonical
- [ ] 🔁 `ApiStateAccessor` (upstream `http_api.rs`) implementing `selendra_state::ProvenStateAccessor` (only the test storage implements it so far), so containers' `get_with_proof` work; clients verify with `verify_proof` (checks namespace, container prefix and canonical key)
- [ ] 🔁 WebSocket tx status + events
- [ ] 🔁 **Ethereum JSON-RPC** (`sov-ethereum`): `eth_sendRawTransaction`, `eth_call`, `eth_getLogs`, `eth_subscribe`, `eth_getProof`, `debug_trace*`
- [ ] ✍️ MetaMask "Add network" config (chain ID, RPC URL, symbol, explorer)
- [ ] ✍️ OpenAPI spec for Selendra
- [ ] 🔁 TypeScript client (`web3`, `signers`, `serializers`) renamed `@selendra/*`; `sel` prefix — signers must prepend the `0xB5 "SELENDRA"` header (no `chain_hash`); publish test vectors (header + payload → signature) for SDK authors; send hex with `0x`
- [ ] ✍️ CLI wallet (keygen, transfer, query; prints `sel1…` and `0x…`) — signs through `selendra_primitives::signing`; lenient hex input (MetaMask-exported private keys lack `0x`); one-time converter for upstream sov-cli key files (`{"private_key":{"key_pair":[…]}}`)
- [ ] ✍️ Block explorer / indexer (EVM-compatible, e.g. Blockscout, + native modules)

## Phase 14 — Testing & security ⚠️

- [ ] Unit tests for every copied file (port upstream tests too)
- [ ] Integration tests: mock DA + mock zkVM end-to-end, then Avail + SP1
- [ ] Fuzz: tx decoding (native + RLP), blob parsing, Avail cell decoding, STF with random txs (extend `fuzz/`; addresses, keys and `FullyBakedTx`/`RawTx` already covered in Phase 3, state keys in Phase 4)
- [ ] Property test: native vs zk execution give same root
- [ ] Guest benchmark (cycles, heap): `SlotKey::new` allocates 2–3× per key (`from_parts` 2×) and SP1's bump allocator never frees → encode into a stack buffer, one `Arc<[u8]>` allocation
- [ ] Load test (port `sov-synthetic-load` / soak tools), incl. EVM-heavy load
- [ ] Threat model doc (sequencer censorship, Avail data withholding, prover liveness, EVM exploits, bridge)
- [ ] Internal review of every ⚠️ item, then external audit (Avail adapter + EVM integration in scope)
- [ ] Bug bounty

## Phase 15 — Networks

- [ ] Local devnet (docker-compose: node + mock DA, then node + Avail local dev chain)
- [ ] Public testnet on Avail Turing testnet, operator mode
- [ ] Testnet with optimistic/zk proofs enabled
- [ ] Monitoring: metrics (Prometheus/Influx), alerts (incl. AVAIL balance, DA submission lag, prover lag)
- [ ] Runbooks: upgrade, key rotation, sequencer failover
- [ ] Upgrade path for runtime changes (versioned STF / hard-fork height, revm upgrades)
- [ ] Mainnet genesis ceremony, launch on Avail mainnet

---

## Milestones

1. **M1 – "hello chain":** Phases 1–6 + BasicKernel + mock DA + mock zkVM → transfer tokens between `sel1…` addresses on a local node
2. **M2 – EVM:** `selendra-evm` + Ethereum JSON-RPC → deploy a Solidity contract with Foundry, use MetaMask (still mock DA)
3. **M3 – real node:** full node, standard sequencer, REST API, CLI wallet, devnet
4. **M4 – Avail:** Avail adapter (extraction, self-signed blobs, send/proofs), public testnet on Avail Turing (operator mode)
5. **M5 – proofs:** SP1 guest with `AvailDaVerifier` (batched KZG) + aggregation; governance switch `Operator` → `Zk` on testnet
6. **M6 – UX:** soft confirmations, TS SDK, explorer
7. **M7 – mainnet:** audit, bounty, launch on Avail mainnet

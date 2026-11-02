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
| Address prefix | `ADDRESS_PREFIX = { const = "sel" }` in `constants.toml` | Must be set **before genesis**; e.g. `sel16adfsqvzky9t042tlmfujeq88g8wzuhnm2nzxfd0qgdxsudeldf` |
| Keys | ed25519 (`sel1…`) + secp256k1 (`0x…`, EIP-712 / Ethereum txs) | |
| zkVM | SP1 (only adapter with proof aggregation) | Has BLS12-381, keccak, ed25519 precompiles |
| Sequencing | **Preferred sequencer, 1 s soft blocks, lazy DA posting** | Post to Avail when `max_txs` reached OR `max_age` elapsed; **never post when empty** |
| Sequencing params | **On-chain, no hard-coded limits, changeable by governance at runtime** | `block_time_ms`, `max_txs`, `max_bytes`, `max_age_secs`, `deferred_slots_count` stored in kernel state (Phase 11) |
| Operating mode | **`Operator` at launch → `Zk` for mainnet; skip `Optimistic`** | Sovereign sets mode only at genesis → we add a governance switch (Phase 6) |
| Governance | **Testing: single admin key, no multisig, no timelock** → before public testnet/mainnet: multisig + `timelock` → token governance (SEL) | Admin controls: sequencing params, operating mode, SEL mint/burn, fee-token list & rates. Admin address is config, not hard-coded |
| Genesis allocation (testing) | **All 300,000,000 SEL to team test accounts**:<br>`sel1fs6stajfuu65eavsgujjx2slhydhk7xakzlqum35cs72ydqpl45` (ed25519) → 150,000,000 SEL<br>`0x02f9647E14d07ac4c76295ed34eBa30a47b626A3` (secp256k1, MetaMask) → 150,000,000 SEL | Random **test-only** keys in `keys/*.key` (gitignored). Same accounts act as admin. Replace with real addresses via genesis config before any public network |
| EVM chain ID | **2027** (testing, configurable in genesis) | ⚠️ 2027 is already registered to "CitizenChain" (`ethereum-lists/chains` `eip155-2027.json`) → OK for local devnet, **must pick an unused ID before public testnet** |
| Gas / native token | **Name `Selendra`, symbol `SEL`, 18 decimals, genesis supply 300,000,000 SEL** | = 3,000,000 × 10¹⁸ base units (fits `Amount(u128)`). Supply changeable later by governance mint/burn. Same token is EVM native currency (1:1, no scaling) |
| Multi-token gas | **SEL = default fee token; other fee tokens priced by price oracle** | Admin approves which tokens are allowed; their SEL rate comes from the oracle (`token/USD ÷ SEL/USD`). Native txs may pay in any allowed token; EVM txs pay in SEL. Not in Sovereign → new `fee-tokens` + `price-oracle` modules (Phase 6) |
| Sponsored fees | **Any account (dApp) can pay fees for a list of accounts**, limited to its own contracts, with per-tx / per-account / total budget limits and expiry | Many sponsorships at once (Sovereign `paymaster` allows only one payer per sequencer) → new `fee-sponsor` module (Phase 6) |
| State-root hash | **SHA-256** (NOMT trees + `global_root`) | 128-bit collision security, most-studied hash, SP1 precompile. Alternatives (SHA3/Keccak equal; BLAKE3/Poseidon less margin; SHA-512 variants no precompile) don't add real security. EVM still uses Keccak-256 internally (Ethereum standard) |
| Fee model | **EIP-1559 base fee (2 gas dimensions) + optional tip; on-chain params changeable by admin at runtime** | Base fee → 10% burned / 90% provers; tip → sequencer. Params in `fee-params` state (Phase 6), not compile-time `constants.toml` |
| Fee genesis values | `initial_base_fee_per_gas = [1 gwei, 1 gwei]` (10⁹ base units of SEL)<br>`base_fee_max_change_denominator = 48` (≈ 2 %/s with 1 s blocks)<br>`elasticity_multiplier = 2` (target 50 % full)<br>`percent_base_fee_to_burn = 10`<br>`min_base_fee_per_gas = [0.1 gwei, 0.1 gwei]` (floor)<br>`block_gas_limit = [1e11, 1e11]` (Sovereign default, **devnet only** → set from SP1 benchmark)<br>`max_tx_gas = [1e9, 1e9]`, `max_forced_tx_gas = [5e5, 5e5]`<br>`max_batch_size_bytes` = Avail per-extrinsic limit | Rule for `block_gas_limit`: a full 1 s block must be provable in < 1 s on the prover setup |
| Genesis values | `block_time_ms = 1000` (1 s blocks)<br>`max_txs = 1000` (post when ≥ 1000 txs buffered)<br>`max_age_secs = 3600` (post at least every 1 h **if** any tx)<br>`skip_if_empty = true` (no txs → no DA submission)<br>`deferred_slots_count = 240` (~80 min on Avail; must stay > 180 slots = 1 h) | `max_bytes` set from Avail's per-extrinsic data limit (check current value) |

## Phase 0 — Remaining decisions

- [ ] Before public testnet: real genesis allocation (team, treasury, sequencer bond, prover rewards, faucet…)
- [ ] Before public testnet: multisig signers + threshold (e.g. 3-of-5) and timelock delay (e.g. 48 h)
- [ ] Before public testnet: unused EVM chain ID, register in `ethereum-lists/chains` (chainlist.org)
- [ ] First extra fee tokens (e.g. bridged USDC/USDT?)
- [ ] Oracle provider: Pyth (pull model, Wormhole-signed, works on any chain — recommended) vs RedStone vs Chainlink (needs deployment)
- [ ] SEL/USD source while SEL has no market: admin-set price → later on-chain DEX TWAP (SEL/USDC) with bounds
- [x] Write `docs/selendra-spec.md` with all decisions (keep in sync when decisions change)

## Phase 1 — Repo & tooling

- [x] `git init`, Cargo workspace, `rust-toolchain.toml` (pin version), `rustfmt.toml`, `clippy.toml` — Rust 1.93.0 (same as upstream), edition 2024
- [ ] Crate layout: `crates/{primitives,interface,state,modules-api,macros,stf,kernel,modules/*,node,sequencer,db,adapters/{avail,mock-da,sp1,mock-zkvm},evm,cli}` — created one at a time when its code is written: add to `members` in `Cargo.toml`, use `[lints] workspace = true`, `#![forbid(unsafe_code)]` in the crate root
- [x] CI: fmt, clippy `-D warnings`, test, `cargo deny` (licenses/advisories), `cargo audit`, `cargo udeps` — `.github/workflows/ci.yml`, same checks via `make ci`
- [x] `#![forbid(unsafe_code)]` everywhere except where justified — workspace lint + attribute in every crate root
- [x] Track copied code: `docs/provenance.md` — file → upstream path + commit + what changed (needed for future upstream security patches)
- [x] Script to diff our copied files against upstream for security fixes — `scripts/upstream-diff.sh`

## Phase 2 — Core interface (the traits) 🔁

From `crates/rollup-interface`:
- [x] 🔁 `DaSpec`, `DaVerifier`, `BlobReaderTrait`, `DaService` → `selendra-interface::da` (state machine) + `::node::da` (native only)
- [x] 🔁 `StateTransitionFunction`, `ApplySlotOutput`, `ExecutionContext`, tx receipts/outcomes → `::stf` (optimistic-mode parts stripped; `StateTransitionVerifier` + `ProofSender` come with `::zk`)
- [ ] 🔁 `Zkvm`, `ZkvmHost`, `ZkvmGuest`, `ZkVerifier`, `OuterZkvmHost` → `::zk`
- [ ] 🔁 `StateTransitionPublicData` (proof public outputs) ⚠️
- [ ] ✍️ Strip what we don't need (Risc0, Calestia-specific bits, unused generics)
- [ ] ✍️ Selendra `Spec`: `Da = AvailDaSpec`, `Address = MultiAddressEvm`, `InnerZkvm/OuterZkvm = SP1`, `CryptoSpec`

## Phase 3 — Crypto, primitives & addresses ⚠️

- [ ] 🔁 Crypto spec, key types, signature verify wrappers (audited crates: `ed25519-consensus`, `k256`, `sha2`)
- [ ] 🔁 `Address` (28-byte, bech32m) from `sov-modules-api/src/common/address.rs`
- [ ] ✍️ Set `ADDRESS_PREFIX = "sel"` in `constants.toml`; rename `sov` in schemas, JSON schema pattern, CLI, docs, TS clients
- [ ] ✍️ Update test vectors: `[1..=28]` → `sel1…`, `[11; 28]` → `sel1…`; add the RFC 8032 key vector
- [ ] ✍️ Reject `sov1…` addresses (wrong HRP) — test it
- [ ] 🔁 `MultiAddress<EthereumAddress>` + `EthereumAddress` + `EthereumPublicKey` from `sov-address` (feature `evm`)
- [ ] ✍️ Test `Standard`/`Vm` parsing: 28 bytes vs 20 bytes, `sel` prefix vs `0x`
- [ ] ✍️ Chain ID + domain separation in every signed message (prevent cross-chain replay)
- [ ] 🔁 Borsh serialization conventions; ✍️ fuzz all decoders (`cargo fuzz`)
- [ ] ✍️ No-panic review of all parsing code

## Phase 4 — State & storage ⚠️

From `sov-state`, `sov-db`:
- [ ] 🔁 State containers: `StateValue/Map/Vec` + Kernel + Accessory namespaces
- [ ] 🔁 `Storage` trait, `StateCheckpoint`, witness (`ArrayWitness`)
- [ ] 🔁 NOMT backend: `NomtProverStorage` (native) + `NomtVerifierStorage` (guest) — pin `nomt` 1.0.5
- [ ] 🔁 Two-root commitment `user_root || kernel_root` → `global_root()`
- [ ] 🔁 `rockbound` (RocksDB wrapper) or plain `rocksdb`
- [ ] 🔁 `NomtStorageManager` (fork-aware overlays, finalize, pruning)
- [ ] 🔁 Ledger DB schema (slots, batches, txs, events, proofs, state roots, STF infos)
- [ ] ✍️ Drop legacy `user_jmt_values` column-family names (fresh chain, no compat needed)
- [ ] ✍️ Property tests: native root == guest root for random read/write sets
- [ ] ✍️ Hash = SHA-256 everywhere in state (`sha2` with SP1-patched precompile in guest); single `Hasher` type in `Spec`, no mixing
- [ ] ✍️ Verify Merkle domain separation: leaf vs internal node prefixes in NOMT; user vs kernel root combination in `global_root()` ⚠️
- [ ] ✍️ Verify keys are hashed before tree insertion (`H(key)`) — attacker can't choose tree positions

## Phase 5 — Module system

From `sov-modules-api`, `sov-modules-macros`:
- [ ] 🔁 `Module` trait, `ModuleInfo`, `Context`, `TxState`, events, errors
- [ ] 🔁 Derive macros: `ModuleInfo`, `Genesis`, `DispatchCall`, `Event`, `Hooks`, `MessageCodec`
- [ ] 🔁 Hooks: pre/post dispatch tx, begin/end block, finalize
- [ ] 🔁 Gas metering (`SlotGasMeter`, per-tx gas, base fee)
- [ ] 🔁 Capabilities traits: `GasEnforcer`, `TransactionAuthenticator`, `TransactionAuthorizer`, `SequencerAuthorization`, `SequencerRemuneration`, `ProofProcessor` ⚠️
- [ ] 🔁 Authenticator that accepts both native (ed25519) and Ethereum (secp256k1 RLP / EIP-712) txs
- [ ] ✍️ Rename/re-namespace everything; remove `sov-revenue-share` coupling
- [ ] Later: `UniversalWallet`, `RuntimeRestApi`, `CliWallet` derives

## Phase 6 — Core modules ⚠️

- [ ] 🔁 `accounts` (credential → address)
- [ ] 🔁 `bank` (tokens, gas token, mint/burn auth) — highest-risk module, extra tests

### Native token SEL ⚠️
- [ ] ✍️ `constants.toml`: `GAS_TOKEN_DECIMALS = 18` (Sovereign default is 6); generate new Selendra `GAS_TOKEN_ID`
- [ ] ✍️ Bank genesis `gas_token_config`: `token_name = "Selendra"`, `token_decimals = 18`, balances = team test accounts (1,500,000 × 10¹⁸ each), `admins = [admin]` (→ timelock later)
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
- [ ] 🔁 `chain-state` (slot, heights, roots, gas price)
- [ ] 🔁 `blob-storage` (deferred blobs) — only if soft confirmations
- [ ] 🔁 `sequencer-registry` (register, bond, slash) — DA address = `AvailAddress`
- [ ] 🔁 Incentives: `operator-incentives` (launch) + `prover-incentives` (zk); ❌ skip `attester-incentives`
- [ ] ✍️ ❌ Do **not** copy `sov-revenue-share`
- [ ] ✍️ Selendra-specific modules (your app logic): ____________
- [ ] Optional: `paymaster`, Hyperlane (bridging)

## Phase 7 — EVM (enabled by default) ⚠️

From `sov-evm`, `sov-ethereum`, `sov-address` (feature `evm`):
- [ ] 🔁 `sov-evm` module (revm) → `selendra-evm`; include in `Runtime<S>` by default
- [ ] ✍️ Gas token = EVM native balance (single SEL balance via `bank`, 18 decimals both sides, no dual accounts)
- [ ] ✍️ EVM chain ID in genesis config (`2027` for devnet); EIP-155 replay protection
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
- [ ] 🔁 Kernel: start with `BasicKernel`; then `SoftConfirmationsKernel`
- [ ] 🔁 Standard capabilities struct wired to our modules
- [ ] ✍️ `Runtime<S>` for Selendra (core modules + EVM)
- [ ] ✍️ Genesis config format + `genesis.json` for devnet (`sel1…` and `0x…` balances)
- [ ] ✍️ Determinism checks: no `HashMap` iteration, no floats, no time/rand in STF

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
- [ ] ✍️ **Self-signed blobs**: blob = `{sequencer_pubkey, signature, payload}`; sign incl. Avail block number/nonce (anti re-post); `sender()` = pubkey — Avail matrix has no signer info
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
- [ ] 🔁 SP1 adapter + guest program (`zk/sp1-guest`) ⚠️
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
- [ ] ✍️ Sign batches before posting (self-signed blob format, Phase 9)
- [ ] 🔁 Blob sender with retries + in-flight tracking
- [ ] 🔁 Preferred sequencer + soft confirmations (speculative execution, state-root cross-check)
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

- [ ] 🔁 REST: `/sequencer`, `/ledger`, `/rollup`, `/modules/*` (axum)
- [ ] 🔁 WebSocket tx status + events
- [ ] 🔁 **Ethereum JSON-RPC** (`sov-ethereum`): `eth_sendRawTransaction`, `eth_call`, `eth_getLogs`, `eth_subscribe`, `eth_getProof`, `debug_trace*`
- [ ] ✍️ MetaMask "Add network" config (chain ID, RPC URL, symbol, explorer)
- [ ] ✍️ OpenAPI spec for Selendra
- [ ] 🔁 TypeScript client (`web3`, `signers`, `serializers`) renamed `@selendra/*`; `sel` prefix
- [ ] ✍️ CLI wallet (keygen, transfer, query; prints `sel1…` and `0x…`)
- [ ] ✍️ Block explorer / indexer (EVM-compatible, e.g. Blockscout, + native modules)

## Phase 14 — Testing & security ⚠️

- [ ] Unit tests for every copied file (port upstream tests too)
- [ ] Integration tests: mock DA + mock zkVM end-to-end, then Avail + SP1
- [ ] Fuzz: tx decoding (native + RLP), blob parsing, Avail cell decoding, STF with random txs
- [ ] Property test: native vs zk execution give same root
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

# Serialization conventions

Rules for every type that is hashed, signed, proven or stored in state. Breaking one of
them can make nodes disagree, make the prover fail, or let one value have two encodings.

## Which format

| Data | Format | Why |
|---|---|---|
| Anything hashed, signed, proven or stored in state (txs, blobs, state values, proof public outputs) | **borsh** | Specified, canonical, independent of serde attributes. Pinned exactly (`borsh = "=x.y.z"`) |
| Proof public outputs | **borsh**, enforced by the trait bounds of `ZkvmGuest::commit` / `ZkVerifier` | Adapters commit raw bytes (e.g. SP1 `commit_slice`), never the zkVM's default `commit` (bincode) |
| Hints from host to zk guest | serde (any format) | Prover-internal; nobody else checks these bytes |
| RPC / REST / config files | JSON (serde) | Human-readable. JSON shape may change without a fork |
| Tests, local caches | `postcard` or anything | Not consensus |

Never use bincode for consensus data, and never derive a consensus encoding from serde.

## Canonical encodings

Every value has exactly **one** accepted byte string. Decoders reject everything else, and
the fuzz targets check it: whenever decoding succeeds, re-encoding must give back the input.

- Fixed-size types encode as raw bytes with no length prefix: `Address` (28), `EthereumAddress` (20),
  `Ed25519PublicKey` (32), `EthereumPublicKey` (33, compressed SEC1), signatures (64), `CodeCommitmentHash` (32).
- Decoding validates: public keys must be valid curve points in their canonical encoding
  (ed25519 keys must also not be of small order, or anyone could sign for them); secp256k1
  signatures must be low-S; hand-written decoders accept only `0`/`1` as an `Option` tag.
- Normalize at construction, not at use: e.g. an uncompressed secp256k1 key is converted to
  compressed when parsed, so `as_ref()`, borsh and serde always agree.
- Store one representation. Do not keep a parsed value next to its bytes unless the bytes are
  derived from the parsed value (never copied from input).
- String and JSON forms are canonical too, and the fuzz targets check that anything accepted
  prints back as the input:
  - hex is `0x` + lowercase digits (no missing prefix, no uppercase);
  - base64 (`FullyBakedTx` JSON) is standard alphabet with exact padding;
  - numbers (`SlotNumber`, `RollupHeight`) are plain decimal, no `+` or leading zeros;
  - transaction JSON (`FullyBakedTx`, `RawTx`) must be an object (not the array form serde
    also accepts) with no unknown fields.

  Documented exceptions that normalize: `sel1…` accepts all-uppercase (bech32 allows it; extra
  padding symbols or non-zero padding bits are rejected); `0x…` addresses accept all-lowercase
  or all-uppercase, but mixed case must be a valid EIP-55 checksum; `EthereumPublicKey::from_str`
  accepts an uncompressed key and stores it compressed.
- Decode with `borsh::from_slice`, which rejects trailing bytes.

## Untrusted input

Every decoder may receive attacker-controlled bytes (from DA blobs, txs, RPC).

- Never panic: no `unwrap`/`expect`/indexing on input-dependent values. A panic in the zk guest
  stops proving for everyone (liveness attack).
- Bound lengths **before** allocating, e.g. `RawTx` ≤ 1 MiB, `FullyBakedTx` ≤ 1.05 MiB.
- Do length arithmetic without overflow. The SP1 guest is **32-bit** (`usize` = 32 bits) and
  overflow checks are on in release builds, so `a + b` on two decoded lengths can panic there.
  Compare by subtraction (`b > MAX - a`) or use `checked_*` / `saturating_*`.
- No `HashMap`/`HashSet` in consensus types (iteration order); use `BTreeMap`/`BTreeSet`.
  Their borsh decoding rejects unsorted or duplicate keys only because the workspace enables
  borsh's `de_strict_order` feature. A "sorted `Vec`" needs its own strictly-increasing check.
- No floats in consensus code (`float_arithmetic` is denied workspace-wide).

## Signatures

Never sign or verify a bare payload. Use `selendra_primitives::signing`, which signs
`0xB5 "SELENDRA" | version | domain | chain_id (u64 LE) | payload`, so a signature is bound to
its purpose (`SigningDomain`) and its network (`SELENDRA_CHAIN_ID` = 1961) and can never be a
valid Ethereum transaction or EIP-191/712 message.

## Checking

- `cargo test` — unit tests, including known-answer vectors and rejection tests.
- `cd fuzz && cargo +nightly fuzz run <target>` — targets `addresses`, `keys`, `tx_decoding`
  (no panics + canonical round-trip). Add a target for every new decoder.

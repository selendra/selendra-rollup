# Serialization conventions

Rules for every type that is hashed, signed, proven or stored in state. Breaking one of
them can make nodes disagree, make the prover fail, or let one value have two encodings.

## Which format

| Data | Format | Why |
|---|---|---|
| Anything hashed, signed, proven or stored in state (txs, blobs, state values, proof public outputs) | **borsh** | Specified, canonical, independent of serde attributes. Pinned exactly (`borsh = "=x.y.z"`) |
| Proof public outputs | **borsh**, enforced by the trait bounds of `ZkvmGuest::commit` / `ZkVerifier` | Adapters commit raw bytes (e.g. SP1 `commit_slice`), never the zkVM's default `commit` (bincode) |
| Hints from host to zk guest | serde (any format) for the container (e.g. `StateTransitionWitness`); **borsh** for each storage witness hint | Prover-internal, but the guest decodes them: hints have one accepted encoding (see "Witness hints and storage proofs") |
| RPC / REST / config files | JSON (serde) | Human-readable. JSON shape may change without a fork |
| Tests, local caches | `postcard` or anything | Not consensus |

Never use bincode for consensus data, and never derive a consensus encoding from serde.

## Canonical encodings

Every value has exactly **one** accepted byte string. Decoders reject everything else, and
the fuzz targets check it: whenever decoding succeeds, re-encoding must give back the input.

- Fixed-size types encode as raw bytes with no length prefix: `Address` (28), `EthereumAddress` (20),
  `Ed25519PublicKey` (32), `EthereumPublicKey` (33, compressed SEC1), signatures (64), `CodeCommitmentHash` (32), `StorageRoot` (64).
- Decoding validates: public keys must be valid curve points in their canonical encoding
  (ed25519 keys must also not be of small order, or anyone could sign for them); secp256k1
  signatures must be low-S; ed25519 signatures must have a canonical `R` (`y < p`, no sign bit
  on `x = 0`) and `s < l` (native dalek-ng decodes `R` with `y >= p`, the SP1 guest does not, so
  accepting it would split nodes from the prover); hand-written decoders accept only `0`/`1` as
  an `Option` tag.
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

## State keys

Every value in state is stored under a `SlotKey` (`selendra-state`): a 2-byte `Prefix`
`[module, item]` followed by the encoded item key. Each state item (container) has its own
prefix, so different items can never share a key. Changing any layout below changes every
state root (a fork).

| Container | Key | Value |
|---|---|---|
| `StateValue` | `[module, item]` | `codec(value)` |
| `StateMap` | `[module, item] ‖ key_codec(key)` | `codec(value)` |
| `StateVec` length | `[module, item]` | `codec(len: u64)` |
| `StateVec` element `i` | `[module, item] ‖ i` as `u64` LE (8 bytes, = borsh) | `codec(element)` |

- The default codec is `BorshCodec` (borsh for keys and values). E.g. `StateMap<u64, _>` at
  prefix `(1, 2)` stores key `5` under `[1, 2, 5, 0, 0, 0, 0, 0, 0, 0]`.
- `StateVec` element keys use fixed little-endian bytes whatever the codec, so the 2-byte length
  key and 10-byte element keys can never collide. Upstream Sovereign stored elements under item
  `item + 128`, which panicked for `item ≥ 128` and collided with that other item.
- A vec stores exactly elements `0..len` (`pop`, `remove`, `clear`, `set_all` delete what they
  drop) **as long as no operation failed**. Container operations make several accessor calls and
  are not atomic: when an accessor returns `Err` (e.g. out of gas) the caller must discard all
  of that accessor's writes (Phase 5: the transaction is reverted), never catch the error and
  keep them. Even so, `StateVec` shrinks its length before deleting and grows it after writing,
  so after a failure every element in `0..len` is still present, and every read is
  bounds-checked against `len` (a leftover element past `len` is never returned).
- `User`, `Kernel` and `Accessory` are separate key spaces: the same key in two namespaces
  is two different values.
- Decoding a stored value panics on failure (`StateItemDecoder::decode_unwrap`; the message
  shows at most 32 bytes). A failure means one of:
  - the stored type breaks the **round-trip precondition**: for every value `v` that can be
    constructed, `decode(encode(v))` must succeed and give `v`. A type whose decoder is stricter
    than its encoder (`RawTx`/`FullyBakedTx` today: public fields, unbounded encoder, size-capped
    decoder) must enforce its bound at construction or must not be stored, otherwise whoever
    chooses the stored value can make every later read panic. Containers `debug_assert!` the
    round trip on every write (debug builds only);
  - two items share a prefix, or the database is corrupt (bugs);
  - in the zk guest, an invalid witness: reads return the prover's unverified hints, which are
    checked against the state root only later. Panicking (no proof) is the intended result; this
    must never become a recoverable error, or control flow would depend on unverified bytes.
- Encoding a stored key or value panics where borsh refuses it: a collection longer than
  `u32::MAX` or of zero-sized types, a **NaN float**, or an error from a hand-written
  `BorshSerialize`. So state key and value types contain **no floats** (see "Untrusted input")
  and have infallible `BorshSerialize` impls.
- Encodings of the key types (each has exactly one accepted encoding):
  - `SlotKey`: borsh like `Vec<u8>` (the whole key, prefix included), at least 2 bytes. JSON and
    `Display` use `0x` + lowercase hex. `SlotKey::try_from_bytes` rejects < 2 bytes and never panics.
  - `SlotValue`: borsh like `Vec<u8>`; JSON `0x` + lowercase hex.
  - `Prefix`: borsh the 2 bytes; JSON and `Display` `"0x0102"`.
  - `Namespace` / `ProvableNamespace`: borsh one tag byte (`0` user, `1` kernel, `2` accessory);
    JSON only the snake_case string (`"user"`). Serde's derived decoding would also accept `{"user":null}`.

## Witness hints and storage proofs

The native prover records a **witness** for the zk guest (`selendra-state`: `Witness`,
`ArrayWitness`): an ordered list of hints, each the **borsh** encoding of one value. The guest
consumes them in the same order.

- `Witness::try_get_hint` / `get_hint` decode with `borsh::from_slice`, so trailing bytes are
  rejected and each hint has one accepted encoding (upstream used `T::deserialize(&mut slice)`,
  which ignored them). A hint is consumed even when it fails to decode.
- Every hint is unverified until `Storage::compute_state_update` checks the reads against the
  previous state root. A missing or undecodable hint is an **invalid witness**: `get_hint`
  panics, which is the intended result (no proof), and must never become a recoverable error.
  Leftover hints do not change the result but make the witness malleable:
  `Witness::ensure_consumed` reports them, and the guest's state transition must fail on them
  after `materialize_update` (Phase 8; upstream asserts `witness.is_empty()` there).
- `ArrayWitness` itself: borsh like `Vec<Vec<u8>>` (the remaining hints); serde a sequence of
  hints, each `0x` + lowercase hex in JSON and a byte sequence in binary formats.
- Hint types: a read value is `Option<SlotValue>`; a size query's answer is the bare leaf,
  `Option<NodeLeaf>` (never upstream's `NodeLeafAndMaybeValue` with a `ReadType` tag the guest
  had to check). The exact sequence, including the proof hints of `compute_state_update`, is
  defined by each storage (see the `Storage` docs, "The witness protocol").

State leaves (changing either changes every state root or witness):

| Item | Encoding |
|---|---|
| `NodeLeaf` (borsh, e.g. a leaf hint) | `size` (u32 LE) ‖ `val_hash` (32 bytes): 36 bytes |
| What a leaf commits to: `val_hash_and_size` | `val_hash` (32 bytes) ‖ `size` (u32 LE): 36 bytes |
| `val_hash` | `Storage::Hasher(value bytes)` (SHA-256) |
| `size` | `SlotValue::size()`: the length as `u32`, saturating at `u32::MAX` (never reached in the 32-bit guest, where a value holds < 2^31 bytes; upstream panicked) |

`StorageProof<P>` (from API clients and light clients): borsh the fields in order — `key`
(`SlotKey`), `value` (`Option<SlotValue>`, tag `0`/`1`), `proof` (`P`), `namespace`
(`ProvableNamespace`). JSON: an object with exactly the fields `key`, `value` (required, `null`
when absent), `proof`, `namespace`; no unknown fields, no array form. Verify a proof with the
container's `verify_proof`, which checks the namespace, that the key belongs to that container
(prefix, and for maps that the key bytes are the canonical encoding of the decoded key), then
opens it against the root; `Storage::open_proof` alone does not check the container.

## NOMT state trees, roots and proofs

Each provable namespace (user, kernel) is one NOMT binary trie hashed with
`BinaryHasher<Storage::Hasher>` (SHA-256): internal node `H(left ‖ right)` with the MSB cleared,
leaf `H(key_path ‖ value_hash)` with the MSB set, `[0; 32]` the empty sub-trie. A slot is the
leaf with:

| Item | Value |
|---|---|
| `key_path` | `H(SlotKey bytes)`, the whole key including its prefix (nobody chooses a key's tree position) |
| `value_hash` | `H(val_hash_and_size)` (NOMT stores the 36 bytes `val_hash_and_size` as the leaf's value) |

Known answer (`crates/state/src/nomt/vectors.rs`, checked against real NOMT and recomputed with
Python's `hashlib`): the slot keys `0x010101` → `0x0a000000` and `0x010102` → `0x14000000`
(`StateMap<u8, u32>` at prefix `[1, 1]`, entries `1 → 10`, `2 → 20`) give the key path
`0x75c8fd04ad916aec3e3d5cb76a452b116b3d4d0912a0a485e9fb8e3d240e210c` and value hash
`0x8779dca21abd1566b0e17b01af2b08520fdd985127b1b8862e193a47d9adc843` for the first, and the
tree root `0x41fb4b75571d866034946fd190e7baaa0e6e8add2e241bd666804ee9e8a50c92`.

`StorageRoot` (the state root, `Storage::Root` of the NOMT storages):

- borsh: `user_root ‖ kernel_root`, exactly 64 raw bytes (no length prefix). Stored by the node.
- JSON / `Display`: one `0x` + lowercase hex string of the 64 bytes (binary serde formats: 64
  bytes). Wrong length, missing `0x` and uppercase are rejected.
- Pre-genesis: 64 zero bytes (both trees empty).
- `global_root()` (what the zk proof commits to): `H("SELENDRA/state-root/v1" ‖ user_root ‖
  kernel_root)`, tag `GLOBAL_ROOT_TAG`. Upstream hashed the untagged `user_root ‖ kernel_root`,
  a 64-byte preimage with the exact shape of a NOMT internal node: the global root was (but for
  one bit) the root of a tree with the user tree on the left and the kernel tree on the right.
  Pinned: pre-genesis `0xf47d4e573e5b2d5c704dab9cf25e6e17c14c3675344d4cb0240709bb8c568ad2`.

`NomtProof` (`Storage::Proof` of the NOMT storages, and their multi-proof hint): a nomt-core
`MultiProof` that is well-formed. nomt-core's own type is malleable (a `TriePosition` compares
only its first `depth` bits, so the bits past them and its `node_index` take any value) and its
verification indexes unchecked (it panics on depth > 256, too few siblings, a path depth above
its bisection, a path that is a prefix of another). Decoding therefore checks:

- every terminator position has depth ≤ 256, equal to its path's depth, zero bits past the
  depth and the `node_index` derived from its path (equal to `TriePosition::from_path_and_depth`
  of its masked path; the root position at depth 0);
- terminal paths strictly ascending, none a prefix of the next;
- each path's depth where verification places its terminal, and exactly as many siblings as
  verification consumes (a hash-free walk of nomt-core's `verify_range`);
- the input is the re-encoding of the result.

borsh: nomt-core 1.0.5's borsh encoding of the `MultiProof`: `paths` (`u32` LE count, then per
path the terminal and `depth` as `u64` LE), then `siblings` (`u32` LE count, then 32 bytes each).
A terminal is tag `0` + leaf (`key_path`, `value_hash`) or tag `1` + terminator position (32
path bytes, `depth` `u16` LE, `node_index` `u64` LE). Pinned in `nomt/vectors.rs` (a real NOMT
proof and a three-terminal one), so a nomt-core upgrade that changes it fails the tests. JSON:
the borsh bytes as one `0x` + lowercase hex string (binary serde formats: the bytes);
nomt-core's derived serde form is not accepted (unknown fields, array form).

The verifier also rejects (as an invalid witness, not a decoding error) a multi-proof with a
path that no access of the block needs, and an empty multi-proof for accesses (NOMT proves keys
of an empty tree with one root terminator), so each execution has one witness.

Witness hints of the NOMT storages, in order: one `Option<NodeLeaf>` per `get_leaf`, one
`Option<SlotValue>` per `get` and per `put_in_witness` (the guest reads that one with `get`),
then in `compute_state_update` one `NomtProof` for the user namespace and then one for the
kernel namespace, each only if that namespace has a read or a write in the block
(`namespace_needs_proof`, shared by prover and verifier). Historical and unbound reads add
nothing. A namespace whose only access is a delete of an absent key is accessed: it gets a
proof (the prover must still give NOMT such deletes as reads of the key's absence: NOMT 1.0.5
panics committing a session whose only changes are such deletes into an empty database).

## Signatures

Never sign or verify a bare payload. Use `selendra_primitives::signing`, which signs
`0xB5 "SELENDRA" | version | domain | chain_id (u64 LE) | payload`, so a signature is bound to
its purpose (`SigningDomain`) and its network (`SELENDRA_CHAIN_ID` = 1961) and can never be a
valid Ethereum transaction or EIP-191/712 message.

## Checking

- `cargo test` — unit tests, including known-answer vectors and rejection tests.
- `cd fuzz && cargo +nightly fuzz run <target>` — targets `addresses`, `keys`, `state_keys`, `state_witness`, `tx_decoding`
  (no panics + canonical round-trip). Add a target for every new decoder.

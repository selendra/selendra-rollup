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
- Bound lengths **before** allocating, e.g. `RawTx` ≤ 1 MiB, `FullyBakedTx` ≤ 1.05 MiB. Every
  variable-length field of a decoded input (call messages) is a `SafeVec<T, N>` or a
  `SizedSafeString<N>` (see "Bounded containers and strings"), never a bare `Vec`/`String`.
- Do length arithmetic without overflow. The SP1 guest is **32-bit** (`usize` = 32 bits) and
  overflow checks are on in release builds, so `a + b` on two decoded lengths can panic there.
  Compare by subtraction (`b > MAX - a`) or use `checked_*` / `saturating_*`.
- No `HashMap`/`HashSet` in consensus types (iteration order); use `BTreeMap`/`BTreeSet`.
  Their borsh decoding rejects unsorted or duplicate keys only because the workspace enables
  borsh's `de_strict_order` feature. A "sorted `Vec`" needs its own strictly-increasing check.
- No floats in consensus code (`float_arithmetic` is denied workspace-wide).

## Consensus types

Every type stored in state, signed, sent in a call message or event, or committed to by a
proof is a **consensus type**: it implements the marker trait
`selendra_interface::common::ConsensusType`. The trait is implemented only for types that
contain, at no depth, any of:

- `usize` / `isize`: borsh encodes them as 64 bits, and the 32-bit zk guest fails to decode a
  value above `u32::MAX` that a native node accepts (the block becomes unprovable). Use `u64`
  or `u32`. One exception: a hand-written impl in the Selendra crates for a type whose own
  decoder rejects every such value above `u32::MAX` on every target, documented on the impl
  and tested; today only `NomtProof` (below);
- `f32` / `f64` (see above);
- `HashMap` / `HashSet` (iteration order depends on a per-process seed). Use
  `BTreeMap`/`BTreeSet`.

It is implemented for `bool`, the fixed-width integers, `String`, `str`, `()`, `Bytes`, and
for `Vec`, slices, arrays, `Option`, `Box`, `BTreeMap`, `BTreeSet` and tuples (up to 12) of
consensus types; for `PhantomData<T>` with any `T` (it stores nothing); and for the consensus
types of the Selendra crates (heights and slot numbers, `HexString`, `CredentialId`,
`SafeVec`, `SizedSafeString`, `RawTx`, `FullyBakedTx`, events, proof public data, `Time`,
addresses, keys, signatures, the state roots `StorageRoot` and `TestRoot`, amounts, gas,
module ids, …; "Module system types"). Every
`StateRoot` is one (a supertrait), so generic code can store `<S as Storage>::Root` and put it
in proof public data. Because containers implement it only when their contents do,
the check sees through type aliases, nested structs and generic parameters, which a check of
field syntax cannot. The `DaSpec` slot hash and address and the zkVM code commitment must be
consensus types (trait bounds). Module crates derive it (`#[derive(ConsensusType)]`,
re-exported by `selendra-modules-api`); a hand-written impl outside the Selendra crates is a
review flag. Foreign types get a newtype.

The derive (structs and enums; unions are rejected) bounds the impl by the field types, not
by the type's generic parameters: `Wrapper<T>` is a consensus type exactly when its fields
are, so `Wrapper<usize>` is not, and a `PhantomData<S>` field bounds nothing. A field type
without generic parameters is checked where the type is defined (E0277 there, e.g. a `usize`
field or a field of an alias to `f64`); a field type with generic parameters is checked where
the type is used with concrete ones (as a state value, call message, event, …). Recursive
types (`Option<Box<Self>>`, `Vec<Tree<T>>`) are supported. Two generic types holding each
other (`A<T>` holding a `B<T>` holding an `A<T>`) are not, with the inferred bounds alone: each
impl is bounded by the other's field type, and the trait solver loops (E0275) where they are
used. For them, the container attribute `#[consensus_type(bound(PRED, …))]` (unquoted where
predicates; `bound()` for none) replaces the inferred bounds: the impl's `where` clause is the
type's own plus exactly those predicates, and every field type, generic or not, is checked where
the type is defined under exactly those bounds. So the attribute decides how widely the impl
applies, more or fewer types than the inferred bounds (`bound()` drops the bound a recursive
field puts on the parameters it mentions), but never to a type whose fields are not consensus
types (`#[consensus_type(bound())] struct W<T>(T);` fails with E0277 at the definition).
`bound(T: ConsensusType)` on one type of the pair (or both) breaks the cycle. `bound` on a type
without type parameters is an error (no bound is inferred there). The derive is a marker impl
only: it never changes an encoding.

`selendra-state`'s `BorshCodec` encodes and decodes consensus types only, so every key and
value stored with it, in any module and with or without a derive, is one: `StateValue<usize>`
or `StateMap<u64, f64>` does not compile (E0277). A module's call messages and events
(`CallMessage`, `Module::Event`) and a runtime's call type (`DispatchCall::Decodable`) must be
consensus types too (trait bounds), and `TxDetails` is one; the other transaction types will
be made consensus types as they land.

Every public borsh type of `selendra-state` is a consensus type, each impl documenting why
its encoding is canonical and the same on 32 and 64 bits: `Prefix`, `SlotKey`, `SlotValue`,
`Namespace`, `ProvableNamespace`, `NodeLeaf`, `StorageProof<P>` (when `P` is), `NomtProof`,
`StorageRoot` and `ArrayWitness`. `Storage::Proof` must be one (like `Storage::Root`), so
`StorageProof<<S as Storage>::Proof>` can be stored or signed generically, and so must every
witness hint (`Witness::add_hint`/`get_hint`): the 32-bit guest decodes what the native
prover encoded. `NomtProof` is the one case where the decoder, not the field types, makes
the encoding safe: nomt-core's `MultiProof` has two `usize` fields (a path's `depth`, a
terminator's `node_index`, borsh `u64`s), and `NomtProof`'s decoder accepts only depths up to
256 and the `node_index` derived from the path, so a value above `u32::MAX` is rejected
natively by that check and on 32 bits by borsh: both accept the same bytes. A compile-time
assertion in `selendra-state` (`consensus_types.rs`) lists them; tests check each round trip
and the rejection of non-canonical bytes (other tags, trailing bytes, short keys, the
`usize` fields above `u32::MAX`).

What the trait does not check: that `BorshSerialize` never fails (a documented rule), and the
round-trip precondition below.

## Bounded containers and strings

`selendra_interface::common`:

| Type | borsh | JSON / serde | JSON schema |
|---|---|---|---|
| `SafeVec<T, N>` (at most `N` elements) | as `Vec<T>`: `u32` LE length, then the elements | as `Vec<T>` (a sequence) | `SafeVec_{N}_of_{T}`: `type: array`, `maxItems: N` |
| `SizedSafeString<N>` (at most `N` bytes of printable ASCII `0x20..=0x7e`); `SafeString` = `SizedSafeString<128>` | as `String` | a JSON string | `SafeStringMax{N}`: `maxLength: N`, `pattern: ^[\x20-\x7e]*$` |
| `HexString<SafeVec<u8, N>>` | as `SafeVec<u8, N>` | `0x` + lowercase hex, at most `2N` digits | `HexBytesMax{N}`: `pattern: ^0x(?:[a-f0-9]{2}){0,N}$` |

- Every decoder (borsh, any serde format, `FromStr`) rejects more than `N` elements or bytes
  before allocating for them. borsh and binary serde formats check the claimed length, and
  the count as elements arrive. A string (`SizedSafeString`, a hex string in JSON) is checked
  as the format hands it over, before it is copied or hex-decoded; the format's own buffer
  (e.g. serde_json's for an escaped string) is bounded by the input.
  `crates/interface/tests/decode_allocations.rs` counts the allocations. `HexString` takes the
  cap from its inner type (`HexBytes::MAX_LEN`: `N` for `SafeVec<u8, N>` and `[u8; N]`).
- `SafeVec` rejects collections of zero-sized types (as borsh does for `Vec`). A serde size
  hint only sizes the first allocation: elements are read until the sequence ends, so an
  under-reported hint is accepted.
- Every operation that can grow a `SafeVec` is fallible (`try_*`) and changes nothing when it
  fails; an invalid range is an error, never a panic. So every value that can be built
  encodes to bytes the decoders accept.
- Schema names include `N` (upstream named every capped hex string `HexHash`, so schemas of
  different caps collided), and patterns are lowercase, like the accepted strings.

## Transactions

`RawTx` (at most `MAX_RAW_TX_SIZE` = 1 MiB) and `FullyBakedTx` (data and sequencing data
together at most `MAX_FULLY_BAKED_TX_SIZE` = 1.05 MiB) have private fields and fallible
constructors (`RawTx::new`, `FullyBakedTx::new` / `with_sequencing_data`, `TxTooLarge`), with
the same caps as their decoders: a value that no decoder accepts cannot be built. Encodings:

- `RawTx`: borsh as `Vec<u8>`; JSON `{"data": [bytes…]}` (an object, no unknown fields).
- `FullyBakedTx`: borsh `data` (as `Vec<u8>`), then `sequencing_data` (`Option`, tag `0`/`1`
  only); JSON `{"data": base64, "sequencing_data": base64 | null}` (canonical padded base64,
  no unknown fields). `len()` is the borsh length.
- `MAX_RAW_TX_SIZE + 5 ≤ MAX_FULLY_BAKED_TX_SIZE` (compile-time assertion): a `RawTx` behind
  a one-byte tag always fits in a `FullyBakedTx`.

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
  of that accessor's writes (a metered accessor's failure poisons its phase, whose writes are
  then reverted: see "Metered state access"), never catch the error and keep them. Even so,
  `StateVec` shrinks its length before deleting and grows it after writing, so after a failure
  every element in `0..len` is still present, and every read is bounds-checked against `len` (a
  leftover element past `len` is never returned).
- `User`, `Kernel` and `Accessory` are separate key spaces: the same key in two namespaces
  is two different values.
- Decoding a stored value panics on failure (`StateItemDecoder::decode_unwrap`; the message
  shows at most 32 bytes). A failure means one of:
  - the stored type breaks the **round-trip precondition**: for every value `v` that can be
    constructed, `decode(encode(v))` must succeed and give `v`. A type whose decoder is stricter
    than its encoder (e.g. a public `Vec` field with a size-capped decoder, as `RawTx` and
    `FullyBakedTx` had upstream) must enforce its bound at construction (like `RawTx`,
    `FullyBakedTx`, `SafeVec` and `SizedSafeString` do) or must not be stored, otherwise whoever
    chooses the stored value can make every later read panic. Containers `debug_assert!` the
    round trip on every write (debug builds only);
  - two items share a prefix, or the database is corrupt (bugs);
  - in the zk guest, an invalid witness: reads return the prover's unverified hints, which are
    checked against the state root only later. Panicking (no proof) is the intended result; this
    must never become a recoverable error, or control flow would depend on unverified bytes.
- Encoding a stored key or value panics where borsh refuses it: a collection longer than
  `u32::MAX` or of zero-sized types, a NaN float, or an error from a hand-written
  `BorshSerialize`. State key and value types are consensus types (`BorshCodec` requires it, see
  "Consensus types"), so they contain **no floats**, and their `BorshSerialize` impls must be
  infallible.
- Encodings of the key types (each has exactly one accepted encoding):
  - `SlotKey`: borsh like `Vec<u8>` (the whole key, prefix included), at least 2 bytes. JSON and
    `Display` use `0x` + lowercase hex. `SlotKey::try_from_bytes` rejects < 2 bytes and never panics.
  - `SlotValue`: borsh like `Vec<u8>`; JSON `0x` + lowercase hex.
  - `Prefix`: borsh the 2 bytes; JSON and `Display` `"0x0102"`.
  - `Namespace` / `ProvableNamespace`: borsh one tag byte (`0` user, `1` kernel, `2` accessory);
    JSON only the snake_case string (`"user"`). Serde's derived decoding would also accept `{"user":null}`.

## Metered state access

Transactions access state through metered accessors (`selendra_state::metered`). Their gas
and the order of their storage accesses are part of consensus: the native node and the zk
guest must charge the same gas, fail at the same access, and record the same reads and
witness hints. Changing anything below changes `gas_used` (a fork).

**Formulas.** Every term comes from the spec's gas schedule (`StateAccessCosts`). `key_len` is
the whole `SlotKey` (prefix included), `size`/`len` the value's bytes. All arithmetic is
checked: an overflow is a `GasOverflow` failure, never a wrap or a panic.

| Access | First charge, before touching storage | Second charge, once the value is known present |
|---|---|---|
| read (`get`) | `access + hash_update + hash_per_byte·key_len + read` | `read_per_byte·size + hash_update + hash_per_byte·size` |
| read and decode (`get_decoded`, every typed container read) | the same | the same `+ decode_per_byte·size` |
| `set` (User, Kernel) | `access + hash_update + hash_per_byte·key_len + write + write_per_byte·len + hash_update + hash_per_byte·len` | – |
| `delete` (User, Kernel) | `set` with `len = 0` | – |
| `set`/`delete` (Accessory) | `accessory_write + accessory_write_per_byte·(key_len + len)` (`len = 0` for a delete) | – |
| open a nested scope (`open_scope`; `to_revertable`) | `scope_open`, before the scope is pushed | – |
| emit an event (`EventContainer::add_event`) | `event_base + event_per_byte·(key_len + borsh_len)`, after the key bound (`key_len` ≤ 256, below), before the event is kept | – |

- A read takes `size` from the transaction's journal, or from the checkpoint's size query
  (in the guest only the value's leaf comes from the witness); an absent value gets no second
  charge. The value is fetched only after the second charge succeeds.
- A read of a key the transaction wrote (a journal hit) is charged the full formula, like a
  first read. `StateVec::get` is two reads (the length, then the element); `iter()` reads the
  length once.
- Accessory writes are charged (upstream: free) and journaled like the others.
- Opening a nested scope is charged `scope_open` (upstream's `to_revertable`: free, so the
  scopes a call opened were bounded only by the number of calls). It is charged only after
  the phase and the accessor's scope are checked, so opening on a poisoned phase or through a
  stale accessor charges nothing. A refused charge opens nothing. Closing a scope is free, and so is the phase's base scope (opened by the state
  transition function, not a module).
- **Value size bound:** a metered write of more than `MAX_STATE_VALUE_SIZE` = 1 MiB
  (`1 << 20` bytes, checked on the value's length before any charge) fails with
  `ValueTooLarge`. Genesis writes are metered (`GenesisStateAccessor`, below), so the bound
  applies to them. Unmetered writes (kernel, block hooks) are only checked in debug builds
  until Phase 8.
- **Event key bound:** an event key of more than `MAX_EVENT_KEY_LEN` = 256 bytes (its UTF-8
  length, `key.len()`; checked before the event is charged) fails with `EventKeyTooLong`
  (`MeteredRef::check_event_key`, called by every `EventContainer::add_event`). It is the
  same constant (`selendra-state`'s) the ledger stores event keys under (`event_by_key`,
  "Node state databases"), so every event a transaction keeps can be stored: a longer key would
  make the node fail to materialize the slot.

**Failures and reverts.** A metered phase (`MeteredTx`: pre-execution, or the call with its
hooks) runs in a base scope of the transaction's journal (`TxScratchpad`) over the block's
checkpoint.
- The first failed access (`OutOfGas`, `GasOverflow`, `ValueTooLarge`, `EventKeyTooLong`,
  `ScopeMisuse`; a
  refused scope open included) **poisons** the phase. A refused charge charges nothing. Every
  later access returns `Poisoned` before touching the meter or storage, so it adds neither gas
  nor a witness hint.
- `MeteredTx::finalize(result)` commits the base scope into the scratchpad only if the phase
  is not poisoned **and** `result` is `Ok`; otherwise it reverts it. The gas used is kept either
  way. Reverting a nested scope never clears the poison.
- Nested scopes (`open_scope`/`close_scope`) commit into their parent or revert. Closing a
  scope out of order, twice, or from another phase is `ScopeMisuse` (and poisons). A scope left
  open (a leaked guard) is reverted by the next access through an enclosing accessor and by
  `finalize`. `open_scope` itself never returns an error: if it fails (poisoned phase, closed
  accessor scope, refused `scope_open` charge) it poisons the phase, opens nothing and returns
  a token that matches no scope.
- A scope token is valid only in the phase that issued it: it carries a serial number unique
  within the phase and the phase's identity (a shared allocation compared by address, never
  read as a value), so a token of another phase never matches, even one of another
  checkpoint alive at the same time with the same depth and serial. The identity never
  reaches state, the witness or gas. Tokens are neither `Send` nor `Sync`, so no safe `static`
  can hold one (only a `static mut` could, which needs `unsafe`, forbidden in the workspace;
  the identity check still rejects such a token in a later phase).
- `TxScratchpad::commit` applies the journal to the checkpoint in key order (namespace, then
  key); `revert` drops it, accessory writes included. Reads stay recorded in the checkpoint
  either way, so they are verified against the state root.

**Events.** `key_len` is the event key's length in bytes, `borsh_len` the length of the
event's borsh encoding (`borsh::object_length`, computed the same way natively and in the
guest). An encoding that fails cannot be priced and is a `GasOverflow` failure (borsh encoders
must be infallible). Events are kept only natively (the guest charges and drops them), in the
scope they were emitted in: a committed nested scope hands its events to its parent, a reverted,
dropped or leaked one drops them, and a phase's events are returned only if it is committed.
Events reach the state transition function only through the module system's accessors, which
all charge: `EventContainer` is sealed (no other crate implements it, so none writes its own
`TxState`), and a committed nested scope's charged events go only to the accessor it was opened
on (they cannot be named or built outside the crate). Upstream's events were free.

**Accessors** (`selendra-modules-api`, `state`). Every transaction accessor is a metered
phase or a scope of one, charging the formulas above through `selendra-state`'s blanket impls:

| Accessor | Phase | Rights | Meter |
|---|---|---|---|
| `PreExecWorkingSet` (authentication, gas reservation) | its own | `PreExecRights`: User R/W | the caller's `BasicGasMeter` |
| `WorkingSet` (the call and its hooks; a `TxState`) | its own | `TxRights`: User/Kernel R/W, Accessory W | the caller's `BasicGasMeter` |
| `RevertableTxState` (`to_revertable`; a `TxState`) | its parent's, a nested scope | its parent's | its parent's |
| `GenesisStateAccessor` (a `GenesisState`; true slot = genesis) | its own, over the genesis checkpoint | `TxRights` | `BasicGasMeter` with the most gas at a zero price (genesis is recorded, not paid) |
| `BlockState` (block hooks) | none: unmetered, infallible, on the block's checkpoint | User/Kernel R/W, Accessory W | – |

`WorkingSet::finalize(result)` / `PreExecWorkingSet::finalize(result)` return the scratchpad,
the meter and the outcome (`TxOutcome`: `Committed`, or `Reverted(Poisoned(first failure) |
Module(error))`); the state transition function (Phase 8) settles the gas used on the returned
scratchpad whatever the outcome. Module code charges other work through the accessor's
`GasMeter` (one blanket impl over every metered accessor: a refused charge poisons the phase
like a refused access).

**Metered utilities** (`selendra-modules-api`, `gas`), charged with the spec's
`GAS_SCHEDULE`, all through the accessor's phase (a refused charge poisons it). `MeteredHasher`
and `metered_from_slice` charge before the work; `MeteredReader` charges each call right after
its inner read, for the bytes that read delivered (so it never charges for bytes it did not
deliver; when the charge is refused, the bytes are already in the caller's buffer, but the
phase is poisoned, so they cannot lead to a kept write):

| Utility | Charge |
|---|---|
| `MeteredHasher` (SHA-256, the state hasher) | `hash_per_byte·len` per `update`, `hash_update` for `finalize`: hashing `n` bytes costs `hash_update + hash_per_byte·n` however it is split, like hashing a state value (upstream: a fixed cost per update, the finalization free) |
| `MeteredBorshDeserialize::metered_from_slice` | `decode_per_byte·len` for the whole input, then `borsh::from_slice` (trailing bytes rejected, after being charged). Upstream charged per read call while decoding and left trailing bytes to the caller |
| `MeteredReader` (`io::Read`) | `per_read_bias + per_byte·n` per call that delivers `n > 0` bytes (`new`: `decode_per_byte`, no bias). `read_exact` charges the bytes it consumed also when the input ends or the inner reader fails, and a refused charge is then the error (upstream discarded it: the bytes were free) |

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
- Hints are consensus types (`Witness::add_hint`, `try_get_hint` and `get_hint` require
  `ConsensusType`; `compile_fail` doctests on `Witness` pin each with a `usize`): the 32-bit
  guest decodes what the native prover encoded, so every hint type decodes the same natively
  and on 32 bits. No hint has an unbounded `usize`: the only `usize` fields are the two in
  `NomtProof` (the multi-proof hint), which its decoder bounds (see "Consensus types").
- Hint types: a read value is `Option<SlotValue>`; a size query's answer is the bare leaf,
  `Option<NodeLeaf>` (never upstream's `NodeLeafAndMaybeValue` with a `ReadType` tag the guest
  had to check). The exact sequence, including the proof hints of `compute_state_update`, is
  defined by each storage (see the `Storage` docs, "The witness protocol").
- A checkpoint's versions (visible slot number, rollup height) are read from its own state,
  never passed in from outside the checkpoint:
  - by the closure of `StateCheckpoint::new_with`: the checkpoint's first reads, so their
    hints come first in the witness and they are verified against the prior state root;
  - by the closure of `refresh_versions`: reads of the checkpoint's current state, so values
    the kernel wrote earlier in the block come from the checkpoint's write cache (no hint);
    only a key not yet read or written is a first read, with a hint, verified.

  Either way the reads are committed at once, so a later `discard_revertable_storage_cache`
  cannot drop them (or the writes they read) from verification.

  `refresh_versions` commits everything revertable in the checkpoint, so it belongs between
  transactions. The compiler enforces that for transactions run on a `TxScratchpad`: the
  scratchpad (and the `MeteredTx` phases that own it) takes the checkpoint by value and gives
  it back only from `commit`/`revert`, with no way to reach it in between, so refreshing
  during a transaction does not compile (E0382, E0616; doctests on `refresh_versions`). It
  does not cover writes made on the checkpoint directly (kernel, block hooks) or a committed
  scratchpad's writes (a transaction's, or genesis's: `GenesisStateAccessor` writes through a
  scratchpad): a caller that may still drop those with
  `discard_revertable_storage_cache` (a sequencer dropping a transaction) must decide before
  refreshing.

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
`BinaryHasher<Storage::Hasher>`, where the hasher is always `selendra_state::StateHasher`
(SHA-256, `sha2 =0.10.9`, the version the SP1 guest patches): internal node `H(left ‖ right)`
with the MSB cleared, leaf `H(key_path ‖ value_hash)` with the MSB set, `[0; 32]` the empty
sub-trie. A slot is the leaf with:

| Item | Value |
|---|---|
| `key_path` | `H(SlotKey bytes)`, the whole key including its prefix (nobody chooses a key's tree position); `selendra_state::key_path` |
| `value_hash` | `H(val_hash_and_size)` (NOMT stores the 36 bytes `val_hash_and_size` as the leaf's value; `selendra_state::leaf_value_bytes`) |

The verifier and the node's prover call the same two functions. The leaf hint's borsh order
(`size ‖ val_hash`) is not what the tree commits to (`val_hash ‖ size`): only the hint's fields
are used. The MSB tag is what keeps a leaf's 64-byte preimage from being opened as an internal
node's children and the reverse (`crates/state/src/nomt/vectors.rs` shows both attacks on an
untagged hasher); it leaves 255 bits of each node hash (collisions about 2^127.5).

Known answer (`crates/state/src/nomt/vectors.rs`, checked against real NOMT and recomputed with
Python's `hashlib`): the slot keys `0x010101` → `0x0a000000` and `0x010102` → `0x14000000`
(`StateMap<u8, u32>` at prefix `[1, 1]`, entries `1 → 10`, `2 → 20`) give the key path
`0x75c8fd04ad916aec3e3d5cb76a452b116b3d4d0912a0a485e9fb8e3d240e210c` and value hash
`0x8779dca21abd1566b0e17b01af2b08520fdd985127b1b8862e193a47d9adc843` for the first, and the
tree root `0x41fb4b75571d866034946fd190e7baaa0e6e8add2e241bd666804ee9e8a50c92`. With that user
tree and an empty kernel tree, the global root (below) is
`0xb92091904e678ae0016fee3132b4468fbe773646fee760e546518bebb0c05c9b`. These are
`selendra_state::test_vectors` (feature `test-utils`), and the node's prover storage is checked
against them (`crates/db/src/prover/tests.rs`).

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

## Node state databases (on disk)

What a node stores (`selendra-db`; node-only, not consensus: a format change needs a migration
or a resync, never a fork). Under the database directory: the NOMT trees `user_nomt/` and
`kernel_nomt/` (key path `H(SlotKey)` → the 36 bytes `val_hash_and_size`, as above; NOMT's own
file format), and four RocksDB instances. Versions (slot numbers) and other numbers in keys are
big-endian (`u64`: 8 bytes, `u32`: 4 bytes), so byte order is number order.

| Column family | RocksDB | Key | Value |
|---|---|---|---|
| `user_state_values`, `kernel_state_values` | `state-db/` (live) | the raw `SlotKey` bytes | the raw `SlotValue` bytes; a deleted key is absent |
| `user_state_historical_values`, `kernel_state_historical_values` | `archival-state-db/` | `SlotKey` bytes ‖ version | `0x01 ‖ value` for a write, `0x00` for a delete |
| `user_state_pruning`, `kernel_state_pruning` | `archival-state-db/` | version ‖ `SlotKey` bytes | empty |
| `user_state_version_metadata`, `kernel_state_version_metadata` | both | `[0]` committed version (live), `[1]` pruned version (archival) | version |
| `state_root_hashes` | both, and `accessory/` | version | the 64 bytes `user_root ‖ kernel_root` (= `StorageRoot` borsh) |
| `module_accessory_state` | `accessory/` | borsh `Vec<u8>` key ‖ version | borsh `Option<Vec<u8>>` (`None`: deleted) |
| `accessory_keys_by_version` | `accessory/` | version ‖ borsh `Vec<u8>` key | empty |
| `db_metadata` | `accessory/` | ASCII name: `state_hasher`, `accessory_pruned_version` | `state_hasher`: the 32 bytes `H("SELENDRA/state-hasher/v1")`; `accessory_pruned_version`: the accessory pruning watermark (`u64`) |
| `slot_by_number` | `ledger/` | slot number | borsh `StoredSlot`: DA hash (32), DA height (`u64`), roots (64: `user ‖ kernel`), timestamp (`i64` ms), then the batch, transaction, event and discarded-blob ranges (each `start ‖ end`, `u64`) |
| `slot_by_hash` | `ledger/` | DA block hash (32) | slot number |
| `batch_by_number`, `tx_by_number`, `event_by_number`, `discarded_blob_by_number` | `ledger/` | item number | borsh `StoredBatch` (hash, tx range, receipt bytes, slot), `StoredTransaction` (hash, event range, `Option` body bytes, receipt bytes, batch), `StoredEvent`, `StoredDiscardedBlob` (`DiscardedBlob`, slot) |
| `batch_by_hash`, `tx_by_hash`, `discarded_blob_by_hash` | `ledger/` | hash (32) ‖ item number | empty |
| `event_by_key` | `ledger/` | `u16` key length ‖ event key (at most `MAX_EVENT_KEY_LEN` = 256 bytes: `selendra-state`'s constant, which the state transition function enforces when an event is emitted) ‖ tx number ‖ event number | empty |
| `event_count_by_key` | `ledger/` | the raw event key | count (`u64` big-endian; no row at 0) |
| `aggregated_proof_by_slot` | `ledger/` | slot number ‖ `u32` index | the proof bytes |
| `proof_receipt_by_slot` | `ledger/` | slot number ‖ `u32` index | borsh `([u8; 32], Vec<u8>)`: blob hash, receipt bytes |
| `proof_receipt_by_hash` | `ledger/` | blob hash (32) ‖ slot number ‖ `u32` index | empty |
| `stf_info_by_slot` | `ledger/` | slot number | the STF info bytes |

- The archival value is tagged so an empty value (e.g. a `StateValue<()>`, borsh of `()` is
  empty) is not read back as a delete; upstream rockbound archived deletes as the empty string,
  so its databases are not readable by ours (any other archival value is reported as
  corruption).
- A historical read of a key at version `v` takes the row `key ‖ v'` with the largest `v' <= v`
  and skips rows of other keys that start with the same bytes (a `StateVec`'s length at `P` and
  its element 0 at `P ‖ 0u64`; upstream rockbound returned "absent" there).
- Every decoder rejects data that is not exactly an encoding (wrong length, trailing bytes):
  stored data that does not decode is an error, never a panic.
- Every committed version stores its root in all four RocksDB instances (the ledger in its slot
  row: one slot per version), and the NOMT trees hold the newest one, so the databases are
  checked against each other when opened.
- Ledger receipts, transaction bodies, proofs and STF info are opaque bytes; their encoding is
  the node's (borsh, Phase 10). Item numbers (batch, transaction, event, discarded blob) count
  from 0 across slots, and each slot records its four ranges, so the next numbers come from the
  newest slot alone. A slot's writes are point writes only (a snapshot reader cannot see range
  deletes); a rollback (startup crash recovery) uses range deletes and is written straight to
  the database.
- Hasher guard: the first open of empty databases writes `db_metadata/state_hasher` with the
  configured hasher `H` (`SHA-256("SELENDRA/state-hasher/v1")` =
  `0x83500e863799fb8a52f07a55b6360bc1e83f638c765875a926ea0fd7ac582aaf`); every later open
  must compute the same tag, before anything writes data hashed with `H`. (Opening the
  databases writes nothing hashed with `H` but can already change files: NOMT's own log replay
  and hash-table growth, RocksDB creating missing column families.) Databases that hold data
  but no tag are refused (databases from before the guard: resync).
- Pruning (`selendra-db` `pruner`) deletes rows of the archival and accessory stores up to a
  cutoff version, consuming the index rows (`*_pruning`, `accessory_keys_by_version`) it
  inspects: a row is deleted when a newer write of its key at or below the cutoff exists, and a
  key's newest row at or below the cutoff only if it is a delete marker. The watermarks
  (`[1]` in each `*_version_metadata` of `archival-state-db/`, `db_metadata/accessory_pruned_version`)
  are the newest version whose reads may have lost a row: reads at or below them are
  `PrunedVersion` errors. The ledger and `state_root_hashes` are not pruned.
- Upstream's legacy `*_jmt_values` column-family names are not used (fresh chain).

## Signatures

Never sign or verify a bare payload. Use `selendra_primitives::signing`, which signs
`0xB5 "SELENDRA" | version | domain | chain_id (u64 LE) | payload`, so a signature is bound to
its purpose (`SigningDomain`) and its network (`SELENDRA_CHAIN_ID` = 1961) and can never be a
valid Ethereum transaction or EIP-191/712 message.

The signed bytes are a `SigningBytes`, a newtype with a private field that only
`signing_bytes(domain, chain_id, payload)` builds; `verify_signing_bytes` and
`sign_signing_bytes` take it, and the `verify`/`sign` convenience functions build it. APIs that
verify signatures over protocol messages (transactions, the authenticator) take
`&SigningBytes`, so a bare payload is a type error. `Signature::verify` / `PrivateKey::sign` on
raw bytes are the low-level layer (key tests, RFC 8032 vectors).

Account addresses: an ed25519 key's native account (and a multisig credential's) is
`Address::from_hash_prefix` of its 32-byte credential (the first 28 bytes); a secp256k1 key's
account is its Ethereum address (`MultiAddress::Vm`). There is no `From<CredentialId>` for
`Address` or `MultiAddress`: a credential does not say which kind of key produced it.

## Mock adapters

`selendra-mock-da` and `selendra-mock-zkvm` (tests and local chains only: the mock DA verifier
accepts every claim, and a mock proof is a claim its verifier believes). Their types are still
held to the rules above, because modules store them (`DaSpec::SlotHash`/`Address`, the code
commitment) and the guest decodes them. Every public borsh type is a consensus type
(`MockHash`, `MockAddress`, `MockDaSpec`, `MockCodeCommitment`, `MockProof`).

| Type | borsh | Text and JSON | Binary serde (postcard) |
|---|---|---|---|
| `MockHash` (block hash, blob hash, transaction id) | the 32 bytes | `0x` + 64 lowercase hex digits | a sequence of 32 bytes |
| `MockAddress` (`MockDaSpec::Address`) | the 32 bytes | `0x` + 64 lowercase hex digits (schema `^0x[a-f0-9]{64}$`) | a sequence of 32 bytes |
| `MockCodeCommitment` (= its `CodeCommitmentHash`; upstream: 8 bytes, zero-padded) | the 32 bytes | JSON only (no `Display`/`FromStr`): `0x` + 64 lowercase hex digits | a sequence of 32 bytes |
| `MockProof` | `is_valid` (`0`/`1`) ‖ `pub_data` (`u32` LE length, bytes) ‖ `code_commitment` (32 bytes) | none | none |
| `MockDaSpec` | nothing (a unit struct) | none | none |
| `MockBlockHeader` (serde only) | none | an object with exactly `height`, `prev_hash`, `hash`, `time` (milliseconds); no array form | the fields in order |
| `MockBlob` (serde only: never stored or signed) | none | an object with exactly `address`, `hash`, `blob`; `blob` an object with exactly `inner` (the bytes not verified yet) and `accumulator` (the verified bytes), each an array of byte values; no array forms, no string form of the bytes | the fields in order (`inner` and `accumulator` each a length, then the bytes) |
| `MockBlock` (native, serde only) | none | an object with exactly `header`, `batch_blobs`, `proof_blobs`; no array form | the fields in order |

- Text and JSON accept only the form they print (no missing `0x`, no uppercase; upstream
  accepted both for addresses and printed no prefix in JSON).
- A `MockProof` is decoded with `borsh::from_slice` by every verifier entry point
  (`verify_with_proof`, `verify_with_pub_values`, `extract_public_data`), and so is its public
  data: trailing bytes are rejected and malformed input is an error, never a panic (upstream:
  bincode, and the host `expect`ed inner proofs to decode). `verify_with_pub_values` takes the
  whole encoded `MockProof` (the mock has no separate proof channel).
- The mock guest's hint is the postcard encoding of one value (`encode_hint`), read with
  `postcard::take_from_bytes` and rejected unless every byte is consumed (upstream:
  `bincode::deserialize`, which ignored trailing bytes). postcard accepts over-long varints, so
  a hint has one accepted value, not one accepted encoding: hints are prover-internal, and the
  proof's public output is what counts. `try_read_from_host` returns the error;
  `ZkvmGuest::read_from_host` panics on it (a guest cannot continue without its hint: no proof).
- The guest's public output is the concatenation of the borsh encodings of every committed
  item, like SP1's `commit_slice` (upstream kept only the last commit).
- `MockBlockHeader::new(height, time)` derives the hashes from the height: `height` (parent)
  and `height + 1` (block), each a big-endian `u128` in the first 16 bytes, then zeros (upstream
  added 1 to a `u64` and overflowed at `u64::MAX`). `MockBlob::new_with_hash` hashes the data
  as `SHA-256(SHA-256(data))`.

## Module system types

`selendra-modules-api` (Phase 5). Every public borsh type is a consensus type (`Amount`,
`GasUnit<N>`, `GasPrice<N>`, `BlockGasInfo<G>`, `ModuleId` and every `hash32_id!` type,
`OperatingMode`, `SequencerType`, `PriorityFeeBips`, `TxDetails<S>`, `NotInstantiable`,
`SelendraSpec`), and a spec's `Gas` and `Address`, a module's call messages and events
(`Module::CallMessage`: `CallMessage`; `Module::Event`) and a runtime's call type
(`DispatchCall::Decodable`) must be (trait bounds).

| Type | borsh | JSON (and other human-readable formats) | Binary serde (postcard) |
|---|---|---|---|
| `Amount` (token base units) | `u128` LE (16 bytes) | a decimal **string**: digits only, no sign, no leading zeros (`"0"` itself excepted), at most `u128::MAX`; a JSON number is rejected. `FromStr`/`Display` the same. Schema: `^(0\|[1-9][0-9]*)$`, `maxLength` 39 | `u128` |
| `GasUnit<N>` (gas; `Spec::Gas` = `GasUnit<2>`) | the `N` values, `u64` LE each, no length prefix | an array of exactly `N` numbers (schema `GasUnit{N}`) | as `[u64; N]` |
| `GasPrice<N>` | the `N` amounts, `u128` LE each, no length prefix | an array of exactly `N` amount strings (schema `GasPrice{N}`, items `Amount`; upstream's schema said numbers) | as `[Amount; N]` |
| `BlockGasInfo<G>` | `gas_limit`, `gas_used`, `base_fee_per_gas` (64 bytes for `GasUnit<2>`) | an object with exactly `gas_limit`, `gas_used`, `base_fee_per_gas`; no unknown fields, no array form | the fields in order |
| `ModuleId` and every `hash32_id!` id | the 32 bytes | bech32m `<prefix>1…` (`module_1…` for `ModuleId`): lowercase only, the canonical encoding only (no extra padding symbol, zero padding bits); `FromStr`/`Display` the same. Schema named after the type, pattern `^<prefix>1[02-9ac-hj-np-z]{58}$` | the 32 bytes |
| `OperatingMode` | one byte, explicit tags: `1` = `Zk`, `2` = `Operator` (`0` never assigned) | `"zk"` / `"operator"` | the variant index |
| `SequencerType` | one byte: `0` = `Preferred`, `1` = `NonPreferred` | `"Preferred"` / `"NonPreferred"` | the variant index |
| `PriorityFeeBips` (basis points: `100` = 1%) | `u64` LE | a number | `u64` |
| `TxDetails<S>` (a transaction's fees, gas limit and runtime version) | `max_priority_fee_bips` (`u64`), `max_fee` (`u128`), `gas_limit` (`Option<S::Gas>`: tag `0`, or tag `1` and the gas), `runtime_version` (`u32`), all LE: 29 bytes without a gas limit, 45 with one (`GasUnit<2>`) | an object with exactly these four fields: `gas_limit` an array or `null` (never missing), `max_fee` an amount string, the others numbers; unknown fields (upstream's `chain_hash_fragment` included) rejected | the fields in order |
| `NotInstantiable` (call message of a module without calls) | never decodes (no values) | never decodes; schema `null` | never decodes |
| `SelendraSpec` (a marker) | no bytes | `null` | nothing |

- **`ModuleId`** = `SHA-256("SELENDRA/module-id/v1" ‖ name)` with the state hasher, from the
  module's stable name (`^[a-z][a-z0-9_]{0,31}$`, checked by the module derive), not from its
  Rust path. Known answer: `bank` → `module_1hudzpucnkw7pzx8eye8am5g00y7xtduwfr5dcuepvnkhwrkwa07shpzs2t`.
- **`hash32_id!`** prefixes are 1 to 20 characters of `a-z`, `0-9`, `_` (checked at compile
  time); 32 bytes are 52 data symbols, the last holding 4 padding bits, which must be zero
  (upstream accepted any: 16 strings per id).
- **Gas arithmetic** is checked per dimension; an overflow is an error or `None`, never a wrap,
  a saturation or a panic. A gas value in tokens is `Σ gas[i] · price[i]` (`checked_value`).
- **Gas meters** change only through atomic charges: a refused charge changes nothing (upstream's
  slot meter reduced the preferred sequencer's budget before checking the slot's), and their
  fields are private. A transaction meter keeps `remaining + used == initial` and the value of
  the gas used computable at its price. The slot meter gives the preferred sequencer
  `⌊limit / 10⌋ · 9` of each dimension.
- **Priority fee:** `apply(quantity) = ⌊quantity · bips / 10_000⌋`, exact for every `u128`
  quantity (upstream dropped a remainder above `2^64`), an error if it does not fit;
  `from_percentage` is checked.
- **Gas schedule** (`Spec::GAS_SCHEDULE`): per-operation costs only (state access as in "Metered
  state access", encoding per byte, public-key decode, signature verification fixed and per
  byte per scheme, events). Block and transaction gas limits and the base fee are runtime values
  (Phase 6 `fee-params`), not constants. `SelendraSpec`'s values are placeholders until Phase 6
  calibrates them.
- **`TxDetails::runtime_version`** selects an entry of the runtime's version table (the spec
  version and schema hash the signing payload commits to); it replaces upstream's 64-bit
  `chain_hash_fragment`. Phase 6 adds the fee token and payer (a pre-genesis format change).
  `Context` and `AuthenticatedTransactionData` are never serialized.

### Modules

A module's identity is two constants of `ModuleInfo`, written once, intrinsic to the module
type (a module nested in another as a dependency has the same ones):

- **`DISCRIMINANT: u8`** numbers the module for everything: the first byte of every state
  prefix of the module (`Prefix::new(DISCRIMINANT, item)`), and the tag of its calls and events
  in the runtime's encodings. Unique within a runtime, never `0`.
- **`NAME`** (`^[a-z][a-z0-9_]{0,31}$`), unique within a runtime: the key of the module's
  calls and events in JSON, the first half of its event keys, and the source of its
  `ModuleId`.

Upstream named a module three ways: its `prefix()` (REST names) and id from its Rust path,
the module byte of its state prefixes from a `constants.toml` discriminant, its call tags from
its position in the runtime.

**Module discriminants.**

| Range | For |
|---|---|
| 0 | reserved (rejected by the module derive and the runtime's checks) |
| 1–127 | Selendra's runtime modules (allocated in Phase 6, each pinned by a known-answer test) |
| 128–223 | other modules (future, applications) |
| 224–255 | test modules |

Only `0` is enforced: nothing can tell a test module from a production one.

**`#[derive(ModuleInfo)]`** (`selendra-modules-api` re-exports it; it also implements
`Default`, the module's constructor) reads the identity from
`#[module_info(discriminant = N, name = "…")]` (an integer literal in 1..=255 and a valid
name, each exactly once) and one attribute per field: `#[id]` (exactly one field: the
`ModuleId`, `ModuleId::from_name(NAME)`), `#[state(item = N)]` (optionally
`codec = path`: the codec is `path()` instead of `Default::default()`), `#[module]` (a
dependency, with the same spec) or `#[phantom]`. The first generic parameter is the spec.
Anything else (a missing or repeated attribute or key, an unknown key, discriminant 0, an
invalid name, an item id outside 0..=255 or used twice, an enum or tuple struct) is a compile
error spanned at the input. A hand-written `ModuleInfo` gets none of these per-module checks:
it must itself keep a valid name, unique item ids, a `STATE_LAYOUT` that lists the prefixes it
builds and an id that is `ModuleId::from_name(NAME)`. The checks between modules (unique
discriminants and names, dependencies: genesis rejects them) apply to it as to a derived module.
Discriminant `0` on a hand-written impl is rejected only once the runtime derive exists (its
compile-time layout check).

- **State items:** each `#[state(item = N)]` field is stored under the prefix
  `(DISCRIMINANT, N)`. Ids are explicit: reordering fields, renaming or moving the struct
  changes no prefix, and a removed (or `#[cfg]`'d-out) field leaves its id unused instead of
  renumbering every later item (upstream numbered items by position, with two different
  limits). `ModuleInfo::STATE_LAYOUT` lists each item's id (the second prefix byte) and field
  name (without `r#`), in item-id order; each module pins it with a known-answer test, so
  renumbering, renaming or dropping an item fails a test.
- **Dependencies:** `ModuleInfo::DEPENDENCIES` lists the `(DISCRIMINANT, NAME)` of the modules
  a module holds (its `#[module]` fields, in field order); each must be a module of the runtime
  with exactly that pair. A held module keeps its own discriminant, so it reads and writes the
  same prefixes as the runtime's instance of that module. The runtime's
  genesis runs each module after its dependencies (`sort_values_by_modules_dependencies`:
  duplicates, a missing or mismatched dependency and cycles are errors; the order is
  deterministic, no hash collections).
- **Calls and events** of a module are consensus types. A runtime's call type
  (`DispatchCall::Decodable`) and event type (`RuntimeEventProcessor::RuntimeEvent`) encode as
  the module's `DISCRIMINANT` byte followed by the module's message (borsh), so adding,
  removing or reordering modules changes no encoding; an unknown tag does not decode, and
  `DispatchCall::decode` is `borsh::from_slice` (trailing bytes rejected). In JSON they are
  externally tagged by the module's `NAME` (the runtime derive generates both; Phase 5).
- **Event keys** are `"{NAME}/{event_name}"` (`EventEmitter::emit_event`, e.g.
  `bank/Transfer`), from `ModuleEvent::event_name` (derived from the variant name), never from
  `Debug` output (upstream's were). An event carries the emitting module's discriminant, by
  which the runtime maps it to its event type (upstream: by `TypeId`). The key's length is
  charged with the event, and a key (derived or custom, `emit_event_with_custom_key`) of more
  than `MAX_EVENT_KEY_LEN` = 256 bytes reverts the call ("Metered state access").
  `#[derive(ModuleEvent)]` (enums only; the name is the variant's, without `r#`) rejects an
  event name of more than `MAX_EVENT_NAME_LEN` = 256 − 32 − 1 = 223 bytes at compile time:
  module names are at most `MAX_MODULE_NAME_LEN` = 32 bytes, so a derived key always fits.

## Checking

- `make test` (`cargo test --workspace --all-features`) — unit tests, including known-answer
  vectors and rejection tests; `make guest` runs the guest configuration's. Not a bare
  `cargo test`: building the workspace without features trips the `__if_native!` guards
  (`selendra-interface`'s self dev-dependency turns on its `native`, the other crates' `native`
  stays off) and leaves out the `arbitrary` strategies the tests use. Test one crate with
  `cargo test -p <crate>` and the features `make test`/`make guest` give it.
- `make doctest-codes` — the doctests on nightly rustdoc, which (unlike stable) checks the
  error code each `compile_fail` doctest pins, so a type-level rule (`ConsensusType`, sealed
  traits, private constructors) is proven by the error it is meant to cause.
- The derives: their compile errors by exact-message unit tests in `selendra-macros` (a
  derive's error has no error code, so no `compile_fail` doctest can pin it); what they
  generate by `selendra-modules-api`'s integration tests (`tests/derives/`: layouts, ids,
  dependencies, event names, consensus types), in the guest configuration too.
- `cd fuzz && cargo +nightly fuzz run <target>` — targets `addresses`, `keys`, `mock_adapters`, `modules_api_types`, `safe_types`, `state_keys`, `state_witness`, `tx_decoding`
  (no panics + canonical round-trip). Add a target for every new decoder.

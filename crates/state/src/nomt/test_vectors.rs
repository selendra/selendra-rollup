//! Known-answer vectors of the state trees under the chain's spec ([`StateStorageSpec`]:
//! [`StateHasher`](crate::StateHasher), SHA-256), shared with the node's tests: `selendra-db`
//! commits [`vector_entries`] through its prover storage and checks it computes these values.
//! Test-only (`cfg(test)` or the `test-utils` feature).
//!
//! Every constant was recomputed independently with Python's `hashlib`, and the tree root and
//! the proof also match real NOMT (`nomt/tests.rs`). They are also listed in
//! `docs/serialization.md`.

use nomt_core::trie::TERMINATOR;
use selendra_interface::common::HexString;

use crate::{Prefix, SlotKey, SlotValue, StateStorageSpec, StorageRoot};

/// The entries of the vectors: `StateMap<u8, u32>` at prefix `[1, 1]` with `BorshCodec`,
/// entries `1 → 10` and `2 → 20` (slot keys `0x010101`, `0x010102`; values `u32` LE).
pub fn vector_entries() -> [(SlotKey, SlotValue); 2] {
    let entry = |key: u8, value: u32| {
        (
            SlotKey::from_parts(&Prefix::new(1, 1), &[key]),
            SlotValue::from(value.to_le_bytes().to_vec()),
        )
    };
    [entry(1, 10), entry(2, 20)]
}

/// The root of the tree holding exactly [`vector_entries`] (the user root real NOMT computes
/// for them). Their key paths share 2 bits.
pub const TWO_ENTRY_ROOT: &str =
    "0x41fb4b75571d866034946fd190e7baaa0e6e8add2e241bd666804ee9e8a50c92";

/// The global root of [`two_entry_root`]: `SHA-256("SELENDRA/state-root/v1" ‖ TWO_ENTRY_ROOT ‖
/// 32 zero bytes)`.
pub const TWO_ENTRY_GLOBAL_ROOT: &str =
    "0xb92091904e678ae0016fee3132b4468fbe773646fee760e546518bebb0c05c9b";

/// Real NOMT's `NomtProof` of the first entry in that tree (borsh, as a witness hint or in a
/// `StorageProof`): one path (`u32` 1), a leaf (tag 0, key path, value hash) at depth 3
/// (`usize` as `u64`), 3 siblings (`u32`): two empty sub-tries and the second entry's leaf.
pub const NOMT_PROOF_OF_ENTRY_1: &str = concat!(
    "0x01000000",
    "00",
    "75c8fd04ad916aec3e3d5cb76a452b116b3d4d0912a0a485e9fb8e3d240e210c",
    "8779dca21abd1566b0e17b01af2b08520fdd985127b1b8862e193a47d9adc843",
    "0300000000000000",
    "03000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "a798416cec1f98c2a93ca5b60f45084274032bfec14667a787b406cdd2c3081b",
);

/// The state root after committing [`vector_entries`] to the user tree of an empty state: user
/// root [`TWO_ENTRY_ROOT`], empty kernel tree.
pub fn two_entry_root() -> StorageRoot<StateStorageSpec> {
    let user_root: HexString<[u8; 32]> = TWO_ENTRY_ROOT
        .parse()
        .expect("TWO_ENTRY_ROOT is 32 bytes of hex");
    StorageRoot::new(user_root.0, TERMINATOR)
}

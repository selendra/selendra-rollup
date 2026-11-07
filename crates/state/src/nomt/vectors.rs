//! Known-answer vectors of the consensus tree encoding (key path, value hash, node hashing) and
//! of the `NomtProof` byte layout. The tests against real NOMT (`tests.rs`) only check that NOMT
//! and our verifier agree with each other; these pin what both must compute, on every target.

use nomt_core::hasher::NodeHasher;
use nomt_core::proof::PathProofTerminal;
use nomt_core::trie::{InternalData, KeyPath, LeafData, Node, TERMINATOR};
use nomt_core::trie_pos::TriePosition;
use selendra_interface::common::HexString;

use super::proof::tests::Hasher;
use super::{NomtProof, key_path, value_hash, verify_namespace, verify_storage_proof};
use crate::namespaces::ProvableNamespace;
use crate::{
    DefaultStorageSpec, NodeLeaf, OrderedReadsAndWrites, Prefix, SlotKey, SlotValue, StorageProof,
    StorageRoot,
};

type Spec = DefaultStorageSpec<sha2::Sha256>;

/// The keys of the vectors: `StateMap<u8, u32>` at prefix `[1, 1]` with `BorshCodec`, entries
/// `1 → 10` and `2 → 20` (slot keys `0x010101`, `0x010102`; values `u32` LE).
pub(crate) fn vector_entries() -> [(SlotKey, SlotValue); 2] {
    let entry = |key: u8, value: u32| {
        (
            SlotKey::from_parts(&Prefix::new(1, 1), &[key]),
            SlotValue::from(value.to_le_bytes().to_vec()),
        )
    };
    [entry(1, 10), entry(2, 20)]
}

/// `H(0x010101)`, the key path of the first entry.
const KEY_PATH_1: &str = "0x75c8fd04ad916aec3e3d5cb76a452b116b3d4d0912a0a485e9fb8e3d240e210c";
/// `H(H(value) ‖ size LE)` of the first entry's value `0x0a000000`.
const VALUE_HASH_1: &str = "0x8779dca21abd1566b0e17b01af2b08520fdd985127b1b8862e193a47d9adc843";
/// The root of the trie holding exactly the two entries (also the user root real NOMT computes
/// for them: `tests.rs`). Their key paths share 2 bits.
pub(crate) const TWO_ENTRY_ROOT: &str =
    "0x41fb4b75571d866034946fd190e7baaa0e6e8add2e241bd666804ee9e8a50c92";
/// Real NOMT's `NomtProof` of the first entry in that trie (borsh, as a witness hint or in a
/// `StorageProof`; pinned against NOMT in `tests.rs`): one path (`u32` 1), a leaf (tag 0, key
/// path, value hash) at depth 3 (`usize` as `u64`), 3 siblings (`u32`): two empty sub-tries and
/// the second entry's leaf.
pub(crate) const NOMT_PROOF_OF_ENTRY_1: &str = concat!(
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
/// The borsh encoding of `proof::tests::three_terminal_proof`: 3 paths; a leaf at depth 1; a
/// terminator (tag 1; its position: path `10…` zero-padded, depth 2 as `u16`, `node_index` 4
/// as `u64`) at depth 2; a leaf at depth 2; no siblings.
const THREE_TERMINAL_PROOF: &str = concat!(
    "0x03000000",
    "00",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "0101010101010101010101010101010101010101010101010101010101010101",
    "0100000000000000",
    "01",
    "8000000000000000000000000000000000000000000000000000000000000000",
    "0200",
    "0400000000000000",
    "0200000000000000",
    "00",
    "e222222222222222222222222222222222222222222222222222222222222222",
    "0202020202020202020202020202020202020202020202020202020202020202",
    "0200000000000000",
    "00000000",
);

fn hex(bytes: impl AsRef<[u8]>) -> String {
    HexString(bytes.as_ref()).to_string()
}

fn unhex(s: &str) -> Vec<u8> {
    serde_json::from_str::<HexString<Vec<u8>>>(&format!("\"{s}\""))
        .unwrap()
        .0
}

fn bit(path: &KeyPath, i: usize) -> bool {
    path[i / 8] & (0x80 >> (i % 8)) != 0
}

fn internal(left: Node, right: Node) -> Node {
    Hasher::hash_internal(&InternalData { left, right })
}

/// The leaf of an entry, through the verifier's own key path and value hash.
fn leaf_of((key, value): &(SlotKey, SlotValue)) -> LeafData {
    LeafData {
        key_path: key_path::<Spec>(key),
        value_hash: value_hash::<Spec>(&NodeLeaf::make_leaf::<sha2::Sha256>(value)),
    }
}

/// The root of a trie of two leaves, from nomt-core's node hashing alone: the leaves split at
/// the first bit their key paths differ, and above that every node has an empty sibling.
fn two_leaf_root(a: LeafData, b: LeafData) -> Node {
    let (low, high) = if a.key_path < b.key_path {
        (a, b)
    } else {
        (b, a)
    };
    let shared = (0..256)
        .take_while(|&i| bit(&low.key_path, i) == bit(&high.key_path, i))
        .count();
    let mut node = internal(Hasher::hash_leaf(&low), Hasher::hash_leaf(&high));
    for i in (0..shared).rev() {
        node = if bit(&low.key_path, i) {
            internal(TERMINATOR, node)
        } else {
            internal(node, TERMINATOR)
        };
    }
    node
}

/// Key path `H(whole slot key)`, value hash `H(val_hash_and_size)`, `BinaryHasher` node hashing
/// (independently recomputed with Python's `hashlib`): any change to these changes every state
/// root.
#[test]
fn the_tree_encoding_is_pinned() {
    let [entry_1, entry_2] = vector_entries();
    let (leaf_1, leaf_2) = (leaf_of(&entry_1), leaf_of(&entry_2));
    assert_eq!(hex(leaf_1.key_path), KEY_PATH_1);
    assert_eq!(hex(leaf_1.value_hash), VALUE_HASH_1);
    assert_eq!(hex(two_leaf_root(leaf_1, leaf_2)), TWO_ENTRY_ROOT);

    // The verifier computes the same root inserting both into the empty trie (proven by NOMT's
    // root terminator).
    let root_terminator = NomtProof::new(nomt_core::proof::MultiProof {
        paths: vec![nomt_core::proof::MultiPathProof {
            terminal: PathProofTerminal::Terminator(TriePosition::new()),
            depth: 0,
        }],
        siblings: vec![],
    })
    .unwrap();
    let accesses = OrderedReadsAndWrites {
        ordered_reads: vec![],
        ordered_writes: vector_entries()
            .into_iter()
            .map(|(key, value)| (key, Some(value)))
            .collect(),
    };
    let root = verify_namespace::<Spec>(TERMINATOR, &accesses, &root_terminator).unwrap();
    assert_eq!(hex(root), TWO_ENTRY_ROOT);
}

/// The `NomtProof` wire format (borsh, field and variant order of nomt-core 1.0.5): a nomt-core
/// upgrade that changes it fails here.
#[test]
fn the_proof_layout_is_pinned() {
    let [entry_1, entry_2] = vector_entries();
    // Real NOMT's proof, built by hand.
    let by_hand = nomt_core::proof::MultiProof {
        paths: vec![nomt_core::proof::MultiPathProof {
            terminal: PathProofTerminal::Leaf(leaf_of(&entry_1)),
            depth: 3,
        }],
        siblings: vec![
            TERMINATOR,
            TERMINATOR,
            Hasher::hash_leaf(&leaf_of(&entry_2)),
        ],
    };
    assert_eq!(hex(borsh::to_vec(&by_hand).unwrap()), NOMT_PROOF_OF_ENTRY_1);
    let decoded: NomtProof = borsh::from_slice(&unhex(NOMT_PROOF_OF_ENTRY_1)).unwrap();
    assert_eq!(decoded.inner(), &by_hand);
    assert_eq!(
        serde_json::to_string(&decoded).unwrap(),
        format!("\"{NOMT_PROOF_OF_ENTRY_1}\"")
    );

    // It proves the first entry against the pinned root, and nothing else.
    let mut user_root = [0; 32];
    user_root.copy_from_slice(&unhex(TWO_ENTRY_ROOT));
    let state_root = StorageRoot::<Spec>::new(user_root, TERMINATOR);
    let storage_proof = |value: Option<SlotValue>| StorageProof {
        key: entry_1.0.clone(),
        value,
        proof: decoded.clone(),
        namespace: ProvableNamespace::User,
    };
    assert_eq!(
        verify_storage_proof(state_root, storage_proof(Some(entry_1.1.clone()))).unwrap(),
        (entry_1.0.clone(), Some(entry_1.1.clone()))
    );
    assert!(verify_storage_proof(state_root, storage_proof(Some(entry_2.1.clone()))).is_err());
    assert!(verify_storage_proof(state_root, storage_proof(None)).is_err());
    assert!(
        verify_storage_proof(
            StorageRoot::<Spec>::new(state_root.kernel_root(), state_root.user_root()),
            storage_proof(Some(entry_1.1.clone()))
        )
        .is_err()
    );

    let three = super::proof::tests::three_terminal_proof();
    assert_eq!(hex(borsh::to_vec(&three).unwrap()), THREE_TERMINAL_PROOF);
    let decoded: NomtProof = borsh::from_slice(&unhex(THREE_TERMINAL_PROOF)).unwrap();
    assert_eq!(decoded.inner(), &three);
}

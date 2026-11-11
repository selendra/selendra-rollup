//! Known-answer vectors of the consensus tree encoding (key path, value hash, node hashing,
//! global root) and of the `NomtProof` byte layout, under the chain's [`StateHasher`]. The tests
//! against real NOMT (`tests.rs`) only check that NOMT and our verifier agree with each other;
//! these pin what both must compute, on every target (and in the guest configuration:
//! `make guest`), and show the domain separation the trees rely on. The shared vectors
//! (entries, root, proof) are in [`test_vectors`](super::test_vectors), which `selendra-db`
//! checks its prover storage against.

use core::marker::PhantomData;

use nomt_core::hasher::{BinaryHasher, NodeHasher, node_kind_by_msb};
use nomt_core::proof::{MultiPathProof, MultiProof, PathProofTerminal, verify_multi_proof};
use nomt_core::trie::{InternalData, KeyPath, LeafData, Node, NodeKind, TERMINATOR};
use nomt_core::trie_pos::TriePosition;
use selendra_interface::common::HexString;
use selendra_interface::reexports::digest::Digest;

use super::test_vectors::{
    NOMT_PROOF_OF_ENTRY_1, TWO_ENTRY_GLOBAL_ROOT, TWO_ENTRY_ROOT, two_entry_root, vector_entries,
};
use super::{
    NomtProof, key_path, leaf_value_bytes, value_hash, verify_namespace, verify_storage_proof,
};
use crate::namespaces::ProvableNamespace;
use crate::{
    GLOBAL_ROOT_TAG, MerkleProofSpec, NodeLeaf, OrderedReadsAndWrites, Prefix, SlotKey, SlotValue,
    StateHasher, StateRoot, StateStorageSpec, StorageProof, StorageRoot,
};

type Spec = StateStorageSpec;
/// The node hasher of the state trees.
type Hasher = BinaryHasher<StateHasher>;

/// `H(0x010101)`, the key path of the first entry.
const KEY_PATH_1: &str = "0x75c8fd04ad916aec3e3d5cb76a452b116b3d4d0912a0a485e9fb8e3d240e210c";
/// `H(H(value) ‖ size LE)` of the first entry's value `0x0a000000`.
const VALUE_HASH_1: &str = "0x8779dca21abd1566b0e17b01af2b08520fdd985127b1b8862e193a47d9adc843";
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

fn internal<H: NodeHasher>(left: Node, right: Node) -> Node {
    H::hash_internal(&InternalData { left, right })
}

/// The leaf of an entry, through the verifier's own key path and value hash.
fn leaf_of((key, value): &(SlotKey, SlotValue)) -> LeafData {
    LeafData {
        key_path: key_path::<Spec>(key),
        value_hash: value_hash::<Spec>(&NodeLeaf::make_leaf::<StateHasher>(value)),
    }
}

/// The two children of the root of a trie of two leaves, from node hashing alone: the leaves
/// split at the first bit their key paths differ, and above that every node has an empty
/// sibling.
fn two_leaf_root_children<H: NodeHasher>(a: LeafData, b: LeafData) -> (Node, Node) {
    let (low, high) = if a.key_path < b.key_path {
        (a, b)
    } else {
        (b, a)
    };
    let shared = (0..256)
        .take_while(|&i| bit(&low.key_path, i) == bit(&high.key_path, i))
        .count();
    let (mut left, mut right) = (H::hash_leaf(&low), H::hash_leaf(&high));
    for i in (0..shared).rev() {
        let node = internal::<H>(left, right);
        (left, right) = if bit(&low.key_path, i) {
            (TERMINATOR, node)
        } else {
            (node, TERMINATOR)
        };
    }
    (left, right)
}

/// The root of a trie of two leaves (see [`two_leaf_root_children`]).
fn two_leaf_root<H: NodeHasher>(a: LeafData, b: LeafData) -> Node {
    let (left, right) = two_leaf_root_children::<H>(a, b);
    internal::<H>(left, right)
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
    assert_eq!(hex(two_leaf_root::<Hasher>(leaf_1, leaf_2)), TWO_ENTRY_ROOT);

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
    assert_eq!(state_root, two_entry_root());
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

// -------------------------------------------------------------------------------------------
// The state hasher and the domain separation the trees rely on (`mod.rs`, "Security notes").

/// [`StateHasher`] is SHA-256 (FIPS 180-2 test vector `"abc"`), and it is the hasher of
/// [`StateStorageSpec`].
#[test]
fn state_hasher_is_sha256() {
    fn same<T>(_: PhantomData<T>, _: PhantomData<T>) {}
    same(
        PhantomData::<<StateStorageSpec as MerkleProofSpec>::Hasher>,
        PhantomData::<StateHasher>,
    );
    assert_eq!(
        hex(StateHasher::digest(b"abc")),
        "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// A leaf is `H(key_path ‖ value_hash)` with the MSB set, an internal node `H(left ‖ right)`
/// with the MSB cleared: the same 64-byte preimage gives two hashes that differ in the top bit
/// only, and the kind is read back from that bit. Constants from Python's `hashlib`
/// (`H(x ‖ y) = 0x5189…817c`).
#[test]
fn node_kinds_are_msb_tagged() {
    let (x, y) = ([0x11u8; 32], [0x22u8; 32]);
    let leaf = Hasher::hash_leaf(&LeafData {
        key_path: x,
        value_hash: y,
    });
    let internal_node = internal::<Hasher>(x, y);
    assert_eq!(
        hex(leaf),
        "0xd189c77d29fe5d546a045ec46986852785fea5c13ac7da9c115ff5fb6edf817c"
    );
    assert_eq!(
        hex(internal_node),
        "0x5189c77d29fe5d546a045ec46986852785fea5c13ac7da9c115ff5fb6edf817c"
    );
    let untagged: Node = StateHasher::digest([x, y].concat()).into();
    let mut msb_set = untagged;
    msb_set[0] |= 0x80;
    let mut msb_cleared = untagged;
    msb_cleared[0] &= 0x7f;
    assert_eq!((leaf, internal_node), (msb_set, msb_cleared));
    let difference: Vec<u8> = leaf.iter().zip(internal_node).map(|(a, b)| a ^ b).collect();
    assert_eq!(difference, [&[0x80u8][..], &[0; 31]].concat());

    for (node, kind) in [
        (leaf, NodeKind::Leaf),
        (internal_node, NodeKind::Internal),
        (TERMINATOR, NodeKind::Terminator),
    ] {
        assert_eq!(node_kind_by_msb(&node), kind);
        assert_eq!(Hasher::node_kind(&node), kind);
    }
}

/// A node hasher without domain separation: leaves and internal nodes are both `H(a ‖ b)`. The
/// attacks below succeed against it, which shows what the MSB tag of [`Hasher`] prevents.
struct Untagged;

impl NodeHasher for Untagged {
    fn hash_leaf(data: &LeafData) -> Node {
        StateHasher::digest([data.key_path, data.value_hash].concat()).into()
    }

    fn hash_internal(data: &InternalData) -> Node {
        StateHasher::digest([data.left, data.right].concat()).into()
    }

    fn node_kind(node: &Node) -> NodeKind {
        node_kind_by_msb(node)
    }
}

fn one_path_proof(leaf: LeafData, depth: usize, siblings: Vec<Node>) -> NomtProof {
    NomtProof::new(MultiProof {
        paths: vec![MultiPathProof {
            terminal: PathProofTerminal::Leaf(leaf),
            depth,
        }],
        siblings,
    })
    .expect("a well-formed proof: the attack is in its hashes, not its shape")
}

fn reads(key: &SlotKey, leaf: Option<NodeLeaf>) -> OrderedReadsAndWrites {
    OrderedReadsAndWrites {
        ordered_reads: vec![(key.clone(), leaf)],
        ordered_writes: vec![],
    }
}

fn assert_root_mismatch(result: anyhow::Result<impl core::fmt::Debug>) {
    let err = result.unwrap_err().to_string();
    assert!(err.contains("does not verify against"), "{err}");
}

/// Crafted proofs that reinterpret a node of the other kind (both preimages are 64 bytes) are
/// rejected by both verifiers ([`verify_storage_proof`], [`verify_namespace`]), at the root
/// check. The same proofs verify against the same trie built with [`Untagged`].
#[test]
fn leaf_cannot_be_opened_as_internal_and_vice_versa() {
    // (a) An internal node opened as a leaf. The root of the two-entry trie is
    // `internal(left, right)`; a leaf at depth 0 with key path `left` and value hash `right`
    // would hash to the same 32 bytes untagged, and it "proves" that the first entry (present)
    // is absent: the only leaf it shows has another key path.
    let [entry_1, entry_2] = vector_entries();
    let (leaf_1, leaf_2) = (leaf_of(&entry_1), leaf_of(&entry_2));
    let as_root_leaf = |(left, right): (Node, Node)| {
        one_path_proof(
            LeafData {
                key_path: left,
                value_hash: right,
            },
            0,
            vec![],
        )
    };
    let untagged_proof = as_root_leaf(two_leaf_root_children::<Untagged>(
        leaf_1.clone(),
        leaf_2.clone(),
    ));
    let verified = verify_multi_proof::<Untagged>(
        untagged_proof.inner(),
        two_leaf_root::<Untagged>(leaf_1.clone(), leaf_2.clone()),
    )
    .expect("untagged, the internal node opens as a leaf");
    assert!(verified.confirm_nonexistence(&leaf_1.key_path).unwrap());

    let crafted = as_root_leaf(two_leaf_root_children::<Hasher>(leaf_1.clone(), leaf_2));
    let root = two_entry_root();
    assert_root_mismatch(verify_storage_proof(
        root,
        StorageProof {
            key: entry_1.0.clone(),
            value: None,
            proof: crafted.clone(),
            namespace: ProvableNamespace::User,
        },
    ));
    assert_root_mismatch(verify_namespace::<Spec>(
        root.user_root(),
        &reads(&entry_1.0, None),
        &crafted,
    ));

    // (b) A leaf opened as an internal node. A trie holding one key `K = kp ‖ vh` (64 bytes:
    // anyone who chooses a map key's bytes can write one) is the single leaf
    // `H(H(K) ‖ value_hash)`. Untagged, `H(K)` is also the hash of the leaf `(kp, vh)`, so the
    // root opens as an internal node whose left child is that leaf: a proof that another key
    // (key path `kp`) has the value of value hash `vh`, although only `K` was ever written.
    let target_value = SlotValue::from(vec![0xee; 5]);
    let target_key = (0u8..=255)
        .map(|i| SlotKey::from_parts(&Prefix::new(9, 9), &[i]))
        .find(|key| !bit(&key_path::<Spec>(key), 0))
        .expect("half of all key paths start with a 0 bit");
    let target = leaf_of(&(target_key.clone(), target_value.clone()));
    let crafted_key =
        SlotKey::try_from_bytes(&[target.key_path, target.value_hash].concat()).unwrap();
    let crafted_entry = (crafted_key, SlotValue::from(vec![1]));
    let real_leaf = leaf_of(&crafted_entry);
    assert_eq!(
        real_leaf.key_path,
        Untagged::hash_leaf(&target),
        "the crafted key's path is the target leaf's untagged hash"
    );

    let untagged_proof = one_path_proof(target.clone(), 1, vec![real_leaf.value_hash]);
    let verified =
        verify_multi_proof::<Untagged>(untagged_proof.inner(), Untagged::hash_leaf(&real_leaf))
            .expect("untagged, the leaf opens as an internal node");
    assert!(verified.confirm_value(&target).unwrap());

    // The real (tagged) trie of `K`: its root is `K`'s leaf, as the verifier computes it
    // inserting `K` into the empty trie.
    let root_terminator = NomtProof::new(MultiProof {
        paths: vec![MultiPathProof {
            terminal: PathProofTerminal::Terminator(TriePosition::new()),
            depth: 0,
        }],
        siblings: vec![],
    })
    .unwrap();
    let insert = OrderedReadsAndWrites {
        ordered_reads: vec![],
        ordered_writes: vec![(crafted_entry.0.clone(), Some(crafted_entry.1.clone()))],
    };
    let user_root = verify_namespace::<Spec>(TERMINATOR, &insert, &root_terminator).unwrap();
    assert_eq!(user_root, Hasher::hash_leaf(&real_leaf));

    let crafted = one_path_proof(target, 1, vec![real_leaf.value_hash]);
    assert_root_mismatch(verify_storage_proof(
        StorageRoot::<Spec>::new(user_root, TERMINATOR),
        StorageProof {
            key: target_key.clone(),
            value: Some(target_value.clone()),
            proof: crafted.clone(),
            namespace: ProvableNamespace::User,
        },
    ));
    assert_root_mismatch(verify_namespace::<Spec>(
        user_root,
        &reads(
            &target_key,
            Some(NodeLeaf::make_leaf::<StateHasher>(&target_value)),
        ),
        &crafted,
    ));
}

/// The global root `H(GLOBAL_ROOT_TAG ‖ user ‖ kernel)` is ordered (user first), is never the
/// hash of a node with the same children (its preimage is 22 + 64 bytes), and is pinned for the
/// two-entry state (Python's `hashlib`).
#[test]
fn global_root_separation() {
    let global = |user: Node, kernel: Node| StorageRoot::<Spec>::new(user, kernel).global_root();
    let user = two_entry_root().user_root();
    for (u, k) in [(user, TERMINATOR), ([0x11; 32], [0x22; 32])] {
        assert_ne!(global(u, k), global(k, u));
        let untagged: Node = StateHasher::digest([u, k].concat()).into();
        let node_hashes = [
            internal::<Hasher>(u, k),
            Hasher::hash_leaf(&LeafData {
                key_path: u,
                value_hash: k,
            }),
            untagged,
        ];
        assert!(!node_hashes.contains(&global(u, k)));
    }
    assert_eq!(GLOBAL_ROOT_TAG, b"SELENDRA/state-root/v1");
    assert_eq!(GLOBAL_ROOT_TAG.len(), 22);
    assert_eq!(hex(two_entry_root().global_root()), TWO_ENTRY_GLOBAL_ROOT);
    assert_eq!(hex(global(user, TERMINATOR)), TWO_ENTRY_GLOBAL_ROOT);
}

/// A leaf's value hash commits to the value's size too: the same `val_hash` with another size
/// is another value hash, and a read hint with the wrong size is rejected. The tree commits to
/// `val_hash ‖ size` ([`leaf_value_bytes`]), not to the hint's borsh order `size ‖ val_hash`.
#[test]
fn value_hash_binds_size() {
    let [(key_1, value_1), _] = vector_entries();
    let leaf = NodeLeaf::make_leaf::<StateHasher>(&value_1);
    assert_eq!(leaf.size, 4);
    let bytes = leaf_value_bytes(&leaf);
    assert_eq!(bytes[..32], leaf.val_hash);
    assert_eq!(bytes[32..], 4u32.to_le_bytes());
    assert_eq!(hex(value_hash::<Spec>(&leaf)), VALUE_HASH_1);
    // Hashing the hint's borsh bytes instead would give another value hash.
    let hint_bytes = borsh::to_vec(&leaf).unwrap();
    assert_ne!(hint_bytes, bytes);
    let hint_hash: [u8; 32] = StateHasher::digest(&hint_bytes).into();
    assert_ne!(hint_hash, value_hash::<Spec>(&leaf));

    let proof: NomtProof = borsh::from_slice(&unhex(NOMT_PROOF_OF_ENTRY_1)).unwrap();
    let root = two_entry_root().user_root();
    assert_eq!(
        verify_namespace::<Spec>(root, &reads(&key_1, Some(leaf)), &proof).unwrap(),
        root
    );
    for size in [leaf.size - 1, leaf.size + 1] {
        let resized = NodeLeaf {
            size,
            val_hash: leaf.val_hash,
        };
        assert_ne!(value_hash::<Spec>(&resized), value_hash::<Spec>(&leaf));
        let err = verify_namespace::<Spec>(root, &reads(&key_1, Some(resized)), &proof)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match the previous state"), "{err}");
    }
}

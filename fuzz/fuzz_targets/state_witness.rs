//! Decoders of prover- and client-supplied storage data from `selendra-state`: `ArrayWitness`
//! (borsh and JSON), witness hints (`Witness::try_get_hint`), `NodeLeaf`, `StorageProof`, the
//! NOMT multi-proof `NomtProof` (borsh and JSON; whatever decodes must also never panic proof
//! verification, its update included: checked against the proof's own root) and `StorageRoot`.
#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use nomt_core::hasher::{BinaryHasher, NodeHasher};
use nomt_core::proof::{
    MultiPathProof, MultiProof, PathProofTerminal, verify_multi_proof, verify_multi_proof_update,
};
use nomt_core::trie::{InternalData, KeyPath, Node, TERMINATOR, ValueHash};
use selendra_state::{
    ArrayWitness, DefaultStorageSpec, NodeLeaf, NomtProof, OrderedReadsAndWrites,
    ProvableNamespace, SlotKey, SlotValue, StorageProof, StorageRoot, VAL_HASH_AND_SIZE_LEN,
    Witness, val_hash_and_size, verify_namespace, verify_storage_proof,
};

type Spec = DefaultStorageSpec<sha2::Sha256>;
type Root = StorageRoot<Spec>;

type Hasher = BinaryHasher<sha2::Sha256>;

/// The root a well-formed proof proves: nomt-core's `verify_range` bisection with hashing, so
/// that verification of fuzzed proofs gets past the root check (a fuzzer cannot find a proof
/// whose root is a given value). It indexes and slices unchecked like nomt-core: a panic here is
/// a proof `NomtProof` should have rejected.
fn implied_root(proof: &MultiProof) -> Node {
    fn hash_up(mut node: Node, bits: &[bool], siblings: &[Node]) -> Node {
        // Siblings are top-down; hash bottom-up.
        for (bit, sibling) in bits.iter().rev().zip(siblings.iter().rev()) {
            let (left, right) = if *bit {
                (*sibling, node)
            } else {
                (node, *sibling)
            };
            node = Hasher::hash_internal(&InternalData { left, right });
        }
        node
    }
    fn bits(terminal: &PathProofTerminal) -> Vec<bool> {
        terminal.path().iter().by_vals().collect()
    }
    fn range(start: usize, paths: &[MultiPathProof], siblings: &[Node]) -> (Node, usize) {
        if let [path] = paths {
            let n = path.depth - start;
            let node = path.terminal.node::<Hasher>();
            let bits = bits(&path.terminal);
            return (hash_up(node, &bits[start..path.depth], &siblings[..n]), n);
        }
        let (first, last) = (
            bits(&paths[0].terminal),
            bits(&paths[paths.len() - 1].terminal),
        );
        let common = first[start..]
            .iter()
            .zip(&last[start..])
            .take_while(|(a, b)| a == b)
            .count();
        let bisect = start + common;
        let mid = paths.partition_point(|p| !bits(&p.terminal)[bisect]);
        let (left, l) = range(bisect + 1, &paths[..mid], &siblings[common..]);
        let (right, r) = range(bisect + 1, &paths[mid..], &siblings[common + l..]);
        let node = Hasher::hash_internal(&InternalData { left, right });
        (
            hash_up(node, &first[start..bisect], &siblings[..common]),
            common + l + r,
        )
    }
    if proof.paths.is_empty() {
        return TERMINATOR;
    }
    range(0, &proof.paths, &proof.siblings).0
}

/// Updates in the proof's scope, chosen by `data`: per terminal, its own key path (for a
/// terminator, the path with fuzzed bits past its depth) and a key path that leaves it one bit
/// below its depth (a new leaf next to it), each written, deleted or left alone.
fn in_scope_updates(proof: &MultiProof, data: &[u8]) -> Vec<(KeyPath, Option<ValueHash>)> {
    let byte = |i: usize| data.get(i % data.len().max(1)).copied().unwrap_or(0);
    let mut updates = BTreeMap::new();
    for (i, path) in proof.paths.iter().enumerate() {
        let mut key_path = match &path.terminal {
            PathProofTerminal::Leaf(leaf) => leaf.key_path,
            PathProofTerminal::Terminator(position) => {
                let mut key_path = position.raw_path();
                // Fuzzed bits past the depth (still under the terminator).
                let depth = position.depth();
                for (j, b) in key_path.iter_mut().enumerate() {
                    if j * 8 >= usize::from(depth) {
                        *b = byte(i + j);
                    }
                }
                key_path
            }
        };
        let mut push = |key_path: KeyPath, choice: u8| match choice % 3 {
            0 => {
                updates.insert(key_path, None);
            }
            1 => {
                updates.insert(key_path, Some([choice; 32]));
            }
            _ => {}
        };
        push(key_path, byte(2 * i));
        if path.depth < 256 {
            key_path[path.depth / 8] ^= 0x80 >> (path.depth % 8);
            push(key_path, byte(2 * i + 1));
        }
    }
    updates.into_iter().collect()
}

/// A decoded proof must never panic verification, whatever the accesses: checked against its
/// implied root (so that the read checks and `verify_multi_proof_update` run) and against roots
/// from `data`.
fn verify_never_panics(proof: &NomtProof, data: &[u8]) {
    let root = implied_root(proof.inner());
    // nomt-core directly: every terminal confirms, and in-scope updates (several per terminal,
    // new leaves below it) and out-of-scope ones never panic.
    let verified = verify_multi_proof::<Hasher>(proof.inner(), root)
        .expect("a well-formed proof verifies against its implied root");
    for path in &proof.inner().paths {
        let confirmed = match &path.terminal {
            PathProofTerminal::Leaf(leaf) => verified.confirm_value(leaf),
            PathProofTerminal::Terminator(position) => {
                verified.confirm_nonexistence(&position.raw_path())
            }
        };
        assert_eq!(confirmed.ok(), Some(true), "a terminal of the proof");
    }
    let updates = in_scope_updates(proof.inner(), data);
    let _ = verify_multi_proof_update::<Hasher>(&verified, updates);
    let out_of_scope: BTreeMap<KeyPath, Option<ValueHash>> = data
        .chunks_exact(32)
        .take(4)
        .map(|chunk| (chunk.try_into().unwrap(), Some([1; 32])))
        .collect();
    let _ = verify_multi_proof_update::<Hasher>(&verified, out_of_scope.into_iter().collect());

    // Through `verify_namespace` (keys hash to paths a fuzzer cannot aim, so mostly out of
    // scope) and `verify_storage_proof`, against the implied root and a root from `data`.
    let other_root: [u8; 32] = data
        .get(..32)
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or_default();
    let key = SlotKey::from_parts(
        &selendra_state::Prefix::new(1, 1),
        data.get(..4).unwrap_or(&[]),
    );
    let accesses = OrderedReadsAndWrites {
        ordered_reads: vec![(key.clone(), None)],
        ordered_writes: vec![(key.clone(), Some(SlotValue::from(vec![1])))],
    };
    for prev_root in [root, other_root, TERMINATOR] {
        let _ = verify_namespace::<Spec>(prev_root, &accesses, proof);
        let _ = verify_namespace::<Spec>(prev_root, &OrderedReadsAndWrites::default(), proof);
    }
    let storage_proof = StorageProof {
        key,
        value: None,
        proof: proof.clone(),
        namespace: ProvableNamespace::Kernel,
    };
    let _ = verify_storage_proof::<Spec>(Root::new(other_root, root), storage_proof);
}

/// borsh: decoding must not panic, and anything accepted must be its own canonical encoding.
fn borsh_canonical<T: borsh::BorshDeserialize + borsh::BorshSerialize>(data: &[u8]) -> Option<T> {
    let value = borsh::from_slice::<T>(data).ok()?;
    assert_eq!(
        borsh::to_vec(&value).unwrap(),
        data,
        "non-canonical borsh accepted"
    );
    Some(value)
}

/// JSON: anything accepted must serialize back to the same JSON value (whitespace aside).
fn json_canonical<T: serde::de::DeserializeOwned + serde::Serialize>(s: &str) -> Option<T> {
    let value = serde_json::from_str::<T>(s).ok()?;
    let input: serde_json::Value = serde_json::from_str(s).unwrap();
    assert_eq!(
        serde_json::to_value(&value).unwrap(),
        input,
        "non-canonical JSON accepted"
    );
    Some(value)
}

/// Decodes `hint` as a `T` through a witness: never panics, and a hint accepted as a `T` is the
/// canonical encoding of the decoded value.
fn hint_canonical<T: borsh::BorshDeserialize + borsh::BorshSerialize>(hint: &[u8]) {
    let witness = ArrayWitness::from_hints(vec![hint.to_vec()]);
    if let Ok(value) = witness.try_get_hint::<T>() {
        assert_eq!(
            borsh::to_vec(&value).unwrap(),
            hint,
            "non-canonical hint accepted"
        );
    }
    assert!(
        witness.is_empty(),
        "a hint is consumed even when it does not decode"
    );
    assert!(witness.try_get_hint::<T>().is_err());
}

fuzz_target!(|data: &[u8]| {
    if let Some(witness) = borsh_canonical::<ArrayWitness>(data) {
        let hints: Vec<Vec<u8>> = borsh::from_slice(data).unwrap();
        assert_eq!(witness.len(), hints.len());
        for hint in &hints {
            // The hint types storages read from witnesses.
            hint_canonical::<Option<SlotValue>>(hint);
            hint_canonical::<Option<NodeLeaf>>(hint);
            hint_canonical::<BTreeMap<SlotKey, SlotValue>>(hint);
            hint_canonical::<StorageProof<Vec<u8>>>(hint);
            hint_canonical::<NomtProof>(hint);
        }
        assert_eq!(witness.ensure_consumed().is_ok(), hints.is_empty());
    }
    // The fuzz input as a single hint.
    hint_canonical::<Option<SlotValue>>(data);
    hint_canonical::<Option<NodeLeaf>>(data);

    if let Some(leaf) = borsh_canonical::<NodeLeaf>(data) {
        let combined = leaf.combine_val_hash_and_size();
        assert_eq!(combined.len(), VAL_HASH_AND_SIZE_LEN);
        assert_eq!(combined, val_hash_and_size(leaf.val_hash, leaf.size));
        assert_eq!(combined[..32], leaf.val_hash);
        assert_eq!(combined[32..], leaf.size.to_le_bytes());
    }
    if let Some(proof) = borsh_canonical::<StorageProof<Vec<u8>>>(data) {
        assert!(proof.key.len() >= 2);
    }
    hint_canonical::<NomtProof>(data);
    if let Some(proof) = borsh_canonical::<NomtProof>(data) {
        verify_never_panics(&proof, data);
        // JSON is the borsh bytes as hex.
        let json = serde_json::to_string(&proof).unwrap();
        assert_eq!(serde_json::from_str::<NomtProof>(&json).unwrap(), proof);
    }
    if let Some(proof) = borsh_canonical::<StorageProof<NomtProof>>(data) {
        let _ = verify_storage_proof::<Spec>(Root::PRE_GENESIS, proof);
    }
    if let Some(root) = borsh_canonical::<Root>(data) {
        assert_eq!(data.len(), 64);
        assert_eq!(root.as_ref(), data);
        assert_eq!(serde_json::to_string(&root).unwrap(), format!("\"{root}\""));
    }

    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(witness) = json_canonical::<ArrayWitness>(s) {
        let bytes = borsh::to_vec(&witness).unwrap();
        let decoded: ArrayWitness = borsh::from_slice(&bytes).unwrap();
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            serde_json::to_value(&witness).unwrap()
        );
    }
    json_canonical::<StorageProof<Vec<u8>>>(s);
    if let Some(proof) = json_canonical::<NomtProof>(s) {
        verify_never_panics(&proof, data);
    }
    json_canonical::<StorageProof<NomtProof>>(s);
    if let Some(root) = json_canonical::<Root>(s) {
        assert_eq!(format!("\"{root}\""), s.trim());
    }
});

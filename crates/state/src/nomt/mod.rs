//! The zk-guest half of the storage based on [NOMT](https://github.com/thrumdev/nomt/) (Nearly
//! Optimal Merkle Trie): proof verification ([`verify_storage_proof`], [`verify_namespace`]),
//! the canonical proof type ([`NomtProof`]) and the guest storage ([`NomtVerifierStorage`]).
//! The native prover storage, which drives the NOMT databases, builds on these:
//! `NomtProverStorage` in the node-only `selendra-db` crate.
//!
//! # What the trees commit to
//! Each provable namespace (user, kernel) is one NOMT binary trie, hashed with
//! `BinaryHasher<S::Hasher>` (the chain's [`StateHasher`](crate::StateHasher), SHA-256). A slot
//! `key → value` is the trie leaf
//! - key path: [`key_path`], `H(key)`, the hash of the whole [`SlotKey`] (prefix included), so
//!   that nobody chooses where a key sits in the tree;
//! - value hash: `H(val_hash_and_size)`, i.e. `H(H(value) ‖ size as u32 LE)`: NOMT stores the
//!   36 bytes [`leaf_value_bytes`] as the leaf's value and hashes them as a value
//!   (`ValueHasher`).
//!
//! The verifier here and the node's prover (`selendra-db`) both call [`key_path`] and
//! [`leaf_value_bytes`], so they cannot drift apart; the known-answer vectors
//! (`nomt/vectors.rs`, `test_vectors`) pin what they compute.
//!
//! Internal and leaf nodes are domain-separated by the MSB of the node hash (`BinaryHasher`:
//! cleared for internal nodes, set for leaves; all zeros is the empty sub-trie).
//!
//! # Security notes
//! - **Node kinds are tagged in the MSB.** A node hash is SHA-256 of 64 bytes (`left ‖ right`
//!   or `key_path ‖ value_hash`) with its first bit replaced by the node kind, so 255 bits are
//!   left: second preimages cost about 2^255, and a collision of the truncated hash about
//!   2^127.5. The tag is what stops a leaf's preimage from being opened as an internal node's
//!   children and the reverse (both are 64 bytes); `vectors.rs` shows both attacks succeeding
//!   on an untagged hasher and failing on ours.
//! - **Other hashes are never compared with a node or a root.** A key path is `H(key)` for a
//!   key of any length (64 bytes included), and a value hash is `H` of 36 bytes, so either may
//!   equal some node hash or a global root as a 32-byte string. That is harmless: a key path
//!   only chooses a position and a value hash is only hashed into its leaf; neither is ever
//!   checked against a node or a root. The global root is `H(GLOBAL_ROOT_TAG ‖ user ‖ kernel)`
//!   (86 bytes, never a node preimage: see [`GLOBAL_ROOT_TAG`](crate::GLOBAL_ROOT_TAG)).
//! - **Two byte orders of a leaf.** A leaf *hint* in a witness is the borsh [`NodeLeaf`]:
//!   `size ‖ val_hash`. What the tree *commits to* is [`leaf_value_bytes`]: `val_hash ‖ size`.
//!   The hint's bytes are never hashed; only its fields are, through [`leaf_value_bytes`].
//!   Hashing the borsh bytes instead would silently give other roots than NOMT's.
//! - **Grinding.** Key paths are hashes, so nobody places a key, but anyone can grind keys
//!   whose paths share a long prefix with another key's (about 2^k hashes for k shared bits),
//!   making its proofs deeper (one 32-byte sibling per bit, at most 256). Bounding that cost is
//!   a gas question (gas per key byte and per proof depth, Phase 14 in `TODO.md`).

mod proof;
mod verifier;

#[cfg(all(test, unix, target_pointer_width = "64"))]
mod test_prover;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_vectors;
#[cfg(all(test, unix, target_pointer_width = "64"))]
mod tests;
#[cfg(test)]
mod vectors;

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use nomt_core::hasher::BinaryHasher;
use nomt_core::proof::{verify_multi_proof, verify_multi_proof_update};
use nomt_core::trie::{KeyPath, LeafData, Node, ValueHash};
pub use proof::{InvalidNomtProof, NomtProof};
use selendra_interface::reexports::digest::Digest;
pub use verifier::NomtVerifierStorage;

use crate::storage::MerkleProofSpec;
use crate::{
    NodeLeaf, OrderedReadsAndWrites, SlotKey, SlotValue, StateRoot, StorageProof, StorageRoot,
    VAL_HASH_AND_SIZE_LEN,
};

/// The key path of `key` in a state tree: `H(key)`, the hash of the whole key (prefix
/// included).
///
/// The one definition of where a key sits in the trees: the verifier and the node's prover
/// storage both use it, for every read, write and proof. Changing it changes every state root.
pub fn key_path<S: MerkleProofSpec>(key: &SlotKey) -> KeyPath {
    S::Hasher::digest(key.as_ref()).into()
}

/// The bytes a state tree stores as the value of `leaf`'s key: `val_hash ‖ size` (u32 LE), 36
/// bytes ([`NodeLeaf::combine_val_hash_and_size`]). NOMT hashes them into the leaf's value
/// hash, `H(leaf_value_bytes)`.
///
/// The one definition of what a leaf commits to: the verifier hashes it, and the node's prover
/// storage gives it to NOMT for every read and write (of a value `v`: the leaf
/// [`NodeLeaf::make_leaf`]`(v)`). Not the borsh encoding of a [`NodeLeaf`] (`size ‖ val_hash`,
/// the witness hint's order). Changing it changes every state root.
pub fn leaf_value_bytes(leaf: &NodeLeaf) -> [u8; VAL_HASH_AND_SIZE_LEN] {
    leaf.combine_val_hash_and_size()
}

/// The value hash of a leaf in a state tree: `H(`[`leaf_value_bytes`]`)`.
fn value_hash<S: MerkleProofSpec>(leaf: &NodeLeaf) -> ValueHash {
    S::Hasher::digest(leaf_value_bytes(leaf)).into()
}

/// Verifies a storage proof against a state root and returns the proven key and value.
///
/// Shared by the NOMT storages ([`Storage::open_proof`](crate::Storage::open_proof)). It only
/// proves that the key has that value (or is absent) in the proof's namespace; the containers'
/// `verify_proof` also check that the key belongs to the container.
///
/// # Errors
/// If the proof does not verify against the namespace's root, or does not prove this key, or
/// proves another value for it.
pub fn verify_storage_proof<S: MerkleProofSpec>(
    state_root: StorageRoot<S>,
    proof: StorageProof<NomtProof>,
) -> anyhow::Result<(SlotKey, Option<SlotValue>)> {
    let StorageProof {
        key,
        value,
        proof,
        namespace,
    } = proof;
    let root: Node = state_root.namespace_root(namespace);
    let verified =
        verify_multi_proof::<BinaryHasher<S::Hasher>>(proof.inner(), root).map_err(|e| {
            anyhow::anyhow!("proof does not verify against the {namespace:?} root: {e:?}")
        })?;
    let key_path = key_path::<S>(&key);
    let confirmed = match &value {
        None => verified.confirm_nonexistence(&key_path),
        Some(value) => verified.confirm_value(&LeafData {
            key_path,
            value_hash: value_hash::<S>(&NodeLeaf::make_leaf::<S::Hasher>(value)),
        }),
    }
    .map_err(|_| anyhow::anyhow!("key {key} is not covered by the proof"))?;
    anyhow::ensure!(
        confirmed,
        "the proof does not prove the claimed value of key {key}"
    );
    Ok((key, value))
}

/// Whether the accesses of a namespace need a multi-proof: iff anything was read or written.
///
/// The prover adds a namespace's multi-proof hint to the witness exactly when this is true,
/// and the verifier consumes one exactly when this is true, so both must use this function
/// (if they disagreed, the verifier would read the wrong hint).
pub fn namespace_needs_proof(accesses: &OrderedReadsAndWrites) -> bool {
    !(accesses.ordered_reads.is_empty() && accesses.ordered_writes.is_empty())
}

/// Verifies the accesses of one namespace against its previous root and returns its new root.
///
/// 1. `proof` must verify against `prev_root`.
/// 2. **Every** read must match it: a read leaf must be the leaf of that key (key path and
///    value hash), a read absence must be proven absent. Until here, reads are unverified
///    witness hints.
/// 3. The writes (new values, or `None` for deletes) are applied to the proven paths, which
///    gives the new root.
/// 4. Every path of the proof must be needed by an access (a NOMT witness has one path per
///    group of accessed keys). Extra paths would not change the result, but they would give one
///    execution many witnesses (upstream accepts them).
///
/// The prover can run it on the proof it just built, to check that its own reads match its
/// tree.
///
/// # Errors
/// If any of the above fails (an invalid witness or a stale previous root), or a key is not
/// covered by the proof, or two written keys have the same key path. Never panics.
pub fn verify_namespace<S: MerkleProofSpec>(
    prev_root: [u8; 32],
    accesses: &OrderedReadsAndWrites,
    proof: &NomtProof,
) -> anyhow::Result<[u8; 32]> {
    let verified = verify_multi_proof::<BinaryHasher<S::Hasher>>(proof.inner(), prev_root)
        .map_err(|e| {
            anyhow::anyhow!("multi-proof does not verify against the previous root: {e:?}")
        })?;

    // The proof paths the accesses use (indices in `proof.inner().paths`, in which order the
    // verified proof keeps them).
    let mut used = BTreeSet::new();
    let mut find = |key: &SlotKey, key_path: &KeyPath| {
        verified
            .find_index_for(key_path)
            .map(|index| {
                used.insert(index);
            })
            .map_err(|_| anyhow::anyhow!("key {key} is not covered by the multi-proof"))
    };

    for (key, leaf) in &accesses.ordered_reads {
        let key_path = key_path::<S>(key);
        find(key, &key_path)?;
        let confirmed = match leaf {
            None => verified.confirm_nonexistence(&key_path),
            Some(leaf) => verified.confirm_value(&LeafData {
                key_path,
                value_hash: value_hash::<S>(leaf),
            }),
        }
        .map_err(|_| anyhow::anyhow!("read of key {key} is not covered by the multi-proof"))?;
        anyhow::ensure!(
            confirmed,
            "read of key {key} does not match the previous state"
        );
    }

    // Sorted by key path, as `verify_multi_proof_update` requires.
    let mut updates: BTreeMap<KeyPath, Option<ValueHash>> = BTreeMap::new();
    for (key, value) in &accesses.ordered_writes {
        let value_hash = value
            .as_ref()
            .map(|value| value_hash::<S>(&NodeLeaf::make_leaf::<S::Hasher>(value)));
        let key_path = key_path::<S>(key);
        find(key, &key_path)?;
        match updates.entry(key_path) {
            Entry::Vacant(entry) => {
                entry.insert(value_hash);
            }
            Entry::Occupied(_) => anyhow::bail!("two writes to the key path of key {key}"),
        }
    }
    // An empty proof (no paths) proves the empty trie; NOMT proves keys of an empty trie with
    // one root terminator instead, so with any access an empty proof is rejected here too.
    anyhow::ensure!(
        used.len() == proof.inner().paths.len(),
        "the multi-proof has paths that no access needs"
    );
    verify_multi_proof_update::<BinaryHasher<S::Hasher>>(&verified, updates.into_iter().collect())
        .map_err(|e| anyhow::anyhow!("multi-proof does not cover the writes: {e:?}"))
}

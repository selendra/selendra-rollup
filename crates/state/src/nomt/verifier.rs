//! [`NomtVerifierStorage`]: the zk-guest storage of the NOMT backend.

use core::fmt;
use core::marker::PhantomData;

use super::{NomtProof, namespace_needs_proof, verify_namespace, verify_storage_proof};
use crate::namespaces::{ProvableCompileTimeNamespace, ProvableNamespace};
use crate::storage::{MerkleProofSpec, NodeLeaf, NodeLeafAndMaybeValue};
use crate::{
    OrderedReadsAndWrites, SlotKey, SlotValue, StateAccesses, StateRoot, Storage, StorageProof,
    StorageRoot, Witness,
};

/// A [`Storage`] for the zk guest, based on NOMT: it holds no state, answers every read from
/// the witness and verifies all of them against the previous root in
/// [`compute_state_update`](Storage::compute_state_update).
///
/// # Witness protocol
/// It consumes the hints the NOMT prover storage adds (see [`Storage`], "The witness
/// protocol"), in order:
/// - [`get_leaf`](Storage::get_leaf): one `Option<NodeLeaf>`;
/// - [`get`](Storage::get): one `Option<SlotValue>`;
/// - [`put_in_witness`](Storage::put_in_witness): nothing (the cache reads the value with `get`
///   and checks it against the leaf);
/// - [`compute_state_update`](Storage::compute_state_update): one [`NomtProof`] for the user
///   namespace, then one for the kernel namespace, each only if that namespace was accessed
///   ([`namespace_needs_proof`]).
///
/// A missing or undecodable read hint panics (an invalid witness: see [`Witness`]); a missing
/// or undecodable proof hint, and every read or proof that does not match the previous root,
/// make `compute_state_update` return `Err`. No other input makes it panic.
///
/// It is not a `NativeStorage` (upstream implemented one with
/// `unimplemented!` stubs, only for feature unification in its tests).
pub struct NomtVerifierStorage<S> {
    _spec: PhantomData<fn() -> S>,
}

impl<S> NomtVerifierStorage<S> {
    /// Creates a verifier storage (same as [`Default::default`]).
    pub const fn new() -> Self {
        Self { _spec: PhantomData }
    }
}

// Hand-written: derives would require bounds on the marker `S`.
impl<S> Default for NomtVerifierStorage<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Clone for NomtVerifierStorage<S> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<S> fmt::Debug for NomtVerifierStorage<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NomtVerifierStorage")
    }
}

impl<S: MerkleProofSpec> NomtVerifierStorage<S> {
    /// One namespace of `compute_state_update`: its new root.
    fn update_namespace(
        namespace: ProvableNamespace,
        accesses: &OrderedReadsAndWrites,
        witness: &S::Witness,
        prev_root: [u8; 32],
    ) -> anyhow::Result<[u8; 32]> {
        // An untouched namespace keeps its root, and the prover added no proof for it.
        if !namespace_needs_proof(accesses) {
            return Ok(prev_root);
        }
        let proof: NomtProof = witness.try_get_hint()?;
        verify_namespace::<S>(prev_root, accesses, &proof)
            .map_err(|e| e.context(format!("{namespace:?} namespace")))
    }
}

impl<S: MerkleProofSpec> Storage for NomtVerifierStorage<S> {
    type Hasher = S::Hasher;
    type Witness = S::Witness;
    type Proof = NomtProof;
    type Root = StorageRoot<S>;
    type StateUpdate = ();
    type ChangeSet = ();

    const PRE_GENESIS_ROOT: StorageRoot<S> = StorageRoot::PRE_GENESIS;

    fn put_in_witness(&self, _value: Option<SlotValue>, _witness: &S::Witness) {}

    fn get_leaf<N: ProvableCompileTimeNamespace>(
        &self,
        _key: &SlotKey,
        witness: &S::Witness,
    ) -> Option<NodeLeafAndMaybeValue> {
        // A bare leaf: a hint carrying a value too does not decode (upstream decoded a
        // `NodeLeafAndMaybeValue` and asserted its `ReadType`).
        witness
            .get_hint::<Option<NodeLeaf>>()
            .map(NodeLeafAndMaybeValue::without_value)
    }

    fn get<N: ProvableCompileTimeNamespace>(
        &self,
        _key: &SlotKey,
        witness: &S::Witness,
    ) -> Option<SlotValue> {
        witness.get_hint()
    }

    fn compute_state_update(
        &self,
        state_accesses: StateAccesses,
        witness: &S::Witness,
        prev_state_root: StorageRoot<S>,
    ) -> anyhow::Result<(StorageRoot<S>, ())> {
        let StateAccesses { user, kernel } = state_accesses;
        // User first, then kernel: the order of the proof hints.
        let user_root = Self::update_namespace(
            ProvableNamespace::User,
            &user,
            witness,
            prev_state_root.namespace_root(ProvableNamespace::User),
        )?;
        let kernel_root = Self::update_namespace(
            ProvableNamespace::Kernel,
            &kernel,
            witness,
            prev_state_root.namespace_root(ProvableNamespace::Kernel),
        )?;
        Ok((StorageRoot::new(user_root, kernel_root), ()))
    }

    fn materialize_changes(self, _state_update: ()) {}

    fn open_proof(
        state_root: StorageRoot<S>,
        proof: StorageProof<NomtProof>,
    ) -> anyhow::Result<(SlotKey, Option<SlotValue>)> {
        verify_storage_proof(state_root, proof)
    }
}

#[cfg(test)]
mod tests {
    use nomt_core::hasher::NodeHasher;
    use nomt_core::proof::{MultiPathProof, MultiProof, PathProofTerminal};
    use nomt_core::trie::{InternalData, LeafData, Node, TERMINATOR};
    use nomt_core::trie_pos::TriePosition;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::nomt::proof::tests::Hasher;
    use crate::{ArrayWitness, DefaultStorageSpec, InvalidWitness, Prefix, User};

    type Spec = DefaultStorageSpec<Sha256>;
    type Verifier = NomtVerifierStorage<Spec>;
    type Root = StorageRoot<Spec>;

    fn first_bit(key: &SlotKey) -> bool {
        Sha256::digest(key.as_ref())[0] & 0x80 != 0
    }

    /// Keys whose key paths start with `0`, `1` and `0`.
    fn keys() -> (SlotKey, SlotKey, SlotKey) {
        let all = (0u8..=255).map(|i| SlotKey::from_parts(&Prefix::new(1, 1), &[i]));
        let (zeros, ones): (Vec<_>, Vec<_>) = all.partition(|key| !first_bit(key));
        (zeros[0].clone(), ones[0].clone(), zeros[1].clone())
    }

    fn value(v: u8) -> SlotValue {
        SlotValue::from(vec![v; 3])
    }

    fn leaf_data(key: &SlotKey, value: &SlotValue) -> LeafData {
        LeafData {
            key_path: Sha256::digest(key.as_ref()).into(),
            value_hash: Sha256::digest(value.combine_val_hash_and_size::<Sha256>()).into(),
        }
    }

    fn leaf_node(key: &SlotKey, value: &SlotValue) -> Node {
        Hasher::hash_leaf(&leaf_data(key, value))
    }

    fn internal(left: Node, right: Node) -> Node {
        Hasher::hash_internal(&InternalData { left, right })
    }

    /// A trie with `left → value(1)` and `right → value(2)`, its root and the proof of both.
    fn two_leaf_trie() -> (Node, NomtProof) {
        let (left, right, _) = keys();
        let paths = vec![
            MultiPathProof {
                terminal: PathProofTerminal::Leaf(leaf_data(&left, &value(1))),
                depth: 1,
            },
            MultiPathProof {
                terminal: PathProofTerminal::Leaf(leaf_data(&right, &value(2))),
                depth: 1,
            },
        ];
        let proof = NomtProof::new(MultiProof {
            paths,
            siblings: vec![],
        })
        .unwrap();
        let root = internal(leaf_node(&left, &value(1)), leaf_node(&right, &value(2)));
        (root, proof)
    }

    fn leaf(v: &SlotValue) -> Option<NodeLeaf> {
        Some(NodeLeaf::make_leaf::<Sha256>(v))
    }

    #[test]
    fn verify_namespace_checks_reads_and_applies_writes() {
        let (left, right, absent) = keys();
        let (root, proof) = two_leaf_trie();
        let accesses = OrderedReadsAndWrites {
            ordered_reads: vec![(left.clone(), leaf(&value(1))), (absent.clone(), None)],
            ordered_writes: vec![(right.clone(), Some(value(3)))],
        };
        assert_eq!(
            verify_namespace::<Spec>(root, &accesses, &proof).unwrap(),
            internal(leaf_node(&left, &value(1)), leaf_node(&right, &value(3)))
        );
        // Reads only: the root stays.
        let reads = OrderedReadsAndWrites {
            ordered_reads: vec![
                (left.clone(), leaf(&value(1))),
                (right.clone(), leaf(&value(2))),
            ],
            ordered_writes: vec![],
        };
        assert_eq!(
            verify_namespace::<Spec>(root, &reads, &proof).unwrap(),
            root
        );
        // Deleting one leaf moves the other one up to the root.
        let delete = OrderedReadsAndWrites {
            ordered_reads: vec![(left.clone(), leaf(&value(1)))],
            ordered_writes: vec![(right.clone(), None)],
        };
        assert_eq!(
            verify_namespace::<Spec>(root, &delete, &proof).unwrap(),
            leaf_node(&left, &value(1))
        );
    }

    #[test]
    fn verify_namespace_rejects_lies() {
        let (left, right, absent) = keys();
        let (root, proof) = two_leaf_trie();
        let reads = |reads: Vec<(SlotKey, Option<NodeLeaf>)>| OrderedReadsAndWrites {
            ordered_reads: reads,
            ordered_writes: vec![(right.clone(), None)],
        };
        let check = |accesses: &OrderedReadsAndWrites, why: &str| {
            let err = verify_namespace::<Spec>(root, accesses, &proof).unwrap_err();
            assert!(format!("{err:#}").contains(why), "{err:#}");
        };
        // A wrong leaf, a present key read as absent, an absent key read as present.
        check(
            &reads(vec![(left.clone(), leaf(&value(9)))]),
            "does not match the previous state",
        );
        check(&reads(vec![(left.clone(), None)]), "does not match");
        check(
            &reads(vec![(absent.clone(), leaf(&value(1)))]),
            "does not match",
        );
        // The right size but another hash.
        let mut wrong_hash = NodeLeaf::make_leaf::<Sha256>(&value(1));
        wrong_hash.val_hash[0] ^= 1;
        check(
            &reads(vec![(left.clone(), Some(wrong_hash))]),
            "does not match",
        );
        // A stale previous root.
        let accesses = reads(vec![(left.clone(), leaf(&value(1)))]);
        assert!(verify_namespace::<Spec>(TERMINATOR, &accesses, &proof).is_err());
        assert!(verify_namespace::<Spec>([1; 32], &accesses, &proof).is_err());
        // Two writes to one key: an error, not a panic.
        let duplicate = OrderedReadsAndWrites {
            ordered_reads: vec![],
            ordered_writes: vec![(left.clone(), None), (left.clone(), Some(value(1)))],
        };
        let err = verify_namespace::<Spec>(root, &duplicate, &proof).unwrap_err();
        assert!(err.to_string().contains("two writes"), "{err}");
    }

    #[test]
    fn verify_namespace_rejects_uncovered_keys_and_extra_paths() {
        let (left, right, _) = keys();
        let (root, _) = two_leaf_trie();
        // A proof of `left` alone (with `right`'s leaf as its sibling).
        let left_only = NomtProof::new(MultiProof {
            paths: vec![MultiPathProof {
                terminal: PathProofTerminal::Leaf(leaf_data(&left, &value(1))),
                depth: 1,
            }],
            siblings: vec![leaf_node(&right, &value(2))],
        })
        .unwrap();
        let read_left = OrderedReadsAndWrites {
            ordered_reads: vec![(left.clone(), leaf(&value(1)))],
            ordered_writes: vec![],
        };
        assert_eq!(
            verify_namespace::<Spec>(root, &read_left, &left_only).unwrap(),
            root
        );
        for accesses in [
            OrderedReadsAndWrites {
                ordered_reads: vec![(right.clone(), leaf(&value(2)))],
                ordered_writes: vec![],
            },
            OrderedReadsAndWrites {
                ordered_reads: vec![],
                ordered_writes: vec![(right.clone(), None)],
            },
        ] {
            let err = verify_namespace::<Spec>(root, &accesses, &left_only).unwrap_err();
            assert!(err.to_string().contains("not covered"), "{err}");
        }
        // The two-leaf proof has a path no access needs.
        let (_, both) = two_leaf_trie();
        let err = verify_namespace::<Spec>(root, &read_left, &both).unwrap_err();
        assert!(err.to_string().contains("no access needs"), "{err}");
    }

    #[test]
    fn verify_namespace_on_the_empty_trie() {
        let (left, _, _) = keys();
        let root_terminator = NomtProof::new(MultiProof {
            paths: vec![MultiPathProof {
                terminal: PathProofTerminal::Terminator(TriePosition::new()),
                depth: 0,
            }],
            siblings: vec![],
        })
        .unwrap();
        let accesses = OrderedReadsAndWrites {
            ordered_reads: vec![(left.clone(), None)],
            ordered_writes: vec![(left.clone(), Some(value(1)))],
        };
        assert_eq!(
            verify_namespace::<Spec>(TERMINATOR, &accesses, &root_terminator).unwrap(),
            leaf_node(&left, &value(1))
        );
        // The empty proof also verifies against the empty root, but is not what NOMT gives.
        let empty = NomtProof::new(MultiProof {
            paths: vec![],
            siblings: vec![],
        })
        .unwrap();
        assert!(verify_namespace::<Spec>(TERMINATOR, &accesses, &empty).is_err());
        let nothing = OrderedReadsAndWrites::default();
        assert_eq!(
            verify_namespace::<Spec>(TERMINATOR, &nothing, &empty).unwrap(),
            TERMINATOR
        );
    }

    fn user_accesses() -> StateAccesses {
        let (left, right, _) = keys();
        StateAccesses {
            user: OrderedReadsAndWrites {
                ordered_reads: vec![(left, leaf(&value(1)))],
                ordered_writes: vec![(right, Some(value(3)))],
            },
            kernel: OrderedReadsAndWrites::default(),
        }
    }

    #[test]
    fn compute_state_update_consumes_one_proof_per_accessed_namespace() {
        let (left, right, _) = keys();
        let (root, proof) = two_leaf_trie();
        let kernel_root = [7; 32];
        let prev = Root::new(root, kernel_root);
        let witness = ArrayWitness::default();
        witness.add_hint(&proof);
        let (new, ()) = Verifier::new()
            .compute_state_update(user_accesses(), &witness, prev)
            .unwrap();
        // The untouched kernel root is carried forward, and consumed no hint.
        assert_eq!(
            new,
            Root::new(
                internal(leaf_node(&left, &value(1)), leaf_node(&right, &value(3))),
                kernel_root
            )
        );
        assert_eq!(witness.ensure_consumed(), Ok(()));
        // No accesses: the root stays and nothing is consumed.
        let witness = ArrayWitness::from_hints(vec![vec![1]]);
        let (same, ()) = Verifier::new()
            .compute_state_update(StateAccesses::default(), &witness, prev)
            .unwrap();
        assert_eq!(same, prev);
        assert_eq!(witness.len(), 1);
        // Both namespaces accessed: user proof first, then kernel.
        let both = StateAccesses {
            kernel: user_accesses().user,
            ..user_accesses()
        };
        let witness = ArrayWitness::default();
        witness.add_hint(&proof);
        witness.add_hint(&proof);
        let (new, ()) = Verifier::new()
            .compute_state_update(both.clone(), &witness, Root::new(root, root))
            .unwrap();
        assert_eq!(new.user_root(), new.kernel_root());
        // The kernel proof is missing: an error, not a panic.
        let witness = ArrayWitness::default();
        witness.add_hint(&proof);
        let err = Verifier::new()
            .compute_state_update(both, &witness, Root::new(root, root))
            .unwrap_err();
        assert!(err.downcast_ref::<InvalidWitness>().is_some(), "{err:#}");
    }

    #[test]
    fn compute_state_update_rejects_bad_proof_hints_and_stale_roots() {
        let (root, proof) = two_leaf_trie();
        let prev = Root::new(root, TERMINATOR);
        let mut encoded = borsh::to_vec(&proof).unwrap();
        // Undecodable, non-canonical (trailing byte) and tampered proofs.
        let tampered = {
            let last = encoded.len() - 1;
            let mut bytes = encoded.clone();
            bytes[last] ^= 1;
            bytes
        };
        encoded.push(0);
        for hint in [vec![], vec![1, 2, 3], encoded, tampered] {
            let witness = ArrayWitness::from_hints(vec![hint]);
            assert!(
                Verifier::new()
                    .compute_state_update(user_accesses(), &witness, prev)
                    .is_err()
            );
        }
        // A stale previous user root.
        let witness = ArrayWitness::default();
        witness.add_hint(&proof);
        let err = Verifier::new()
            .compute_state_update(user_accesses(), &witness, Root::PRE_GENESIS)
            .unwrap_err();
        assert!(format!("{err:#}").contains("User namespace"), "{err:#}");
    }

    #[test]
    fn reads_come_from_bare_hints() {
        let (left, _, _) = keys();
        let witness = ArrayWitness::default();
        witness.add_hint(&leaf(&value(1)));
        witness.add_hint(&Some(value(1)));
        witness.add_hint(&None::<NodeLeaf>);
        let verifier = Verifier::default();
        assert_eq!(
            verifier
                .get_leaf::<User>(&left, &witness)
                .map(|l| *l.leaf()),
            leaf(&value(1))
        );
        verifier.put_in_witness(Some(value(5)), &witness);
        assert_eq!(verifier.get::<User>(&left, &witness), Some(value(1)));
        assert_eq!(verifier.get_leaf::<User>(&left, &witness), None);
        assert_eq!(witness.ensure_consumed(), Ok(()));
        assert_eq!(Verifier::PRE_GENESIS_ROOT, Root::PRE_GENESIS);
        assert_eq!(format!("{:?}", verifier.clone()), "NomtVerifierStorage");
    }

    /// A leaf hint carrying more than the leaf (upstream's `ReadType` tag) is an invalid
    /// witness.
    #[test]
    #[should_panic(expected = "invalid witness")]
    fn a_leaf_hint_with_trailing_bytes_panics() {
        let (left, _, _) = keys();
        let mut hint = borsh::to_vec(&leaf(&value(1))).unwrap();
        hint.push(0);
        let witness = ArrayWitness::from_hints(vec![hint]);
        Verifier::new().get_leaf::<User>(&left, &witness);
    }

    #[test]
    fn open_proof_checks_key_value_and_namespace() {
        let (left, right, absent) = keys();
        let (root, proof) = two_leaf_trie();
        let state_root = Root::new(root, TERMINATOR);
        let storage_proof = |key: &SlotKey, value: Option<SlotValue>, namespace| StorageProof {
            key: key.clone(),
            value,
            proof: proof.clone(),
            namespace,
        };
        let user = ProvableNamespace::User;
        for (key, value) in [
            (&left, Some(value(1))),
            (&right, Some(value(2))),
            (&absent, None),
        ] {
            assert_eq!(
                Verifier::open_proof(state_root, storage_proof(key, value.clone(), user)).unwrap(),
                (key.clone(), value)
            );
        }
        for bad in [
            storage_proof(&left, Some(value(2)), user),
            storage_proof(&left, None, user),
            storage_proof(&absent, Some(value(1)), user),
            storage_proof(&left, Some(value(1)), ProvableNamespace::Kernel),
        ] {
            assert!(Verifier::open_proof(state_root, bad).is_err());
        }
        // The empty kernel tree: the root terminator proves every key absent.
        let empty = StorageProof {
            key: left.clone(),
            value: None,
            proof: NomtProof::new(MultiProof {
                paths: vec![MultiPathProof {
                    terminal: PathProofTerminal::Terminator(TriePosition::new()),
                    depth: 0,
                }],
                siblings: vec![],
            })
            .unwrap(),
            namespace: ProvableNamespace::Kernel,
        };
        assert!(Verifier::open_proof(state_root, empty.clone()).is_ok());
        assert!(
            Verifier::open_proof(
                state_root,
                StorageProof {
                    namespace: user,
                    ..empty
                }
            )
            .is_err()
        );
    }
}

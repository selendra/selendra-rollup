//! Verifier tests against real NOMT databases ([`NomtTestProver`]): the replay (the verifier,
//! fed only the prover's witness, computes what the prover did), the tamper property (every
//! hint is verified), lying hints, stale roots, untouched namespaces and storage proofs.

use proptest::collection::vec as prop_vec;
use proptest::prelude::{Strategy, any};
use proptest::prop_assert;

use super::test_prover::{NomtTestProver, Root, Spec};
use crate::namespaces::ProvableNamespace;
use crate::test_state::InMemoryState;
use crate::test_utils::{Harness, Model, Op, borsh_roundtrip, catch_quietly, hints, run};
use crate::{
    ArrayWitness, BorshCodec, KernelStateMap, NomtVerifierStorage, OrderedReadsAndWrites, Prefix,
    SlotKey, SlotValue, StateAccesses, StateCheckpoint, StateMap, StateRoot, Storage, Witness,
};

type Verifier = NomtVerifierStorage<Spec>;

fn model_of(prover: &NomtTestProver) -> Model {
    let state = InMemoryState {
        user: prover.values(ProvableNamespace::User),
        kernel: prover.values(ProvableNamespace::Kernel),
        accessory: Default::default(),
    };
    Model {
        committed: state.clone(),
        pending: state,
    }
}

fn prover_with(genesis: &[Op]) -> NomtTestProver {
    let prover = NomtTestProver::new();
    prover.commit_with(|state| {
        run(genesis, state);
    });
    prover
}

/// Random operations (with commits and discards) through a checkpoint over a NOMT prover with
/// a random genesis state, replayed through a checkpoint over the verifier that only has the
/// prover's witness: same results, same accesses, same root, the witness fully consumed, and
/// the committed state is the model's. This is also "native root == guest root" for random
/// read/write sets.
#[test_strategy::proptest(cases = 32)]
fn verifier_replays_the_nomt_prover(
    #[strategy(prop_vec(any::<Op>(), 0..16))] genesis: Vec<Op>,
    #[strategy(prop_vec(any::<Op>(), 0..48))] ops: Vec<Op>,
) {
    let prover = prover_with(&genesis);
    let prev_root = prover.root();

    let mut model = model_of(&prover);
    let expected = run(&ops, &mut model);
    model.commit();

    let mut checkpoint = StateCheckpoint::new(prover.clone());
    let results = run(&ops, &mut checkpoint);
    assert_eq!(results, expected);
    let (accesses, _, witness) = checkpoint.freeze();
    let (root, update) = prover
        .compute_state_update(accesses.clone(), &witness, prev_root)
        .unwrap();

    let witness = borsh_roundtrip(&witness);
    let mut verifier = StateCheckpoint::with_witness(Verifier::new(), witness);
    assert_eq!(run(&ops, &mut verifier), results);
    let (v_accesses, _, v_witness) = verifier.freeze();
    assert_eq!(v_accesses, accesses);
    let (v_root, ()) = Verifier::new()
        .compute_state_update(v_accesses, &v_witness, prev_root)
        .unwrap();
    assert_eq!(v_root, root);
    assert_eq!(v_witness.ensure_consumed(), Ok(()));

    prover.clone().materialize_changes(update);
    assert_eq!(prover.root(), root);
    assert_eq!(prover.values(ProvableNamespace::User), model.committed.user);
    assert_eq!(
        prover.values(ProvableNamespace::Kernel),
        model.committed.kernel
    );
}

/// Changing one byte of any one hint of an honest NOMT witness must make the verifier panic
/// (invalid witness) or the state update fail (see `every_hint_is_verified` for the test
/// storage; this one covers the real multi-proof hints too). No discards: discarded reads are
/// knowingly unverified.
#[test_strategy::proptest(cases = 24)]
fn every_nomt_hint_is_verified(
    #[strategy(prop_vec(any::<Op>(), 0..16))] genesis: Vec<Op>,
    #[strategy(prop_vec(any::<Op>().prop_map(|op| match op {
        Op::Discard => Op::Commit,
        op => op,
    }), 1..32))]
    ops: Vec<Op>,
    position: usize,
    #[strategy(1u8..)] flip: u8,
) {
    let prover = prover_with(&genesis);
    let prev_root = prover.root();
    let mut checkpoint = StateCheckpoint::new(prover.clone());
    run(&ops, &mut checkpoint);
    let (accesses, _, witness) = checkpoint.freeze();
    prover
        .compute_state_update(accesses, &witness, prev_root)
        .unwrap();

    let hints = hints(&witness);
    for index in 0..hints.len() {
        let mut tampered = hints.clone();
        let hint = &mut tampered[index];
        let at = position % hint.len();
        hint[at] ^= flip;
        let witness = ArrayWitness::from_hints(tampered);
        let outcome = catch_quietly(|| {
            let mut verifier = StateCheckpoint::with_witness(Verifier::new(), witness);
            run(&ops, &mut verifier);
            let (accesses, _, witness) = verifier.freeze();
            Verifier::new()
                .compute_state_update(accesses, &witness, prev_root)
                .map(|(root, ())| root)
        });
        prop_assert!(
            !matches!(outcome, Ok(Ok(_))),
            "hint {index} of {} was changed (byte {at} ^ {flip:#04x}) and still accepted",
            hints.len()
        );
    }
}

const MAP: Prefix = Prefix::new(1, 1);
const KERNEL_MAP: Prefix = Prefix::new(2, 0);

fn map() -> StateMap<u8, u32> {
    StateMap::with_codec(MAP, BorshCodec)
}

fn kernel_map() -> KernelStateMap<u8, u32> {
    KernelStateMap::with_codec(KERNEL_MAP, BorshCodec)
}

/// A prover with user `1 → 10, 2 → 20` and kernel `1 → 100`.
fn populated() -> NomtTestProver {
    let prover = NomtTestProver::new();
    prover.commit_with(|state| {
        let Ok(()) = map().set(&1, &10, state);
        let Ok(()) = map().set(&2, &20, state);
        let Ok(()) = kernel_map().set(&1, &100, state);
    });
    prover
}

/// Runs `f` on a prover checkpoint and returns the witness (with the proof hints) and the
/// accesses.
fn witness_of(
    prover: &NomtTestProver,
    f: impl FnOnce(&mut StateCheckpoint<NomtTestProver>),
) -> (ArrayWitness, StateAccesses) {
    let mut checkpoint = StateCheckpoint::new(prover.clone());
    f(&mut checkpoint);
    let (accesses, _, witness) = checkpoint.freeze();
    prover
        .compute_state_update(accesses.clone(), &witness, prover.root())
        .unwrap();
    (witness, accesses)
}

/// Replays `f` on the verifier with `witness` and returns the state update's result.
fn verify_with(
    witness: ArrayWitness,
    prev_root: Root,
    f: impl FnOnce(&mut StateCheckpoint<Verifier>),
) -> anyhow::Result<Root> {
    let mut checkpoint = StateCheckpoint::with_witness(Verifier::new(), witness);
    f(&mut checkpoint);
    let (accesses, _, witness) = checkpoint.freeze();
    let (root, ()) = Verifier::new().compute_state_update(accesses, &witness, prev_root)?;
    witness.ensure_consumed()?;
    Ok(root)
}

/// `witness` with hint `index` replaced by `lie` (borsh-encoded).
fn with_lie<T: borsh::BorshSerialize>(
    witness: &ArrayWitness,
    index: usize,
    lie: &T,
) -> ArrayWitness {
    let mut hints = hints(witness);
    hints[index] = borsh::to_vec(lie).unwrap();
    ArrayWitness::from_hints(hints)
}

#[test]
fn lying_hints_are_rejected() {
    let prover = populated();
    let prev_root = prover.root();
    fn reads<St: Storage>(state: &mut StateCheckpoint<St>) {
        // A present value, a size query of a present value, an absent value.
        let _ = map().get(&1, state);
        let _ = state.get_size(ProvableNamespace::User, &map().slot_key(&2));
        let _ = map().get(&3, state);
        let _ = kernel_map().get(&1, state);
    }
    let (witness, _) = witness_of(&prover, reads);
    // Hints: value 1, leaf 2, value 3 (absent), kernel value 1, user proof, kernel proof.
    assert_eq!(witness.len(), 6);
    assert_eq!(
        verify_with(borsh_roundtrip(&witness), prev_root, reads).unwrap(),
        prev_root
    );
    let value = |v: u32| Some(SlotValue::from(borsh::to_vec(&v).unwrap()));
    let lies = [
        // Another value, and "absent" for a present key.
        with_lie(&witness, 0, &value(11)),
        with_lie(&witness, 0, &None::<SlotValue>),
        // Another leaf, and "absent" for a present key.
        with_lie(
            &witness,
            1,
            &Some(crate::NodeLeaf::make_leaf::<sha2::Sha256>(
                &value(21).unwrap(),
            )),
        ),
        with_lie(&witness, 1, &None::<crate::NodeLeaf>),
        // A value for an absent key.
        with_lie(&witness, 2, &value(30)),
        // A lie in the kernel namespace.
        with_lie(&witness, 3, &value(101)),
        // The proofs swapped.
        {
            let mut hints = hints(&witness);
            hints.swap(4, 5);
            ArrayWitness::from_hints(hints)
        },
    ];
    for (i, lie) in lies.into_iter().enumerate() {
        assert!(verify_with(lie, prev_root, reads).is_err(), "lie {i}");
    }
}

#[test]
fn a_stale_previous_root_is_rejected() {
    let prover = populated();
    let prev_root = prover.root();
    let (witness, accesses) = witness_of(&prover, |state| {
        let _ = map().get(&1, state);
        let Ok(()) = map().set(&4, &40, state);
    });
    for stale in [
        Root::PRE_GENESIS,
        Root::new([1; 32], prev_root.kernel_root()),
    ] {
        let witness = borsh_roundtrip(&witness);
        assert!(
            Verifier::new()
                .compute_state_update(accesses.clone(), &witness, stale)
                .is_err()
        );
    }
    // The prover refuses a stale root too.
    let witness = ArrayWitness::default();
    assert!(
        prover
            .compute_state_update(accesses, &witness, Root::PRE_GENESIS)
            .is_err()
    );
}

fn kernel_only_accesses(key: SlotKey, value: SlotValue) -> StateAccesses {
    StateAccesses {
        user: OrderedReadsAndWrites::default(),
        kernel: OrderedReadsAndWrites {
            ordered_reads: Vec::new(),
            ordered_writes: vec![(key, Some(value))],
        },
    }
}

/// Upstream `verifier_carries_untouched_non_empty_namespace_forward`: a block that touches
/// only the kernel keeps the (non-empty) user root, adds and consumes only the kernel proof.
#[test]
fn verifier_carries_untouched_non_empty_namespace_forward() {
    let prover = NomtTestProver::new();
    let user_key = SlotKey::try_from_bytes(b"user-counter").unwrap();
    let first_root = prover.commit_with(|state| {
        crate::StateWriter::<crate::User>::set(state, &user_key, SlotValue::from(vec![1]))
            .unwrap_or_else(|never| match never {});
    });
    assert_ne!(
        first_root.namespace_root(ProvableNamespace::User),
        nomt_core::trie::TERMINATOR
    );

    let kernel_key = SlotKey::try_from_bytes(b"kernel-only-counter").unwrap();
    let kernel_value = SlotValue::from(vec![2]);
    let witness = ArrayWitness::default();
    let (prover_root, _update) = prover
        .compute_state_update(
            kernel_only_accesses(kernel_key.clone(), kernel_value.clone()),
            &witness,
            first_root,
        )
        .unwrap();
    assert_eq!(witness.len(), 1);

    let (verifier_root, ()) = Verifier::new()
        .compute_state_update(
            kernel_only_accesses(kernel_key, kernel_value),
            &witness,
            first_root,
        )
        .unwrap();
    assert_eq!(verifier_root, prover_root);
    assert_eq!(
        verifier_root.namespace_root(ProvableNamespace::User),
        first_root.namespace_root(ProvableNamespace::User)
    );
    assert_eq!(witness.ensure_consumed(), Ok(()));
}

#[test]
fn blocks_chain_from_the_pre_genesis_root() {
    let prover = NomtTestProver::new();
    assert_eq!(prover.root(), Verifier::PRE_GENESIS_ROOT);
    let mut prev_root = Verifier::PRE_GENESIS_ROOT;
    fn ops<St: Storage>(block: u8, state: &mut StateCheckpoint<St>) {
        let _ = map().get(&block, state);
        let Ok(()) = map().set(&block, &u32::from(block), state);
        if block == 2 {
            let _ = map().remove(&0, state);
        }
    }
    for block in 0u8..3 {
        let (witness, _) = witness_of(&prover, |s| ops(block, s));
        let root = verify_with(witness, prev_root, |s| ops(block, s)).unwrap();
        assert_eq!(prover.commit_with(|s| ops(block, s)), root);
        prev_root = root;
    }
    assert_eq!(prover.values(ProvableNamespace::User).len(), 2);
}

#[test]
fn open_proof_on_nomt_proofs() {
    let prover = populated();
    let root = prover.root();
    let present = map().slot_key(&1);
    let absent = map().slot_key(&9);
    let kernel = kernel_map().slot_key(&1);
    for (namespace, key) in [
        (ProvableNamespace::User, &present),
        (ProvableNamespace::User, &absent),
        (ProvableNamespace::Kernel, &kernel),
        (ProvableNamespace::Kernel, &present),
    ] {
        let proof = prover.prove(namespace, key);
        let expected = (proof.key.clone(), proof.value.clone());
        // The user key is absent from the kernel tree.
        assert_eq!(
            expected.1.is_some(),
            (namespace == ProvableNamespace::User) == (key == &present) || key == &kernel
        );
        // Through JSON and borsh, like an API client would get it.
        let json = serde_json::from_str(&serde_json::to_string(&proof).unwrap()).unwrap();
        assert_eq!(Verifier::open_proof(root, json).unwrap(), expected);
        let decoded = borsh::from_slice(&borsh::to_vec(&proof).unwrap()).unwrap();
        assert_eq!(Verifier::open_proof(root, decoded).unwrap(), expected);
    }

    let proof = prover.prove(ProvableNamespace::User, &present);
    let other_value = crate::StorageProof {
        value: Some(SlotValue::from(vec![0])),
        ..proof.clone()
    };
    let as_absent = crate::StorageProof {
        value: None,
        ..proof.clone()
    };
    let other_key = crate::StorageProof {
        key: map().slot_key(&2),
        ..proof.clone()
    };
    let other_namespace = crate::StorageProof {
        namespace: ProvableNamespace::Kernel,
        ..proof.clone()
    };
    for bad in [other_value, as_absent, other_key, other_namespace] {
        assert!(Verifier::open_proof(root, bad).is_err());
    }
    // A proof against a later root.
    let later = prover.commit_with(|state| {
        let Ok(()) = map().set(&1, &11, state);
    });
    assert!(Verifier::open_proof(later, proof.clone()).is_err());
    assert!(Verifier::open_proof(root, proof).is_ok());
}

/// The known-answer vectors (`vectors.rs`) are what real NOMT computes: the root of the two
/// entries, and its proof of the first one, byte for byte.
#[test]
fn real_nomt_matches_the_known_answer_vectors() {
    use super::test_vectors::{NOMT_PROOF_OF_ENTRY_1, TWO_ENTRY_ROOT, vector_entries};
    let [(key_1, value_1), (key_2, value_2)] = vector_entries();
    assert_eq!(map().slot_key(&1), key_1);
    assert_eq!(map().slot_key(&2), key_2);
    let prover = NomtTestProver::new();
    prover.commit_with(|state| {
        let Ok(()) = map().set(&1, &10, state);
        let Ok(()) = map().set(&2, &20, state);
    });
    let values = prover.values(ProvableNamespace::User);
    assert_eq!(values.get(&key_1), Some(&value_1));
    assert_eq!(values.get(&key_2), Some(&value_2));
    let root = prover.root();
    assert_eq!(root.kernel_root(), nomt_core::trie::TERMINATOR);
    assert_eq!(
        selendra_interface::common::HexString(root.user_root()).to_string(),
        TWO_ENTRY_ROOT
    );
    let proof = prover.prove(ProvableNamespace::User, &key_1);
    assert_eq!(
        selendra_interface::common::HexString(borsh::to_vec(&proof.proof).unwrap()).to_string(),
        NOMT_PROOF_OF_ENTRY_1
    );
}

/// Runs one block on the prover and the verifier: the witness has `hints` hints, the verifier
/// replays it to the same root, and the prover commits it (where NOMT 1.0.5 would panic on
/// unrewritten deletes of absent keys). Returns the new root.
macro_rules! check_block {
    ($prover:expr, $ops:ident, $hints:expr) => {{
        let prover: &NomtTestProver = $prover;
        let prev_root = prover.root();
        let (witness, _) = witness_of(prover, |s| $ops(s));
        assert_eq!(witness.len(), $hints, "hints of {}", stringify!($ops));
        let root = verify_with(borsh_roundtrip(&witness), prev_root, |s| $ops(s)).unwrap();
        assert_eq!(prover.commit_with(|s| $ops(s)), root);
        root
    }};
}

fn delete<N: crate::ProvableCompileTimeNamespace, St: Storage>(
    state: &mut StateCheckpoint<St>,
    key: &SlotKey,
) where
    StateCheckpoint<St>: crate::StateWriter<N, Error = std::convert::Infallible>,
{
    crate::StateWriter::<N>::delete(state, key).unwrap_or_else(|never| match never {});
}

/// A blind delete (no read) of an absent kernel key.
fn blind_kernel_delete<St: Storage>(state: &mut StateCheckpoint<St>) {
    delete::<crate::Kernel, St>(state, &kernel_map().slot_key(&5));
}

/// A read, then a delete, of an absent user key.
fn user_remove<St: Storage>(state: &mut StateCheckpoint<St>) {
    let _ = map().remove(&3, state);
}

/// A read of a present user key, a blind delete of an absent one, a remove of an absent kernel
/// key.
fn reads_and_absent_deletes<St: Storage>(state: &mut StateCheckpoint<St>) {
    let _ = map().get(&1, state);
    delete::<crate::User, St>(state, &map().slot_key(&9));
    let _ = kernel_map().remove(&7, state);
}

/// Deletes of absent keys next to real writes.
fn absent_deletes_and_writes<St: Storage>(state: &mut StateCheckpoint<St>) {
    delete::<crate::User, St>(state, &map().slot_key(&8));
    let Ok(()) = map().set(&4, &40, state);
    blind_kernel_delete(state);
    let Ok(()) = kernel_map().set(&2, &200, state);
}

/// Deterministic cover of the NOMT 1.0.5 workaround (deletes of absent keys become reads of
/// their absence, `test_prover::to_nomt_accesses`; `selendra-db`'s prover does the same) and of
/// the proof-hint rule (one proof per accessed namespace, `namespace_needs_proof`: a namespace
/// whose only access is such a delete is accessed). The proptests reach these cases only at
/// random.
#[test]
fn deletes_of_absent_keys_commit_and_replay() {
    // Empty databases: only a delete (blind, or after a read) in one namespace.
    let prover = NomtTestProver::new();
    // The kernel proof only (a blind delete reads nothing).
    let root = check_block!(&prover, blind_kernel_delete, 1);
    assert_eq!(root, Root::PRE_GENESIS);
    // The read's value, then the user proof.
    let root = check_block!(&prover, user_remove, 2);
    assert_eq!(root, Root::PRE_GENESIS);

    // Next to values: two reads, then both proofs; nothing changes.
    let prover = populated();
    let prev_root = prover.root();
    assert_eq!(
        check_block!(&prover, reads_and_absent_deletes, 4),
        prev_root
    );
    // With real writes in both namespaces: both proofs, both roots change.
    let root = check_block!(&prover, absent_deletes_and_writes, 2);
    assert_ne!(root.user_root(), prev_root.user_root());
    assert_ne!(root.kernel_root(), prev_root.kernel_root());
    assert_eq!(prover.values(ProvableNamespace::User).len(), 3);
    assert_eq!(prover.values(ProvableNamespace::Kernel).len(), 2);
}

/// What the workaround is for: NOMT 1.0.5 panics committing a session whose only value change
/// is a delete of an absent key into an empty database (an underflow in
/// `beatree/ops/update/leaf_stage.rs`, `filter_leaves_changeset`). If this test fails, a NOMT
/// upgrade fixed it: review the workaround (`test_prover::to_nomt_accesses`, and `selendra-db`'s
/// `to_nomt_accesses`).
#[test]
fn nomt_still_panics_on_deleting_an_absent_key_from_an_empty_database() {
    use ::nomt::{KeyReadWrite, SessionParams};
    let dir = tempfile::tempdir().unwrap();
    let nomt = super::test_prover::open_nomt(dir.path());
    // The panic is on NOMT's `beatree-sync` thread (which prints it) and resumed in `commit`.
    let outcome = catch_quietly(|| {
        let session = nomt.begin_session(SessionParams::default());
        let finished = session
            .finish(vec![([7; 32], KeyReadWrite::Write(None))])
            .unwrap();
        finished.commit(&nomt)
    });
    assert!(outcome.is_err(), "NOMT no longer panics: {outcome:?}");
}

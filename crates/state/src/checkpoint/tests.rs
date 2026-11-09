//! `StateCheckpoint` tests against the test storage: the prover/verifier replay, the
//! revertable cache, first reads, invalid witnesses and accessory state.

use borsh::BorshSerialize;
use proptest::collection::vec as prop_vec;
use proptest::prelude::{Strategy, any};
use proptest::prop_assert;
use sha2::Sha256;

use super::*;
use crate::test_state::{InMemoryState, UnwrapInfallible};
use crate::test_storage::TestStorage;
use crate::test_utils::{
    Harness, Model, Op, accessory_map, borsh_roundtrip, catch_quietly, hints, kernel_map, map, run,
    value,
};
use crate::{ArrayWitness, BorshCodec, InvalidWitness, NodeLeaf, Prefix, StateValue, Witness};

// -------------------------------------------------------------------------------------------
// Replay: the verifier, fed only the prover's witness, must compute exactly what the prover did.

fn model_of(storage: &TestStorage) -> Model {
    let committed = storage.committed();
    let state = InMemoryState {
        user: committed.user.clone(),
        kernel: committed.kernel.clone(),
        accessory: Default::default(),
    };
    Model {
        committed: state.clone(),
        pending: state,
    }
}

/// Random operations (with commits and discards) run through a prover checkpoint over a
/// random genesis state, then are replayed through a verifier checkpoint that only has the
/// prover's witness: the results, the state accesses, the accessory writes and the new root
/// must be identical, the witness fully consumed, and the result must match a plain model.
#[test_strategy::proptest]
fn verifier_replays_the_prover(
    #[strategy(prop_vec(any::<Op>(), 0..16))] genesis: Vec<Op>,
    #[strategy(prop_vec(any::<Op>(), 0..48))] ops: Vec<Op>,
) {
    let storage = TestStorage::default().commit_with(|state| {
        run(&genesis, state);
    });
    let prev_root = storage.root();

    let mut model = model_of(&storage);
    let expected = run(&ops, &mut model);
    model.commit();

    let mut prover = StateCheckpoint::new(storage.clone());
    let results = run(&ops, &mut prover);
    assert_eq!(results, expected);
    let (accesses, accessory, witness) = prover.freeze();
    let (root, update) = storage
        .compute_state_update(accesses.clone(), &witness, prev_root)
        .unwrap();

    let witness = borsh_roundtrip(&witness);
    let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
    assert_eq!(run(&ops, &mut verifier), results);
    let (v_accesses, v_accessory, v_witness) = verifier.freeze();
    assert_eq!(v_accesses, accesses);
    let accessory = accessory.freeze();
    assert_eq!(v_accessory.freeze(), accessory);
    let (v_root, _) = TestStorage::Verifier
        .compute_state_update(v_accesses, &v_witness, prev_root)
        .unwrap();
    assert_eq!(v_root, root);
    assert_eq!(v_witness.ensure_consumed(), Ok(()));

    // The committed state is the model's.
    let committed = storage.materialize_changes(update);
    assert_eq!(committed.root(), root);
    assert_eq!(committed.committed().user, model.committed.user);
    assert_eq!(committed.committed().kernel, model.committed.kernel);
    let model_accessory: Vec<_> = model.pending.accessory.into_iter().collect();
    let written: Vec<_> = accessory
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect();
    assert_eq!(written, model_accessory);
}

/// Every hint the verifier consumes must be verified. Prover and verifier share the cache, so
/// a cache that stopped recording a class of first reads (kernel reads, size queries, ...) in
/// `StateAccesses` would still pass the honest replay above; this catches it. Without
/// discards (whose reads are knowingly unverified, see `discarded_reads_are_not_verified`),
/// changing one byte of any one hint of an honest witness must make the verifier panic
/// (invalid witness) or the state update fail: strict decoding gives a changed hint a
/// different value or none, a changed read no longer matches the previous state, and a
/// changed proof hint no longer matches the previous root.
#[test_strategy::proptest(cases = 128)]
fn every_hint_is_verified(
    #[strategy(prop_vec(any::<Op>(), 0..16))] genesis: Vec<Op>,
    #[strategy(prop_vec(any::<Op>().prop_map(|op| match op {
        Op::Discard => Op::Commit,
        op => op,
    }), 1..32))]
    ops: Vec<Op>,
    position: usize,
    #[strategy(1u8..)] flip: u8,
) {
    let storage = TestStorage::default().commit_with(|state| {
        run(&genesis, state);
    });
    let prev_root = storage.root();
    let mut prover = StateCheckpoint::new(storage.clone());
    run(&ops, &mut prover);
    let (accesses, _, witness) = prover.freeze();
    storage
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
            let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
            run(&ops, &mut verifier);
            let (accesses, _, witness) = verifier.freeze();
            TestStorage::Verifier
                .compute_state_update(accesses, &witness, prev_root)
                .map(|(root, _)| root)
        });
        prop_assert!(
            !matches!(outcome, Ok(Ok(_))),
            "hint {index} of {} was changed (byte {at} ^ {flip:#04x}) and still accepted",
            hints.len()
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Revertable cache and first reads

fn storage_with_map(entries: &[(u8, u32)]) -> TestStorage {
    storage_with_maps(entries, &[])
}

fn storage_with_maps(user: &[(u8, u32)], kernel: &[(u8, u32)]) -> TestStorage {
    TestStorage::default().commit_with(|state| {
        let mut map = map();
        for (k, v) in user {
            map.set(k, v, state).unwrap_infallible();
        }
        let mut kernel_map = kernel_map();
        for (k, v) in kernel {
            kernel_map.set(k, v, state).unwrap_infallible();
        }
    })
}

fn leaf(v: u32) -> NodeLeaf {
    NodeLeaf::make_leaf::<Sha256>(&SlotValue::from(v.to_le_bytes().to_vec()))
}

#[test]
fn revertable_cache_commit_and_discard() {
    let mut state = StateCheckpoint::new(storage_with_map(&[(1, 10)]));
    let mut map = map();

    map.set(&1, &11, &mut state).unwrap_infallible();
    map.set(&2, &20, &mut state).unwrap_infallible();
    state.discard_revertable_storage_cache();
    assert_eq!(map.get(&1, &mut state).unwrap_infallible(), Some(10));
    assert_eq!(map.get(&2, &mut state).unwrap_infallible(), None);

    map.set(&1, &12, &mut state).unwrap_infallible();
    state.commit_revertable_storage_cache();
    map.set(&1, &13, &mut state).unwrap_infallible();
    state.discard_revertable_storage_cache();
    assert_eq!(map.get(&1, &mut state).unwrap_infallible(), Some(12));

    let (accesses, _, _) = state.freeze();
    // The reads after the first discard went to storage and were committed with the write of
    // 12; the read after the second discard was served from the cache. The discarded writes
    // are gone.
    assert_eq!(
        accesses.user.ordered_reads,
        [
            (
                map.slot_key(&1),
                Some(NodeLeaf::make_leaf::<Sha256>(&SlotValue::from(
                    10u32.to_le_bytes().to_vec()
                )))
            ),
            (map.slot_key(&2), None)
        ]
    );
    assert_eq!(
        accesses.user.ordered_writes,
        [(
            map.slot_key(&1),
            Some(SlotValue::from(12u32.to_le_bytes().to_vec()))
        )]
    );
}

#[test]
fn first_reads_are_recorded_once_and_in_order() {
    let storage = storage_with_maps(&[(1, 10), (3, 30)], &[(5, 50)]);
    let mut state = StateCheckpoint::new(storage.clone());
    let map = map();
    let kernel = kernel_map();
    for k in [3, 1, 3, 2, 1] {
        map.get(&k, &mut state).unwrap_infallible();
    }
    // Kernel reads, one of them a size query only.
    kernel.get(&6, &mut state).unwrap_infallible();
    state.get_size(ProvableNamespace::Kernel, &kernel.slot_key(&5));
    kernel.get(&6, &mut state).unwrap_infallible();
    let reads = state.first_reads();
    let keys: Vec<_> = reads.user.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(keys, [map.slot_key(&3), map.slot_key(&1), map.slot_key(&2)]);
    let keys: Vec<_> = reads.kernel.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(keys, [kernel.slot_key(&6), kernel.slot_key(&5)]);
    assert_eq!(reads.user[2].1, None);
    assert_eq!(reads.user[0].1.as_ref().unwrap().size(), 4);

    state.commit_revertable_storage_cache();
    assert_eq!(state.first_reads(), FirstTimeReads::default());
    map.get(&4, &mut state).unwrap_infallible();
    map.get(&1, &mut state).unwrap_infallible();
    assert_eq!(state.first_reads().user.len(), 1);

    let (accesses, _, witness) = state.freeze();
    let keys: Vec<_> = accesses
        .user
        .ordered_reads
        .iter()
        .map(|(k, _)| k.clone())
        .collect();
    assert_eq!(
        keys,
        [
            map.slot_key(&3),
            map.slot_key(&1),
            map.slot_key(&2),
            map.slot_key(&4)
        ]
    );
    assert_eq!(accesses.user.ordered_reads[0].1, Some(leaf(30)));
    assert_eq!(
        accesses.kernel.ordered_reads,
        [
            (kernel.slot_key(&6), None),
            (kernel.slot_key(&5), Some(leaf(50)))
        ]
    );
    // One hint per first read.
    assert_eq!(witness.len(), 6);
    storage
        .compute_state_update(accesses, &witness, storage.root())
        .unwrap();
}

#[test]
fn warm_up_reads_are_verified_but_add_no_hints() {
    let storage = storage_with_map(&[(1, 10)]);
    let mut first = StateCheckpoint::new(storage.clone());
    let map = map();
    map.get(&1, &mut first).unwrap_infallible();
    let reads = first.first_reads();

    let mut second = StateCheckpoint::new(storage.clone());
    second.add_read_if_not_present(reads.clone());
    assert_eq!(map.get(&1, &mut second).unwrap_infallible(), Some(10));
    let (accesses, _, witness) = second.freeze();
    assert!(witness.is_empty());
    assert_eq!(accesses.user.ordered_reads.len(), 1);
    storage
        .compute_state_update(accesses, &witness, storage.root())
        .unwrap();

    // A warm-up read that does not match the state fails the state update.
    let mut wrong = reads;
    wrong.user[0].1 = Some(NodeLeafAndMaybeValue::new_read::<Sha256>(SlotValue::from(
        vec![0; 4],
    )));
    let mut third = StateCheckpoint::new(storage.clone());
    third.add_read_if_not_present(wrong);
    let (accesses, _, witness) = third.freeze();
    assert!(
        storage
            .compute_state_update(accesses, &witness, storage.root())
            .is_err()
    );
}

#[test]
fn is_value_cached() {
    let mut state = StateCheckpoint::new(storage_with_map(&[(1, 10)]));
    let mut map = map();
    let key = map.slot_key(&1);
    assert_eq!(
        state.is_value_cached(Namespace::User, &key),
        IsValueCached::No
    );
    map.get(&1, &mut state).unwrap_infallible();
    assert_eq!(
        state.is_value_cached(Namespace::User, &key),
        IsValueCached::Yes(AccessSize::Read(4))
    );
    map.delete(&1, &mut state).unwrap_infallible();
    assert_eq!(
        state.is_value_cached(Namespace::User, &key),
        IsValueCached::Yes(AccessSize::Write(0))
    );
    assert_eq!(
        state.is_value_cached(Namespace::Kernel, &key),
        IsValueCached::No
    );
    accessory_map().set(&1, &5, &mut state).unwrap_infallible();
    let accessory_key = accessory_map().slot_key(&1);
    assert_eq!(
        state.is_value_cached(Namespace::Accessory, &accessory_key),
        IsValueCached::Yes(AccessSize::Write(4))
    );
}

// ---------------------------------------------------------------------------------------------
// The size-then-value protocol and invalid witnesses

/// A size query puts only the leaf in the witness; a later full read adds the value, which the
/// verifier checks against the leaf.
#[test]
fn size_then_value_reads() {
    let storage = storage_with_map(&[(1, 10)]);
    let map = map();
    let key = map.slot_key(&1);
    let mut prover = StateCheckpoint::new(storage.clone());
    assert_eq!(prover.get_size(ProvableNamespace::User, &key), Some(4));
    assert_eq!(prover.get_size(ProvableNamespace::User, &key), Some(4));
    assert_eq!(map.get(&1, &mut prover).unwrap_infallible(), Some(10));
    assert_eq!(map.get(&1, &mut prover).unwrap_infallible(), Some(10));
    let (_, _, witness) = prover.freeze();
    let witness = borsh_roundtrip(&witness);
    assert_eq!(witness.len(), 2);

    let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
    assert_eq!(verifier.get_size(ProvableNamespace::User, &key), Some(4));
    assert_eq!(map.get(&1, &mut verifier).unwrap_infallible(), Some(10));
    let (_, _, witness) = verifier.freeze();
    assert!(witness.is_empty());
}

#[test]
#[should_panic(expected = "does not match its leaf; the witness is invalid")]
fn a_value_that_does_not_match_its_leaf_is_an_invalid_witness() {
    let leaf = NodeLeaf::make_leaf::<Sha256>(&SlotValue::from(vec![1, 0, 0, 0]));
    let witness = ArrayWitness::default();
    witness.add_hint(&Some(leaf));
    witness.add_hint(&Some(SlotValue::from(vec![2, 0, 0, 0])));
    let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
    let key = map().slot_key(&1);
    assert_eq!(verifier.get_size(ProvableNamespace::User, &key), Some(4));
    let _ = map().get(&1, &mut verifier);
}

#[test]
#[should_panic(expected = "its leaf exists but the value is absent")]
fn an_absent_value_with_a_leaf_is_an_invalid_witness() {
    let leaf = NodeLeaf::make_leaf::<Sha256>(&SlotValue::from(vec![1, 0, 0, 0]));
    let witness = ArrayWitness::default();
    witness.add_hint(&Some(leaf));
    witness.add_hint(&None::<SlotValue>);
    let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
    let key = map().slot_key(&1);
    verifier.get_size(ProvableNamespace::User, &key);
    let _ = map().get(&1, &mut verifier);
}

#[test]
#[should_panic(expected = "invalid witness: no hint left")]
fn a_missing_hint_is_an_invalid_witness() {
    let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, Default::default());
    let _ = map().get(&1, &mut verifier);
}

/// The prover's witness for `reads` (one read: its hint, then the proof hint of the state
/// update) with the hint of the read replaced by `lie`.
fn witness_with_lie(
    storage: &TestStorage,
    reads: impl FnOnce(&mut StateCheckpoint<TestStorage>),
    lie: &impl BorshSerialize,
) -> ArrayWitness {
    let mut prover = StateCheckpoint::new(storage.clone());
    reads(&mut prover);
    let (accesses, _, witness) = prover.freeze();
    storage
        .compute_state_update(accesses, &witness, storage.root())
        .unwrap();
    let mut hints = hints(&witness);
    assert_eq!(hints.len(), 2);
    hints[0] = borsh::to_vec(lie).unwrap();
    ArrayWitness::from_hints(hints)
}

/// The prover's witness with the hint of the first read replaced.
fn tampered_witness(storage: &TestStorage) -> ArrayWitness {
    witness_with_lie(
        storage,
        |prover| {
            map().get(&1, prover).unwrap_infallible();
        },
        &Some(SlotValue::from(99u32.to_le_bytes().to_vec())),
    )
}

/// Freezes the verifier and asserts that the state update rejects its `namespace` read.
fn assert_read_rejected(
    verifier: StateCheckpoint<TestStorage>,
    namespace: ProvableNamespace,
    storage: &TestStorage,
) {
    let (accesses, _, witness) = verifier.freeze();
    let err = TestStorage::Verifier
        .compute_state_update(accesses, &witness, storage.root())
        .unwrap_err();
    assert!(
        err.to_string().contains(&format!(
            "in {namespace:?} does not match the previous state"
        )),
        "{err}"
    );
}

/// A lying leaf hint of a size query, in either namespace, is accepted at the read (the size
/// is unverified), then caught by the state update.
#[test]
fn a_lying_leaf_hint_fails_the_state_update() {
    let storage = storage_with_maps(&[(1, 10)], &[(1, 10)]);
    for namespace in [ProvableNamespace::User, ProvableNamespace::Kernel] {
        let key = match namespace {
            ProvableNamespace::User => map().slot_key(&1),
            ProvableNamespace::Kernel => kernel_map().slot_key(&1),
        };
        let lie = Some(NodeLeaf::make_leaf::<Sha256>(&SlotValue::from(vec![0; 8])));
        let witness = witness_with_lie(
            &storage,
            |prover| {
                assert_eq!(prover.get_size(namespace, &key), Some(4));
            },
            &lie,
        );
        let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
        assert_eq!(verifier.get_size(namespace, &key), Some(8));
        assert_read_rejected(verifier, namespace, &storage);
    }
}

/// Like `a_lying_hint_fails_the_state_update`, for a kernel read.
#[test]
fn a_lying_kernel_hint_fails_the_state_update() {
    let storage = storage_with_maps(&[], &[(1, 10)]);
    let witness = witness_with_lie(
        &storage,
        |prover| {
            kernel_map().get(&1, prover).unwrap_infallible();
        },
        &Some(SlotValue::from(99u32.to_le_bytes().to_vec())),
    );
    let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
    assert_eq!(
        kernel_map().get(&1, &mut verifier).unwrap_infallible(),
        Some(99)
    );
    assert_read_rejected(verifier, ProvableNamespace::Kernel, &storage);
}

/// So is a lying "absent" hint.
#[test]
fn a_lying_absent_hint_fails_the_state_update() {
    let storage = storage_with_maps(&[], &[(1, 10)]);
    let witness = witness_with_lie(
        &storage,
        |prover| {
            kernel_map().get(&1, prover).unwrap_infallible();
        },
        &None::<SlotValue>,
    );
    let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
    assert_eq!(
        kernel_map().get(&1, &mut verifier).unwrap_infallible(),
        None
    );
    assert_read_rejected(verifier, ProvableNamespace::Kernel, &storage);
}

/// A lying hint is accepted at the read (it is unverified), then caught by the state update.
#[test]
fn a_lying_hint_fails_the_state_update() {
    let storage = storage_with_map(&[(1, 10)]);
    let witness = tampered_witness(&storage);
    let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
    assert_eq!(map().get(&1, &mut verifier).unwrap_infallible(), Some(99));
    assert_read_rejected(verifier, ProvableNamespace::User, &storage);
}

#[test]
#[should_panic(expected = "state update computation failed")]
fn materialize_update_panics_on_an_invalid_witness() {
    let storage = storage_with_map(&[(1, 10)]);
    let witness = tampered_witness(&storage);
    let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
    map().get(&1, &mut verifier).unwrap_infallible();
    let _ = verifier.materialize_update(storage.root());
}

/// Pins the hazard documented on `discard_revertable_storage_cache`: a discarded read is never
/// verified, so a lying hint for it goes unnoticed.
#[test]
fn discarded_reads_are_not_verified() {
    let storage = storage_with_map(&[(1, 10)]);
    let witness = tampered_witness(&storage);
    let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
    assert_eq!(map().get(&1, &mut verifier).unwrap_infallible(), Some(99));
    verifier.discard_revertable_storage_cache();
    let (accesses, _, witness) = verifier.freeze();
    assert!(accesses.user.ordered_reads.is_empty());
    // No accesses left, so no proof hint is consumed and the root is unchanged.
    let (root, _) = TestStorage::Verifier
        .compute_state_update(accesses, &witness, storage.root())
        .unwrap();
    assert_eq!(root, storage.root());
    assert_eq!(witness.ensure_consumed(), Err(InvalidWitness::NotConsumed));
}

#[test]
fn materialize_update_matches_freeze_and_compute() {
    let storage = storage_with_map(&[(1, 10)]);
    let ops = [
        Op::MapGet(1),
        Op::MapSet(2, 5),
        Op::KernelSet(0, 1),
        Op::AccessorySet(0, 1),
    ];
    let mut a = StateCheckpoint::new(storage.clone());
    run(&ops, &mut a);
    let (root, _update, accessory, witness, returned) = a.materialize_update(storage.root());
    assert_eq!(returned.root(), storage.root());
    assert_eq!(accessory.freeze().len(), 1);

    let mut b = StateCheckpoint::new(storage.clone());
    run(&ops, &mut b);
    let (accesses, _, witness_b) = b.freeze();
    let (root_b, _) = storage
        .compute_state_update(accesses, &witness_b, storage.root())
        .unwrap();
    assert_eq!(root, root_b);
    assert_eq!(
        borsh::to_vec(&witness).unwrap(),
        borsh::to_vec(&witness_b).unwrap()
    );
}

// ---------------------------------------------------------------------------------------------
// Accessory state

/// Upstream's checkpoint dropped the pending write on an accessory delete, so deleting a value
/// that was already committed did nothing.
#[test]
fn accessory_delete_removes_a_committed_value() {
    let storage = TestStorage::default().commit_with(|state| {
        accessory_map().set(&1, &10, state).unwrap_infallible();
    });
    let key = accessory_map().slot_key(&1);
    assert!(storage.committed().accessory.contains_key(&key));
    let storage = storage.commit_with(|state| {
        accessory_map().delete(&1, state).unwrap_infallible();
    });
    assert!(storage.committed().accessory.is_empty());
}

#[cfg(feature = "native")]
#[test]
fn accessory_state_is_readable_natively() {
    let storage = TestStorage::default().commit_with(|state| {
        let mut map = accessory_map();
        map.set(&1, &10, state).unwrap_infallible();
        map.set(&2, &20, state).unwrap_infallible();
    });
    let mut checkpoint = StateCheckpoint::new(storage);
    let mut map = accessory_map();
    {
        let mut accessory = checkpoint.accessory_state();
        assert_eq!(map.get(&1, &mut accessory).unwrap_infallible(), Some(10));
        map.set(&1, &11, &mut accessory).unwrap_infallible();
        assert_eq!(map.remove(&2, &mut accessory).unwrap_infallible(), Some(20));
        assert_eq!(map.get(&1, &mut accessory).unwrap_infallible(), Some(11));
        assert_eq!(map.get(&2, &mut accessory).unwrap_infallible(), None);
    }

    let mut delta = checkpoint.take_accessory_delta();
    assert_eq!(map.get(&1, &mut delta).unwrap_infallible(), Some(11));
    map.set(&3, &30, &mut delta).unwrap_infallible();
    checkpoint.set_accessory_delta(delta);
    assert_eq!(
        map.get(&3, &mut checkpoint.accessory_state())
            .unwrap_infallible(),
        Some(30)
    );

    let (_, mut delta, _) = checkpoint.freeze();
    assert_eq!(map.get(&2, &mut delta).unwrap_infallible(), None);
    map.delete(&3, &mut delta).unwrap_infallible();
    let writes = delta.freeze();
    let keys: Vec<_> = writes
        .iter()
        .map(|(k, v)| (k.clone(), v.is_some()))
        .collect();
    assert_eq!(
        keys,
        [
            (map.slot_key(&1), true),
            (map.slot_key(&2), false),
            (map.slot_key(&3), false)
        ]
    );
}

/// Historical reads go to the storage directly, with a throwaway witness (see
/// `NativeStorage`): they leave the checkpoint's accesses, witness and later reads untouched.
#[cfg(feature = "native")]
#[test]
fn historical_reads_bypass_the_checkpoint() {
    use crate::NativeStorage;

    let storage = storage_with_map(&[(1, 10)]);
    let key = map().slot_key(&1);
    let mut checkpoint = StateCheckpoint::new(storage.clone());
    let throwaway = ArrayWitness::default();
    let version = Some(checkpoint.storage().latest_version());
    let old = checkpoint
        .storage()
        .get_historical::<User>(&key, version, &throwaway)
        .unwrap();
    assert_eq!(old, Some(SlotValue::from(10u32.to_le_bytes().to_vec())));
    checkpoint
        .storage()
        .get_leaf_historical::<User>(&key, version, &throwaway)
        .unwrap();
    assert_eq!(
        checkpoint.is_value_cached(Namespace::User, &key),
        IsValueCached::No
    );
    assert_eq!(checkpoint.first_reads(), FirstTimeReads::default());

    // A later read is an ordinary first read with its own hint.
    assert_eq!(map().get(&1, &mut checkpoint).unwrap_infallible(), Some(10));
    let (accesses, _, witness) = checkpoint.freeze();
    assert_eq!(accesses.user.ordered_reads, [(key, Some(leaf(10)))]);
    assert_eq!(witness.len(), 1);
    storage
        .compute_state_update(accesses, &witness, storage.root())
        .unwrap();
}

#[test]
fn debug_does_not_dump_state() {
    let checkpoint = StateCheckpoint::new(TestStorage::default());
    assert_eq!(format!("{checkpoint:?}"), "StateCheckpoint { .. }");
}

// ---------------------------------------------------------------------------------------------
// Upstream scenarios (`sov-modules-api/src/state/accessors/tests.rs`)

/// Sizes and values read for the first time, after a write, and in both orders.
fn upstream_test_values<St: Storage>(state: &mut StateCheckpoint<St>) {
    const NS: Namespace = Namespace::User;
    const PNS: ProvableNamespace = ProvableNamespace::User;

    // Overriding an empty value.
    let mut value = StateValue::<u64>::with_codec(Prefix::new(1, 0), BorshCodec);
    let key = value.slot_key();
    assert_eq!(state.is_value_cached(NS, &key), IsValueCached::No);
    assert_eq!(state.get_size(PNS, &key), None);
    assert_eq!(value.get(state).unwrap_infallible(), None);
    value.set(&77, state).unwrap_infallible();
    assert_eq!(
        state.is_value_cached(NS, &key),
        IsValueCached::Yes(AccessSize::Write(8))
    );
    assert_eq!(state.get_size(PNS, &key), Some(8));
    assert_eq!(value.get(state).unwrap_infallible(), Some(77));

    // Overriding a pre-set value, size first.
    let mut value = StateValue::<u64>::with_codec(Prefix::new(10, 0), BorshCodec);
    let key = value.slot_key();
    assert_eq!(state.is_value_cached(NS, &key), IsValueCached::No);
    assert_eq!(state.get_size(PNS, &key), Some(8));
    assert_eq!(
        state.is_value_cached(NS, &key),
        IsValueCached::Yes(AccessSize::Read(8))
    );
    assert_eq!(value.get(state).unwrap_infallible(), Some(22));
    value.set(&66, state).unwrap_infallible();
    assert_eq!(value.get(state).unwrap_infallible(), Some(66));

    // Reading first, then the size.
    let value = StateValue::<u64>::with_codec(Prefix::new(11, 0), BorshCodec);
    let key = value.slot_key();
    assert_eq!(value.get(state).unwrap_infallible(), Some(99));
    assert_eq!(
        state.is_value_cached(NS, &key),
        IsValueCached::Yes(AccessSize::Read(8))
    );
    assert_eq!(state.get_size(PNS, &key), Some(8));
}

#[test]
fn witness_generation() {
    let storage = TestStorage::default().commit_with(|state| {
        StateValue::<u64>::with_codec(Prefix::new(10, 0), BorshCodec)
            .set(&22, state)
            .unwrap_infallible();
        StateValue::<u64>::with_codec(Prefix::new(11, 0), BorshCodec)
            .set(&99, state)
            .unwrap_infallible();
    });
    let root = storage.root();

    let mut prover = StateCheckpoint::new(storage.clone());
    upstream_test_values(&mut prover);
    let (accesses, _, witness) = prover.freeze();
    let (prover_root, _) = storage
        .compute_state_update(accesses, &witness, root)
        .unwrap();

    let mut verifier = StateCheckpoint::with_witness(TestStorage::Verifier, witness);
    upstream_test_values(&mut verifier);
    let (accesses, _, witness) = verifier.freeze();
    let (verifier_root, _) = TestStorage::Verifier
        .compute_state_update(accesses, &witness, root)
        .unwrap();
    assert_eq!(verifier_root, prover_root);
    assert!(witness.is_empty());
}

#[test]
fn discarded_accesses_are_not_frozen() {
    let storage = storage_with_map(&[(1, 10)]);
    let mut state = StateCheckpoint::new(storage);
    map().get(&1, &mut state).unwrap_infallible();
    value().set(&99, &mut state).unwrap_infallible();
    state.discard_revertable_storage_cache();
    let (accesses, _, _) = state.freeze();
    assert_eq!(accesses, StateAccesses::default());
}

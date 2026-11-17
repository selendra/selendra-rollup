//! Checkpoint versions against the test storage: the bootstrap and refresh reads are first
//! reads of the checkpoint, replayed by the verifier in the same order, verified against the
//! root, and never revertable.

use proptest::collection::vec as prop_vec;
use proptest::prelude::any;
use selendra_interface::common::{RollupHeight, SlotNumber, VisibleSlotNumber};

use super::*;
use crate::namespaces::ProvableNamespace;
use crate::test_state::UnwrapInfallible;
use crate::test_storage::TestStorage;
use crate::test_utils::{Op, borsh_roundtrip, hints, run};
use crate::{
    ArrayWitness, BorshCodec, KernelStateValue, Prefix, StateAccesses, StateValue, Witness,
};

// -------------------------------------------------------------------------------------------
// The kernel of these tests

/// Where the kernel keeps the visible slot number.
fn visible() -> KernelStateValue<u64> {
    KernelStateValue::with_codec(Prefix::new(9, 0), BorshCodec)
}

/// Where the kernel keeps the rollup height.
fn height() -> KernelStateValue<u64> {
    KernelStateValue::with_codec(Prefix::new(9, 1), BorshCodec)
}

/// A user value the kernel also reads (upstream's chain-state reads the rollup height from user
/// state).
fn user_height() -> StateValue<u64> {
    StateValue::with_codec(Prefix::new(9, 2), BorshCodec)
}

/// The kernel's closure: both versions from kernel state (absent before the first block:
/// genesis), and a user read.
fn read_versions<St: Storage>(reader: &mut BootstrapReader<'_, St>) -> CheckpointVersions {
    let Ok(visible) = visible().get(reader);
    let Ok(height) = height().get(reader);
    let Ok(_) = user_height().get(reader);
    CheckpointVersions {
        visible_slot_number: VisibleSlotNumber::new_dangerous(visible.unwrap_or(0)),
        rollup_height: RollupHeight::new(height.unwrap_or(0)),
    }
}

fn versions(visible: u64, height: u64) -> CheckpointVersions {
    CheckpointVersions {
        visible_slot_number: VisibleSlotNumber::new_dangerous(visible),
        rollup_height: RollupHeight::new(height),
    }
}

/// The kernel writes the versions of the next block.
fn write_versions(state: &mut StateCheckpoint<TestStorage>, new: CheckpointVersions) {
    visible()
        .set(&new.visible_slot_number.get(), state)
        .unwrap_infallible();
    height()
        .set(&new.rollup_height.get(), state)
        .unwrap_infallible();
}

/// A storage with the given versions (each absent if `None`) and `genesis` run on it.
fn storage_with(visible_height: Option<(u64, u64)>, genesis: &[Op]) -> TestStorage {
    TestStorage::default().commit_with(|state| {
        if let Some((v, h)) = visible_height {
            write_versions(state, versions(v, h));
            user_height().set(&h, state).unwrap_infallible();
            // So that a discard in `genesis` keeps them.
            state.commit_revertable_storage_cache();
        }
        run(genesis, state);
    })
}

fn assert_versions(state: &impl VersionReader, expected: CheckpointVersions) {
    assert_eq!(
        state.current_visible_slot_number(),
        expected.visible_slot_number
    );
    assert_eq!(
        state.max_allowed_slot_number_to_access(),
        expected.visible_slot_number.as_true()
    );
    assert_eq!(state.rollup_height_to_access(), expected.rollup_height);
}

fn keys(reads: &[(SlotKey, Option<crate::NodeLeaf>)]) -> Vec<SlotKey> {
    reads.iter().map(|(key, _)| key.clone()).collect()
}

/// The first entries of the ordered reads are exactly the bootstrap keys, in order.
fn assert_bootstrap_reads_first(accesses: &StateAccesses) {
    let kernel = keys(&accesses.kernel.ordered_reads);
    assert_eq!(kernel[..2], [visible().slot_key(), height().slot_key()]);
    let user = keys(&accesses.user.ordered_reads);
    assert_eq!(user[..1], [user_height().slot_key()]);
}

// -------------------------------------------------------------------------------------------
// Replay

/// Prover `new_with`, random operations (commits and discards included), freeze; then the
/// verifier's `new_with` from the witness alone: the same versions, results, accesses and root,
/// and the bootstrap reads come first.
#[test_strategy::proptest]
fn versions_replay(
    #[strategy(proptest::option::of((any::<u64>(), any::<u64>())))] stored: Option<(u64, u64)>,
    #[strategy(prop_vec(any::<Op>(), 0..16))] genesis: Vec<Op>,
    #[strategy(prop_vec(any::<Op>(), 0..32))] ops: Vec<Op>,
) {
    let storage = storage_with(stored, &genesis);
    let expected = stored.map_or(CheckpointVersions::GENESIS, |(v, h)| versions(v, h));
    let prev_root = storage.root();

    let mut prover = StateCheckpoint::new_with(storage.clone(), Default::default(), read_versions);
    assert_versions(&prover, expected);
    let results = run(&ops, &mut prover);
    assert_versions(&prover, expected);
    let (accesses, _, witness) = prover.freeze();
    assert_bootstrap_reads_first(&accesses);
    let (root, _) = storage
        .compute_state_update(accesses.clone(), &witness, prev_root)
        .unwrap();

    let witness = borsh_roundtrip(&witness);
    let mut verifier = StateCheckpoint::new_with(TestStorage::Verifier, witness, read_versions);
    assert_versions(&verifier, expected);
    assert_eq!(run(&ops, &mut verifier), results);
    let (v_accesses, _, v_witness) = verifier.freeze();
    assert_eq!(v_accesses, accesses);
    let (v_root, _) = TestStorage::Verifier
        .compute_state_update(v_accesses, &v_witness, prev_root)
        .unwrap();
    assert_eq!(v_root, root);
    assert_eq!(v_witness.ensure_consumed(), Ok(()));
}

/// The kernel writes the next versions, then refreshes: the checkpoint executes at the new
/// versions from then on, and the verifier replays the same versions, reads and root.
#[test]
fn refresh_reads_the_new_versions() {
    let storage = storage_with(Some((3, 2)), &[Op::MapSet(1, 10)]);
    let prev_root = storage.root();
    let block = |state: &mut StateCheckpoint<TestStorage>| {
        assert_versions(state, versions(3, 2));
        run(&[Op::MapGet(1), Op::MapSet(2, 20)], state);
        write_versions(state, versions(5, 3));
        // Still at the old versions until the refresh.
        assert_versions(state, versions(3, 2));
        state.refresh_versions(read_versions);
        assert_versions(state, versions(5, 3));
        assert_eq!(state.versions(), versions(5, 3));
        assert_eq!(
            state.max_allowed_slot_number_to_access(),
            SlotNumber::new(5)
        );
        run(&[Op::MapGet(2), Op::KernelGet(1)], state)
    };

    let mut prover = StateCheckpoint::new_with(storage.clone(), Default::default(), read_versions);
    let results = block(&mut prover);
    let (accesses, _, witness) = prover.freeze();
    assert_bootstrap_reads_first(&accesses);
    let (root, _) = storage
        .compute_state_update(accesses.clone(), &witness, prev_root)
        .unwrap();

    let mut verifier = StateCheckpoint::new_with(
        TestStorage::Verifier,
        borsh_roundtrip(&witness),
        read_versions,
    );
    assert_eq!(block(&mut verifier), results);
    let (v_accesses, _, v_witness) = verifier.freeze();
    assert_eq!(v_accesses, accesses);
    let (v_root, _) = TestStorage::Verifier
        .compute_state_update(v_accesses, &v_witness, prev_root)
        .unwrap();
    assert_eq!(v_root, root);
    assert_eq!(v_witness.ensure_consumed(), Ok(()));
}

/// Before the first block the kernel values are absent: the closure gives the genesis
/// versions, and the absent reads are recorded and verified like any other. The test-only
/// constructors start at genesis too.
#[test]
fn absent_kernel_values_give_genesis_versions() {
    let storage = TestStorage::default();
    let prover = StateCheckpoint::new_with(storage.clone(), Default::default(), read_versions);
    assert_versions(&prover, CheckpointVersions::GENESIS);
    assert_eq!(
        prover.max_allowed_slot_number_to_access(),
        SlotNumber::GENESIS
    );
    let (accesses, _, witness) = prover.freeze();
    assert_eq!(
        accesses.kernel.ordered_reads,
        [(visible().slot_key(), None), (height().slot_key(), None)]
    );
    assert_eq!(
        accesses.user.ordered_reads,
        [(user_height().slot_key(), None)]
    );
    storage
        .compute_state_update(accesses, &witness, storage.root())
        .unwrap();

    assert_versions(
        &StateCheckpoint::new(storage.clone()),
        CheckpointVersions::GENESIS,
    );
    assert_versions(
        &StateCheckpoint::with_witness(TestStorage::Verifier, Default::default()),
        CheckpointVersions::GENESIS,
    );
}

/// The prover's witness with the hint of its first read (the visible slot number) replaced by
/// `lie`.
fn witness_with_lying_version(storage: &TestStorage, lie: u64) -> ArrayWitness {
    let prover = StateCheckpoint::new_with(storage.clone(), Default::default(), read_versions);
    let (accesses, _, witness) = prover.freeze();
    storage
        .compute_state_update(accesses, &witness, storage.root())
        .unwrap();
    let mut hints = hints(&witness);
    hints[0] = borsh::to_vec(&Some(SlotValue::from(borsh::to_vec(&lie).unwrap()))).unwrap();
    ArrayWitness::from_hints(hints)
}

/// Asserts that the state update rejects the verifier's kernel reads.
fn assert_kernel_read_rejected(verifier: StateCheckpoint<TestStorage>, storage: &TestStorage) {
    let (accesses, _, witness) = verifier.freeze();
    let err = TestStorage::Verifier
        .compute_state_update(accesses, &witness, storage.root())
        .unwrap_err();
    assert!(
        err.to_string().contains(&format!(
            "in {:?} does not match the previous state",
            ProvableNamespace::Kernel
        )),
        "{err}"
    );
}

/// A lying hint for a version read is accepted at the read (the verifier executes at the lie),
/// then caught by the state update.
#[test]
fn a_lying_version_hint_fails_the_state_update() {
    let storage = storage_with(Some((3, 2)), &[]);
    let witness = witness_with_lying_version(&storage, 99);
    let verifier = StateCheckpoint::new_with(TestStorage::Verifier, witness, read_versions);
    assert_versions(&verifier, versions(99, 2));
    assert_kernel_read_rejected(verifier, &storage);
}

#[test]
fn debug_does_not_dump_state() {
    let mut checkpoint = StateCheckpoint::new(TestStorage::default());
    checkpoint.refresh_versions(|reader| {
        assert_eq!(format!("{reader:?}"), "BootstrapReader { .. }");
        CheckpointVersions::GENESIS
    });
}

// -------------------------------------------------------------------------------------------
// Regressions of upstream's bootstrap bugs

/// P5-09: upstream's bootstrap reads went into the revertable part of the cache, so a later
/// `discard_revertable_storage_cache` dropped them from verification while the versions read
/// from them stayed: a prover could lie about the versions. Here they are committed, so they
/// survive the discard and the lie is caught.
#[test]
fn bootstrap_reads_survive_discard() {
    let storage = storage_with(Some((3, 2)), &[]);
    let mut prover = StateCheckpoint::new_with(storage.clone(), Default::default(), read_versions);
    prover.discard_revertable_storage_cache();
    let (accesses, _, _) = prover.freeze();
    assert_eq!(
        keys(&accesses.kernel.ordered_reads),
        [visible().slot_key(), height().slot_key()]
    );
    assert_eq!(
        keys(&accesses.user.ordered_reads),
        [user_height().slot_key()]
    );

    let witness = witness_with_lying_version(&storage, 99);
    let mut verifier = StateCheckpoint::new_with(TestStorage::Verifier, witness, read_versions);
    assert_versions(&verifier, versions(99, 2));
    verifier.discard_revertable_storage_cache();
    assert_kernel_read_rejected(verifier, &storage);
}

/// P5-09, for a refresh: its reads, and the writes the new versions were read from, survive a
/// later discard.
#[test]
fn refresh_reads_survive_discard() {
    let storage = storage_with(Some((3, 2)), &[]);
    let next = KernelStateValue::<u64>::with_codec(Prefix::new(9, 3), BorshCodec);
    let mut prover = StateCheckpoint::new(storage.clone());
    write_versions(&mut prover, versions(5, 3));
    prover.refresh_versions(|reader| {
        let Ok(_) = next.get(reader);
        read_versions(reader)
    });
    prover.discard_revertable_storage_cache();
    assert_versions(&prover, versions(5, 3));
    let (accesses, _, _) = prover.freeze();
    // The versions were read from the cached writes; `next` and the user value from storage.
    assert_eq!(keys(&accesses.kernel.ordered_reads), [next.slot_key()]);
    assert_eq!(
        keys(&accesses.user.ordered_reads),
        [user_height().slot_key()]
    );
    let written: Vec<_> = accesses
        .kernel
        .ordered_writes
        .iter()
        .map(|(key, _)| key.clone())
        .collect();
    assert_eq!(written, [visible().slot_key(), height().slot_key()]);
}

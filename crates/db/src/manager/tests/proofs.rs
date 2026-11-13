//! Proofs and witnesses of unfinalized state: storages on uncommitted blocks prove their own
//! newest state, and the guest verifier replays their witnesses.

use std::collections::{BTreeMap, HashMap};

use proptest::collection::vec as prop_vec;
use proptest::prelude::any;
use proptest::prop_assert_eq;
use selendra_state::test_utils::{
    InMemoryState, KERNEL_MAP, MAP, Model, Op, VALUE, VEC, accessory_map, borsh_roundtrip,
    kernel_map, map, run,
};
use selendra_state::{NomtVerifierStorage, Prefix, StateCheckpoint, StateUpdate, Witness};

use super::*;
use crate::harness::{assert_proof_consistent, header_slot_info};
use crate::ledger::SlotContents;
use crate::{WitnessMode, harness::TestStorageManager};

type Verifier = NomtVerifierStorage<Spec>;

/// Upstream `get_with_proof_reads_overlay_latest_user_and_accessory_state_across_multiple_
/// blocks` (UPS:1184): three blocks saved and none finalized; the state after each proves its
/// own newest values, which are not committed: proofs of unfinalized state, against the root
/// after the block, consistent with the accessory and historical reads at that version.
#[test]
fn get_with_proof_reads_overlay_latest_user_and_accessory_state_across_multiple_blocks() {
    let mut m = Manager::new();
    let user_key = SlotKey::try_from_bytes(b"user-counter").unwrap();
    let accessory_key = SlotKey::try_from_bytes(b"accessory-counter").unwrap();
    let mut prev_root = Root::PRE_GENESIS;
    for height in 1..=3u8 {
        let hdr = TestHeader::linear(height.into());
        let value = |offset: u8| SlotValue::from(vec![height.checked_add(offset).unwrap()]);
        let root = write_block(
            &mut m,
            &hdr,
            &[(user_key.clone(), Some(value(0)))],
            &[(user_key.clone(), Some(value(100)))],
            &[(accessory_key.clone(), Some(value(200)))],
        );
        assert_ne!(root, prev_root);
        let (overlay, _) = m.create_state_after(&hdr).unwrap();
        let (fresh, _) = m.create_state_after(&hdr).unwrap();
        let proven = assert_proof_consistent(
            &overlay,
            &fresh,
            &user_key,
            Some(&value(0)),
            (&accessory_key, Some(&value(200))),
        );
        assert_eq!(proven, (SlotNumber::new(u64::from(height) - 1), root));
        assert_eq!(m.latest_version(), None, "nothing is committed");
        prev_root = root;
    }
}

/// Historical reads below the tip of a storage on uncommitted blocks skip its newer snapshots
/// (`AccessoryDb::get_value_bound` and rockbound's `get_historical_borrowed`): with nothing
/// committed (its snapshots from version 0 on), and with the first block committed (its
/// snapshots after the base version 0). Reads at the tip cannot tell: every snapshot is at or
/// below it.
#[test]
fn historical_reads_below_tip_of_storage_on_uncommitted_blocks() {
    let k = SlotKey::try_from_bytes(b"counter").unwrap();
    let byte = |b: u8| Some(SlotValue::from(vec![b]));
    for finalize_first in [false, true] {
        let mut m = Manager::new();
        let chain = linear(3);
        for hdr in &chain {
            let h = u8::try_from(hdr.height).unwrap();
            write_block(
                &mut m,
                hdr,
                &[(k.clone(), byte(h))],
                &[],
                &[(k.clone(), byte(h + 200))],
            );
        }
        if finalize_first {
            m.finalize(&chain[0]).unwrap();
        }
        let (storage, _) = m.create_state_after(&chain[2]).unwrap();
        let witness = Default::default();
        for v in 0..3u8 {
            let version = Some(SlotNumber::new(v.into()));
            assert_eq!(
                storage
                    .get_historical::<User>(&k, version, &witness)
                    .unwrap(),
                byte(v + 1),
                "user at {v}, first block committed: {finalize_first}"
            );
            assert_eq!(
                storage.get_accessory_historical(&k, version).unwrap(),
                byte(v + 201),
                "accessory at {v}, first block committed: {finalize_first}"
            );
        }
    }
}

/// The prefixes of the user containers [`Op`]s use.
const USER_PREFIXES: [Prefix; 3] = [VALUE, MAP, VEC];

/// Every key [`Op`]s can touch.
fn all_keys() -> Vec<SlotKey> {
    let mut keys = vec![SlotKey::singleton(&VALUE), SlotKey::singleton(&VEC)];
    for k in 0u8..6 {
        keys.push(map().slot_key(&k));
        keys.push(kernel_map().slot_key(&k));
        keys.push(SlotKey::from_parts(&VEC, &u64::from(k).to_le_bytes()));
    }
    for k in 0u8..4 {
        keys.push(accessory_map().slot_key(&k));
    }
    keys
}

fn with_prefix(state: &BTreeMap<SlotKey, SlotValue>, prefix: &Prefix) -> Vec<(SlotKey, SlotValue)> {
    state
        .iter()
        .filter(|(key, _)| key.prefix() == *prefix)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// `storage` sees `state`: point reads of every key, and iteration.
pub(super) fn assert_state(storage: &TestStorage, state: &InMemoryState) {
    assert_point_reads(storage, state);
    for prefix in &USER_PREFIXES {
        let read: Vec<_> = storage
            .maybe_iter_user_values_with_prefix(SlotKey::singleton(prefix), None)
            .unwrap()
            .unwrap()
            .collect();
        assert_eq!(read, with_prefix(&state.user, prefix));
    }
    let read: Vec<_> = storage
        .maybe_iter_kernel_values_with_prefix(SlotKey::singleton(&KERNEL_MAP), None)
        .unwrap()
        .unwrap()
        .collect();
    assert_eq!(read, with_prefix(&state.kernel, &KERNEL_MAP));
}

/// `storage`'s point reads of every key see `state`.
pub(super) fn assert_point_reads(storage: &TestStorage, state: &InMemoryState) {
    let witness = Default::default();
    for key in all_keys() {
        assert_eq!(
            storage.get::<User>(&key, &witness),
            state.user.get(&key).cloned()
        );
        assert_eq!(
            storage.get::<Kernel>(&key, &witness),
            state.kernel.get(&key).cloned()
        );
        assert_eq!(
            storage.get_accessory(&key),
            state.accessory.get(&key).cloned()
        );
    }
}

/// Executes `ops` as block `hdr` on `m` with the witness on: the guest verifier, fed only the
/// witness, replays it to the same results, accesses and root, and consumes the witness. Saves
/// the block; the state after it is the model's. Returns the model after the block and the root.
pub(super) fn execute(
    m: &mut TestStorageManager<Spec>,
    hdr: &TestHeader,
    ops: &[Op],
    parent: &InMemoryState,
) -> Result<(InMemoryState, Root), proptest::test_runner::TestCaseError> {
    let (storage, ledger) = m.create_state_for(hdr).unwrap();
    assert_eq!(storage.witness_mode(), WitnessMode::On);
    let prev_root = storage.root().unwrap();
    let mut model = Model {
        committed: parent.clone(),
        pending: parent.clone(),
    };
    let expected = run(ops, &mut model);
    selendra_state::test_utils::Harness::commit(&mut model);

    let mut checkpoint = StateCheckpoint::new(storage.clone());
    let results = run(ops, &mut checkpoint);
    prop_assert_eq!(&results, &expected);
    let (accesses, accessory, witness) = checkpoint.freeze();
    let (root, mut update) = storage
        .compute_state_update(accesses.clone(), &witness, prev_root)
        .unwrap();

    let mut verifier = StateCheckpoint::with_witness(Verifier::new(), borsh_roundtrip(&witness));
    prop_assert_eq!(run(ops, &mut verifier), results);
    let (v_accesses, _, v_witness) = verifier.freeze();
    prop_assert_eq!(&v_accesses, &accesses);
    let (v_root, ()) = Verifier::new()
        .compute_state_update(v_accesses, &v_witness, prev_root)
        .unwrap();
    prop_assert_eq!(v_root, root);
    prop_assert_eq!(v_witness.ensure_consumed(), Ok(()));

    update.add_accessory_items(accessory.freeze());
    let change_set = storage.materialize_changes(update);
    let ledger_change_set = ledger
        .materialize_slot(
            change_set.version(),
            change_set.roots(),
            header_slot_info(hdr),
            SlotContents::default(),
        )
        .unwrap();
    m.save_change_set(hdr, change_set, ledger_change_set)
        .unwrap();
    let (after, _) = m.create_state_after(hdr).unwrap();
    assert_state(&after, &model.committed);
    assert_eq!(after.root().unwrap(), root);
    Ok((model.committed, root))
}

/// A10: `verifier_replays_the_prover_storage` (`prover/tests.rs`) on storages built on
/// uncommitted blocks: two forks of three unfinalized blocks from a shared first block, each
/// block executed with random operations on the state after its unfinalized parent and replayed
/// by the guest verifier from the witness alone (same results, accesses and root). Then the main
/// fork is finalized: the committed state is its model's, and the other fork's state is still
/// read by its storage, and is stale.
#[test_strategy::proptest(cases = 6)]
fn witness_replay_on_overlay_storage(
    #[strategy(prop_vec(prop_vec(any::<Op>(), 0..24), 5))] blocks: Vec<Vec<Op>>,
) {
    let mut m = Manager::with_config(|config| config.witness = WitnessMode::On);
    let g = TestHeader::linear(1);
    let a2 = g.child(TestHeader::MAIN_FORK);
    let a3 = a2.child(TestHeader::MAIN_FORK);
    let b2 = g.child(2);
    let b3 = b2.child(2);
    let mut states: HashMap<HexHash, (InMemoryState, Root)> = HashMap::new();
    let empty = InMemoryState::default();
    for (hdr, ops) in [&g, &a2, &b2, &a3, &b3].into_iter().zip(&blocks) {
        let parent = states
            .get(&hdr.prev)
            .map_or(&empty, |(state, _)| state)
            .clone();
        let result = execute(&mut m, hdr, ops, &parent)?;
        states.insert(hdr.hash, result);
    }
    let (after_b3, _) = m.create_state_after(&b3).unwrap();
    m.finalize(&a3).unwrap();
    let (state_a3, root_a3) = &states[&a3.hash];
    let (finalized, _) = m.create_finalized_state().unwrap();
    assert_state(&finalized, state_a3);
    prop_assert_eq!(finalized.root().unwrap(), *root_a3);
    // The discarded fork's storage reads its own state (also keys only the main fork wrote),
    // but cannot iterate (rockbound would merge the main fork's committed rows) nor compute.
    let (state_b3, root_b3) = &states[&b3.hash];
    assert_point_reads(&after_b3, state_b3);
    let err = after_b3
        .maybe_iter_user_values_with_prefix(SlotKey::singleton(&MAP), None)
        .err()
        .unwrap();
    assert_stale(&err, true);
    let err = after_b3
        .compute_state_update(Default::default(), &Default::default(), *root_b3)
        .unwrap_err();
    assert_stale(&err, true);
}

//! Tests of [`NomtProverStorage`] on real databases ([`TestDbs`]): the guest verifier replays
//! its witnesses (and rejects tampered and lying ones), stale storages and roots, witness
//! modes, proofs, historical and stale reads, iteration, and upstream's `prover_storage.rs`
//! tests that need no storage manager.

use std::collections::BTreeMap;

use proptest::collection::vec as prop_vec;
use proptest::prelude::{Strategy, any};
use proptest::{prop_assert, prop_assert_eq};
use selendra_interface::common::HexString;
use selendra_interface::reexports::digest::Digest;
use selendra_state::namespaces::{Kernel, User};
use selendra_state::test_utils::{
    Harness, InMemoryState, KERNEL_MAP, MAP, Model, Op, VALUE, VEC, accessory_map, borsh_roundtrip,
    catch_quietly, hints, kernel_map, map, run, vec as state_vec,
};
use selendra_state::test_vectors::{
    NOMT_PROOF_OF_ENTRY_1, TWO_ENTRY_GLOBAL_ROOT, TWO_ENTRY_ROOT, two_entry_root, vector_entries,
};
use selendra_state::{
    ArrayWitness, BorshCodec, KernelStateMap, NomtVerifierStorage, OrderedReadsAndWrites, Prefix,
    StateCheckpoint, StateMap, StateStorageSpec, StateValue, StateWriter,
};
use sha2::Sha256;

use super::*;
use crate::harness::{Gate, TestDbs};
use crate::{CommitPoint, FlatStateDb, StateDbConfig};

/// The chain's storage spec (SHA-256).
type Spec = StateStorageSpec;
type Prover = NomtProverStorage<Spec, u64>;
type Verifier = NomtVerifierStorage<Spec>;
type Root = StorageRoot<Spec>;
type Dbs = TestDbs<Spec>;

const ON: WitnessMode = WitnessMode::On;
const OFF: WitnessMode = WitnessMode::Off;

fn witness() -> ArrayWitness {
    ArrayWitness::default()
}

fn key(bytes: &[u8]) -> SlotKey {
    SlotKey::try_from_bytes(bytes).unwrap()
}

fn slot_value(bytes: &[u8]) -> SlotValue {
    SlotValue::from(bytes.to_vec())
}

fn u32_value(v: u32) -> SlotValue {
    SlotValue::from(borsh::to_vec(&v).unwrap())
}

// -------------------------------------------------------------------------------------------
// Upstream tests (`prover_storage.rs`) that need no storage manager.

#[test]
fn unbound_read_resolver_preserves_missing_value() {
    assert_eq!(
        Prover::resolve_unbound_read::<SlotValue>(Ok(None), "UserDb"),
        None
    );
}

#[test]
#[should_panic(expected = "Unable to read from UserDb")]
fn unbound_read_resolver_panics_on_db_error() {
    let _ = Prover::resolve_unbound_read::<SlotValue>(
        Err(anyhow::anyhow!("injected read failure")),
        "UserDb",
    );
}

fn writes(
    user: Vec<(SlotKey, Option<SlotValue>)>,
    kernel: Vec<(SlotKey, Option<SlotValue>)>,
) -> StateAccesses {
    StateAccesses {
        user: OrderedReadsAndWrites {
            ordered_reads: Vec::new(),
            ordered_writes: user,
        },
        kernel: OrderedReadsAndWrites {
            ordered_reads: Vec::new(),
            ordered_writes: kernel,
        },
    }
}

/// Upstream `write_block`: writes `value` at `user_key` in both namespaces and at
/// `accessory_key`, and commits it.
fn write_block(
    dbs: &mut Dbs,
    prev_root: Root,
    user_key: &SlotKey,
    accessory_key: &SlotKey,
    value: &SlotValue,
) -> Root {
    let storage = dbs.storage(OFF);
    let both = vec![(user_key.clone(), Some(value.clone()))];
    let (root, mut update) = storage
        .compute_state_update(writes(both.clone(), both), &witness(), prev_root)
        .unwrap();
    update.add_accessory_item(accessory_key.clone(), Some(value.clone()));
    dbs.commit(storage.materialize_changes(update));
    root
}

fn assert_proof_matches_storage_and_accessory(
    storage: &Prover,
    user_key: &SlotKey,
    accessory_key: &SlotKey,
    expected_value: &SlotValue,
    expected_root: Root,
) {
    let (proof, slot_number, root_hash) = storage
        .get_with_proof_once::<User>(user_key.clone())
        .unwrap();
    assert_eq!(slot_number, storage.latest_version_unbound());
    assert_eq!(root_hash, expected_root);
    assert_eq!(proof.value, Some(expected_value.clone()));
    assert_eq!(
        Prover::open_proof(root_hash, proof.clone()).unwrap(),
        (user_key.clone(), Some(expected_value.clone()))
    );
    // Through the public, retrying method too.
    assert_eq!(
        storage.get_with_proof::<User>(user_key.clone()).unwrap(),
        (proof, slot_number, root_hash)
    );
    assert_eq!(
        storage.get_accessory_unbound(accessory_key.clone(), Some(slot_number)),
        Some(expected_value.clone())
    );
}

fn kernel_only_accesses(kernel_key: SlotKey, value: SlotValue) -> StateAccesses {
    writes(Vec::new(), vec![(kernel_key, Some(value))])
}

/// A block that touches only the kernel keeps the (non-empty) user root, and its witness has
/// only the kernel proof, which the verifier consumes.
#[test]
fn verifier_carries_untouched_non_empty_namespace_forward() {
    let mut dbs = Dbs::new();
    let user_key = key(b"user-counter");
    let accessory_key = key(b"accessory-counter");
    let first_root = write_block(
        &mut dbs,
        Prover::PRE_GENESIS_ROOT,
        &user_key,
        &accessory_key,
        &slot_value(&[1]),
    );
    assert_ne!(
        first_root.namespace_root(ProvableNamespace::User),
        nomt::trie::TERMINATOR
    );

    let prover_storage = dbs.storage(ON);
    let kernel_key = key(b"kernel-only-counter");
    let kernel_value = slot_value(&[2]);
    let witness = witness();
    let (prover_root, _update) = prover_storage
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

/// Two commits during one attempt, the second restoring the user namespace: its root before
/// and after the value read, and NOMT's, are all equal, but the value read is the first
/// commit's. The attempt must retry (the versions differ), not prove that value against a root
/// that does not contain it.
#[test]
fn get_with_proof_retries_when_a_commit_is_reverted_during_the_read() {
    let mut dbs = Dbs::new();
    let k = map().slot_key(&1);
    let set = |dbs: &mut Dbs, v: u32| {
        dbs.commit_with(OFF, |state| {
            let Ok(()) = map().set(&1, &v, state);
        })
    };
    let first_root = set(&mut dbs, 10);
    let storage = dbs.storage(OFF);
    let mut steps = Vec::new();
    let mut roots = Vec::new();
    let attempt = storage.get_with_proof_once_with::<User>(k.clone(), |step| {
        steps.push(step);
        let v = match step {
            FetchStep::RootRead => 11,
            FetchStep::ValueRead => 10,
            FetchStep::BeforeSession | FetchStep::AfterSessionOpen => return,
        };
        roots.push(set(&mut dbs, v));
    });
    assert_eq!(
        steps,
        [
            FetchStep::RootRead,
            FetchStep::ValueRead,
            FetchStep::BeforeSession,
            FetchStep::AfterSessionOpen
        ]
    );
    // The scenario: the user root is back to the first one, at a newer version.
    assert_ne!(roots[0].user_root(), first_root.user_root());
    assert_eq!(roots[1].user_root(), first_root.user_root());
    assert!(matches!(attempt, Err(GetWithProofError::StateRootMismatch)));

    // Without commits in between, it proves the newest state.
    let (proof, version, root) = storage.get_with_proof_once::<User>(k.clone()).unwrap();
    assert_eq!(version, SlotNumber::new(2));
    assert_eq!(root, dbs.root());
    assert_eq!(proof.value, Some(u32_value(10)));
    assert_eq!(
        Prover::open_proof(root, proof).unwrap(),
        (k, Some(u32_value(10)))
    );
}

/// A commit that lands after both flat-store root reads but before the NOMT session opens
/// (`FetchStep::BeforeSession`) moves NOMT's root away from the one read: the attempt retries
/// instead of proving against a root the value was not read at.
#[test]
fn get_with_proof_retries_when_a_commit_lands_before_the_session() {
    let mut dbs = Dbs::new();
    let k = map().slot_key(&1);
    let set = |dbs: &mut Dbs, v: u32| {
        dbs.commit_with(OFF, |state| {
            let Ok(()) = map().set(&1, &v, state);
        })
    };
    set(&mut dbs, 10);
    let storage = dbs.storage(OFF);
    let mut steps = Vec::new();
    let attempt = storage.get_with_proof_once_with::<User>(k.clone(), |step| {
        steps.push(step);
        if step == FetchStep::BeforeSession {
            set(&mut dbs, 11);
        }
    });
    assert_eq!(
        steps,
        [
            FetchStep::RootRead,
            FetchStep::ValueRead,
            FetchStep::BeforeSession,
            FetchStep::AfterSessionOpen
        ]
    );
    assert!(matches!(attempt, Err(GetWithProofError::StateRootMismatch)));
    let (proof, version, _) = storage.get_with_proof_once::<User>(k).unwrap();
    assert_eq!(
        (proof.value, version),
        (Some(u32_value(11)), SlotNumber::new(1))
    );
}

/// A commit paused before the flat live DB ([`CommitPoint::BeforeLive`], with the flat store's
/// caches locked for writing and NOMT already a version ahead) on another thread: a
/// `get_with_proof` does not wait for it. Its flat-store reads go on (point reads skip the
/// locked caches, root reads take no lock) and still see the previous version, it passes every
/// fetch step, and the NOMT session's root then differs: it retries. Once the commit is
/// released, it proves the new version.
#[test]
fn get_with_proof_does_not_wait_for_a_commit_paused_before_live() {
    let mut dbs = Dbs::new();
    let k = map().slot_key(&1);
    dbs.commit_with(OFF, |state| {
        let Ok(()) = map().set(&1, &10, state);
    });
    let storage = dbs.storage(OFF);
    let (change_set, root) = dbs.change_set_with(OFF, |state| {
        let Ok(()) = map().set(&1, &11, state);
    });
    let gate = Gate::new();
    dbs.set_commit_hook(Some(gate.hook_at(CommitPoint::BeforeLive)));
    std::thread::scope(|scope| {
        let commit = scope.spawn(|| dbs.commit(change_set));
        assert!(gate.wait_reached(Gate::TIMEOUT), "the commit did not pause");
        let mut steps = Vec::new();
        let start = std::time::Instant::now();
        let attempt = storage.get_with_proof_once_with::<User>(k.clone(), |step| steps.push(step));
        // Had the attempt waited for the commit's lock, only the gate's timeout would have
        // ended it, and the commit would have failed.
        assert!(
            start.elapsed() < Gate::TIMEOUT / 2 && !commit.is_finished(),
            "the attempt waited for the commit"
        );
        assert_eq!(
            steps,
            [
                FetchStep::RootRead,
                FetchStep::ValueRead,
                FetchStep::BeforeSession,
                FetchStep::AfterSessionOpen
            ]
        );
        assert!(matches!(attempt, Err(GetWithProofError::StateRootMismatch)));
        assert_eq!(
            storage.get_unbound::<User>(k.clone()),
            Some(u32_value(10)),
            "the flat store's newest value while paused"
        );
        gate.release();
        commit.join().unwrap();
    });
    assert_eq!(dbs.root(), root);
    let (proof, version, proven_root) = storage.get_with_proof_once::<User>(k).unwrap();
    assert_eq!(
        (proof.value, version, proven_root),
        (Some(u32_value(11)), SlotNumber::new(1), root)
    );
}

/// A storage created before a commit proves the newest committed state (NOMT has no history).
#[test]
fn get_with_proof_reads_latest_committed_state_from_stale_storage() {
    let mut dbs = Dbs::new();
    let user_key = key(b"user-counter");
    let accessory_key = key(b"accessory-counter");
    let first_root = write_block(
        &mut dbs,
        Prover::PRE_GENESIS_ROOT,
        &user_key,
        &accessory_key,
        &slot_value(&[1]),
    );
    let stale_storage = dbs.storage(OFF);

    let second_value = slot_value(&[2]);
    let expected_root = write_block(
        &mut dbs,
        first_root,
        &user_key,
        &accessory_key,
        &second_value,
    );

    assert!(stale_storage.latest_version() < stale_storage.latest_version_unbound());
    assert_proof_matches_storage_and_accessory(
        &stale_storage,
        &user_key,
        &accessory_key,
        &second_value,
        expected_root,
    );
}

/// The positive control: a storage created after the newest commit proves it.
#[test]
fn get_with_proof_reads_latest_committed_state_from_fresh_storage() {
    let mut dbs = Dbs::new();
    let user_key = key(b"user-counter");
    let accessory_key = key(b"accessory-counter");
    let first_root = write_block(
        &mut dbs,
        Prover::PRE_GENESIS_ROOT,
        &user_key,
        &accessory_key,
        &slot_value(&[1]),
    );
    let second_value = slot_value(&[2]);
    let expected_root = write_block(
        &mut dbs,
        first_root,
        &user_key,
        &accessory_key,
        &second_value,
    );

    let fresh_storage = dbs.storage(OFF);
    assert_eq!(
        fresh_storage.latest_version(),
        fresh_storage.latest_version_unbound()
    );
    assert_proof_matches_storage_and_accessory(
        &fresh_storage,
        &user_key,
        &accessory_key,
        &second_value,
        expected_root,
    );
}

// -------------------------------------------------------------------------------------------
// Replay: the verifier, fed only the prover storage's witness, computes what it did.

/// The prefixes of the user containers [`Op`]s use.
const USER_PREFIXES: [Prefix; 3] = [VALUE, MAP, VEC];

/// The committed values with `prefix`, through a storage's iteration (ascending, deletes
/// skipped).
fn iterate(storage: &Prover, kernel: bool, prefix: &Prefix) -> Vec<(SlotKey, SlotValue)> {
    let prefix = SlotKey::singleton(prefix);
    if kernel {
        storage
            .maybe_iter_kernel_values_with_prefix(prefix, None)
            .unwrap()
            .unwrap()
            .collect()
    } else {
        storage
            .maybe_iter_user_values_with_prefix(prefix, None)
            .unwrap()
            .unwrap()
            .collect()
    }
}

fn with_prefix(state: &BTreeMap<SlotKey, SlotValue>, prefix: &Prefix) -> Vec<(SlotKey, SlotValue)> {
    state
        .iter()
        .filter(|(key, _)| key.prefix() == *prefix)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// The newest committed state of `dbs` is `state`: through iteration, bound and unbound reads.
fn assert_committed(dbs: &Dbs, state: &InMemoryState) {
    let storage = dbs.storage(OFF);
    for prefix in &USER_PREFIXES {
        assert_eq!(
            iterate(&storage, false, prefix),
            with_prefix(&state.user, prefix)
        );
    }
    assert_eq!(
        iterate(&storage, true, &KERNEL_MAP),
        with_prefix(&state.kernel, &KERNEL_MAP)
    );
    for (key, value) in &state.user {
        assert_eq!(storage.get::<User>(key, &witness()).as_ref(), Some(value));
        assert_eq!(
            storage.get_unbound::<User>(key.clone()).as_ref(),
            Some(value)
        );
    }
    for (key, value) in &state.kernel {
        assert_eq!(storage.get::<Kernel>(key, &witness()).as_ref(), Some(value));
    }
    for k in 0u8..4 {
        let key = accessory_map().slot_key(&k);
        assert_eq!(
            storage.get_accessory(&key),
            state.accessory.get(&key).cloned()
        );
    }
}

/// The state a (possibly stale) storage sees is `state`, and historical reads at `version` too.
fn assert_state_at(
    storage: &Prover,
    reader: &Prover,
    version: SlotNumber,
    state: &InMemoryState,
    keys: &[SlotKey],
) {
    let version = Some(version);
    for key in keys {
        let user = state.user.get(key).cloned();
        let kernel = state.kernel.get(key).cloned();
        let accessory = state.accessory.get(key).cloned();
        assert_eq!(storage.get::<User>(key, &witness()), user, "{key}");
        assert_eq!(storage.get::<Kernel>(key, &witness()), kernel, "{key}");
        assert_eq!(storage.get_accessory(key), accessory, "{key}");
        assert_eq!(
            reader
                .get_historical::<User>(key, version, &witness())
                .unwrap(),
            user,
            "{key}"
        );
        assert_eq!(
            reader
                .get_leaf_historical::<Kernel>(key, version, &witness())
                .unwrap()
                .map(|leaf| *leaf.leaf()),
            kernel.as_ref().map(NodeLeaf::make_leaf::<Sha256>),
            "{key}"
        );
        assert_eq!(
            reader.get_accessory_historical(key, version).unwrap(),
            accessory,
            "{key}"
        );
    }
}

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

/// Random blocks of operations (with commits and discards) through checkpoints over the prover
/// storage with the witness on, each replayed through a checkpoint over the guest verifier that
/// only has the witness: same results, same accesses, same root, the witness fully consumed.
/// Each block is committed; the databases then hold the model's state, and storages left behind
/// at each version (stale) and historical reads still see that version's state. This is
/// "native root == guest root" for random read/write sets on the real prover.
#[test_strategy::proptest(cases = 12)]
fn verifier_replays_the_prover_storage(
    #[strategy(prop_vec(prop_vec(any::<Op>(), 0..32), 1..4))] blocks: Vec<Vec<Op>>,
) {
    let mut dbs = Dbs::new();
    let mut model = Model::default();
    let mut versions = Vec::new();
    for ops in &blocks {
        let prev_root = dbs.root();
        let expected = run(ops, &mut model);
        model.commit();

        let storage = dbs.storage(ON);
        let mut checkpoint = StateCheckpoint::new(storage.clone());
        let results = run(ops, &mut checkpoint);
        prop_assert_eq!(&results, &expected);
        let (accesses, accessory, witness) = checkpoint.freeze();
        let (root, mut update) = storage
            .compute_state_update(accesses.clone(), &witness, prev_root)
            .unwrap();

        let mut verifier =
            StateCheckpoint::with_witness(Verifier::new(), borsh_roundtrip(&witness));
        prop_assert_eq!(run(ops, &mut verifier), results);
        let (v_accesses, _, v_witness) = verifier.freeze();
        prop_assert_eq!(&v_accesses, &accesses);
        let (v_root, ()) = Verifier::new()
            .compute_state_update(v_accesses, &v_witness, prev_root)
            .unwrap();
        prop_assert_eq!(v_root, root);
        prop_assert_eq!(v_witness.ensure_consumed(), Ok(()));

        update.add_accessory_items(accessory.freeze());
        prop_assert_eq!(update.root(), root);
        dbs.commit(storage.materialize_changes(update));
        prop_assert_eq!(dbs.root(), root);
        assert_committed(&dbs, &model.committed);
        versions.push((dbs.storage(OFF), model.committed.clone(), root));
    }

    let reader = dbs.storage(OFF);
    let keys = all_keys();
    for (version, (stale, state, root)) in versions.iter().enumerate() {
        let version = SlotNumber::new(u64::try_from(version).unwrap());
        prop_assert_eq!(stale.latest_version(), version);
        prop_assert_eq!(reader.get_root_hash(version), Some(*root));
        prop_assert_eq!(stale.get_root_hash(version), Some(*root));
        assert_state_at(stale, &reader, version, state, &keys);
    }
    // Reopened (once every storage, which keeps the NOMT databases open, is dropped): the same
    // state.
    let last_root = versions.last().unwrap().2;
    drop((versions, reader));
    let dbs = dbs.reopen();
    prop_assert_eq!(dbs.root(), last_root);
    assert_committed(&dbs, &model.committed);
}

/// Changing one byte of any one hint of an honest witness of the prover storage must make the
/// verifier panic (invalid witness) or its state update fail. No discards: discarded reads are
/// knowingly unverified.
#[test_strategy::proptest(cases = 8)]
fn every_hint_of_the_prover_storage_is_verified(
    #[strategy(prop_vec(any::<Op>(), 0..16))] genesis: Vec<Op>,
    #[strategy(prop_vec(any::<Op>().prop_map(|op| match op {
        Op::Discard => Op::Commit,
        op => op,
    }), 1..32))]
    ops: Vec<Op>,
    position: usize,
    #[strategy(1u8..)] flip: u8,
) {
    let mut dbs = Dbs::new();
    dbs.commit_with(OFF, |state| {
        run(&genesis, state);
    });
    let prev_root = dbs.root();
    let storage = dbs.storage(ON);
    let mut checkpoint = StateCheckpoint::new(storage.clone());
    run(&ops, &mut checkpoint);
    let (accesses, _, witness) = checkpoint.freeze();
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

// -------------------------------------------------------------------------------------------
// Deterministic cases.

/// Databases with user `1 → 10, 2 → 20` and kernel `1 → 100` (at version 0).
fn populated() -> Dbs {
    populate(Dbs::new())
}

fn populate(mut dbs: Dbs) -> Dbs {
    dbs.commit_with(OFF, |state| {
        let Ok(()) = map().set(&1, &10, state);
        let Ok(()) = map().set(&2, &20, state);
        let Ok(()) = kernel_map().set(&1, &100, state);
    });
    dbs
}

/// Runs `f` on a checkpoint over a new storage with the witness on and computes its state
/// update; returns the witness and the accesses.
fn witness_of(
    dbs: &Dbs,
    f: impl FnOnce(&mut StateCheckpoint<Prover>),
) -> (ArrayWitness, StateAccesses) {
    let storage = dbs.storage(ON);
    let mut checkpoint = StateCheckpoint::new(storage.clone());
    f(&mut checkpoint);
    let (accesses, _, witness) = checkpoint.freeze();
    storage
        .compute_state_update(accesses.clone(), &witness, dbs.root())
        .unwrap();
    (witness, accesses)
}

/// Replays `f` on the verifier with `witness`; returns the state update's root.
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
    let dbs = populated();
    let prev_root = dbs.root();
    fn reads<St: Storage>(state: &mut StateCheckpoint<St>) {
        // A present value, a size query of a present value, an absent value, a kernel value.
        let _ = map().get(&1, state);
        let _ = state.get_size(ProvableNamespace::User, &map().slot_key(&2));
        let _ = map().get(&3, state);
        let _ = kernel_map().get(&1, state);
    }
    let (witness, _) = witness_of(&dbs, reads);
    // Hints: value 1, leaf 2, value 3 (absent), kernel value 1, user proof, kernel proof.
    assert_eq!(witness.len(), 6);
    assert_eq!(
        verify_with(borsh_roundtrip(&witness), prev_root, reads).unwrap(),
        prev_root
    );
    let lies = [
        // Another value, and "absent" for a present key.
        with_lie(&witness, 0, &Some(u32_value(11))),
        with_lie(&witness, 0, &None::<SlotValue>),
        // Another leaf, and "absent" for a present key.
        with_lie(
            &witness,
            1,
            &Some(NodeLeaf::make_leaf::<Sha256>(&u32_value(21))),
        ),
        with_lie(&witness, 1, &None::<NodeLeaf>),
        // A value for an absent key.
        with_lie(&witness, 2, &Some(u32_value(30))),
        // A lie in the kernel namespace.
        with_lie(&witness, 3, &Some(u32_value(101))),
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

fn read_and_write(state: &mut StateCheckpoint<Prover>) {
    let _ = map().get(&1, state);
    let Ok(()) = map().set(&4, &40, state);
}

/// A previous root other than the storage's is an error in both witness modes (upstream
/// checked it only in strict mode), and computing a state update on a stale storage is a typed
/// [`StaleStorage`] error (whatever root is passed), so callers can retry with a new storage.
#[test]
fn a_stale_previous_root_or_storage_is_rejected() {
    let mut dbs = populated();
    let prev_root = dbs.root();
    for mode in [ON, OFF] {
        let storage = dbs.storage(mode);
        let mut checkpoint = StateCheckpoint::new(storage.clone());
        read_and_write(&mut checkpoint);
        let (accesses, _, witness) = checkpoint.freeze();
        let read_hints = witness.len();
        for stale in [
            Root::PRE_GENESIS,
            Root::new([1; 32], prev_root.kernel_root()),
        ] {
            let err = storage
                .compute_state_update(accesses.clone(), &witness, stale)
                .unwrap_err();
            assert!(err.to_string().contains("wrong previous root"), "{err}");
            assert!(err.downcast_ref::<StaleStorage>().is_none(), "{err}");
        }
        // No proof hint was added.
        assert_eq!(witness.len(), read_hints);
        storage
            .compute_state_update(accesses, &witness, prev_root)
            .unwrap();
    }

    // A storage left behind by a commit: neither the old root nor the new one works.
    let stale = dbs.storage(ON);
    let new_root = dbs.commit_with(OFF, |state| {
        let Ok(()) = map().set(&9, &90, state);
    });
    let mut checkpoint = StateCheckpoint::new(stale.clone());
    read_and_write(&mut checkpoint);
    let (accesses, _, witness) = checkpoint.freeze();
    for root in [prev_root, new_root] {
        let err = stale
            .compute_state_update(accesses.clone(), &witness, root)
            .unwrap_err();
        assert!(err.to_string().contains("stale storage"), "{err}");
        assert_eq!(
            err.downcast_ref::<StaleStorage>(),
            Some(&StaleStorage {
                storage_version: Some(SlotNumber::GENESIS),
                committed_version: Some(SlotNumber::new(1)),
                discarded_fork: false,
            })
        );
    }
}

/// With the witness off, nothing is added to the witness, and the root is the same.
#[test]
fn witness_off_adds_nothing() {
    let dbs = populated();
    let compute = |mode| {
        let storage = dbs.storage(mode);
        let mut checkpoint = StateCheckpoint::new(storage.clone());
        read_and_write(&mut checkpoint);
        let _ = checkpoint.get_size(ProvableNamespace::User, &map().slot_key(&2));
        let _ = kernel_map().remove(&1, &mut checkpoint);
        let (accesses, _, witness) = checkpoint.freeze();
        let len = witness.len();
        let (root, _) = storage
            .compute_state_update(accesses, &witness, dbs.root())
            .unwrap();
        (root, len, witness.len())
    };
    let (root_on, reads_on, all_on) = compute(ON);
    let (root_off, reads_off, all_off) = compute(OFF);
    assert_eq!(root_on, root_off);
    assert_eq!((reads_on, all_on), (3, 5));
    assert_eq!((reads_off, all_off), (0, 0));
}

/// An empty storage: nothing to prove, no roots, future versions are errors.
#[test]
fn empty_storage() {
    let dbs = Dbs::new();
    let storage = dbs.storage(ON);
    let k = map().slot_key(&1);
    assert!(storage.is_empty());
    assert_eq!(storage.latest_version(), SlotNumber::GENESIS);
    assert_eq!(storage.latest_version_unbound(), SlotNumber::GENESIS);
    let err = storage.get_with_proof::<User>(k.clone()).unwrap_err();
    assert!(err.to_string().contains("nothing to prove"), "{err}");
    assert_eq!(storage.get_root_hash(SlotNumber::GENESIS), None);
    assert_eq!(storage.get_latest_root_hash(), None);
    assert_eq!(storage.get_latest_root_hash_unbound(), None);
    assert_eq!(
        storage
            .get_historical::<User>(&k, None, &witness())
            .unwrap(),
        None
    );
    assert_eq!(storage.get_accessory_historical(&k, None).unwrap(), None);
    assert_eq!(storage.get::<User>(&k, &witness()), None);
    assert_eq!(storage.get_unbound::<Kernel>(k.clone()), None);
}

/// Historical and unbound reads add no hints, even with the witness on (the guest replays only
/// the bound reads).
#[test]
fn historical_and_unbound_reads_add_no_hints() {
    let mut dbs = populated();
    dbs.commit_with(OFF, |state| {
        let Ok(()) = map().set(&1, &11, state);
    });
    let storage = dbs.storage(ON);
    let k = map().slot_key(&1);
    let kernel_k = kernel_map().slot_key(&1);
    let w = witness();
    for version in [None, Some(SlotNumber::GENESIS), Some(SlotNumber::new(1))] {
        assert!(
            storage
                .get_historical::<User>(&k, version, &w)
                .unwrap()
                .is_some()
        );
        assert!(
            storage
                .get_historical::<Kernel>(&kernel_k, version, &w)
                .unwrap()
                .is_some()
        );
        assert!(
            storage
                .get_leaf_historical::<User>(&k, version, &w)
                .unwrap()
                .is_some()
        );
        assert!(
            storage
                .get_leaf_historical::<Kernel>(&kernel_k, version, &w)
                .unwrap()
                .is_some()
        );
    }
    assert!(storage.get_unbound::<User>(k.clone()).is_some());
    assert!(storage.get_with_proof::<User>(k.clone()).is_ok());
    assert!(w.is_empty(), "{} hints", w.len());
    // The control: a bound read on the same witness adds one.
    assert!(storage.get::<User>(&k, &w).is_some());
    assert_eq!(w.len(), 1);
}

fn is_future_version(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<HistoricalValueError>(),
        Some(HistoricalValueError::FutureVersion { .. })
    )
}

/// A historical read after the storage's version is an error, not "absent" (upstream:
/// `Ok(None)`), in every namespace; so is any version on an empty storage.
#[test]
fn future_versions_are_errors() {
    let empty = Dbs::new();
    let k = map().slot_key(&1);
    let storage = empty.storage(OFF);
    let genesis = Some(SlotNumber::GENESIS);
    assert!(is_future_version(
        &storage
            .get_historical::<User>(&k, genesis, &witness())
            .unwrap_err()
    ));
    assert!(is_future_version(
        &storage.get_accessory_historical(&k, genesis).unwrap_err()
    ));

    let dbs = populated();
    let storage = dbs.storage(OFF);
    let next = Some(SlotNumber::new(1));
    assert_eq!(
        storage
            .get_historical::<User>(&k, genesis, &witness())
            .unwrap(),
        Some(u32_value(10))
    );
    assert!(is_future_version(
        &storage
            .get_historical::<User>(&k, next, &witness())
            .unwrap_err()
    ));
    assert!(is_future_version(
        &storage
            .get_leaf_historical::<Kernel>(&k, next, &witness())
            .unwrap_err()
    ));
    assert!(is_future_version(
        &storage.get_accessory_historical(&k, next).unwrap_err()
    ));
    // Bound root reads end at the storage's version; unbound ones give the newest at or below.
    assert_eq!(storage.get_root_hash(SlotNumber::new(1)), None);
    assert_eq!(
        storage.get_root_hash_unbound(SlotNumber::new(7)),
        Some(dbs.root())
    );
}

/// A block that writes only user keys commits and reads back (upstream's flat store refused
/// it, so its prover panicked).
#[test]
fn user_only_blocks_commit() {
    let mut dbs = Dbs::new();
    let first = dbs.commit_with(ON, |state| {
        let Ok(()) = map().set(&1, &10, state);
    });
    assert_eq!(first.kernel_root(), nomt::trie::TERMINATOR);
    let second = dbs.commit_with(ON, |state| {
        let Ok(()) = map().set(&1, &11, state);
    });
    assert_ne!(first, second);
    let storage = dbs.storage(ON);
    assert_eq!(storage.latest_version(), SlotNumber::new(1));
    let mut checkpoint = StateCheckpoint::new(storage.clone());
    assert_eq!(map().get(&1, &mut checkpoint), Ok(Some(11)));
    assert_eq!(
        storage
            .get_historical::<User>(&map().slot_key(&1), Some(SlotNumber::GENESIS), &witness())
            .unwrap(),
        Some(u32_value(10))
    );
}

/// The `StateVec` case of rockbound's B1 bug: `len` lives at the vector's prefix and element 0
/// at `prefix ‖ 0u64`, a longer key. After `len` is written at genesis, a storage left behind
/// and historical reads must still find it (upstream read `None`: a length of 0).
#[test]
fn state_vec_length_reads_back_from_stale_storages_and_history() {
    let mut dbs = Dbs::new();
    let mut vector = state_vec();
    dbs.commit_with(ON, |state| {
        let Ok(()) = vector.push(&7, state);
    });
    let stale = dbs.storage(ON);
    // Only the element changes.
    dbs.commit_with(ON, |state| {
        let Ok(Ok(())) = vector.set(0, &8, state) else {
            panic!("index 0 exists");
        };
    });
    let stale_too = dbs.storage(ON);
    dbs.commit_with(ON, |state| {
        let Ok(()) = vector.push(&9, state);
    });

    let mut checkpoint = StateCheckpoint::new(stale);
    assert_eq!(vector.len(&mut checkpoint), Ok(1));
    assert_eq!(vector.get(0, &mut checkpoint), Ok(Some(7)));
    let mut checkpoint = StateCheckpoint::new(stale_too);
    assert_eq!(vector.len(&mut checkpoint), Ok(1));
    assert_eq!(vector.get(0, &mut checkpoint), Ok(Some(8)));

    let storage = dbs.storage(OFF);
    let len_key = SlotKey::singleton(&VEC);
    for (version, len) in [(0, 1u64), (1, 1), (2, 2)] {
        assert_eq!(
            storage
                .get_historical::<User>(&len_key, Some(SlotNumber::new(version)), &witness())
                .unwrap(),
            Some(SlotValue::from(borsh::to_vec(&len).unwrap())),
            "version {version}"
        );
    }
    let mut checkpoint = StateCheckpoint::new(storage);
    assert_eq!(vector.len(&mut checkpoint), Ok(2));
}

/// rockbound's B2 bug: an empty value (`StateValue<()>`) read back as deleted from the archive.
/// It is `Some(())` from a stale storage, in history and in proofs.
#[test]
fn empty_values_are_not_deletes() {
    let mut dbs = Dbs::new();
    let mut unit = StateValue::<()>::with_codec(Prefix::new(4, 0), BorshCodec);
    let unit_key = SlotKey::singleton(&Prefix::new(4, 0));
    dbs.commit_with(ON, |state| {
        let Ok(()) = unit.set(&(), state);
    });
    let stale = dbs.storage(ON);
    let root = dbs.commit_with(ON, |state| {
        let Ok(()) = map().set(&1, &1, state);
    });

    let mut checkpoint = StateCheckpoint::new(stale);
    assert_eq!(unit.get(&mut checkpoint), Ok(Some(())));
    let storage = dbs.storage(OFF);
    let empty = Some(SlotValue::from(Vec::new()));
    for version in [0, 1] {
        assert_eq!(
            storage
                .get_historical::<User>(&unit_key, Some(SlotNumber::new(version)), &witness())
                .unwrap(),
            empty
        );
    }
    let (proof, _, proven_root) = storage.get_with_proof::<User>(unit_key.clone()).unwrap();
    assert_eq!(proven_root, root);
    assert_eq!(proof.value, empty);
    assert_eq!(Prover::open_proof(root, proof).unwrap(), (unit_key, empty));
}

/// `maybe_iter_*`: ascending key order, from the cursor (inclusive), deleted keys skipped; a
/// cursor without the prefix and a stale storage (one of the empty databases included) are
/// errors.
#[test]
fn iteration() {
    let mut dbs = Dbs::new();
    let mut wide = StateMap::<u16, u32>::with_codec(MAP, BorshCodec);
    let pre_genesis = dbs.storage(OFF);
    assert!(iterate(&pre_genesis, false, &MAP).is_empty());
    dbs.commit_with(OFF, |state| {
        for k in [300u16, 1, 256, 2, 0xffff] {
            let Ok(()) = wide.set(&k, &u32::from(k), state);
        }
        let Ok(()) =
            KernelStateMap::<u8, u32>::with_codec(KERNEL_MAP, BorshCodec).set(&1, &1, state);
    });
    // A storage of the empty databases is stale once genesis (version 0) is committed, like its point
    // reads (which still see nothing).
    assert!(pre_genesis.is_empty());
    assert_eq!(
        pre_genesis.get::<User>(&wide.slot_key(&1), &witness()),
        None
    );
    for kernel in [false, true] {
        let prefix = SlotKey::singleton(if kernel { &KERNEL_MAP } else { &MAP });
        let iter = if kernel {
            pre_genesis
                .maybe_iter_kernel_values_with_prefix(prefix, None)
                .map(|_| ())
        } else {
            pre_genesis
                .maybe_iter_user_values_with_prefix(prefix, None)
                .map(|_| ())
        };
        let err = iter.unwrap_err();
        assert!(
            err.to_string().contains("Version on disk is newer"),
            "{err}"
        );
    }
    let stale = dbs.storage(OFF);
    dbs.commit_with(OFF, |state| {
        let Ok(_) = wide.remove(&256, state);
    });
    let storage = dbs.storage(OFF);

    let keys = |cursor: Option<u16>| -> Vec<SlotKey> {
        storage
            .maybe_iter_user_values_with_prefix(
                SlotKey::singleton(&MAP),
                cursor.map(|k| wide.slot_key(&k)),
            )
            .unwrap()
            .unwrap()
            .map(|(key, _)| key)
            .collect()
    };
    // Ascending by key bytes (borsh `u16` is little-endian).
    let mut expected: Vec<SlotKey> = [300u16, 1, 2, 0xffff]
        .iter()
        .map(|k| wide.slot_key(k))
        .collect();
    expected.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    assert_eq!(keys(None), expected);
    assert_eq!(
        keys(Some(2)),
        expected[expected
            .iter()
            .position(|k| *k == wide.slot_key(&2))
            .unwrap()..]
    );

    let cursor_elsewhere = storage.maybe_iter_user_values_with_prefix(
        SlotKey::singleton(&MAP),
        Some(SlotKey::singleton(&VALUE)),
    );
    assert!(cursor_elsewhere.is_err());
    assert!(
        stale
            .maybe_iter_user_values_with_prefix(SlotKey::singleton(&MAP), None)
            .is_err()
    );
    // The other namespace.
    assert_eq!(iterate(&storage, true, &KERNEL_MAP).len(), 1);
    assert_eq!(iterate(&storage, true, &MAP).len(), 0);
}

/// Runs one block on the prover storage and the verifier: the witness has `hints` hints, the
/// verifier replays it to the same root, and it commits (where NOMT 1.0.5 panics on deletes of
/// absent keys passed through). Returns the new root.
fn check_block(dbs: &mut Dbs, ops: fn(&mut dyn Ops), hints: usize) -> Root {
    let prev_root = dbs.root();
    let (witness, _) = witness_of(dbs, |s| ops(s));
    assert_eq!(witness.len(), hints);
    let root = verify_with(borsh_roundtrip(&witness), prev_root, |s| ops(s)).unwrap();
    assert_eq!(dbs.commit_with(ON, |s| ops(s)), root);
    root
}

/// The operations of [`check_block`], on either storage.
trait Ops {
    fn remove_user(&mut self, k: u8);
    fn remove_kernel(&mut self, k: u8);
    fn delete_user(&mut self, k: u8);
    fn delete_kernel(&mut self, k: u8);
    fn get_user(&mut self, k: u8);
    fn set_user(&mut self, k: u8, v: u32);
    fn set_kernel(&mut self, k: u8, v: u32);
}

impl<St: Storage> Ops for StateCheckpoint<St> {
    fn remove_user(&mut self, k: u8) {
        let _ = map().remove(&k, self);
    }

    fn remove_kernel(&mut self, k: u8) {
        let _ = kernel_map().remove(&k, self);
    }

    fn delete_user(&mut self, k: u8) {
        let Ok(()) = StateWriter::<User>::delete(self, &map().slot_key(&k));
    }

    fn delete_kernel(&mut self, k: u8) {
        let Ok(()) = StateWriter::<Kernel>::delete(self, &kernel_map().slot_key(&k));
    }

    fn get_user(&mut self, k: u8) {
        let _ = map().get(&k, self);
    }

    fn set_user(&mut self, k: u8, v: u32) {
        let Ok(()) = map().set(&k, &v, self);
    }

    fn set_kernel(&mut self, k: u8, v: u32) {
        let Ok(()) = kernel_map().set(&k, &v, self);
    }
}

/// Deletes of absent keys become reads of their absence for NOMT (the workaround for the NOMT
/// 1.0.5 panic, see `to_nomt_accesses`), and a namespace whose only access is such a delete still
/// gets a proof (`namespace_needs_proof`), on empty and populated databases.
#[test]
fn deletes_of_absent_keys_commit_and_replay() {
    // Empty databases: only a delete (blind, or after a read) in one namespace.
    let mut dbs = Dbs::new();
    // The kernel proof only (a blind delete reads nothing).
    let root = check_block(&mut dbs, |s| s.delete_kernel(5), 1);
    assert_eq!(root, Root::PRE_GENESIS);
    // The read's value, then the user proof.
    let root = check_block(&mut dbs, |s| s.remove_user(3), 2);
    assert_eq!(root, Root::PRE_GENESIS);
    assert_eq!(dbs.storage(OFF).latest_version(), SlotNumber::new(1));

    // Next to values: two reads, then both proofs; nothing changes.
    let mut dbs = populated();
    let prev_root = dbs.root();
    let root = check_block(
        &mut dbs,
        |s| {
            s.get_user(1);
            s.delete_user(9);
            s.remove_kernel(7);
        },
        4,
    );
    assert_eq!(root, prev_root);
    // With real writes in both namespaces: both proofs, both roots change.
    let root = check_block(
        &mut dbs,
        |s| {
            s.delete_user(8);
            s.set_user(4, 40);
            s.delete_kernel(5);
            s.set_kernel(2, 200);
        },
        2,
    );
    assert_ne!(root.user_root(), prev_root.user_root());
    assert_ne!(root.kernel_root(), prev_root.kernel_root());
    // A real delete next to an absent one.
    let root = check_block(
        &mut dbs,
        |s| {
            s.delete_user(1);
            s.delete_user(8);
        },
        1,
    );
    assert_ne!(root.user_root(), prev_root.user_root());
    let storage = dbs.storage(OFF);
    assert_eq!(iterate(&storage, false, &MAP).len(), 2);
    assert_eq!(iterate(&storage, true, &KERNEL_MAP).len(), 2);
}

/// The self-check (B8): with the witness on, a flat store whose values disagree with the NOMT
/// tree makes `compute_state_update` fail instead of producing a witness the guest rejects.
/// With the witness off, NOMT does not check reads, so it goes through.
#[test]
fn reads_that_disagree_with_nomt_fail_the_self_check() {
    // Both directories at once (taking one, then waiting for another, can wait forever).
    let mut dirs = crate::test_utils::tempdirs(2);
    let other = dirs.pop().unwrap();
    let dbs = populate(Dbs::new_in(dirs.pop().unwrap(), None));
    let roots = dbs.group().roots();
    // A flat store at the same version and root, with another value for map key 1.
    let config = StateDbConfig::for_tests(other.path());
    let mut flat = FlatStateDb::new(
        &config.path,
        config.user_state_cache_size,
        config.kernel_state_cache_size,
    )
    .unwrap();
    let changes = HistoricalStateReader::materialize_values(
        vec![(map().slot_key(&1), Some(u32_value(11)))],
        vec![(kernel_map().slot_key(&1), Some(u32_value(100)))],
        roots,
        SlotNumber::GENESIS,
    )
    .unwrap();
    flat.commit(changes).unwrap();
    let mut readers = dbs.group().readers::<u64>().unwrap();
    readers.historical_state = flat.reader().unwrap();

    for (mode, ok) in [(ON, false), (OFF, true)] {
        let storage = Prover::create(
            StorageReaders {
                session_builder: readers.session_builder.clone(),
                historical_state: readers.historical_state.clone(),
                accessory: readers.accessory.clone(),
            },
            mode,
        );
        let mut checkpoint = StateCheckpoint::new(storage.clone());
        assert_eq!(map().get(&1, &mut checkpoint), Ok(Some(11)));
        let (accesses, _, witness) = checkpoint.freeze();
        let result = storage.compute_state_update(accesses, &witness, dbs.root());
        match result {
            Ok(_) => assert!(ok, "the self-check passed"),
            Err(err) => {
                assert!(!ok, "{err:#}");
                assert!(format!("{err:#}").contains("self-check"), "{err:#}");
            }
        }
    }
}

/// The NOMT 1.0.5 panic the absent-delete workaround avoids, directly on this crate's NOMT
/// configuration. If this fails, a NOMT upgrade fixed it: review `to_nomt_accesses`.
#[test]
fn nomt_still_panics_on_deleting_an_absent_key_from_an_empty_database() {
    let dbs = Dbs::new();
    let outcome = catch_quietly(|| {
        let sessions = dbs
            .group()
            .readers::<u64>()
            .unwrap()
            .session_builder
            .begin_both_sessions(OFF)
            .unwrap();
        let user = sessions
            .user
            .finish(vec![([7; 32], KeyReadWrite::Write(None))])
            .unwrap();
        let kernel = sessions.kernel.finish(Vec::new()).unwrap();
        dbs.group().nomt().commit(
            StateFinishedSession::new(user, kernel).into_state_overlay(),
            &Default::default(),
        )
    });
    assert!(outcome.is_err(), "NOMT no longer panics: {outcome:?}");
}

/// `to_nomt_accesses`: keyed by `selendra-state`'s shared [`key_path`] (`H(whole key)`) with
/// its [`leaf_value_bytes`], sorted by key path, reads then writes merged, absent deletes
/// become reads, duplicates are errors.
#[test]
fn nomt_accesses_use_shared_key_path() {
    let (a, b, c) = (key(b"aa"), key(b"bb"), key(b"cc"));
    let path = |k: &SlotKey| key_path::<Spec>(k);
    // The shared definitions are the convention: `H(key)` and `val_hash ‖ size`.
    assert_eq!(path(&a), <KeyPath>::from(Sha256::digest(b"aa")));
    let leaf = NodeLeaf::make_leaf::<Sha256>(&slot_value(b"x"));
    assert_eq!(
        leaf_value_bytes(&leaf),
        slot_value(b"x").combine_val_hash_and_size::<Sha256>()
    );
    let accesses = OrderedReadsAndWrites {
        ordered_reads: vec![(a.clone(), Some(leaf)), (b.clone(), None)],
        ordered_writes: vec![
            (a.clone(), None),
            (b.clone(), None),
            (c.clone(), Some(slot_value(b"y"))),
        ],
    };
    // `b` is absent, `a` is not.
    let absent = path(&b);
    let nomt = to_nomt_accesses::<Spec>(&accesses, |p| Ok(*p == absent)).unwrap();
    let mut expected = vec![
        (
            path(&a),
            KeyReadWrite::ReadThenWrite(Some(leaf_value_bytes(&leaf).to_vec()), None),
        ),
        (path(&b), KeyReadWrite::Read(None)),
        (
            path(&c),
            KeyReadWrite::Write(Some(
                leaf_value_bytes(&NodeLeaf::make_leaf::<Sha256>(&slot_value(b"y"))).to_vec(),
            )),
        ),
    ];
    expected.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(format!("{nomt:?}"), format!("{expected:?}"));

    let duplicate_reads = OrderedReadsAndWrites {
        ordered_reads: vec![(a.clone(), None), (a.clone(), None)],
        ordered_writes: Vec::new(),
    };
    assert!(to_nomt_accesses::<Spec>(&duplicate_reads, |_| Ok(false)).is_err());
    let duplicate_writes = OrderedReadsAndWrites {
        ordered_reads: Vec::new(),
        ordered_writes: vec![(a.clone(), None), (a, None)],
    };
    assert!(to_nomt_accesses::<Spec>(&duplicate_writes, |_| Ok(false)).is_err());
    let failing = OrderedReadsAndWrites {
        ordered_reads: Vec::new(),
        ordered_writes: vec![(b, None)],
    };
    assert!(to_nomt_accesses::<Spec>(&failing, |_| anyhow::bail!("I/O")).is_err());
}

/// The real prover storage, under the chain's spec, computes `selendra-state`'s known-answer
/// vectors: committing the two vector entries gives the pinned user root (kernel tree empty)
/// and global root, and NOMT's proof of the first entry is the pinned one. The prover and the
/// verifier share `key_path`/`leaf_value_bytes`, so the replay tests can no longer catch a
/// change of the hashing convention: this test does (as do `selendra-state`'s vectors).
#[test]
fn prover_storage_matches_known_answer_vectors() {
    let mut dbs = TestDbs::<StateStorageSpec>::new();
    let root = dbs.commit_with(ON, |state| {
        for (key, value) in vector_entries() {
            let Ok(()) = StateWriter::<User>::set(state, &key, value);
        }
    });
    assert_eq!(HexString(root.user_root()).to_string(), TWO_ENTRY_ROOT);
    assert_eq!(
        root.kernel_root(),
        StorageRoot::<Spec>::PRE_GENESIS.kernel_root()
    );
    assert_eq!(root, two_entry_root());
    assert_eq!(
        HexString(root.global_root()).to_string(),
        TWO_ENTRY_GLOBAL_ROOT
    );

    let [(key_1, value_1), (key_2, value_2)] = vector_entries();
    let storage = dbs.storage(OFF);
    let (proof, version, proof_root) = storage.get_with_proof::<User>(key_1.clone()).unwrap();
    assert_eq!((version, proof_root), (SlotNumber::GENESIS, root));
    assert_eq!(proof.value, Some(value_1.clone()));
    assert_eq!(
        HexString(borsh::to_vec(&proof.proof).unwrap()).to_string(),
        NOMT_PROOF_OF_ENTRY_1
    );
    assert_eq!(
        Prover::open_proof(root, proof).unwrap(),
        (key_1.clone(), Some(value_1))
    );
    // The bound reads see the entries too (through the flat store).
    assert_eq!(storage.get::<User>(&key_2, &witness()), Some(value_2));
}

/// Accessory items added to the state update are committed at the block's version and read
/// back bound, unbound and historically.
#[test]
fn accessory_items_are_committed() {
    let mut dbs = Dbs::new();
    let k = key(b"acc");
    dbs.commit_with(OFF, |state| {
        let Ok(()) = StateWriter::<selendra_state::Accessory>::set(state, &k, slot_value(b"a"));
    });
    let stale = dbs.storage(OFF);
    dbs.commit_with(OFF, |state| {
        let Ok(()) = StateWriter::<selendra_state::Accessory>::delete(state, &k);
    });
    let storage = dbs.storage(OFF);
    assert_eq!(stale.get_accessory(&k), Some(slot_value(b"a")));
    assert_eq!(storage.get_accessory(&k), None);
    assert_eq!(stale.get_accessory_unbound(k.clone(), None), None);
    assert_eq!(
        storage.get_accessory_unbound(k.clone(), Some(SlotNumber::GENESIS)),
        Some(slot_value(b"a"))
    );
    assert_eq!(
        storage
            .get_accessory_historical(&k, Some(SlotNumber::GENESIS))
            .unwrap(),
        Some(slot_value(b"a"))
    );
    assert_eq!(storage.get_unbound::<selendra_state::Accessory>(k), None);
}

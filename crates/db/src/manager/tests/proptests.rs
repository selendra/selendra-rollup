//! Property tests of the storage manager (few cases with small histories: each case opens real
//! databases):
//! - `fork_tree_model` (P1): random fork trees (upstream's `ForkDescription`), random
//!   executions, storages and finalizations against a model of every block's state;
//! - `crash_then_recovery_and_replay_match_an_uncrashed_run` (P3): a fault at a random commit
//!   point of a random finalization, reopened and finished, ends byte for byte like an uncrashed
//!   run;
//! - `pruning_model` (P5): random histories, `versions_to_keep`, budgets and pinning storages;
//! - `verifier_replays_the_prover_storage_on_forks`: TODO.md's property-test item (native root
//!   == guest root) on storages built on random forks of unfinalized blocks.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroU64;

use proptest::collection::vec as prop_vec;
use proptest::prelude::*;
use proptest::sample::Index;
use selendra_state::test_utils::{InMemoryState, Op};

use super::forks::{ForkDescription, ForkMap};
use super::proofs::{assert_state, execute};
use super::*;
use crate::harness::block_hash;
use crate::test_utils::blocks::dump;
use crate::test_utils::tempdirs;
use crate::{CommitPoint, HistoricalValueError, PrunerConfig, WitnessMode, fail_at};

/// The state of a block in the models: every key's value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct State {
    user: BTreeMap<SlotKey, SlotValue>,
    kernel: BTreeMap<SlotKey, SlotValue>,
    accessory: BTreeMap<SlotKey, SlotValue>,
}

type Writes = Vec<(SlotKey, Option<SlotValue>)>;

const USER_KEYS: u8 = 6;
const KERNEL_KEYS: u8 = 3;
const ACCESSORY_KEYS: u8 = 3;

/// Key `i` of a namespace (`b'u'`, `b'k'`, `b'a'`).
fn model_key(namespace: u8, i: u8) -> SlotKey {
    SlotKey::try_from_bytes(&[namespace, i]).unwrap()
}

/// What block `hdr` writes at its key `i`: its hash and `i`, so blocks and keys differ.
fn block_value(hdr: &TestHeader, i: u8) -> SlotValue {
    let hash: [u8; 32] = hdr.hash.into();
    SlotValue::from([&hash[..], &[i]].concat())
}

/// The user, kernel and accessory writes of block `hdr` that `bits` choose: per user key two
/// bits (nothing, set, set, delete), one kernel key, one accessory write or delete; plus a tag
/// key with the block's hash, so that no two blocks have the same root.
fn block_writes(hdr: &TestHeader, bits: u16) -> [Writes; 3] {
    let mut user = vec![(model_key(b't', 0), Some(block_value(hdr, 0xff)))];
    for i in 0..USER_KEYS {
        match (bits >> (2 * u16::from(i))) & 3 {
            0 => {}
            3 => user.push((model_key(b'u', i), None)),
            _ => user.push((model_key(b'u', i), Some(block_value(hdr, i)))),
        }
    }
    let mut kernel = Vec::new();
    if let Some(i) = u8::try_from((bits >> 12) & 3).unwrap().checked_sub(1) {
        kernel.push((
            model_key(b'k', i),
            Some(block_value(hdr, i.wrapping_add(100))),
        ));
    }
    let accessory = match bits >> 14 {
        0 => Vec::new(),
        1 => vec![(model_key(b'a', 0), Some(block_value(hdr, 200)))],
        2 => vec![(model_key(b'a', 1), Some(block_value(hdr, 201)))],
        _ => vec![(model_key(b'a', 0), None)],
    };
    [user, kernel, accessory]
}

fn apply(state: &mut State, writes: &[Writes; 3]) {
    for (map, writes) in [&mut state.user, &mut state.kernel, &mut state.accessory]
        .into_iter()
        .zip(writes)
    {
        for (key, value) in writes {
            match value {
                Some(value) => map.insert(key.clone(), value.clone()),
                None => map.remove(key),
            };
        }
    }
}

/// `storage`'s bound reads of every model key are `state`'s.
fn assert_reads(storage: &TestStorage, state: &State) -> Result<(), TestCaseError> {
    let witness = Default::default();
    for i in 0..USER_KEYS {
        let key = model_key(b'u', i);
        prop_assert_eq!(
            storage.get::<User>(&key, &witness),
            state.user.get(&key).cloned()
        );
    }
    let tag = model_key(b't', 0);
    prop_assert_eq!(
        storage.get::<User>(&tag, &witness),
        state.user.get(&tag).cloned()
    );
    for i in 0..KERNEL_KEYS {
        let key = model_key(b'k', i);
        prop_assert_eq!(
            storage.get::<Kernel>(&key, &witness),
            state.kernel.get(&key).cloned()
        );
    }
    for i in 0..ACCESSORY_KEYS {
        let key = model_key(b'a', i);
        prop_assert_eq!(
            storage.get_accessory(&key),
            state.accessory.get(&key).cloned()
        );
    }
    Ok(())
}

/// Upstream's `ForkDescription` strategy (its `Arbitrary`), smaller: forks of 1 to 5 blocks, up
/// to 2 children each, 3 levels.
fn fork_description() -> impl Strategy<Value = ForkDescription> {
    let leaf = (1u64..=3, 1u64..=4).prop_map(|(start_height, length)| ForkDescription {
        start_height,
        length,
        child_forks: Vec::new(),
    });
    leaf.prop_recursive(3, 24, 3, |inner| {
        (1u64..=3, 2u64..=5, prop_vec(inner, 0..3)).prop_map(|(start_height, length, children)| {
            // A child fork starts on one of its parent's blocks.
            let max_start = length.checked_sub(1).unwrap();
            let child_forks = children
                .into_iter()
                .map(|mut child| {
                    child.start_height = child.start_height.clamp(1, max_start);
                    child
                })
                .collect();
            ForkDescription {
                start_height,
                length,
                child_forks,
            }
        })
    })
}

/// Whether `hash` is `ancestor` or one of its descendants in `map`.
fn descends_from(map: &ForkMap, hash: &HexHash, ancestor: &HexHash) -> bool {
    let mut current = *hash;
    loop {
        if current == *ancestor {
            return true;
        }
        match map.blocks.get(&current) {
            Some((hdr, _)) => current = hdr.prev,
            None => return false,
        }
    }
}

/// P1 (upstream's `#[ignore]`d `proptest_nomt_forks_exploration`, with a model): a random fork
/// tree, and random actions on it: execute and save a block whose parent is saved or
/// finalized, create the state after a saved or the finalized block (kept as long as the test
/// can), finalize a saved block. A model holds every block's state and root. After every
/// action: the manager's maps agree with the model's saved blocks; every kept storage reads its
/// own state with its own root, also after finalizations (the snapshot illusion, upstream's P6);
/// a proof from one of them is of the state the model says (the newest committed state for a
/// committed block, the block's own if unfinalized, `StaleStorage` at once if discarded). After
/// a finalization, discarded blocks are refused. In the end, finalizing the highest saved block
/// leaves the manager empty, with the model's committed state.
#[test_strategy::proptest(cases = 8)]
fn fork_tree_model(
    #[strategy(fork_description())] fork: ForkDescription,
    #[strategy(prop_vec(any::<(u8, Index, u16)>(), 10..40))] actions: Vec<(u8, Index, u16)>,
) {
    let map = ForkMap::from(fork);
    let start = map.start.unwrap();
    let mut hashes: Vec<HexHash> = map.blocks.keys().copied().collect();
    hashes.sort_unstable();
    let mut m = Manager::new();
    let mut saved: HashMap<HexHash, (State, Root)> = HashMap::new();
    let mut finalized: Option<(HexHash, State, Root)> = None;
    let mut committed: HashSet<HexHash> = HashSet::new();
    let mut storages: Vec<(TestStorage, HexHash, State, Root)> = Vec::new();
    for (action, pick, bits) in actions {
        match action % 4 {
            0 | 1 => {
                let executable: Vec<HexHash> = hashes
                    .iter()
                    .copied()
                    .filter(|hash| {
                        let prev = map.header(hash).prev;
                        !saved.contains_key(hash)
                            && !committed.contains(hash)
                            && (saved.contains_key(&prev)
                                || finalized.as_ref().is_some_and(|(f, ..)| *f == prev)
                                || (finalized.is_none() && *hash == start))
                    })
                    .collect();
                if executable.is_empty() {
                    continue;
                }
                let hdr = map
                    .header(&executable[pick.index(executable.len())])
                    .clone();
                let mut state = match (saved.get(&hdr.prev), &finalized) {
                    (Some((state, _)), _) | (None, Some((_, state, _))) => state.clone(),
                    (None, None) => State::default(),
                };
                let writes = block_writes(&hdr, bits);
                let root = write_block(&mut m, &hdr, &writes[0], &writes[1], &writes[2]);
                apply(&mut state, &writes);
                saved.insert(hdr.hash, (state, root));
            }
            2 => {
                let mut candidates: Vec<HexHash> = saved.keys().copied().collect();
                candidates.sort_unstable();
                candidates.extend(finalized.as_ref().map(|(hash, ..)| *hash));
                if candidates.is_empty() {
                    continue;
                }
                let hash = candidates[pick.index(candidates.len())];
                let (state, root) = match saved.get(&hash) {
                    Some((state, root)) => (state.clone(), *root),
                    None => {
                        let (_, state, root) = finalized.as_ref().unwrap();
                        (state.clone(), *root)
                    }
                };
                let (storage, _) = m.create_state_after(map.header(&hash)).unwrap();
                prop_assert_eq!(storage.witness_mode(), WitnessMode::Off);
                storages.push((storage, hash, state, root));
                if storages.len() > 4 {
                    storages.remove(0);
                }
            }
            _ => {
                let mut candidates: Vec<HexHash> = saved.keys().copied().collect();
                if candidates.is_empty() {
                    continue;
                }
                candidates.sort_unstable();
                let hash = candidates[pick.index(candidates.len())];
                let hdr = map.header(&hash).clone();
                m.finalize(&hdr).unwrap();
                let (state, root) = saved[&hash].clone();
                committed.extend(map.chain_up_to(&hash).iter().map(|hdr| hdr.hash));
                let discarded: Vec<HexHash> = saved
                    .keys()
                    .copied()
                    .filter(|saved| !descends_from(&map, saved, &hash))
                    .collect();
                saved.retain(|saved, _| *saved != hash && descends_from(&map, saved, &hash));
                finalized = Some((hash, state, root));
                for block in &discarded {
                    if committed.contains(block) {
                        continue;
                    }
                    let hdr = map.header(block);
                    prop_assert!(m.create_state_after(hdr).is_err());
                    prop_assert!(m.finalize(hdr).is_err());
                    for child in map.children(block) {
                        prop_assert!(m.create_state_for(map.header(&child)).is_err());
                    }
                }
            }
        }

        prop_assert_eq!(m.check_invariants(), saved.len());
        prop_assert_eq!(m.unfinalized_count(), saved.len());
        for (storage, _, state, root) in &storages {
            assert_reads(storage, state)?;
            prop_assert_eq!(storage.root().unwrap(), *root);
        }
        if let Some((storage, hash, state, root)) =
            (!storages.is_empty()).then(|| &storages[pick_index(bits, storages.len())])
        {
            let key = model_key(b'u', u8::try_from(bits % u16::from(USER_KEYS)).unwrap());
            let proof = storage.get_with_proof::<User>(key.clone());
            if committed.contains(hash) {
                let (_, newest, newest_root) = finalized.as_ref().unwrap();
                let (proof, _, proven_root) = proof.unwrap();
                prop_assert_eq!(proof.value, newest.user.get(&key).cloned());
                prop_assert_eq!(proven_root, *newest_root);
            } else if saved.contains_key(hash) {
                let (proof, _, proven_root) = proof.unwrap();
                prop_assert_eq!(proof.value, state.user.get(&key).cloned());
                prop_assert_eq!(proven_root, *root);
            } else {
                assert_stale(&proof.unwrap_err(), true);
            }
        }
    }

    // Finalizing the highest saved block discards every other one.
    let highest = saved
        .keys()
        .max_by_key(|hash| (map.header(hash).height, **hash))
        .copied();
    if let Some(hash) = highest {
        m.finalize(map.header(&hash)).unwrap();
        let (state, root) = saved[&hash].clone();
        finalized = Some((hash, state, root));
    }
    prop_assert_eq!(m.unfinalized_count(), 0);
    prop_assert_eq!(m.check_invariants(), 0);
    if let Some((_, state, root)) = &finalized {
        let (storage, _) = m.create_finalized_state().unwrap();
        assert_reads(&storage, state)?;
        prop_assert_eq!(storage.root().unwrap(), *root);
    }
}

/// An index in `0..len` from `bits` (independent enough of the other uses of `bits`).
fn pick_index(bits: u16, len: usize) -> usize {
    usize::from(bits.rotate_left(5)) % len
}

/// The block of the main fork at `height` with its deterministic writes.
fn chain_block(height: u64) -> (TestHeader, [Writes; 3]) {
    let hdr = TestHeader::linear(height);
    let bits = u16::try_from(height.wrapping_mul(0x2f1b) & 0xffff).unwrap();
    let writes = block_writes(&hdr, bits);
    (hdr, writes)
}

/// Executes and saves the main fork's blocks `heights`.
fn execute_chain(m: &mut Manager, heights: std::ops::RangeInclusive<u64>) {
    for height in heights {
        let (hdr, writes) = chain_block(height);
        write_block(m, &hdr, &writes[0], &writes[1], &writes[2]);
    }
}

/// P3: a main fork of `blocks` blocks, executed, then finalized in steps (after the blocks
/// `finalize_after` marks, and the last one). One finalization is hit by a fault at a random
/// commit point (or between two blocks' commits); the manager is dropped and reopened (crash
/// recovery), the blocks after its finalized block are executed again and the last one
/// finalized. Every RocksDB row and the roots equal an uncrashed run's.
#[test_strategy::proptest(cases = 8)]
fn crash_then_recovery_and_replay_match_an_uncrashed_run(
    #[strategy(2u64..=5)] blocks: u64,
    #[strategy(prop_vec(any::<bool>(), 4))] finalize_after: Vec<bool>,
    #[strategy(0usize..8)] point: usize,
    crash_at: Index,
) {
    let points = [
        CommitPoint::BeforeKernelNomt,
        CommitPoint::BeforeUserNomt,
        CommitPoint::BeforeLedger,
        CommitPoint::BeforeAccessory,
        CommitPoint::BeforeArchival,
        CommitPoint::BeforeLive,
        CommitPoint::AfterLive,
        CommitPoint::BetweenSegments,
    ];
    let point = points[point];
    let mut targets: Vec<u64> = (1..blocks)
        .filter(|height| finalize_after[usize::try_from(*height - 1).unwrap()])
        .collect();
    targets.push(blocks);
    let crash_at = crash_at.index(targets.len());

    let [crashed_dir, replay_dir] = <[_; 2]>::try_from(tempdirs(2)).ok().unwrap();
    let mut replay = Manager::new_in(replay_dir, |_| {});
    execute_chain(&mut replay, 1..=blocks);
    for target in &targets {
        replay.finalize(&TestHeader::linear(*target)).unwrap();
    }

    let mut m = Manager::new_in(crashed_dir, |_| {});
    execute_chain(&mut m, 1..=blocks);
    for (index, target) in targets.iter().enumerate() {
        if index == crash_at {
            m.set_commit_hook(Some(fail_at(point)));
        }
        let finalized = m.finalize(&TestHeader::linear(*target));
        if index != crash_at || finalized.is_ok() {
            // `BetweenSegments` on a one-block finalization: never reached.
            finalized.unwrap();
            m.set_commit_hook(None);
            continue;
        }
        let err = finalized.unwrap_err();
        prop_assert!(format!("{err:#}").contains("injected fault"), "{err:#}");
        // Reopened: the blocks after the finalized one are lost, executed again.
        m = m.reopen();
        let height = m.finalized().map_or(0, |block| block.da_height);
        prop_assert!(!m.is_poisoned());
        execute_chain(&mut m, height.checked_add(1).unwrap()..=blocks);
        m.finalize(&TestHeader::linear(blocks)).unwrap();
        break;
    }

    prop_assert_eq!(m.finalized(), replay.finalized());
    let (crashed, _) = m.create_finalized_state().unwrap();
    let (uncrashed, _) = replay.create_finalized_state().unwrap();
    prop_assert_eq!(crashed.root().unwrap(), uncrashed.root().unwrap());
    let mut state = State::default();
    for height in 1..=blocks {
        apply(&mut state, &chain_block(height).1);
    }
    assert_reads(&crashed, &state)?;
    prop_assert!(
        dump(m.path()) == dump(replay.path()),
        "{point:?} at finalization {crash_at}"
    );
}

/// P5: a random history of user and accessory writes (deletes included) on the main fork, pruned
/// periodically with a random `versions_to_keep` and budget, while storages taken at random
/// versions are held for random spans. After every finalization each held storage reads its own
/// version's state (pins), and at the end: reads from the newest cutoff on are the model's,
/// reads below it are the model's or exactly `PrunedVersion` (never another value), unbound
/// reads are the tip's; once pruning has caught up, each key keeps at most `L - cutoff + 1` rows
/// in the archival and accessory stores (the "pinned span" over `k`), and `k + 1` once the
/// storages are dropped.
#[test_strategy::proptest(cases = 8)]
fn pruning_model(
    #[strategy(prop_vec(any::<u16>(), 4..14))] history: Vec<u16>,
    #[strategy(1u64..=3)] versions_to_keep: u64,
    #[strategy(1u64..=4)] max_keys_per_run: u64,
    #[strategy(prop_vec(any::<(bool, u8)>(), 14))] pins: Vec<(bool, u8)>,
) {
    let nz = |n: u64| NonZeroU64::new(n).unwrap();
    let mut m = Manager::with_config(|config| {
        config.pruning = PrunerConfig::Periodic {
            every_versions: nz(1),
            versions_to_keep: nz(versions_to_keep),
            max_keys_per_run: nz(max_keys_per_run),
        }
    });
    let mut states: Vec<State> = Vec::new();
    let mut state = State::default();
    let mut held: Vec<(TestStorage, usize, u64)> = Vec::new();
    let mut max_cutoff: Option<u64> = None;
    for (index, bits) in history.iter().enumerate() {
        let version = u64::try_from(index).unwrap();
        held.retain(|(_, _, release)| *release > version);
        let hdr = TestHeader::linear(version.checked_add(1).unwrap());
        // No kernel writes and no tag: only user keys and accessory keys.
        let [user, _, accessory] = block_writes(&hdr, *bits);
        let user: Writes = user
            .into_iter()
            .filter(|(key, _)| key.as_ref()[0] == b'u')
            .collect();
        let writes = [user, Vec::new(), accessory];
        write_block(&mut m, &hdr, &writes[0], &writes[1], &writes[2]);
        m.finalize(&hdr).unwrap();
        apply(&mut state, &writes);
        states.push(state.clone());
        if let Some(cutoff) = m.last_prune().and_then(|stats| stats.cutoff) {
            prop_assert!(
                max_cutoff.is_none_or(|max| cutoff.get() >= max),
                "cutoffs never decrease"
            );
            max_cutoff = Some(cutoff.get());
        }
        let (pin, span) = pins[index];
        if pin {
            let (storage, _) = m.create_finalized_state().unwrap();
            held.push((storage, index, version + 1 + u64::from(span % 6)));
        }
        for (storage, at, _) in &held {
            assert_reads(storage, &states[*at])?;
        }
        if let Some((_, at, _)) = held.iter().min_by_key(|(_, at, _)| *at) {
            prop_assert!(max_cutoff.is_none_or(|cutoff| cutoff <= u64::try_from(*at).unwrap()));
        }
    }
    let latest = u64::try_from(states.len() - 1).unwrap();

    let check_history = |m: &mut Manager, floor: Option<u64>| -> Result<(), TestCaseError> {
        let (fresh, _) = m.create_finalized_state().unwrap();
        for (version, state) in (0u64..).zip(&states) {
            for i in 0..USER_KEYS {
                let key = model_key(b'u', i);
                let read = fresh.get_historical::<User>(
                    &key,
                    Some(SlotNumber::new(version)),
                    &Default::default(),
                );
                check_read(read, state.user.get(&key), version, floor)?;
            }
            for i in 0..ACCESSORY_KEYS {
                let key = model_key(b'a', i);
                let read = fresh.get_accessory_historical(&key, Some(SlotNumber::new(version)));
                check_read(read, state.accessory.get(&key), version, floor)?;
            }
        }
        for i in 0..USER_KEYS {
            let key = model_key(b'u', i);
            prop_assert_eq!(
                fresh.get_unbound::<User>(key.clone()),
                state.user.get(&key).cloned()
            );
        }
        Ok(())
    };
    check_history(&mut m, max_cutoff)?;

    // Pruning caught up with the storages still held: each key keeps at most one row at or
    // below the cutoff and one per version after it.
    drain(&mut m);
    if let Some(cutoff) = m.last_prune().unwrap().cutoff {
        let span = latest.checked_sub(cutoff.get()).unwrap();
        check_rows(&m, span)?;
    }
    for (storage, at, _) in &held {
        assert_reads(storage, &states[*at])?;
    }

    // Without them, `[latest - k, latest]` is kept, and `k + 1` rows per key at most.
    drop(held);
    prop_assert_eq!(m.oldest_pinned_version(), None);
    drain(&mut m);
    let floor = latest.checked_sub(versions_to_keep);
    prop_assert_eq!(
        m.last_prune().unwrap().cutoff.map(|cutoff| cutoff.get()),
        floor
    );
    check_history(&mut m, floor)?;
    check_rows(&m, versions_to_keep)?;
}

/// Prunes until no store has a backlog.
fn drain(m: &mut Manager) {
    while m.prune_now().unwrap().has_backlog() {}
}

/// At most `span + 1` archival rows of each user key and accessory rows of each accessory key.
fn check_rows(m: &Manager, span: u64) -> Result<(), TestCaseError> {
    let rows = dump(m.path());
    let count = |dir: &str, cf: &str| {
        rows.get(&(dir.to_owned(), cf.to_owned()))
            .map_or(0, Vec::len)
    };
    let per_key = usize::try_from(span.checked_add(1).unwrap()).unwrap();
    let user_rows = count(
        crate::FlatStateDb::ARCHIVAL_DB_PATH_SUFFIX,
        "user_state_historical_values",
    );
    prop_assert!(
        user_rows <= usize::from(USER_KEYS) * per_key,
        "{user_rows} user rows, span {span}"
    );
    let accessory_rows = count(crate::AccessoryDb::DB_PATH_SUFFIX, "module_accessory_state");
    prop_assert!(
        accessory_rows <= usize::from(ACCESSORY_KEYS) * per_key,
        "{accessory_rows} accessory rows, span {span}"
    );
    Ok(())
}

/// A historical read at `version`: from `floor` on, exactly the model's value; below it, the
/// model's value or exactly `PrunedVersion` (the oldest available version above `version`, at
/// most `floor`).
fn check_read(
    read: anyhow::Result<Option<SlotValue>>,
    expected: Option<&SlotValue>,
    version: u64,
    floor: Option<u64>,
) -> Result<(), TestCaseError> {
    match read {
        Ok(value) => prop_assert_eq!(value.as_ref(), expected, "version {}", version),
        Err(err) => {
            let below_floor = floor.is_some_and(|floor| version < floor);
            prop_assert!(below_floor, "version {version}, floor {floor:?}: {err:#}");
            match err.downcast_ref::<HistoricalValueError>() {
                Some(HistoricalValueError::PrunedVersion {
                    requested_version,
                    oldest_available_version: Some(oldest),
                }) => {
                    prop_assert_eq!(*requested_version, version);
                    prop_assert!(version < *oldest && Some(*oldest) <= floor, "{err:#}");
                }
                _ => prop_assert!(false, "not a PrunedVersion error: {err:#}"),
            }
        }
    }
    Ok(())
}

/// A step of `verifier_replays_the_prover_storage_on_forks`: the parent of a new block (among
/// the finalized block and the saved ones), its operations, and the block to finalize after it
/// (among the saved ones), if any.
fn replay_step() -> impl Strategy<Value = (Index, Vec<Op>, Option<Index>)> {
    (
        any::<Index>(),
        prop_vec(any::<Op>(), 0..16),
        any::<Option<Index>>(),
    )
}

/// TODO.md's property-test item (native root == guest root for random read/write sets) on the
/// storages a node executes blocks on: random blocks of random operations, each on a random
/// saved or the finalized block (forks of unfinalized blocks), executed with the witness on and
/// replayed by the guest verifier from the witness alone (same results, accesses, root: the
/// `execute` of `proofs.rs`), with random finalizations in between. Generalizes
/// `witness_replay_on_overlay_storage` (one fixed tree) and `verifier_replays_the_prover_storage`
/// (committed blocks only).
#[test_strategy::proptest(cases = 6)]
fn verifier_replays_the_prover_storage_on_forks(
    #[strategy(prop_vec(replay_step(), 2..7))] steps: Vec<(Index, Vec<Op>, Option<Index>)>,
) {
    let mut m = Manager::with_config(|config| config.witness = WitnessMode::On);
    let mut headers: HashMap<HexHash, TestHeader> = HashMap::new();
    let mut saved: BTreeMap<HexHash, (InMemoryState, Root)> = BTreeMap::new();
    let mut finalized: Option<(TestHeader, InMemoryState, Root)> = None;
    let mut next_fork = TestHeader::MAIN_FORK;
    let descends = |headers: &HashMap<HexHash, TestHeader>, hash: &HexHash, ancestor: &HexHash| {
        let mut current = *hash;
        loop {
            if current == *ancestor {
                return true;
            }
            match headers.get(&current) {
                Some(hdr) => current = hdr.prev,
                None => return false,
            }
        }
    };
    for (parent, ops, finalize) in steps {
        let parents: Vec<&TestHeader> = finalized
            .iter()
            .map(|(hdr, ..)| hdr)
            .chain(saved.keys().map(|hash| &headers[hash]))
            .collect();
        let (hdr, parent_state) = if parents.is_empty() {
            (TestHeader::linear(1), InMemoryState::default())
        } else {
            let parent = parents[parent.index(parents.len())].clone();
            next_fork = next_fork.checked_add(1).unwrap();
            let height = parent.height.checked_add(1).unwrap();
            let state = saved.get(&parent.hash).map_or_else(
                || finalized.as_ref().unwrap().1.clone(),
                |(state, _)| state.clone(),
            );
            let hdr = TestHeader {
                hash: block_hash(next_fork, height),
                prev: parent.hash,
                height,
            };
            (hdr, state)
        };
        let (state, root) = execute(&mut m, &hdr, &ops, &parent_state)?;
        headers.insert(hdr.hash, hdr.clone());
        saved.insert(hdr.hash, (state, root));
        if let Some(pick) = finalize {
            let candidates: Vec<HexHash> = saved.keys().copied().collect();
            let hash = candidates[pick.index(candidates.len())];
            m.finalize(&headers[&hash]).unwrap();
            let (state, root) = saved[&hash].clone();
            saved.retain(|saved, _| *saved != hash && descends(&headers, saved, &hash));
            finalized = Some((headers[&hash].clone(), state, root));
        }
        prop_assert_eq!(m.check_invariants(), saved.len());
    }
    let highest = saved
        .keys()
        .max_by_key(|hash| (headers[hash].height, **hash))
        .copied();
    if let Some(hash) = highest {
        m.finalize(&headers[&hash]).unwrap();
        let (state, root) = saved[&hash].clone();
        finalized = Some((headers[&hash].clone(), state, root));
    }
    let (_, state, root) = finalized.unwrap();
    let (storage, _) = m.create_finalized_state().unwrap();
    assert_state(&storage, &state);
    prop_assert_eq!(storage.root().unwrap(), root);
    prop_assert_eq!(m.unfinalized_count(), 0);
}

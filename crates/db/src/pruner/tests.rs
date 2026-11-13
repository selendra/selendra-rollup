//! Tests of pruning on the state databases ([`TestDbs`], [`DbGroup::prune`]): the cutoff and
//! pins, what `versions_to_keep` keeps, the fixes to upstream's pruners (separate budgets, the
//! accessory watermark, the accessory index, delete markers), crashes between the two writes of
//! a pass, and readers pinning their base version. The storage manager's pruning (periodic,
//! at startup, upstream's tests): `manager::tests::pruning`.

use std::num::NonZeroU64;

use rockbound::schema::Schema;
use selendra_interface::common::SlotNumber;
use selendra_state::namespaces::{Kernel, User};
use selendra_state::{NativeStorage, SlotKey, SlotValue, StateStorageSpec, Storage};

use super::*;
use crate::harness::{TestDbs, TestStorage};
use crate::schema::{AccessoryKeysByVersion, ModuleAccessoryState, VersionedNamespace};
use crate::test_utils::blocks::dump;
use crate::{AccessoryDb, CommitPoint, HistoricalValueError, WitnessMode, fail_at};

type Spec = StateStorageSpec;
type Dbs = TestDbs<Spec>;
type Prover = TestStorage<Spec>;
/// One namespace's writes of a version.
type Writes = Vec<(SlotKey, Option<SlotValue>)>;

fn nz(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).unwrap()
}

fn key(bytes: &[u8]) -> SlotKey {
    SlotKey::try_from_bytes(bytes).unwrap()
}

/// The value written at `version` in these tests.
fn val(version: u64) -> Option<SlotValue> {
    Some(SlotValue::from(version.to_be_bytes().to_vec()))
}

fn v(version: u64) -> Option<SlotNumber> {
    Some(SlotNumber::new(version))
}

fn user_at(storage: &Prover, key: &SlotKey, version: u64) -> anyhow::Result<Option<SlotValue>> {
    storage.get_historical::<User>(key, v(version), &Default::default())
}

fn kernel_at(storage: &Prover, key: &SlotKey, version: u64) -> anyhow::Result<Option<SlotValue>> {
    storage.get_historical::<Kernel>(key, v(version), &Default::default())
}

fn accessory_at(
    storage: &Prover,
    key: &SlotKey,
    version: u64,
) -> anyhow::Result<Option<SlotValue>> {
    storage.get_accessory_historical(key, v(version))
}

/// `result` is exactly `PrunedVersion { requested_version, oldest_available_version }`.
fn assert_pruned<T: core::fmt::Debug>(
    result: anyhow::Result<T>,
    requested: u64,
    oldest_available: u64,
) {
    let err = result.expect_err("a pruned version");
    match err.downcast_ref::<HistoricalValueError>() {
        Some(HistoricalValueError::PrunedVersion {
            requested_version,
            oldest_available_version,
        }) => assert_eq!(
            (*requested_version, *oldest_available_version),
            (requested, Some(oldest_available)),
            "{err:#}"
        ),
        _ => panic!("not a PrunedVersion error: {err:#}"),
    }
}

/// The rows of column family `cf` of the database directory `dir` under `dbs`.
fn row_count(dbs: &Dbs, dir: &str, cf: &str) -> usize {
    dump(dbs.path())
        .get(&(dir.to_owned(), cf.to_owned()))
        .map_or(0, Vec::len)
}

/// The accessory index rows (all versions).
fn index_rows(dbs: &Dbs) -> Vec<(SlotNumber, Vec<u8>)> {
    let start: (SlotNumber, &[u8]) = (SlotNumber::GENESIS, &[]);
    let end: (SlotNumber, &[u8]) = (SlotNumber::MAX, &[]);
    let mut iter = dbs
        .group()
        .accessory_db()
        .iter_range::<AccessoryKeysByVersion>(&start, &end)
        .unwrap();
    iter.seek_to_first();
    iter.map(|row| row.unwrap().key).collect()
}

#[test]
fn cutoff_is_the_older_of_the_window_and_the_oldest_pin() {
    assert_eq!(cutoff(None, nz(1), None), None);
    assert_eq!(cutoff(v(3), nz(5), None), None);
    assert_eq!(cutoff(v(3), nz(3), None), v(0));
    assert_eq!(cutoff(v(10), nz(3), None), v(7));
    assert_eq!(cutoff(v(10), nz(3), v(5)), v(5));
    assert_eq!(cutoff(v(10), nz(3), v(9)), v(7));
    assert_eq!(cutoff(v(10), nz(3), v(0)), v(0));
    assert_eq!(cutoff(v(u64::MAX), nz(u64::MAX), None), v(0));
}

#[test]
fn pins_are_counted_and_released() {
    let pins = VersionPins::default();
    assert_eq!(pins.oldest(), None);
    let five = pins.pin(SlotNumber::new(5));
    let three = pins.pin(SlotNumber::new(3));
    let three_clone = three.clone();
    let three_again = pins.pin(SlotNumber::new(3));
    assert_eq!(
        (five.version(), three.version()),
        (v(5).unwrap(), v(3).unwrap())
    );
    assert_eq!(pins.oldest(), v(3));
    drop(three);
    drop(three_clone);
    assert_eq!(pins.oldest(), v(3), "another pin of version 3 is alive");
    drop(three_again);
    assert_eq!(pins.oldest(), v(5));
    drop(five);
    assert_eq!(pins.oldest(), None);
    // Poison-tolerant: a pin dropped while another thread panicked holding the lock.
    let pin = pins.pin(SlotNumber::new(7));
    let shared = pins.clone();
    let _ = std::thread::spawn(move || {
        let _guard = shared.pins.lock().unwrap();
        panic!("poison the pins lock");
    })
    .join();
    drop(pin);
    assert_eq!(pins.oldest(), None);
}

/// `versions_to_keep = k` keeps `k + 1` versions readable, `[L - k, L]`, in the user values, the
/// kernel values and the accessory store; reads below fail with exactly `PrunedVersion` (the
/// watermark is `L - k - 1` for keys written every version).
#[test]
fn versions_to_keep_k_keeps_k_plus_one_versions() {
    let mut dbs = Dbs::new();
    let (u, k, a) = (key(b"u1"), key(b"k1"), key(b"a1"));
    for version in 0..=9 {
        dbs.commit_writes(
            &[(u.clone(), val(version))],
            &[(k.clone(), val(version))],
            &[(a.clone(), val(version))],
        );
    }
    let stats = dbs.prune(3, 1000).unwrap();
    assert_eq!(stats.cutoff, v(6));
    assert!(!stats.has_backlog());
    // Versions 0..=6 consumed: 6 predecessors each.
    for store in [stats.flat_user, stats.flat_kernel, stats.accessory] {
        assert_eq!(
            (store.entries, store.rows_deleted, store.backlog),
            (7, 6, false)
        );
    }
    let storage = dbs.storage(WitnessMode::Off);
    for version in 0..=9 {
        if version < 6 {
            assert_pruned(user_at(&storage, &u, version), version, 6);
            assert_pruned(kernel_at(&storage, &k, version), version, 6);
            assert_pruned(accessory_at(&storage, &a, version), version, 6);
        } else {
            assert_eq!(user_at(&storage, &u, version).unwrap(), val(version));
            assert_eq!(kernel_at(&storage, &k, version).unwrap(), val(version));
            assert_eq!(accessory_at(&storage, &a, version).unwrap(), val(version));
        }
    }
    // The newest values, and the root reads, are untouched.
    assert_eq!(storage.get::<User>(&u, &Default::default()), val(9));
    assert_eq!(storage.get_accessory(&a), val(9));
    assert!(storage.get_root_hash(SlotNumber::GENESIS).is_some());
    // Nothing left to prune: the next pass inspects nothing.
    drop(storage);
    let stats = dbs.prune(3, 1000).unwrap();
    assert_eq!(stats.rows_deleted(), 0);
    assert_eq!(stats.flat_user.entries, 0);
}

/// P2: user and kernel values have a budget each. Upstream gave the kernel what the user values
/// left of one budget (`max - user deletes`), so a user backlog that filled it starved kernel
/// pruning (no kernel pass at all).
#[test]
fn kernel_pruning_progresses_under_user_backlog() {
    let mut dbs = Dbs::new();
    let users: Vec<SlotKey> = (0u8..20).map(|i| key(&[b'u', i])).collect();
    let kernel = key(b"k1");
    for version in 0..=4 {
        let user: Writes = users.iter().map(|u| (u.clone(), val(version))).collect();
        dbs.commit_writes(&user, &[(kernel.clone(), val(version))], &[]);
    }
    // Consume version 0's entries (first writes: nothing to delete).
    let stats = dbs.prune(4, 1000).unwrap();
    assert_eq!((stats.cutoff, stats.rows_deleted()), (v(0), 0));
    // Now every user entry has a predecessor: the user budget is all deletes.
    let stats = dbs.prune(1, 8).unwrap();
    assert_eq!(stats.cutoff, v(3));
    assert_eq!(
        (
            stats.flat_user.entries,
            stats.flat_user.rows_deleted,
            stats.flat_user.backlog
        ),
        (8, 8, true)
    );
    // The kernel's entries of versions 1..=3, each deleting its predecessor.
    assert_eq!(
        (
            stats.flat_kernel.entries,
            stats.flat_kernel.rows_deleted,
            stats.flat_kernel.backlog
        ),
        (3, 3, false)
    );
    let storage = dbs.storage(WitnessMode::Off);
    assert_pruned(kernel_at(&storage, &kernel, 2), 2, 3);
    assert_eq!(kernel_at(&storage, &kernel, 3).unwrap(), val(3));
}

/// A1: an accessory read at or below the pruned rows is a `PrunedVersion` error. Upstream kept no
/// watermark: with the key's older row deleted, the lookup landed on another key's row and read
/// `None`, a silent wrong answer.
#[test]
fn accessory_read_below_watermark_is_pruned_error() {
    let mut dbs = Dbs::new();
    let (a, b) = (key(b"a1"), key(b"b1"));
    for version in 0..=5 {
        let mut accessory = vec![(b.clone(), val(version))];
        if version == 0 || version == 3 {
            accessory.push((a.clone(), val(version)));
        }
        dbs.commit_writes(&[], &[], &accessory);
    }
    let storage = dbs.storage(WitnessMode::Off);
    assert_eq!(accessory_at(&storage, &a, 1).unwrap(), val(0));
    drop(storage);

    let stats = dbs.prune(1, 1000).unwrap();
    assert_eq!(stats.cutoff, v(4));
    // `a@0` (before `a@3`) and `b@0..=3`.
    assert_eq!(stats.accessory.rows_deleted, 5);
    let storage = dbs.storage(WitnessMode::Off);
    for version in 0..=3 {
        assert_pruned(accessory_at(&storage, &a, version), version, 4);
        assert_pruned(accessory_at(&storage, &b, version), version, 4);
    }
    assert_eq!(accessory_at(&storage, &a, 4).unwrap(), val(3));
    assert_eq!(accessory_at(&storage, &a, 5).unwrap(), val(3));
    assert_eq!(accessory_at(&storage, &b, 4).unwrap(), val(4));
    // The merged read (the accessory DB's own API) and the unbound read too.
    let db = AccessoryDb::with_reader(rockbound::cache::delta_reader::DeltaReader::new(
        dbs.group().accessory_db().clone(),
        Vec::new(),
    ));
    let err = db.get_value_option(&a, SlotNumber::new(1)).unwrap_err();
    assert!(
        matches!(
            err.downcast_ref::<HistoricalValueError>(),
            Some(HistoricalValueError::PrunedVersion { .. })
        ),
        "{err:#}"
    );
    assert_eq!(db.get_value_option(&a, SlotNumber::MAX).unwrap(), val(3));
    assert_pruned(storage.get_accessory_unbound(a.clone(), v(2)), 2, 4);
    assert_eq!(
        storage.get_accessory_unbound(a.clone(), None).unwrap(),
        val(3)
    );
}

/// The accessory index (`AccessoryKeysByVersion`, one row per write) no longer grows without
/// bound: pruning consumes its rows up to the cutoff (upstream only read it for rollbacks, never
/// pruned it). Rows of deleted keys go entirely, delete markers included. Rolling back the
/// newest version still works afterwards.
#[test]
fn accessory_index_rows_are_bounded() {
    let mut dbs = Dbs::new();
    let (hot, once, gone) = (key(b"hot"), key(b"once"), key(b"gone"));
    for version in 0..=9 {
        let mut accessory = vec![(hot.clone(), val(version))];
        match version {
            0 => accessory.extend([(once.clone(), val(0)), (gone.clone(), val(0))]),
            2 => accessory.push((gone.clone(), None)),
            _ => {}
        }
        dbs.commit_writes(&[], &[], &accessory);
    }
    let accessory_dir = AccessoryDb::DB_PATH_SUFFIX;
    let values_cf = ModuleAccessoryState::COLUMN_FAMILY_NAME;
    assert_eq!(index_rows(&dbs).len(), 13);
    assert_eq!(row_count(&dbs, accessory_dir, values_cf), 13);

    let stats = dbs.prune(2, 1000).unwrap();
    assert_eq!(stats.cutoff, v(7));
    // Only versions 8 and 9 keep index rows.
    let rows = index_rows(&dbs);
    assert_eq!(
        rows.iter()
            .map(|(version, _)| version.get())
            .collect::<Vec<_>>(),
        [8, 9]
    );
    // `hot@7..=9`, `once@0`: `gone`'s rows are gone, its marker included.
    assert_eq!(row_count(&dbs, accessory_dir, values_cf), 4);
    let storage = dbs.storage(WitnessMode::Off);
    assert_eq!(accessory_at(&storage, &once, 9).unwrap(), val(0));
    assert_eq!(accessory_at(&storage, &gone, 9).unwrap(), None);
    assert_eq!(accessory_at(&storage, &hot, 7).unwrap(), val(7));
    drop(storage);

    // Rolling back the newest version (crash recovery's step) still finds its index rows.
    let db = dbs.group().accessory_db();
    AccessoryDb::rollback(db).unwrap();
    assert_eq!(
        AccessoryDb::latest_version_and_root(db)
            .unwrap()
            .map(|(version, _)| version),
        v(8)
    );
    let reader = AccessoryDb::with_reader(rockbound::cache::delta_reader::DeltaReader::new(
        db.clone(),
        Vec::new(),
    ));
    assert_eq!(
        reader.get_value_option(&hot, SlotNumber::MAX).unwrap(),
        val(8)
    );
    assert_eq!(index_rows(&dbs).len(), 1);
}

/// A pass whose accessory write is lost (a crash after the flat store's write): the flat store is
/// pruned, the accessory store reads as before (no watermark, no deletes), nothing is poisoned,
/// and the next pass prunes the accessory store. A pass failing before its first write changes
/// nothing.
#[test]
fn crash_between_flat_and_accessory_pruning_writes() {
    let mut dbs = Dbs::new();
    let (u, a) = (key(b"u1"), key(b"a1"));
    for version in 0..=5 {
        dbs.commit_writes(
            &[(u.clone(), val(version))],
            &[],
            &[(a.clone(), val(version))],
        );
    }

    dbs.set_commit_hook(Some(fail_at(CommitPoint::BeforePruneFlat)));
    let err = dbs.prune(1, 1000).unwrap_err();
    assert!(format!("{err:#}").contains("injected fault"), "{err:#}");
    assert!(!dbs.group().is_poisoned());
    let storage = dbs.storage(WitnessMode::Off);
    assert_eq!(user_at(&storage, &u, 0).unwrap(), val(0));
    assert_eq!(accessory_at(&storage, &a, 0).unwrap(), val(0));
    drop(storage);

    dbs.set_commit_hook(Some(fail_at(CommitPoint::BeforePruneAccessory)));
    let err = dbs.prune(1, 1000).unwrap_err();
    assert!(format!("{err:#}").contains("injected fault"), "{err:#}");
    assert!(!dbs.group().is_poisoned());
    // As after a crash: reopened.
    let mut dbs = dbs.reopen();
    let storage = dbs.storage(WitnessMode::Off);
    assert_pruned(user_at(&storage, &u, 0), 0, 4);
    assert_eq!(user_at(&storage, &u, 4).unwrap(), val(4));
    for version in 0..=5 {
        assert_eq!(accessory_at(&storage, &a, version).unwrap(), val(version));
    }
    drop(storage);

    let stats = dbs.prune(1, 1000).unwrap();
    // The flat store's entries were consumed by the first write.
    assert_eq!(stats.flat_user.entries, 0);
    assert_eq!(
        (stats.accessory.entries, stats.accessory.rows_deleted),
        (5, 4)
    );
    let storage = dbs.storage(WitnessMode::Off);
    assert_pruned(accessory_at(&storage, &a, 3), 3, 4);
    assert_eq!(accessory_at(&storage, &a, 4).unwrap(), val(4));
    assert_eq!(user_at(&storage, &u, 5).unwrap(), val(5));
}

/// Critique #10: readers from `DbGroup::readers` (and storages on them, and their clones) pin
/// their base version: a pass stops its cutoff there, so their bound reads (which read the
/// archive once newer versions are committed) never meet pruned rows (B14: upstream's stale
/// storage panicked on its next read). Once the last clone is dropped, pruning catches up.
#[test]
fn readers_pin_their_base_version() {
    let mut dbs = Dbs::new();
    let u = key(b"u1");
    for version in 0..=2 {
        dbs.commit_writes(
            &[(u.clone(), val(version))],
            &[],
            &[(u.clone(), val(version))],
        );
    }
    let readers = dbs.group().readers::<u64>().unwrap();
    assert_eq!(readers.historical_state.pinned_version(), v(2));
    drop(readers);
    assert_eq!(dbs.group().oldest_pinned_version(), None);

    let stale = dbs.storage(WitnessMode::Off);
    let stale_clone = stale.clone();
    drop(stale);
    for version in 3..=9 {
        dbs.commit_writes(
            &[(u.clone(), val(version))],
            &[],
            &[(u.clone(), val(version))],
        );
    }
    assert_eq!(dbs.group().oldest_pinned_version(), v(2));
    let stats = dbs.prune(2, 1000).unwrap();
    assert_eq!(stats.cutoff, v(2), "held at the pin, not at 9 - 2");
    assert_eq!(stale_clone.get::<User>(&u, &Default::default()), val(2));
    assert_eq!(stale_clone.get_accessory(&u), val(2));
    assert_eq!(user_at(&stale_clone, &u, 2).unwrap(), val(2));

    drop(stale_clone);
    assert_eq!(dbs.group().oldest_pinned_version(), None);
    let stats = dbs.prune(2, 1000).unwrap();
    assert_eq!(stats.cutoff, v(7));
    let storage = dbs.storage(WitnessMode::Off);
    assert_pruned(user_at(&storage, &u, 2), 2, 7);
    assert_pruned(accessory_at(&storage, &u, 2), 2, 7);
    assert_eq!(user_at(&storage, &u, 7).unwrap(), val(7));
}

/// The flat store's deleted keys lose every archival row once pruned past their deletion
/// (rockbound's P1 fix, through the databases).
#[test]
fn deleted_flat_keys_leave_no_rows() {
    let mut dbs = Dbs::new();
    let (gone, hot) = (key(b"gone"), key(b"hot"));
    dbs.commit_writes(&[(gone.clone(), val(0)), (hot.clone(), val(0))], &[], &[]);
    dbs.commit_writes(&[(gone.clone(), None), (hot.clone(), val(1))], &[], &[]);
    for version in 2..=4 {
        dbs.commit_writes(&[(hot.clone(), val(version))], &[], &[]);
    }
    let archival = crate::FlatStateDb::ARCHIVAL_DB_PATH_SUFFIX;
    let historical = User::HISTORICAL_COLUMN_FAMILY;
    assert_eq!(row_count(&dbs, archival, historical), 7);
    dbs.prune(1, 1000).unwrap();
    // `hot@3`, `hot@4`.
    assert_eq!(row_count(&dbs, archival, historical), 2);
    let storage = dbs.storage(WitnessMode::Off);
    assert_eq!(user_at(&storage, &gone, 3).unwrap(), None);
    assert_eq!(storage.get::<User>(&gone, &Default::default()), None);
}

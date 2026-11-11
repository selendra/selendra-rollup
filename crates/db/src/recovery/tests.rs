//! Tests of startup crash recovery (through [`DbGroup::open`]): a commit interrupted at every
//! point for every kind of block (one that leaves the roots unchanged included: upstream's
//! phantom rows), at genesis, crashes during recovery itself, NOMT hash-table growth around a
//! crash, databases no interrupted commit can leave, and real kills of a child process.
//!
//! Faults are injected with a per-instance hook ([`fail_at`]): an `Err` at the point, then the
//! databases are dropped and reopened. Every write is synced before the next point, so that is
//! the on-disk state a kill there leaves; `kill_9_mid_commit` checks it with real kills.

use std::collections::BTreeMap;
use std::hash::{BuildHasher, RandomState};
use std::io::{BufRead, BufReader, Lines};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use nomt::trie::KeyPath;
use rockbound::SchemaBatch;
use selendra_state::{SlotKey, SlotValue};
use sha2::Sha256;

use super::*;
use crate::faults::CommitHook;
use crate::schema::{AccessoryKeysByVersion, StateRootHashes};
use crate::test_utils::blocks::{Writes, block, dump, key};
use crate::test_utils::{tempdir, tempdirs};
use crate::{DbGroup, NomtChangeSet, StateDbConfig, WitnessMode, fail_at};

type H = Sha256;

fn config(dir: &Path) -> StateDbConfig {
    StateDbConfig::for_tests(dir)
}

fn config_with_buckets(dir: &Path, buckets: u32) -> StateDbConfig {
    let mut config = config(dir);
    let buckets = core::num::NonZeroU32::new(buckets).unwrap();
    config.user.hashtable_buckets = buckets;
    config.kernel.hashtable_buckets = buckets;
    config
}

fn open(dir: &Path) -> DbGroup<H> {
    DbGroup::open(&config(dir)).expect("open the state databases")
}

fn assert_error(err: &anyhow::Error, what: &str) {
    let err = format!("{err:#}");
    assert!(err.contains(what), "expected {what:?} in: {err}");
}

fn writes(pairs: &[(&str, Option<&str>)]) -> Writes {
    pairs
        .iter()
        .map(|(k, v)| {
            (
                key(k.as_bytes()),
                v.map(|v| SlotValue::from(v.as_bytes().to_vec())),
            )
        })
        .collect()
}

/// The writes of one block.
#[derive(Clone, Default)]
struct BlockWrites {
    user: Writes,
    kernel: Writes,
    accessory: Writes,
}

impl BlockWrites {
    fn change_set(&self, group: &DbGroup<H>, version: u64) -> NomtChangeSet {
        block(
            group,
            version,
            self.user.clone(),
            self.kernel.clone(),
            self.accessory.clone(),
        )
    }
}

/// Versions 0 and 1: writes and deletes in every namespace.
fn base() -> [BlockWrites; 2] {
    [
        BlockWrites {
            user: writes(&[("u1", Some("u1@0")), ("u2", Some("u2@0"))]),
            kernel: writes(&[("k1", Some("k1@0")), ("k2", Some("k2@0"))]),
            accessory: writes(&[("a1", Some("a1@0")), ("a2", Some("a2@0"))]),
        },
        BlockWrites {
            user: writes(&[("u1", Some("u1@1")), ("u2", None)]),
            kernel: writes(&[("k2", Some("k2@1"))]),
            accessory: writes(&[("a1", Some("a1@1")), ("a2", None)]),
        },
    ]
}

/// A block after the crashed one (none of its keys written before).
fn next_block() -> BlockWrites {
    BlockWrites {
        user: writes(&[("u4", Some("u4@3"))]),
        kernel: writes(&[("k3", Some("k3@3"))]),
        accessory: writes(&[("a4", Some("a4@3"))]),
    }
}

/// The kinds of block a commit is interrupted in (version 2, on top of [`base`]).
#[derive(Clone, Copy, Debug)]
enum Kind {
    UserAndKernel,
    UserOnly,
    KernelOnly,
    /// Rewrites values with what they already are: no root changes (upstream decided recovery
    /// by root, so it rolled nothing back and left the version's rows behind).
    RootsUnchanged,
    AccessoryOnly,
}

const KINDS: [Kind; 5] = [
    Kind::UserAndKernel,
    Kind::UserOnly,
    Kind::KernelOnly,
    Kind::RootsUnchanged,
    Kind::AccessoryOnly,
];

impl Kind {
    fn writes(self) -> BlockWrites {
        match self {
            Self::UserAndKernel => BlockWrites {
                user: writes(&[("u1", None), ("u3", Some("u3@2"))]),
                kernel: writes(&[("k1", Some("k1@2"))]),
                accessory: writes(&[("a1", Some("a1@2")), ("a3", Some("a3@2"))]),
            },
            Self::UserOnly => BlockWrites {
                user: writes(&[("u1", Some("u1@2"))]),
                ..BlockWrites::default()
            },
            Self::KernelOnly => BlockWrites {
                kernel: writes(&[("k1", Some("k1@2"))]),
                ..BlockWrites::default()
            },
            Self::RootsUnchanged => BlockWrites {
                user: writes(&[("u1", Some("u1@1"))]),
                kernel: writes(&[("k2", Some("k2@1"))]),
                accessory: writes(&[("a1", Some("a1@1"))]),
            },
            Self::AccessoryOnly => BlockWrites {
                accessory: writes(&[("a1", None), ("a3", Some("a3@2"))]),
                ..BlockWrites::default()
            },
        }
    }

    fn changes_kernel(self) -> bool {
        matches!(self, Self::UserAndKernel | Self::KernelOnly)
    }

    fn changes_user(self) -> bool {
        matches!(self, Self::UserAndKernel | Self::UserOnly)
    }
}

/// What recovery rolls back after a commit interrupted at `point`: what was written before it.
fn expected_steps(
    point: CommitPoint,
    changes_kernel: bool,
    changes_user: bool,
) -> Vec<RecoveryStep> {
    if point == CommitPoint::AfterLive {
        return Vec::new();
    }
    let reached = CommitPoint::COMMIT
        .iter()
        .position(|p| *p == point)
        .expect("a commit point");
    [
        (1, changes_kernel, RecoveryStep::KernelNomt),
        (2, changes_user, RecoveryStep::UserNomt),
        // The accessory and archival writes always include the version's root.
        (3, true, RecoveryStep::Accessory),
        (4, true, RecoveryStep::Archival),
    ]
    .into_iter()
    .filter(|(written_before, changed, _)| reached >= *written_before && *changed)
    .map(|(_, _, step)| step)
    .collect()
}

/// The committed state a test expects: its version and every key's value.
#[derive(Clone, Debug, Default)]
struct Model {
    version: Option<u64>,
    user: BTreeMap<SlotKey, Option<SlotValue>>,
    kernel: BTreeMap<SlotKey, Option<SlotValue>>,
    accessory: BTreeMap<SlotKey, Option<SlotValue>>,
}

impl Model {
    fn apply(&mut self, version: u64, block: &BlockWrites) {
        self.version = Some(version);
        for (map, writes) in [
            (&mut self.user, &block.user),
            (&mut self.kernel, &block.kernel),
            (&mut self.accessory, &block.accessory),
        ] {
            map.extend(writes.iter().cloned());
        }
    }

    /// Commits `block` to `group` as the next version and applies it.
    fn commit(&mut self, group: &mut DbGroup<H>, block: &BlockWrites) -> NomtRoots {
        let version = self.version.map_or(0, |v| v.checked_add(1).unwrap());
        group.commit(block.change_set(group, version)).unwrap();
        self.apply(version, block);
        group.roots()
    }

    /// Reads every key through fresh readers: the flat store, the NOMT trees (the value hashes)
    /// and the accessory DB.
    fn check(&self, group: &DbGroup<H>) {
        assert_eq!(
            group.latest_version().unwrap().map(|version| version.get()),
            self.version
        );
        let readers = group.readers::<u64>().unwrap();
        let sessions = readers
            .session_builder
            .begin_both_sessions(WitnessMode::Off)
            .unwrap();
        for (namespace, values, session) in [
            (ProvableNamespace::User, &self.user, &sessions.user),
            (ProvableNamespace::Kernel, &self.kernel, &sessions.kernel),
        ] {
            for (key, expected) in values {
                assert_eq!(
                    readers.historical_state.get_value(namespace, key).unwrap(),
                    *expected,
                    "{namespace:?} {key}"
                );
                let key_path: KeyPath = H::digest(key.as_ref()).into();
                assert_eq!(
                    session.read(key_path).unwrap(),
                    expected
                        .as_ref()
                        .map(|v| v.combine_val_hash_and_size::<H>().to_vec()),
                    "NOMT {namespace:?} {key}"
                );
            }
        }
        drop(sessions);
        if let Some(version) = self.version {
            for (key, expected) in &self.accessory {
                assert_eq!(
                    readers
                        .accessory
                        .get_value_option(key, SlotNumber::new(version))
                        .unwrap(),
                    *expected,
                    "accessory {key}"
                );
            }
        }
    }
}

/// No database holds a row of `version`: no root, no flat-store keys, no accessory index rows.
fn assert_no_rows_at(group: &DbGroup<H>, version: u64) {
    let version = SlotNumber::new(version);
    let end = version.checked_add(1).unwrap();
    let start: (SlotNumber, &[u8]) = (version, &[]);
    let end: (SlotNumber, &[u8]) = (end, &[]);
    let mut index = group
        .accessory_db()
        .iter_range::<AccessoryKeysByVersion>(&start, &end)
        .unwrap();
    index.seek_to_first();
    assert_eq!(index.count(), 0, "accessory index rows of {version}");
    assert_eq!(
        AccessoryDb::root_at(group.accessory_db(), version).unwrap(),
        None
    );
    let flat = group.flat();
    assert_eq!(flat.root_archival_at(version).unwrap(), None);
    let user_keys = flat
        .user_db()
        .iter_pruning_keys_at_version(version.get())
        .unwrap()
        .count();
    let kernel_keys = flat
        .kernel_db()
        .iter_pruning_keys_at_version(version.get())
        .unwrap()
        .count();
    assert_eq!((user_keys, kernel_keys), (0, 0), "flat keys of {version}");
}

/// Commits the base blocks, then `crashed` as version 2 with a fault at `point`, and closes the
/// databases. Returns the model of what reopening them must find, and the crashed block's roots.
fn crash_after_base(dir: &Path, point: CommitPoint, crashed: &BlockWrites) -> (Model, NomtRoots) {
    let mut model = Model::default();
    let mut group = open(dir);
    for block in &base() {
        model.commit(&mut group, block);
    }
    let change_set = crashed.change_set(&group, 2);
    let roots = change_set.roots();
    group.set_commit_hook(Some(fail_at(point)));
    let err = group.commit(change_set).unwrap_err();
    assert_error(&err, "injected fault");
    assert!(group.is_poisoned());
    if point == CommitPoint::AfterLive {
        model.apply(2, crashed);
    }
    (model, roots)
}

// ---------------------------------------------------------------------------------------------
// Every commit point × every kind of block.

/// A commit of version 2 interrupted at `point`, for every kind of block. After reopening:
/// - recovery rolled back exactly the databases written before `point`, and all are at
///   version 1 (2 if the live DB was written) with the same roots (the open's check);
/// - reads match the model, and no database holds a row of the interrupted version;
/// - every column family of every RocksDB database is byte-for-byte the same as in a run that
///   never saw the interrupted block (an uncrashed replay), and the NOMT roots are equal: so
///   any block committed next as version 2 (another one included) leaves no trace of it;
/// - committing the same block again gives the same roots, and the databases stay equal to
///   the replay's through it and the next block.
fn crash_matrix(point: CommitPoint) {
    for kind in KINDS {
        let case = format!("{point:?}, {kind:?}");
        let dirs = tempdirs(2);
        let (crashed_dir, replay_dir) = (dirs[0].path(), dirs[1].path());
        let crashed = kind.writes();
        let after_live = point == CommitPoint::AfterLive;

        let (mut model, roots) = crash_after_base(crashed_dir, point, &crashed);
        let mut group = open(crashed_dir);
        let mut replay = open(replay_dir);
        let mut replay_model = Model::default();
        for block in &base() {
            replay_model.commit(&mut replay, block);
        }
        if after_live {
            replay_model.commit(&mut replay, &crashed);
        }

        assert_eq!(
            group.last_recovery(),
            &RecoveryReport {
                rolled_back: expected_steps(point, kind.changes_kernel(), kind.changes_user()),
                live: Some(SlotNumber::new(if after_live { 2 } else { 1 })),
            },
            "{case}"
        );
        assert_eq!(group.roots(), replay.roots(), "{case}");
        model.check(&group);
        if !after_live {
            assert_no_rows_at(&group, 2);
        }
        assert!(
            dump(crashed_dir) == dump(replay_dir),
            "{case}: the interrupted commit left rows behind"
        );

        if !after_live {
            model.commit(&mut group, &crashed);
            assert_eq!(group.roots(), roots, "{case}: the same block, other roots");
            replay_model.commit(&mut replay, &crashed);
            model.check(&group);
            assert!(dump(crashed_dir) == dump(replay_dir), "{case}");
        }
        model.commit(&mut group, &next_block());
        replay_model.commit(&mut replay, &next_block());
        assert_eq!(group.roots(), replay.roots(), "{case}");
        model.check(&group);
        assert!(dump(crashed_dir) == dump(replay_dir), "{case}");
        drop(group);
        assert_eq!(open(crashed_dir).last_recovery().rolled_back, [], "{case}");
    }
}

#[test]
fn crash_matrix_before_kernel_nomt() {
    crash_matrix(CommitPoint::BeforeKernelNomt);
}

#[test]
fn crash_matrix_before_user_nomt() {
    crash_matrix(CommitPoint::BeforeUserNomt);
}

#[test]
fn crash_matrix_before_accessory() {
    crash_matrix(CommitPoint::BeforeAccessory);
}

#[test]
fn crash_matrix_before_archival() {
    crash_matrix(CommitPoint::BeforeArchival);
}

#[test]
fn crash_matrix_before_live() {
    crash_matrix(CommitPoint::BeforeLive);
}

#[test]
fn crash_matrix_after_live() {
    crash_matrix(CommitPoint::AfterLive);
}

/// A crash during the genesis commit (nothing committed before) is recovered to empty
/// databases, from which genesis commits again (upstream refused to start: "delete the
/// databases").
#[test]
fn crash_during_genesis_commit_recovers_to_empty() {
    let genesis = &base()[0];
    for point in CommitPoint::COMMIT {
        let dirs = tempdirs(2);
        let (crashed_dir, replay_dir) = (dirs[0].path(), dirs[1].path());
        let after_live = point == CommitPoint::AfterLive;
        let roots = {
            let mut group = open(crashed_dir);
            let change_set = genesis.change_set(&group, 0);
            let roots = change_set.roots();
            group.set_commit_hook(Some(fail_at(point)));
            assert_error(&group.commit(change_set).unwrap_err(), "injected fault");
            roots
        };
        let mut group = open(crashed_dir);
        let mut replay = open(replay_dir);
        let mut model = Model::default();
        let mut replay_model = Model::default();
        if after_live {
            model.apply(0, genesis);
            replay_model.commit(&mut replay, genesis);
        }
        assert_eq!(
            group.last_recovery(),
            &RecoveryReport {
                rolled_back: expected_steps(point, true, true),
                live: after_live.then_some(SlotNumber::GENESIS),
            },
            "{point:?}"
        );
        assert_eq!(group.roots(), replay.roots(), "{point:?}");
        model.check(&group);
        assert!(dump(crashed_dir) == dump(replay_dir), "{point:?}");
        if !after_live {
            assert_eq!(group.roots(), NomtRoots::PRE_GENESIS);
            assert_no_rows_at(&group, 0);
            assert_eq!(model.commit(&mut group, genesis), roots, "{point:?}");
            replay_model.commit(&mut replay, genesis);
            model.check(&group);
            assert!(dump(crashed_dir) == dump(replay_dir), "{point:?}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Crashes during recovery.

const ROLLBACK_STEPS: [RecoveryStep; 4] = [
    RecoveryStep::KernelNomt,
    RecoveryStep::UserNomt,
    RecoveryStep::Accessory,
    RecoveryStep::Archival,
];

/// Recovery interrupted before any of its rollbacks (after a crash before the live DB, so every
/// one has work): the next open finishes exactly the rollbacks that had not run, and the one
/// after that has nothing left to do. After a crash past the live DB (the control), recovery
/// has no work and reaches no recovery point.
#[test]
fn crash_during_recovery_is_idempotent() {
    let crashed = Kind::UserAndKernel.writes();
    for (done, step) in ROLLBACK_STEPS.iter().enumerate() {
        let dir = tempdir();
        let (model, _) = crash_after_base(dir.path(), CommitPoint::BeforeLive, &crashed);
        let err = DbGroup::<H>::open_with_hook(
            &config(dir.path()),
            Some(fail_at(CommitPoint::Recovery(*step))),
        )
        .unwrap_err();
        assert_error(&err, "injected fault");
        let group = open(dir.path());
        assert_eq!(
            group.last_recovery().rolled_back,
            ROLLBACK_STEPS[done..],
            "interrupted before {step:?}"
        );
        model.check(&group);
        drop(group);
        let group = open(dir.path());
        assert_eq!(group.last_recovery().rolled_back, []);
        model.check(&group);
    }

    let dir = tempdir();
    let (model, _) = crash_after_base(dir.path(), CommitPoint::AfterLive, &crashed);
    let no_recovery: CommitHook = Arc::new(|point| {
        anyhow::ensure!(
            !matches!(point, CommitPoint::Recovery(_)),
            "recovery reached {point:?}"
        );
        Ok(())
    });
    let group = DbGroup::<H>::open_with_hook(&config(dir.path()), Some(no_recovery)).unwrap();
    assert_eq!(group.last_recovery().rolled_back, []);
    model.check(&group);
}

// ---------------------------------------------------------------------------------------------
// NOMT hash-table growth around a crash.

/// The NOMT hash tables grow only after recovery: a crash, then a reopen with more buckets,
/// rolls back on the old table and grows it afterwards. A commit made on a grown table is
/// rolled back just the same (NOMT's rollback log stores key/value tracebacks, not pages).
#[test]
fn crash_then_reopen_with_more_buckets() {
    let crashed = Kind::UserAndKernel.writes();

    // Crash (both trees ahead), then reopen with twice the buckets.
    let dir = tempdir();
    let (mut model, roots) = crash_after_base(dir.path(), CommitPoint::BeforeAccessory, &crashed);
    let mut group = DbGroup::<H>::open(&config_with_buckets(dir.path(), 1000)).unwrap();
    assert_eq!(
        group.last_recovery().rolled_back,
        [RecoveryStep::KernelNomt, RecoveryStep::UserNomt]
    );
    assert_eq!(group.nomt().bucket_counts(), (1000, 1000));
    model.check(&group);
    assert_eq!(model.commit(&mut group, &crashed), roots);
    drop(group);
    drop(dir);

    // Grow, then crash with only the kernel tree written, then reopen (growing again).
    let dir = tempdir();
    let mut model = Model::default();
    {
        let mut group = open(dir.path());
        for block in &base() {
            model.commit(&mut group, block);
        }
    }
    let mut group = DbGroup::<H>::open(&config_with_buckets(dir.path(), 1000)).unwrap();
    assert_eq!(group.nomt().bucket_counts(), (1000, 1000));
    let change_set = crashed.change_set(&group, 2);
    let roots = change_set.roots();
    group.set_commit_hook(Some(fail_at(CommitPoint::BeforeUserNomt)));
    assert_error(&group.commit(change_set).unwrap_err(), "injected fault");
    drop(group);
    let mut group = DbGroup::<H>::open(&config_with_buckets(dir.path(), 2000)).unwrap();
    assert_eq!(
        group.last_recovery().rolled_back,
        [RecoveryStep::KernelNomt]
    );
    assert_eq!(group.nomt().bucket_counts(), (2000, 2000));
    model.check(&group);
    assert_eq!(model.commit(&mut group, &crashed), roots);
}

/// A crash after recovery but before growing (the [`RecoveryStep::Grow`] point): the next open
/// with the same larger bucket count has nothing to roll back and grows the tables.
#[test]
fn crash_before_growing_then_reopen() {
    let crashed = Kind::UserAndKernel.writes();
    let dir = tempdir();
    let (mut model, roots) = crash_after_base(dir.path(), CommitPoint::BeforeLive, &crashed);
    let large = config_with_buckets(dir.path(), 1000);
    let err = DbGroup::<H>::open_with_hook(
        &large,
        Some(fail_at(CommitPoint::Recovery(RecoveryStep::Grow))),
    )
    .unwrap_err();
    assert_error(&err, "injected fault");
    {
        // Recovered, not grown.
        let nomt = NomtStateDb::<H>::open_no_grow(&large).unwrap();
        assert_eq!(nomt.bucket_counts(), (500, 500));
    }
    let mut group = DbGroup::<H>::open(&large).unwrap();
    assert_eq!(group.last_recovery().rolled_back, []);
    assert_eq!(group.nomt().bucket_counts(), (1000, 1000));
    model.check(&group);
    assert_eq!(model.commit(&mut group, &crashed), roots);
}

// ---------------------------------------------------------------------------------------------
// States no interrupted commit leaves.

/// Commits the base blocks; returns the model.
fn with_base(dir: &Path) -> Model {
    let mut model = Model::default();
    let mut group = open(dir);
    for block in &base() {
        model.commit(&mut group, block);
    }
    model
}

/// The NOMT roots on disk (the databases closed).
fn nomt_roots(dir: &Path) -> NomtRoots {
    NomtStateDb::<H>::open_no_grow(&config(dir))
        .unwrap()
        .root_hashes()
}

/// Databases no interrupted commit can leave are refused with an `Err` (upstream panicked in
/// its final root check, or bailed). When a database records the next version, recovery rolls
/// nothing back on them: it decides before the first rollback, and never spends a NOMT tree's
/// rollback log on a root that is neither the live DB's nor the next version's. When none
/// does, a NOMT tree not at the live DB's root is rolled back unchecked, by one logged commit
/// per open (the cases of trees ahead with no other database ahead).
#[test]
fn open_irreconcilable_dbs_is_error_not_panic() {
    let other_roots = NomtRoots::from_bytes([7; NomtRoots::LENGTH]);
    let crashed = Kind::UserAndKernel.writes();

    // The archival DB two versions ahead of the live DB.
    {
        let dir = tempdir();
        let (_, roots) = crash_after_base(dir.path(), CommitPoint::BeforeLive, &crashed);
        {
            let flat = FlatStateDb::new(dir.path(), 1000, 1000).unwrap();
            flat.archival_db()
                .put::<StateRootHashes>(&SlotNumber::new(3), &other_roots)
                .unwrap();
        }
        for _ in 0..2 {
            let err = DbGroup::<H>::open(&config(dir.path())).unwrap_err();
            assert_error(&err, "the flat archival DB (version Some(3)");
            assert_error(&err, "cannot be recovered");
            // Nothing rolled back.
            assert_eq!(nomt_roots(dir.path()), roots);
            let accessory = AccessoryDb::options().open_in(dir.path()).unwrap();
            assert_eq!(
                AccessoryDb::latest_version_and_root(&Arc::new(accessory)).unwrap(),
                Some((SlotNumber::new(2), roots))
            );
        }
    }

    // The NOMT trees three commits ahead, no other database. A rollback leaves them ahead (the
    // check after it fails), so the open fails; the next opens roll them back further (NOMT's
    // log keeps more than the last commit after a restart: see the module docs), each failing,
    // until both trees are back at the live DB's roots: then all databases agree again.
    {
        let dir = tempdir();
        let model = with_base(dir.path());
        let group = open(dir.path());
        let third = BlockWrites {
            kernel: writes(&[("k4", Some("k4@4"))]),
            ..BlockWrites::default()
        };
        for (version, block) in [(2, &crashed), (3, &next_block()), (4, &third)] {
            let overlay = block.change_set(&group, version).into_nomt_overlay();
            group.nomt().commit(overlay, &Faults::default()).unwrap();
        }
        drop(group);
        let mut failed = 0;
        let group = loop {
            match DbGroup::<H>::open(&config(dir.path())) {
                Ok(group) => break group,
                Err(err) => {
                    assert_error(&err, "after rolling back the last commit of the NOMT");
                    assert_error(&err, "cannot be recovered");
                    failed += 1;
                    assert!(failed < 8, "{err:#}");
                }
            }
        };
        assert!(failed >= 2, "an open succeeded with the trees ahead");
        assert_eq!(group.last_recovery().live, Some(SlotNumber::new(1)));
        model.check(&group);
    }

    // A NOMT tree ahead of the live DB with nothing logged to roll back (written with NOMT's
    // rollback log off).
    {
        let dir = tempdir();
        drop(open(dir.path()));
        let config = config(dir.path());
        let mut options = config.kernel.nomt_options(&config.kernel_nomt_path());
        options.rollback(false);
        let tree = nomt::Nomt::<nomt::hasher::BinaryHasher<H>>::open(options).unwrap();
        let session = tree.begin_session(nomt::SessionParams::default());
        let key_path: KeyPath = H::digest(b"k1").into();
        session
            .finish(vec![(
                key_path,
                nomt::KeyReadWrite::Write(Some(vec![1; 36])),
            )])
            .unwrap()
            .commit(&tree)
            .unwrap();
        drop(tree);
        for _ in 0..2 {
            let err = DbGroup::<H>::open(&config).unwrap_err();
            assert_error(&err, "rolling back the last commit of the kernel NOMT tree");
            assert_error(&err, "not enough logged");
        }
    }

    // A NOMT tree at neither the live DB's root nor the next version's (which the accessory DB
    // recorded): refused before its rollback log is used. With the bogus accessory version
    // removed, the same tree rolls back (unchecked: no database records the next version).
    {
        let dir = tempdir();
        let model = with_base(dir.path());
        let group = open(dir.path());
        let overlay = crashed.change_set(&group, 2).into_nomt_overlay();
        group.nomt().commit(overlay, &Faults::default()).unwrap();
        let ahead = group.roots();
        let mut roots = SchemaBatch::new();
        roots
            .put::<StateRootHashes>(&SlotNumber::new(2), &other_roots)
            .unwrap();
        AccessoryDb::commit(group.accessory_db(), &SchemaBatch::new(), &roots).unwrap();
        drop(group);
        let err = DbGroup::<H>::open(&config(dir.path())).unwrap_err();
        assert_error(&err, "NOMT Kernel tree's root");
        assert_error(&err, "is neither the flat live DB's");
        assert_eq!(nomt_roots(dir.path()), ahead);

        let accessory = Arc::new(AccessoryDb::options().open_in(dir.path()).unwrap());
        AccessoryDb::rollback(&accessory).unwrap();
        drop(accessory);
        let group = open(dir.path());
        assert_eq!(
            group.last_recovery().rolled_back,
            [RecoveryStep::KernelNomt, RecoveryStep::UserNomt]
        );
        model.check(&group);
    }

    // The accessory DB behind the live DB.
    {
        let dir = tempdir();
        with_base(dir.path());
        let accessory = Arc::new(AccessoryDb::options().open_in(dir.path()).unwrap());
        AccessoryDb::rollback(&accessory).unwrap();
        drop(accessory);
        let err = DbGroup::<H>::open(&config(dir.path())).unwrap_err();
        assert_error(&err, "the accessory DB (version Some(0)");
        assert_error(&err, "cannot be recovered");
    }

    // The accessory DB, then the archival DB, one version ahead, but with another root than the
    // live DB's at the live version: refused before anything is rolled back.
    for archival in [false, true] {
        let dir = tempdir();
        let (_, roots) = crash_after_base(dir.path(), CommitPoint::BeforeLive, &crashed);
        let name = if archival {
            let flat = FlatStateDb::new(dir.path(), 1000, 1000).unwrap();
            flat.archival_db()
                .put::<StateRootHashes>(&SlotNumber::new(1), &other_roots)
                .unwrap();
            "flat archival DB"
        } else {
            AccessoryDb::options()
                .open_in(dir.path())
                .unwrap()
                .put::<StateRootHashes>(&SlotNumber::new(1), &other_roots)
                .unwrap();
            "accessory DB"
        };
        let err = DbGroup::<H>::open(&config(dir.path())).unwrap_err();
        assert_error(&err, &format!("the {name} is at version 2, one after"));
        assert_error(
            &err,
            &format!("its roots at 1 ({other_roots}) are not the live DB's"),
        );
        assert_error(&err, "cannot be recovered");
        // Nothing rolled back.
        assert_eq!(nomt_roots(dir.path()), roots, "{name}");
        let accessory = Arc::new(AccessoryDb::options().open_in(dir.path()).unwrap());
        assert_eq!(
            AccessoryDb::latest_version_and_root(&accessory).unwrap(),
            Some((SlotNumber::new(2), roots)),
            "{name}"
        );
        drop(accessory);
        let flat = FlatStateDb::new(dir.path(), 1000, 1000).unwrap();
        assert_eq!(
            flat.latest_version_and_root_archival().unwrap(),
            Some((SlotNumber::new(2), roots)),
            "{name}"
        );
    }

    // The accessory and archival DBs one version ahead, with different roots.
    {
        let dir = tempdir();
        let (_, roots) = crash_after_base(dir.path(), CommitPoint::BeforeLive, &crashed);
        AccessoryDb::options()
            .open_in(dir.path())
            .unwrap()
            .put::<StateRootHashes>(&SlotNumber::new(2), &other_roots)
            .unwrap();
        let err = DbGroup::<H>::open(&config(dir.path())).unwrap_err();
        assert_error(&err, "with different roots");
        assert_error(&err, "cannot be recovered");
        assert_eq!(nomt_roots(dir.path()), roots);
    }
}

// ---------------------------------------------------------------------------------------------
// Real kills (SIGKILL) of a child process.
//
// The parent runs this test binary again, with only the ignored test `kill_9_child`, and kills
// it (`Child::kill`: SIGKILL, so no destructor, flush or core dump runs). The environment tells
// the child what to do; without it the child returns at once (`cargo test -- --ignored` runs
// it alone).

const CHILD_DIR: &str = "SELENDRA_DB_TEST_DIR";
const CHILD_KILL_AT: &str = "SELENDRA_DB_KILL_AT";
/// Prefix of the child's lines for the parent (libtest prints its own lines too).
const CHILD_MARKER: &str = "selendra-db-kill-child: ";
/// `CHILD_KILL_AT` for [`kill_9_during_large_commits`].
const LARGE_COMMITS: &str = "large-commits";
const LARGE_KEYS: u32 = 2000;
/// The large commits' lines: the writes of a version begin (at
/// [`CommitPoint::BeforeKernelNomt`]) and end (at [`CommitPoint::AfterLive`]).
const BEGIN: &str = "begin ";
const END: &str = "end ";

/// The child process, killed by its parent (on drop too, if the parent fails first).
struct KilledChild {
    child: Child,
    lines: Lines<BufReader<ChildStdout>>,
}

impl KilledChild {
    /// Runs `kill_9_child` with the databases in `dir`, doing what `kill_at` says.
    fn spawn(dir: &Path, kill_at: &str) -> Self {
        let module = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, path)| path);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                &format!("{module}::kill_9_child"),
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_DIR, dir)
            .env(CHILD_KILL_AT, kill_at)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        Self { child, lines }
    }

    /// Reads the child's output until its line starting with `what`; returns the rest of it.
    fn wait_for(&mut self, what: &str) -> String {
        let expected = format!("{CHILD_MARKER}{what}");
        loop {
            let line = self
                .lines
                .next()
                .unwrap_or_else(|| panic!("the child exited before printing {what:?}"))
                .unwrap();
            // libtest prints `test … ... ` first, without a line break.
            if let Some((_, rest)) = line.split_once(&expected) {
                return rest.to_owned();
            }
        }
    }

    /// SIGKILL, then waits for the child.
    fn kill(mut self) {
        self.child.kill().unwrap();
        let status = self.child.wait().unwrap();
        assert_eq!(status.signal(), Some(9), "{status}");
    }
}

impl Drop for KilledChild {
    fn drop(&mut self) {
        // Already reaped if `kill` ran: both calls then fail harmlessly.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The large commits' databases: enough buckets for [`LARGE_KEYS`] keys per tree.
fn large_config(dir: &Path) -> StateDbConfig {
    config_with_buckets(dir, 8192)
}

/// Version `version` of the large commits: every key rewritten, in every namespace.
fn large_block(version: u64) -> BlockWrites {
    let writes = |namespace: &str| -> Writes {
        (0..LARGE_KEYS)
            .map(|i| {
                (
                    key(format!("{namespace}{i}").as_bytes()),
                    Some(SlotValue::from(format!("{version}/{i}").into_bytes())),
                )
            })
            .collect()
    };
    BlockWrites {
        user: writes("u"),
        kernel: writes("k"),
        accessory: writes("a"),
    }
}

/// The child: see the section comment. Returns at once unless run by a parent test.
#[test]
#[ignore = "the child process of the kill_9 tests; does nothing when run alone"]
fn kill_9_child() {
    let (Some(dir), Ok(kill_at)) = (std::env::var_os(CHILD_DIR), std::env::var(CHILD_KILL_AT))
    else {
        return;
    };
    let dir = PathBuf::from(dir);
    if kill_at == LARGE_COMMITS {
        // Tells the parent when each commit's writes begin and end.
        let committing = Arc::new(AtomicU64::new(0));
        let version_of_hook = Arc::clone(&committing);
        let markers: CommitHook = Arc::new(move |reached| {
            let version = version_of_hook.load(Ordering::SeqCst);
            match reached {
                CommitPoint::BeforeKernelNomt => println!("{CHILD_MARKER}{BEGIN}{version}"),
                CommitPoint::AfterLive => println!("{CHILD_MARKER}{END}{version}"),
                _ => {}
            }
            Ok(())
        });
        let mut group = DbGroup::<H>::open_with_hook(&large_config(&dir), Some(markers)).unwrap();
        loop {
            let version = group
                .latest_version()
                .unwrap()
                .map_or(0, |version| version.get().checked_add(1).unwrap());
            assert!(version < 1000, "not killed");
            let change_set = large_block(version).change_set(&group, version);
            committing.store(version, Ordering::SeqCst);
            group.commit(change_set).unwrap();
        }
    }
    let point = CommitPoint::COMMIT
        .into_iter()
        .find(|point| format!("{point:?}") == kill_at)
        .expect("a commit point");
    let hook: CommitHook = Arc::new(move |reached| {
        if reached == point {
            println!("{CHILD_MARKER}reached");
            // Killed by now; give up if the parent failed.
            std::thread::sleep(Duration::from_secs(60));
            anyhow::bail!("not killed at {point:?}");
        }
        Ok(())
    });
    let mut group = DbGroup::<H>::open_with_hook(&config(&dir), Some(hook)).unwrap();
    let change_set = Kind::UserAndKernel.writes().change_set(&group, 2);
    let err = group.commit(change_set).unwrap_err();
    panic!("not killed: {err:#}");
}

/// A real kill (SIGKILL) at a commit point leaves what the injected faults assume: the next
/// open recovers it the same way. The kill lands between two synced writes, so this tests no
/// partially written NOMT or RocksDB commit (`kill_9_during_large_commits` kills inside the
/// writes).
#[test]
fn kill_9_mid_commit() {
    let dir = tempdir();
    let model = with_base(dir.path());
    for point in [
        CommitPoint::BeforeUserNomt,
        CommitPoint::BeforeArchival,
        CommitPoint::BeforeLive,
    ] {
        let mut child = KilledChild::spawn(dir.path(), &format!("{point:?}"));
        child.wait_for("reached");
        child.kill();
        let group = open(dir.path());
        assert_eq!(
            group.last_recovery(),
            &RecoveryReport {
                rolled_back: expected_steps(point, true, true),
                live: Some(SlotNumber::new(1)),
            },
            "{point:?}"
        );
        model.check(&group);
    }
}

/// Kills (SIGKILL) a child process at a random time inside the writes of a large commit: from
/// its first NOMT write to its live DB write, a window measured on the child's commit before
/// (its second: the first one after opening the databases is slower, with cold caches). So the
/// kill can land in the middle of a NOMT commit (between its write-ahead log, page and meta
/// writes) or of a RocksDB write. The only test of partially written commits: the next
/// open must find each database whole (NOMT's write-ahead log, RocksDB's atomic write batches)
/// at the version before the killed commit or at its version, and recovery must bring them to
/// one committed version, every value of which reads back. A kill stops only the process: what
/// it wrote is kept (this is a process crash, not a power loss).
///
/// A kill can still leave no commit half written: inside the kernel tree's commit before it
/// took effect, or once the live DB's write is synced (a kill during the sync waits for it).
/// So rounds go on until [`HITS`] kills left a commit half written (recovery rolled something
/// back), and the test fails after [`MAX_ROUNDS`] (about two kills in three hit on a tmpfs,
/// measured). The rounds are printed, and listed on failure.
#[test]
fn kill_9_during_large_commits() {
    const HITS: usize = 2;
    const MAX_ROUNDS: u64 = 20;
    let dir = tempdir();
    let random = RandomState::new();
    let mut rounds = Vec::new();
    let mut hits = 0;
    for round in 0..MAX_ROUNDS {
        let mut child = KilledChild::spawn(dir.path(), LARGE_COMMITS);
        // A first commit, then one whose writes are timed.
        child.wait_for(END);
        let measured = child.wait_for(BEGIN);
        let start = Instant::now();
        assert_eq!(child.wait_for(END), measured);
        let window = start.elapsed();
        // The next one, killed inside its writes.
        let killed: u64 = child.wait_for(BEGIN).parse().unwrap();
        let window_nanos = u64::try_from(window.as_nanos()).unwrap().max(1);
        let delay = Duration::from_nanos(random.hash_one(round) % window_nanos);
        std::thread::sleep(delay);
        child.kill();

        let group = DbGroup::<H>::open(&large_config(dir.path())).unwrap();
        let version = group.latest_version().unwrap().map(|version| version.get());
        let rolled_back = &group.last_recovery().rolled_back;
        rounds.push(format!(
            "round {round}: killed {delay:?} into the writes of version {killed} (window \
             {window:?}): live version {version:?}, rolled back {rolled_back:?}"
        ));
        eprintln!("{}", rounds.last().unwrap());
        assert!(
            version == killed.checked_sub(1) || version == Some(killed),
            "{rounds:#?}"
        );
        if !rolled_back.is_empty() {
            hits += 1;
        }
        let mut model = Model::default();
        if let Some(version) = version {
            model.apply(version, &large_block(version));
        }
        model.check(&group);
        if hits >= HITS {
            return;
        }
    }
    panic!("fewer than {HITS} kills landed inside a commit's writes: {rounds:#?}");
}

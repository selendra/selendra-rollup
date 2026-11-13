//! Pruning by the storage manager: upstream's pruning tests (`nomt_based/tests.rs`: historical
//! state, hot key, backpressure, prune once at startup, failure; without their background
//! thread, so the floors are exact), its regressions (B13, the interval, critique #7/#11), the
//! last 2 of the 15 deferred `prover_storage.rs` tests (`stale_reader_*`) in pinned form, and
//! storages on uncommitted blocks pinning their base version.

use std::num::NonZeroU64;

use super::*;
use crate::{CommitPoint, HistoricalValueError, PruneStats, PrunerConfig, fail_at};

fn nz(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).unwrap()
}

fn periodic(every_versions: u64, versions_to_keep: u64, max_keys_per_run: u64) -> PrunerConfig {
    PrunerConfig::Periodic {
        every_versions: nz(every_versions),
        versions_to_keep: nz(versions_to_keep),
        max_keys_per_run: nz(max_keys_per_run),
    }
}

fn once_at_startup(versions_to_keep: u64, max_keys_per_run: u64) -> PrunerConfig {
    PrunerConfig::OnceAtStartup {
        versions_to_keep: nz(versions_to_keep),
        max_keys_per_run: nz(max_keys_per_run),
    }
}

/// Upstream's 3-byte keys (`[k, 0, 0]`).
fn ukey(k: u8) -> SlotKey {
    SlotKey::try_from_bytes(&[k, 0, 0]).unwrap()
}

fn named(name: &[u8]) -> SlotKey {
    SlotKey::try_from_bytes(name).unwrap()
}

fn val(n: u64) -> Option<SlotValue> {
    Some(SlotValue::from(n.to_be_bytes().to_vec()))
}

type Writes = Vec<(SlotKey, Option<SlotValue>)>;

/// Executes, saves and finalizes the block of `version` on the main fork (header
/// `TestHeader::linear(version + 1)`) with these user and accessory writes.
fn commit(m: &mut Manager, version: u64, user: &[(SlotKey, Option<SlotValue>)], accessory: Writes) {
    let hdr = TestHeader::linear(version.checked_add(1).unwrap());
    write_block(m, &hdr, user, &[], &accessory);
    m.finalize(&hdr).unwrap();
}

fn user_at(
    storage: &TestStorage,
    key: &SlotKey,
    version: u64,
) -> anyhow::Result<Option<SlotValue>> {
    storage.get_historical::<User>(key, Some(SlotNumber::new(version)), &Default::default())
}

fn accessory_at(
    storage: &TestStorage,
    key: &SlotKey,
    version: u64,
) -> anyhow::Result<Option<SlotValue>> {
    storage.get_accessory_historical(key, Some(SlotNumber::new(version)))
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

fn cutoff(m: &Manager) -> Option<u64> {
    m.last_prune()
        .expect("a pruning pass ran")
        .cutoff
        .map(|cutoff| cutoff.get())
}

/// Upstream's workload: version 0 writes nothing, version `h` in `1..=10` writes keys `h..=10`
/// (so key `k` is written at versions `1..=k`, with the version as its value), later versions
/// write a dummy key.
fn upstream_writes(version: u64) -> Writes {
    let keys: Vec<u8> = match version {
        0 => Vec::new(),
        1..=10 => (u8::try_from(version).unwrap()..=10).collect(),
        _ => vec![u8::MAX],
    };
    keys.into_iter().map(|k| (ukey(k), val(version))).collect()
}

/// Upstream `test_historical_state_with_pruning` (every block, 5 kept): values read at the kept
/// versions are exact, older versions are exactly `PrunedVersion`. Pruning is synchronous here,
/// so the floor is exactly `L - k` (upstream's lagged by two blocks behind its pruner thread).
#[test]
fn historical_state_with_pruning() {
    let mut m = Manager::with_config(|config| config.pruning = periodic(1, 5, 1000));
    for version in 0..14 {
        commit(&mut m, version, &upstream_writes(version), Vec::new());
    }
    assert_eq!(cutoff(&m), Some(13 - 5));
    let (storage, _) = m.create_finalized_state().unwrap();
    for k in 1..=10u8 {
        let key = ukey(k);
        assert_eq!(
            storage.get::<User>(&key, &Default::default()),
            val(u64::from(k))
        );
        for version in 0..14 {
            if version < 8 {
                assert_pruned(user_at(&storage, &key, version), version, 8);
            } else {
                assert_eq!(
                    user_at(&storage, &key, version).unwrap(),
                    val(version.min(u64::from(k))),
                    "key {k} at version {version}"
                );
            }
        }
    }
}

/// Upstream `test_hot_key_pruning_keeps_only_recent_versions`: a key written at every version
/// keeps exactly `k + 1` readable versions.
#[test]
fn hot_key_pruning_keeps_only_recent_versions() {
    let mut m = Manager::with_config(|config| config.pruning = periodic(1, 5, 1000));
    let hot = ukey(42);
    let hot_value = |version: u64| val(0x1000 + version);
    for version in 0..=14 {
        let writes = if version == 0 {
            Vec::new()
        } else {
            vec![(hot.clone(), hot_value(version))]
        };
        commit(&mut m, version, &writes, Vec::new());
    }
    let (storage, _) = m.create_finalized_state().unwrap();
    assert_eq!(
        storage.get::<User>(&hot, &Default::default()),
        hot_value(14)
    );
    let mut retained = 0;
    for version in 0..=14 {
        if version < 9 {
            assert_pruned(user_at(&storage, &hot, version), version, 9);
        } else {
            assert_eq!(
                user_at(&storage, &hot, version).unwrap(),
                hot_value(version)
            );
            retained += 1;
        }
    }
    assert_eq!(retained, 5 + 1);
}

/// Upstream `test_pruner_backpressure_respawns_until_drained` (`max_keys_per_run = 8`): a backlog
/// larger than the budget is pruned over several finalizations, one pass each while a pass
/// leaves a backlog, also before the interval has passed; then it is drained.
#[test]
fn pruner_backpressure_drains() {
    let mut m = Manager::with_config(|config| config.pruning = periodic(10, 2, 8));
    let keys: Vec<SlotKey> = (0u8..20).map(ukey).collect();
    for version in 0..5 {
        let writes: Writes = keys
            .iter()
            .map(|k| (k.clone(), val(0x1000 + version)))
            .collect();
        commit(&mut m, version, &writes, Vec::new());
    }
    let tick = ukey(0xAA);
    let mut saw_backlog = false;
    let mut backlog_before = false;
    for version in 5..40 {
        let runs = m.prune_runs();
        commit(
            &mut m,
            version,
            &[(tick.clone(), val(0x2000 + version))],
            Vec::new(),
        );
        if backlog_before {
            assert_eq!(
                m.prune_runs(),
                runs + 1,
                "a backlog is pruned at the next finalization"
            );
        }
        backlog_before = m.last_prune().is_some_and(PruneStats::has_backlog);
        saw_backlog |= backlog_before;
    }
    assert!(saw_backlog, "the budget of 8 must leave a backlog");
    assert!(!backlog_before, "drained");
    assert!(m.prune_runs() >= 2);
    let (storage, _) = m.create_finalized_state().unwrap();
    assert_eq!(
        storage.get::<User>(&keys[0], &Default::default()),
        val(0x1004)
    );
    assert!(user_at(&storage, &keys[0], 0).is_err());
}

/// The first 14 versions of upstream's workload, committed with pruning off; the manager is
/// dropped and reopened by the caller.
fn backlog_without_pruning() -> Manager {
    let mut m = Manager::new();
    for version in 0..14 {
        commit(&mut m, version, &upstream_writes(version), Vec::new());
    }
    assert_eq!(m.prune_runs(), 0);
    m
}

/// Upstream `test_prune_once_at_startup_runs_to_completion`: reopened with `OnceAtStartup` and a
/// tiny budget, opening prunes the backlog in several passes until drained, and later
/// finalizations never prune.
#[test]
fn prune_once_at_startup_runs_to_completion() {
    let m = backlog_without_pruning();
    let mut m = m.reopen_with(|config| config.pruning = once_at_startup(5, 8));
    assert!(m.prune_runs() >= 2, "{} passes", m.prune_runs());
    assert!(!m.last_prune().unwrap().has_backlog());
    assert_eq!(cutoff(&m), Some(8));
    let (storage, _) = m.create_finalized_state().unwrap();
    for k in 1..=10u8 {
        assert_eq!(
            storage.get::<User>(&ukey(k), &Default::default()),
            val(u64::from(k))
        );
        assert_pruned(user_at(&storage, &ukey(k), 0), 0, 8);
        assert_eq!(
            user_at(&storage, &ukey(k), 8).unwrap(),
            val(8.min(u64::from(k)))
        );
    }
    drop(storage);
    let runs = m.prune_runs();
    for version in 14..17 {
        commit(
            &mut m,
            version,
            &[(ukey(u8::MAX), val(version))],
            Vec::new(),
        );
    }
    assert_eq!(m.prune_runs(), runs, "never again after startup");
}

/// B13: startup pruning ends when nothing is prunable. Here every index entry is a first write
/// (no row to delete): the passes consume the entries (3 passes of at most 8 for 18 entries up
/// to the cutoff) and stop. Empty databases take one pass.
#[test]
fn startup_prune_terminates_when_nothing_prunable() {
    let m = Manager::with_config(|config| config.pruning = once_at_startup(2, 8));
    assert_eq!((m.prune_runs(), m.last_prune().unwrap().cutoff), (1, None));
    drop(m);

    let mut m = Manager::new();
    for version in 0..20u8 {
        commit(
            &mut m,
            u64::from(version),
            &[(ukey(version), val(u64::from(version)))],
            vec![(named(&[b'a', version]), val(u64::from(version)))],
        );
    }
    let m = within(Duration::from_secs(60), move || {
        m.reopen_with(|config| config.pruning = once_at_startup(2, 8))
    });
    assert_eq!(m.prune_runs(), 3);
    let last = m.last_prune().unwrap();
    assert_eq!(
        (last.cutoff, last.has_backlog()),
        (Some(SlotNumber::new(17)), false)
    );
    // Nothing deleted: every version still reads.
    let mut m = m;
    let (storage, _) = m.create_finalized_state().unwrap();
    assert_eq!(user_at(&storage, &ukey(0), 0).unwrap(), val(0));
    assert_eq!(accessory_at(&storage, &named(b"a\0"), 0).unwrap(), val(0));
}

/// Critique #7: startup pruning stops only once no store has a backlog, not once a pass deletes
/// nothing. Here the first pass's 8 entries are all first writes (nothing to delete) and the
/// prunable rows come after them: stopping after a pass that deleted nothing would leave them.
#[test]
fn startup_prune_continues_past_a_batch_of_first_writes() {
    let mut m = Manager::new();
    let hot = ukey(9);
    let mut genesis: Writes = (0u8..8).map(|k| (ukey(k), val(0))).collect();
    genesis.push((hot.clone(), val(0)));
    commit(&mut m, 0, &genesis, Vec::new());
    for version in 1..=5 {
        commit(&mut m, version, &[(hot.clone(), val(version))], Vec::new());
    }
    let mut m = m.reopen_with(|config| config.pruning = once_at_startup(1, 8));
    assert_eq!(m.prune_runs(), 2);
    let (storage, _) = m.create_finalized_state().unwrap();
    assert_pruned(user_at(&storage, &hot, 0), 0, 4);
    assert_eq!(user_at(&storage, &hot, 4).unwrap(), val(4));
    assert_eq!(user_at(&storage, &ukey(0), 4).unwrap(), val(0));
}

/// Upstream `periodic_pruning_failure_error_names_pruning` (critique #11): a pruning pass that
/// fails after a finalization's commits does not fail the finalization (upstream returned an
/// `Err` the runner stops on). The block is committed, nothing is poisoned, the failure is kept
/// (naming pruning, the block and the cause) and logged, and the next finalization prunes.
#[test]
fn periodic_pruning_failure_error_names_pruning() {
    let mut m = Manager::with_config(|config| config.pruning = periodic(1, 1, 1000));
    let (u, a) = (named(b"u1"), named(b"a1"));
    for version in 0..=1 {
        commit(
            &mut m,
            version,
            &[(u.clone(), val(version))],
            vec![(a.clone(), val(version))],
        );
    }
    m.set_commit_hook(Some(fail_at(CommitPoint::BeforePruneAccessory)));
    commit(&mut m, 2, &[(u.clone(), val(2))], vec![(a.clone(), val(2))]);
    assert_eq!(m.finalized().unwrap().slot, SlotNumber::new(2));
    assert!(!m.is_poisoned());
    let error = format!("{:#}", m.last_prune_error().expect("the failure is kept"));
    let block = TestHeader::linear(3);
    for part in [
        "is finalized and committed, but pruning after it failed".to_owned(),
        block.display().to_string(),
        "injected fault at BeforePruneAccessory".to_owned(),
    ] {
        assert!(error.contains(&part), "{part:?} missing from: {error}");
    }
    // The flat store's write landed (cutoff 1), the accessory store's did not.
    let (storage, _) = m.create_finalized_state().unwrap();
    assert_pruned(user_at(&storage, &u, 0), 0, 1);
    assert_eq!(accessory_at(&storage, &a, 0).unwrap(), val(0));
    drop(storage);

    m.set_commit_hook(None);
    commit(&mut m, 3, &[(u.clone(), val(3))], vec![(a.clone(), val(3))]);
    assert!(m.last_prune_error().is_none());
    let (storage, _) = m.create_finalized_state().unwrap();
    assert_pruned(accessory_at(&storage, &a, 0), 0, 2);
    assert_eq!(accessory_at(&storage, &a, 2).unwrap(), val(2));
}

/// The interval: `every_versions = 1` prunes at every finalization (upstream compared with `>`,
/// so an interval of 1 pruned every second block), 3 at every third.
#[test]
fn periodic_interval_one_prunes_every_finalize() {
    for (every, finalizations, passes) in [(1, 6, 6), (3, 7, 3)] {
        let mut m = Manager::with_config(|config| config.pruning = periodic(every, 1, 1000));
        for version in 0..finalizations {
            commit(&mut m, version, &[(ukey(1), val(version))], Vec::new());
        }
        assert_eq!(m.prune_runs(), passes, "every {every}");
    }
}

// ---------------------------------------------------------------------------------------------
// Upstream's `stale_reader_*` tests (`prover_storage.rs`), pinned.

/// Upstream `stale_reader_past_pruned_floor`: pruning keeps 2 versions at every finalization; a
/// storage after the block of version 1 is kept while 14 more versions are committed. Returns
/// the manager, that stale storage, the user and accessory keys (written at every version with
/// the version as value) and the newest version.
fn stale_reader_past_pruned_floor() -> (Manager, TestStorage, SlotKey, SlotKey, u64) {
    let mut m = Manager::with_config(|config| config.pruning = periodic(1, 2, 1000));
    let (user, accessory) = (named(b"hot-key"), named(b"acc-key"));
    let block = |m: &mut Manager, version: u64| {
        commit(
            m,
            version,
            &[(user.clone(), val(version))],
            vec![(accessory.clone(), val(version))],
        );
    };
    block(&mut m, 0);
    block(&mut m, 1);
    let (stale, _) = m.create_state_after(&TestHeader::linear(2)).unwrap();
    for version in 2..=15 {
        block(&mut m, version);
    }
    (m, stale, user, accessory, 15)
}

/// The setup's floor (upstream checked it was pruned): while the stale storage lives, pruning
/// stops at its version (1), so a fresh storage still reads version 1; once it is dropped,
/// pruning catches up and version 1 is exactly `PrunedVersion` (floor `15 - 2`).
#[test]
fn stale_reader_past_pruned_floor_setup() {
    let (mut m, stale, user, accessory, last) = stale_reader_past_pruned_floor();
    assert_eq!(m.oldest_pinned_version(), Some(SlotNumber::new(1)));
    assert_eq!(cutoff(&m), Some(1));
    let (fresh, _) = m.create_finalized_state().unwrap();
    assert_eq!(user_at(&fresh, &user, 1).unwrap(), val(1));
    drop((fresh, stale));
    assert_eq!(m.oldest_pinned_version(), None);
    let stats = m.prune_now().unwrap();
    assert_eq!(stats.cutoff, Some(SlotNumber::new(last - 2)));
    let (fresh, _) = m.create_finalized_state().unwrap();
    assert_pruned(user_at(&fresh, &user, 1), 1, last - 2);
    assert_pruned(accessory_at(&fresh, &accessory, 1), 1, last - 2);
    assert_eq!(user_at(&fresh, &user, last - 2).unwrap(), val(last - 2));
}

/// Replaces upstream `stale_reader_panics_on_pruned_version_via_unversioned_get` (B14): upstream
/// pinned that a storage older than the pruning window *panics* on its next read. Here the
/// storage pins its version: its bound reads return its version's values, and the cutoff stops
/// there; once it is dropped, the next pass prunes past it.
#[test]
fn stale_reader_pinned_reads_its_version_and_holds_pruning() {
    let (mut m, stale, user, accessory, last) = stale_reader_past_pruned_floor();
    assert_eq!(stale.get::<User>(&user, &Default::default()), val(1));
    assert_eq!(stale.get_accessory(&accessory), val(1));
    assert_eq!(user_at(&stale, &user, 1).unwrap(), val(1));
    assert_eq!(cutoff(&m), Some(1), "held at the stale storage's version");
    let rows_before = m.last_prune().unwrap().rows_deleted();
    drop(stale);
    let stats = m.prune_now().unwrap();
    assert_eq!(stats.cutoff, Some(SlotNumber::new(last - 2)));
    assert!(stats.rows_deleted() > rows_before);
}

/// Upstream `stale_reader_unbound_get_returns_live_tip_without_panic` (direct port): the stale
/// storage's unbound read returns the newest committed value.
#[test]
fn stale_reader_unbound_get_returns_live_tip_without_panic() {
    let (_m, stale, user, accessory, last) = stale_reader_past_pruned_floor();
    assert_eq!(stale.get_unbound::<User>(user), val(last));
    assert_eq!(
        stale.get_accessory_unbound(accessory, None).unwrap(),
        val(last)
    );
}

/// Without a pinning storage, historical reads below the floor are exactly `PrunedVersion` (user
/// and accessory), from the floor on they are exact.
#[test]
fn unpinned_historical_read_below_floor_is_pruned_error() {
    let (mut m, stale, user, accessory, last) = stale_reader_past_pruned_floor();
    drop(stale);
    commit(
        &mut m,
        last + 1,
        &[(user.clone(), val(last + 1))],
        vec![(accessory.clone(), val(last + 1))],
    );
    let floor = last + 1 - 2;
    assert_eq!(cutoff(&m), Some(floor));
    let (storage, _) = m.create_finalized_state().unwrap();
    for version in 0..=last + 1 {
        if version < floor {
            assert_pruned(user_at(&storage, &user, version), version, floor);
            assert_pruned(accessory_at(&storage, &accessory, version), version, floor);
        } else {
            assert_eq!(user_at(&storage, &user, version).unwrap(), val(version));
            assert_eq!(
                accessory_at(&storage, &accessory, version).unwrap(),
                val(version)
            );
        }
    }
}

/// Critique #8: an unbound accessory read at a caller's pruned version is an error, not a panic
/// (upstream routed it through the unbound resolver, which panics on any error), and not
/// "absent".
#[test]
fn accessory_unbound_read_below_watermark_is_error_not_panic() {
    let (mut m, stale, _user, accessory, last) = stale_reader_past_pruned_floor();
    drop(stale);
    m.prune_now().unwrap();
    let (storage, _) = m.create_finalized_state().unwrap();
    assert_pruned(
        storage.get_accessory_unbound(accessory.clone(), Some(SlotNumber::new(1))),
        1,
        last - 2,
    );
    assert_eq!(
        storage
            .get_accessory_unbound(accessory.clone(), Some(SlotNumber::new(last - 1)))
            .unwrap(),
        val(last - 1)
    );
    assert_eq!(
        storage.get_accessory_unbound(accessory, None).unwrap(),
        val(last)
    );
}

/// A storage on an uncommitted block reads the keys its blocks do not write at its base version
/// (the newest committed version when it was created, from the archive once newer versions are
/// committed): it pins that version, so pruning keeps it even after the storage's own block is
/// committed and the chain moves on.
#[test]
fn storage_on_uncommitted_blocks_pins_its_base_version() {
    let mut m = Manager::with_config(|config| config.pruning = periodic(1, 1, 1000));
    let (hot, rare) = (named(b"hot"), named(b"rare"));
    commit(
        &mut m,
        0,
        &[(hot.clone(), val(0)), (rare.clone(), val(0))],
        Vec::new(),
    );
    for version in 1..=2 {
        commit(&mut m, version, &[(hot.clone(), val(version))], Vec::new());
    }
    // Block 3 saved, not finalized; a storage after it: base version 2 plus block 3's snapshot.
    let b3 = TestHeader::linear(4);
    write_block(&mut m, &b3, &[(hot.clone(), val(3))], &[], &[]);
    let (after_b3, _) = m.create_state_after(&b3).unwrap();
    assert_eq!(m.oldest_pinned_version(), Some(SlotNumber::new(2)));
    m.finalize(&b3).unwrap();
    // `rare` is written again at 4: without the pin, a pass at version 6 (cutoff 5) would delete
    // `rare@0`, the row `after_b3` reads `rare` from.
    commit(
        &mut m,
        4,
        &[(hot.clone(), val(4)), (rare.clone(), val(4))],
        Vec::new(),
    );
    for version in 5..=6 {
        commit(&mut m, version, &[(hot.clone(), val(version))], Vec::new());
    }
    assert_eq!(after_b3.get::<User>(&rare, &Default::default()), val(0));
    assert_eq!(after_b3.get::<User>(&hot, &Default::default()), val(3));
    assert_eq!(user_at(&after_b3, &rare, 3).unwrap(), val(0));
    assert_eq!(cutoff(&m), Some(2));
    drop(after_b3);
    assert_eq!(m.prune_now().unwrap().cutoff, Some(SlotNumber::new(5)));
    let (storage, _) = m.create_finalized_state().unwrap();
    assert_pruned(user_at(&storage, &rare, 3), 3, 5);
    assert_eq!(user_at(&storage, &rare, 5).unwrap(), val(4));
}

//! `get_with_proof` while a finalization is paused at each commit point (upstream's paused
//! `prover_storage.rs` tests), with per-instance gates: every test runs on its own manager, in
//! parallel with the others (upstream armed one process-wide gate).
//!
//! The protocol: the finalization runs on a scoped thread with a [`Gate`] at a commit point;
//! once it is paused there (holding the overlays write lock), a proof attempt starts on another
//! thread. It reads the flat store without waiting (`RootRead`, `ValueRead`, `BeforeSession`),
//! then waits for the lock to open its NOMT session: `AfterSessionOpen` must not fire, and the
//! lock must be held, until the gate is released (critique #15: the overlay variants would pass
//! without this, whether or not the reader waited). At `BeforeLive` the readers do not wait for
//! the databases themselves (see [`CommitPoint::BeforeLive`]): the wait comes from the manager's
//! lock.
//!
//! Each test runs in [`paused_test`], so a deadlock fails it instead of hanging the test run.

use std::sync::TryLockError;

use super::*;
use crate::harness::{Gate, assert_proof_consistent};
use crate::prover::{FetchStep, GetWithProofError};
use crate::{CommitPoint, NomtStorageManager};

type Attempt = Result<(Option<SlotValue>, SlotNumber, Root), GetWithProofError>;

/// The commit points of one block where a paused commit holds the overlays lock and nothing is
/// committed yet (the flat live DB is written last).
const BEFORE: [CommitPoint; 6] = [
    CommitPoint::BeforeKernelNomt,
    CommitPoint::BeforeUserNomt,
    CommitPoint::BeforeLedger,
    CommitPoint::BeforeAccessory,
    CommitPoint::BeforeArchival,
    CommitPoint::BeforeLive,
];

/// How long a paused test may run before it fails as deadlocked.
const TEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Runs `test` on a new manager on another thread, and fails after [`TEST_TIMEOUT`]. The
/// threads of a test's scope cannot do that: a scope waits for all its threads before it
/// resumes a panic (`join_within`'s too), so a deadlocked one would hang the test. The manager
/// is opened first, outside the timeout, since it may wait for a free database slot.
fn paused_test(test: impl FnOnce(Manager) + Send + 'static) {
    let m = Manager::new();
    within(TEST_TIMEOUT, move || test(m));
}

/// `m` with block 1 finalized and block 2 saved (both write [`values`] at their height and, at
/// [`key`]`(0)`, user `[h]`, kernel `[h + 100]`, accessory `[h + 200]`).
fn setup(mut m: Manager) -> (Manager, [TestHeader; 2], [Root; 2]) {
    let [h1, h2] = [TestHeader::linear(1), TestHeader::linear(2)];
    let mut roots = [Root::PRE_GENESIS; 2];
    for (index, hdr) in [&h1, &h2].into_iter().enumerate() {
        let height = u8::try_from(hdr.height).unwrap();
        let counter = |offset: u8| Some(SlotValue::from(vec![height + offset]));
        let [mut user, mut kernel, mut accessory] = writes(hdr);
        user.push((key(0), counter(0)));
        kernel.push((key(0), counter(100)));
        accessory.push((key(0), counter(200)));
        roots[index] = write_block(&mut m, hdr, &user, &kernel, &accessory);
        if index == 0 {
            m.finalize(hdr).unwrap();
        }
    }
    (m, [h1, h2], roots)
}

/// Finalizes `hdr` with a gate at `point`; while it is paused there, runs one proof attempt of
/// [`key`]`(0)` from `storage` on another thread and checks that it waits for the lock (see the
/// module docs). Returns the attempt's result once the finalization is released and done.
fn proof_during_paused_finalize(
    m: &mut NomtStorageManager<Spec, TestHeader>,
    hdr: &TestHeader,
    point: CommitPoint,
    storage: &TestStorage,
) -> Attempt {
    let gate = Gate::new();
    m.set_commit_hook(Some(gate.hook_at(point)));
    let overlays = m.overlays().clone();
    let result = std::thread::scope(|scope| {
        let finalize = scope.spawn(|| m.finalize(hdr));
        assert!(
            gate.wait_reached(Gate::TIMEOUT),
            "the finalization did not pause at {point:?}"
        );
        assert!(
            matches!(overlays.try_write(), Err(TryLockError::WouldBlock)),
            "the overlays lock is not held at {point:?}"
        );
        let (steps, received) = mpsc::channel();
        let proof = scope.spawn(move || {
            storage
                .get_with_proof_once_with::<User>(key(0), |step| {
                    let _ = steps.send(step);
                })
                .map(|(proof, version, root)| (proof.value, version, root))
        });
        for expected in [
            FetchStep::RootRead,
            FetchStep::ValueRead,
            FetchStep::BeforeSession,
        ] {
            assert_eq!(
                received.recv_timeout(Gate::TIMEOUT),
                Ok(expected),
                "the attempt waited before opening its session at {point:?}"
            );
        }
        // Blocked on the lock: it never opens its session while the commit is paused.
        assert!(
            received.recv_timeout(Duration::from_millis(100)).is_err(),
            "the session opened while the commit was paused at {point:?}"
        );
        assert!(!proof.is_finished());
        assert!(!finalize.is_finished());
        gate.release();
        join_within(finalize, Gate::TIMEOUT).expect("the finalization");
        let result = join_within(proof, Gate::TIMEOUT);
        assert_eq!(received.try_recv(), Ok(FetchStep::AfterSessionOpen));
        result
    });
    m.set_commit_hook(None);
    result
}

/// The value at [`key`]`(0)` after block `h`.
fn counter(h: u8) -> SlotValue {
    SlotValue::from(vec![h])
}

/// A storage of version 1 (stale once block 2 is committed): the attempt waits for the paused
/// finalization of block 2, then its session sees version 2 while its flat-store reads saw
/// version 1: `StateRootMismatch` (retry), never a proof mixing them. The retrying
/// `get_with_proof` then proves version 2.
fn stale_storage_waits_then_mismatches(point: CommitPoint) {
    paused_test(move |m| {
        let (mut m, [h1, h2], roots) = setup(m);
        let (stale, _) = m.create_state_after(&h1).unwrap();
        let attempt = proof_during_paused_finalize(&mut m, &h2, point, &stale);
        assert!(
            matches!(attempt, Err(GetWithProofError::StateRootMismatch)),
            "{point:?}: {attempt:?}"
        );
        assert!(stale.latest_version() < stale.latest_version_unbound());
        let (fresh, _) = m.create_finalized_state().unwrap();
        let proven = assert_proof_consistent(
            &stale,
            &fresh,
            &key(0),
            Some(&counter(2)),
            (&key(0), Some(&counter(202))),
        );
        assert_eq!(proven, (SlotNumber::new(1), roots[1]));
    });
}

#[test]
fn get_with_proof_waits_for_stale_storage_while_commit_is_paused_before_kernel_nomt() {
    stale_storage_waits_then_mismatches(CommitPoint::BeforeKernelNomt);
}

#[test]
fn get_with_proof_waits_for_stale_storage_while_commit_is_paused_before_user_nomt() {
    stale_storage_waits_then_mismatches(CommitPoint::BeforeUserNomt);
}

#[test]
fn get_with_proof_waits_for_stale_storage_while_commit_is_paused_before_ledger() {
    stale_storage_waits_then_mismatches(CommitPoint::BeforeLedger);
}

#[test]
fn get_with_proof_waits_for_stale_storage_while_commit_is_paused_before_accessory() {
    stale_storage_waits_then_mismatches(CommitPoint::BeforeAccessory);
}

#[test]
fn get_with_proof_waits_for_stale_storage_while_commit_is_paused_before_archival() {
    stale_storage_waits_then_mismatches(CommitPoint::BeforeArchival);
}

/// Upstream passed on any `Err` here; the attempt now waits for the manager's lock (the
/// databases do not make it wait at this point) and returns `StateRootMismatch`.
#[test]
fn get_with_proof_does_not_return_inconsistent_success_for_stale_storage_while_commit_is_paused_before_live()
 {
    stale_storage_waits_then_mismatches(CommitPoint::BeforeLive);
}

/// The commit is complete (the flat live DB too) but the lock is still held: the stale
/// storage's flat-store reads already see version 2, its session waits and then sees it too:
/// the first attempt proves version 2.
#[test]
fn get_with_proof_waits_for_stale_storage_while_commit_is_paused_after_live() {
    paused_test(|m| {
        let (mut m, [h1, h2], roots) = setup(m);
        let (stale, _) = m.create_state_after(&h1).unwrap();
        let attempt = proof_during_paused_finalize(&mut m, &h2, CommitPoint::AfterLive, &stale);
        let (value, version, root) = attempt.unwrap();
        assert_eq!(
            (value, version, root),
            (Some(counter(2)), SlotNumber::new(1), roots[1])
        );
    });
}

/// A storage after the unfinalized block 2 (its overlay and snapshots): the attempt waits for
/// the paused finalization of block 2, then proves version 2 on the first attempt (the overlay
/// is gone, and its block committed with the same root), consistent with its reads.
fn overlay_storage_waits_then_succeeds(point: CommitPoint) {
    paused_test(move |m| {
        let (mut m, [_, h2], roots) = setup(m);
        let (overlay, _) = m.create_state_after(&h2).unwrap();
        let attempt = proof_during_paused_finalize(&mut m, &h2, point, &overlay);
        let (value, version, root) = attempt.unwrap_or_else(|err| panic!("{point:?}: {err}"));
        // The session's root (checked against the flat store's by the attempt) is block 2's.
        assert_eq!(
            (value, version, root),
            (Some(counter(2)), SlotNumber::new(1), roots[1]),
            "{point:?}"
        );
        let (fresh, _) = m.create_finalized_state().unwrap();
        let proven = assert_proof_consistent(
            &overlay,
            &fresh,
            &key(0),
            Some(&counter(2)),
            (&key(0), Some(&counter(202))),
        );
        assert_eq!(proven, (SlotNumber::new(1), roots[1]));
        assert_eq!(m.overlays().read().unwrap().len(), 0);
    });
}

#[test]
fn get_with_proof_succeeds_for_overlay_storage_while_commit_is_paused_before_kernel_nomt() {
    overlay_storage_waits_then_succeeds(CommitPoint::BeforeKernelNomt);
}

#[test]
fn get_with_proof_succeeds_for_overlay_storage_while_commit_is_paused_before_user_nomt() {
    overlay_storage_waits_then_succeeds(CommitPoint::BeforeUserNomt);
}

#[test]
fn get_with_proof_succeeds_for_overlay_storage_while_commit_is_paused_before_ledger() {
    overlay_storage_waits_then_succeeds(CommitPoint::BeforeLedger);
}

#[test]
fn get_with_proof_succeeds_for_overlay_storage_while_commit_is_paused_before_accessory() {
    overlay_storage_waits_then_succeeds(CommitPoint::BeforeAccessory);
}

#[test]
fn get_with_proof_succeeds_for_overlay_storage_while_commit_is_paused_before_archival() {
    overlay_storage_waits_then_succeeds(CommitPoint::BeforeArchival);
}

#[test]
fn get_with_proof_succeeds_for_overlay_storage_while_commit_is_paused_before_live() {
    overlay_storage_waits_then_succeeds(CommitPoint::BeforeLive);
}

#[test]
fn get_with_proof_succeeds_for_overlay_storage_while_commit_is_paused_after_live() {
    overlay_storage_waits_then_succeeds(CommitPoint::AfterLive);
}

/// Every point of [`BEFORE`] has its stale and overlay test above.
#[test]
fn paused_tests_cover_every_point_before_live() {
    assert_eq!(
        BEFORE.to_vec(),
        CommitPoint::COMMIT[..CommitPoint::COMMIT.len() - 1].to_vec()
    );
}

/// A12: a NOMT session held on another thread when a finalization starts. NOMT's commit waits
/// for it (the finalization does not finish while it is open), and the finalization completes
/// once it is dropped. Protocol (critique #30): the session is opened before the finalization,
/// which pauses before the NOMT commit (holding the overlays lock); the gate is released, the
/// commit then waits for the session; the session is dropped; the finalization completes.
#[test]
fn finalize_with_open_session_on_other_thread_completes() {
    paused_test(|m| {
        let (mut m, [_, h2], roots) = setup(m);
        let (overlay, _) = m.create_state_after(&h2).unwrap();
        let sessions = overlay
            .session_builder()
            .begin_both_sessions(crate::WitnessMode::Off)
            .unwrap();
        let gate = Gate::new();
        m.set_commit_hook(Some(gate.hook_at(CommitPoint::BeforeKernelNomt)));
        std::thread::scope(|scope| {
            let finalize = scope.spawn(|| m.finalize(&h2));
            assert!(
                gate.wait_reached(Gate::TIMEOUT),
                "the finalization did not pause"
            );
            gate.release();
            std::thread::sleep(Duration::from_millis(50));
            assert!(
                !finalize.is_finished(),
                "the NOMT commit did not wait for the open session"
            );
            drop(sessions);
            join_within(finalize, Gate::TIMEOUT).expect("the finalization");
        });
        assert_eq!(m.latest_version(), Some(SlotNumber::new(1)));
        assert_eq!(prove(&overlay, 0).unwrap(), (Some(counter(2)), roots[1]));
    });
}

/// A storage's live prefix iterator holds the flat store's lock, which the commit's flat-store
/// write waits for while it holds the overlays write lock: a NOMT session opened on the
/// iterator's thread now would never open (the deadlock documented on [`NomtStorageManager`],
/// Locking). Once the iterator is dropped, the finalization completes.
#[test]
fn finalize_waits_for_live_iterator_under_the_overlays_lock() {
    paused_test(|m| {
        let (mut m, [_, h2], roots) = setup(m);
        let (storage, _) = m.create_finalized_state().unwrap();
        let gate = Gate::new();
        // Before the flat-store write: the iterator can still be opened.
        m.set_commit_hook(Some(gate.hook_at(CommitPoint::BeforeArchival)));
        let overlays = m.overlays().clone();
        std::thread::scope(|scope| {
            let finalize = scope.spawn(|| m.finalize(&h2));
            assert!(
                gate.wait_reached(Gate::TIMEOUT),
                "the finalization did not pause"
            );
            let prefix = SlotKey::try_from_bytes(&[0, 0]).unwrap();
            let mut iter = storage
                .maybe_iter_user_values_with_prefix(prefix, None)
                .unwrap()
                .expect("the storage iterates");
            assert_eq!(iter.next(), Some((key(0), counter(1))));
            gate.release();
            std::thread::sleep(Duration::from_millis(100));
            assert!(
                !finalize.is_finished(),
                "the commit did not wait for the iterator"
            );
            assert!(
                matches!(overlays.try_read(), Err(TryLockError::WouldBlock)),
                "the overlays lock is not held while the commit waits for the iterator"
            );
            drop(iter);
            join_within(finalize, Gate::TIMEOUT).expect("the finalization");
        });
        assert_eq!(m.latest_version(), Some(SlotNumber::new(1)));
        assert_eq!(prove(&storage, 0).unwrap(), (Some(counter(2)), roots[1]));
    });
}

/// B11, critique #14: a finalization of several blocks releases the overlays lock between
/// their commits. Paused between the first and the second block's commit, a storage created
/// before the finalization on the newest block proves its state without waiting (its oldest
/// overlay is committed, the others are still there), and a storage on a sibling of the
/// committed block fails at once: its fork was discarded together with the commit, under the
/// same lock. (Upstream held the lock across the whole chain, so readers stalled through a
/// long catch-up.)
#[test]
fn deep_finalize_releases_lock_between_segments() {
    paused_test(|mut m| {
        let chain = linear(3);
        let roots = write_all(&mut m, &chain);
        let sibling = TestHeader::new(2, 1, TestHeader::MAIN_FORK);
        write(&mut m, &sibling);
        let (tip, _) = m.create_state_after(&chain[2]).unwrap();
        let (on_sibling, _) = m.create_state_after(&sibling).unwrap();
        let gate = Gate::new();
        m.set_commit_hook(Some(gate.hook_at(CommitPoint::BetweenSegments)));
        let overlays = m.overlays().clone();
        std::thread::scope(|scope| {
            let finalize = scope.spawn(|| m.finalize(&chain[2]));
            assert!(
                gate.wait_reached(Gate::TIMEOUT),
                "the finalization did not pause"
            );
            {
                let overlays = overlays
                    .try_write()
                    .expect("the lock is released between blocks");
                assert!(
                    !overlays.contains_key(&chain[0].hash),
                    "block 1 is committed"
                );
                assert!(
                    !overlays.contains_key(&sibling.hash),
                    "its sibling is discarded"
                );
                assert!(
                    overlays.contains_key(&chain[1].hash) && overlays.contains_key(&chain[2].hash)
                );
            }
            assert_eq!(
                prove(&tip, 3).unwrap(),
                (Some(values(&chain[2]).user), roots[2])
            );
            assert_stale(&prove(&on_sibling, 1).unwrap_err(), true);
            assert!(!finalize.is_finished());
            gate.release();
            join_within(finalize, Gate::TIMEOUT).expect("the finalization");
        });
        assert_eq!(m.latest_version(), Some(SlotNumber::new(2)));
        assert_eq!(
            prove(&tip, 3).unwrap(),
            (Some(values(&chain[2]).user), roots[2])
        );
    });
}

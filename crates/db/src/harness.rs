//! A test harness: the state databases in a temporary directory, storages on them and commits,
//! crashes ([`TestDbs::crash_at`]) and paused commits ([`Gate`]) (test-only: `cfg(test)` or the
//! `test-utils` feature).

use core::marker::PhantomData;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use selendra_state::{MerkleProofSpec, StateCheckpoint, StateUpdate, Storage, StorageRoot};

use crate::test_utils::{TestDir, tempdir};
use crate::{
    CommitHook, CommitPoint, DbGroup, NomtChangeSet, NomtProverStorage, StateDbConfig, WitnessMode,
    fail_at,
};

/// The storage of [`TestDbs`]: block references are `u64` (unused: no uncommitted overlays).
pub type TestStorage<S> = NomtProverStorage<S, u64>;

/// The state databases ([`DbGroup`], small settings: [`StateDbConfig::for_tests`]) in a
/// temporary directory, deleted on drop. Every method panics on a database error.
///
/// At most 4 exist at once in a process (the others wait): each holds several RocksDB and NOMT
/// databases, which fill a small temporary file system quickly.
pub struct TestDbs<S: MerkleProofSpec> {
    // Dropped (closed) before the directory.
    group: DbGroup<S::Hasher>,
    dir: TestDir,
    _spec: PhantomData<fn() -> S>,
}

impl<S: MerkleProofSpec> core::fmt::Debug for TestDbs<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestDbs")
            .field("path", &self.dir.path())
            .finish_non_exhaustive()
    }
}

impl<S: MerkleProofSpec> Default for TestDbs<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: MerkleProofSpec> TestDbs<S> {
    /// Empty databases in a new temporary directory.
    pub fn new() -> Self {
        Self::with_hook(None)
    }

    /// Empty databases in a new temporary directory, with a commit hook (fault injection).
    pub fn with_hook(hook: Option<CommitHook>) -> Self {
        Self::new_in(tempdir(), hook)
    }

    /// Empty databases in `dir` (from [`tempdirs`](crate::test_utils::tempdirs) when a test
    /// needs several directories).
    pub(crate) fn new_in(dir: TestDir, hook: Option<CommitHook>) -> Self {
        let group = Self::open(dir.path(), hook);
        Self {
            group,
            dir,
            _spec: PhantomData,
        }
    }

    fn open(path: &Path, hook: Option<CommitHook>) -> DbGroup<S::Hasher> {
        DbGroup::open_with_hook(&StateDbConfig::for_tests(path), hook)
            .expect("open the state databases")
    }

    /// Closes and reopens the databases (without a commit hook): crash recovery runs.
    pub fn reopen(self) -> Self {
        let Self { group, dir, _spec } = self;
        // Closed first: the databases take file locks.
        drop(group);
        let group = Self::open(dir.path(), None);
        Self { group, dir, _spec }
    }

    /// Replaces the commit hook.
    pub fn set_commit_hook(&mut self, hook: Option<CommitHook>) {
        self.group.set_commit_hook(hook);
    }

    /// A crash during the commit of `change_set`: commits it with a fault at `point` (the
    /// commit must fail there, and poison the databases), then reopens the databases, which
    /// runs crash recovery ([`DbGroup::last_recovery`] says what it did).
    pub fn crash_at(mut self, point: CommitPoint, change_set: NomtChangeSet) -> Self {
        self.set_commit_hook(Some(fail_at(point)));
        let err = self
            .group
            .commit(change_set)
            .expect_err("the commit must fail at the injected fault");
        assert!(
            format!("{err:#}").contains("injected fault"),
            "the commit failed before the fault at {point:?}: {err:#}"
        );
        assert!(self.group.is_poisoned());
        self.reopen()
    }

    /// The databases.
    pub fn group(&self) -> &DbGroup<S::Hasher> {
        &self.group
    }

    /// The committed root.
    pub fn root(&self) -> StorageRoot<S> {
        self.group.roots().into()
    }

    /// A storage at the newest committed version.
    pub fn storage(&self, witness_mode: WitnessMode) -> TestStorage<S> {
        let readers = self.group.readers().expect("create the storage readers");
        NomtProverStorage::create(readers, witness_mode)
    }

    /// Commits a change set.
    pub fn commit(&mut self, change_set: NomtChangeSet) {
        self.group.commit(change_set).expect("commit");
    }

    /// Runs `f` on a checkpoint over a new storage and returns its changes (accessory writes
    /// included) for the next version, uncommitted, with their root.
    pub fn change_set_with(
        &self,
        witness_mode: WitnessMode,
        f: impl FnOnce(&mut StateCheckpoint<TestStorage<S>>),
    ) -> (NomtChangeSet, StorageRoot<S>) {
        let mut checkpoint = StateCheckpoint::new(self.storage(witness_mode));
        f(&mut checkpoint);
        let (root, mut update, accessory, _witness, storage) =
            checkpoint.materialize_update(self.root());
        update.add_accessory_items(accessory.freeze());
        (storage.materialize_changes(update), root)
    }

    /// Runs `f` on a checkpoint over a new storage, then commits its changes (accessory writes
    /// included) as the next version. Returns the new root.
    pub fn commit_with(
        &mut self,
        witness_mode: WitnessMode,
        f: impl FnOnce(&mut StateCheckpoint<TestStorage<S>>),
    ) -> StorageRoot<S> {
        let (change_set, root) = self.change_set_with(witness_mode, f);
        self.commit(change_set);
        assert_eq!(
            self.root(),
            root,
            "the committed root is not the computed one"
        );
        root
    }
}

/// Pauses a commit at one [`CommitPoint`] until the test releases it: other threads can then
/// act while the commit is half done. Per instance (upstream had one process-wide gate).
///
/// The commit runs on another thread with the gate's hook ([`hook_at`](Self::hook_at)); the
/// test waits for it to arrive ([`wait_reached`](Self::wait_reached)), acts, then
/// [`release`](Self::release)s it. The paused hook never panics (it runs inside a commit that
/// may hold locks, which a panic would poison): if it is not released within its timeout
/// (10 s by default), it returns `Err`, failing the commit, and the test's own checks panic.
#[derive(Debug)]
pub struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
    timeout: Duration,
}

#[derive(Debug, Default)]
struct GateState {
    reached: bool,
    released: bool,
}

impl Gate {
    /// How long a paused commit waits for [`release`](Self::release) by default.
    pub const TIMEOUT: Duration = Duration::from_secs(10);

    /// A gate whose paused commit gives up after [`TIMEOUT`](Self::TIMEOUT).
    pub fn new() -> Arc<Self> {
        Self::with_timeout(Self::TIMEOUT)
    }

    /// A gate whose paused commit gives up after `timeout`.
    pub fn with_timeout(timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::default(),
            changed: Condvar::new(),
            timeout,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A commit hook that pauses the first time `point` is reached, until
    /// [`release`](Self::release) (or the timeout: then it returns `Err`); every other point,
    /// and `point` reached again, passes.
    pub fn hook_at(self: &Arc<Self>, point: CommitPoint) -> CommitHook {
        let gate = Arc::clone(self);
        Arc::new(move |reached| {
            if reached != point {
                return Ok(());
            }
            let mut state = gate.lock();
            if state.reached {
                return Ok(());
            }
            state.reached = true;
            gate.changed.notify_all();
            let deadline = Instant::now().checked_add(gate.timeout);
            while !state.released {
                let left = deadline.map_or(gate.timeout, |deadline| {
                    deadline.saturating_duration_since(Instant::now())
                });
                anyhow::ensure!(
                    !left.is_zero(),
                    "the gate at {point:?} timed out: not released within {:?}",
                    gate.timeout
                );
                state = gate
                    .changed
                    .wait_timeout(state, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            Ok(())
        })
    }

    /// Waits until the commit is paused at the gate's point; `false` if it is not within
    /// `timeout`.
    pub fn wait_reached(&self, timeout: Duration) -> bool {
        let state = self.lock();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| !state.reached)
            .unwrap_or_else(PoisonError::into_inner);
        state.reached
    }

    /// Lets the paused commit go on (or, before it arrives, lets it pass).
    pub fn release(&self) {
        self.lock().released = true;
        self.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use selendra_interface::common::SlotNumber;
    use selendra_state::test_utils::map;
    use selendra_state::{NativeStorage, StateStorageSpec};

    use super::*;
    use crate::RecoveryStep;

    type Dbs = TestDbs<StateStorageSpec>;
    const OFF: WitnessMode = WitnessMode::Off;

    fn set(value: u32) -> impl FnOnce(&mut StateCheckpoint<TestStorage<StateStorageSpec>>) {
        move |state| {
            let Ok(()) = map().set(&1, &value, state);
        }
    }

    /// A commit paused at a point (here: NOMT and the accessory DB written, not the flat
    /// store) on another thread: a storage of the previous version still sees that version
    /// as the newest until the gate is released.
    #[test]
    fn gate_pauses_a_commit_until_released() {
        let mut dbs = Dbs::new();
        dbs.commit_with(OFF, set(1));
        let storage = dbs.storage(OFF);
        let (change_set, root) = dbs.change_set_with(OFF, set(2));
        let gate = Gate::new();
        dbs.set_commit_hook(Some(gate.hook_at(CommitPoint::BeforeArchival)));
        std::thread::scope(|scope| {
            let commit = scope.spawn(|| dbs.group.commit(change_set));
            assert!(gate.wait_reached(Gate::TIMEOUT), "the commit did not pause");
            assert_eq!(storage.latest_version_unbound(), SlotNumber::GENESIS);
            assert!(!commit.is_finished());
            gate.release();
            commit.join().unwrap().unwrap();
        });
        assert_eq!(storage.latest_version_unbound(), SlotNumber::new(1));
        assert_eq!(dbs.root(), root);
    }

    /// A gate never released fails the commit with an `Err` after its timeout (no panic, which
    /// would poison the locks the commit holds), and the databases recover on reopen.
    #[test]
    fn gate_timeout_fails_the_commit_without_panicking() {
        let mut dbs = Dbs::new();
        let root = dbs.commit_with(OFF, set(1));
        let (change_set, _) = dbs.change_set_with(OFF, set(2));
        let gate = Gate::with_timeout(Duration::from_millis(50));
        dbs.set_commit_hook(Some(gate.hook_at(CommitPoint::BeforeAccessory)));
        let err = dbs.group.commit(change_set).unwrap_err();
        assert!(format!("{err:#}").contains("timed out"), "{err:#}");
        assert!(gate.wait_reached(Duration::ZERO));
        assert!(dbs.group().is_poisoned());
        let dbs = dbs.reopen();
        assert_eq!(
            dbs.group().last_recovery().rolled_back,
            [RecoveryStep::UserNomt]
        );
        assert_eq!(dbs.root(), root);
    }

    /// `crash_at` fails the commit at the point and reopens: recovery rolls back what was
    /// written, and the same block then commits to the same root.
    #[test]
    fn crash_at_recovers_on_reopen() {
        let mut dbs = Dbs::new();
        let root = dbs.commit_with(OFF, set(1));
        let (change_set, next_root) = dbs.change_set_with(OFF, set(2));
        let mut dbs = dbs.crash_at(CommitPoint::BeforeLive, change_set);
        assert_eq!(
            dbs.group().last_recovery().rolled_back,
            [
                RecoveryStep::UserNomt,
                RecoveryStep::Accessory,
                RecoveryStep::Archival
            ]
        );
        assert_eq!(dbs.root(), root);
        assert_eq!(dbs.commit_with(OFF, set(2)), next_root);
    }
}

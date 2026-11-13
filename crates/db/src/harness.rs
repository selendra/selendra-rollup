//! A test harness: the state databases in a temporary directory, storages on them and commits,
//! crashes ([`TestDbs::crash_at`]) and paused commits ([`Gate`]); the storage manager in a
//! temporary directory ([`TestManager`]) with a test block header ([`TestHeader`]) (test-only:
//! `cfg(test)` or the `test-utils` feature).

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use std::convert::Infallible;
use std::hash::Hash;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use selendra_interface::common::{HexHash, SlotNumber};
use selendra_interface::da::{BlockHeaderTrait, Time};
use selendra_interface::node::storage::HierarchicalStorageManager;
use selendra_interface::reexports::digest::Digest;
use selendra_state::namespaces::{Accessory, Kernel, User};
use selendra_state::{
    MerkleProofSpec, NativeStorage, SlotKey, SlotValue, StateCheckpoint, StateHasher, StateUpdate,
    StateWriter, Storage, StorageRoot,
};

use crate::ledger::{LedgerChangeSet, LedgerReader, SlotContents, SlotInfo};
use crate::test_utils::{TestDir, tempdir};
use crate::{
    CommitHook, CommitPoint, DbGroup, NomtChangeSet, NomtProverStorage, NomtRoots,
    NomtStorageManager, StateDbConfig, StorageManagerConfig, WitnessMode, fail_at,
};

/// The DA block of the test slot at `version`: hash `SHA-256(version as u64 big-endian)`,
/// height `version`, timestamp `version` milliseconds (at most `i64::MAX`).
pub fn test_slot_info(version: SlotNumber) -> SlotInfo {
    SlotInfo {
        da_hash: StateHasher::digest(version.get().to_be_bytes()).into(),
        da_height: version.get(),
        timestamp: Time::from_millis(i64::try_from(version.get()).unwrap_or(i64::MAX)),
    }
}

/// An empty ledger slot (no batches, proofs or STF info) for the state change set at
/// `version` with roots `roots`, on top of `ledger`'s newest slot; its DA block is
/// [`test_slot_info`]`(version)`.
///
/// # Panics
/// If the slot cannot be materialized (see [`LedgerReader::materialize_slot`]).
pub fn empty_slot(ledger: &LedgerReader, version: SlotNumber, roots: NomtRoots) -> LedgerChangeSet {
    ledger
        .materialize_slot(
            version,
            roots,
            test_slot_info(version),
            SlotContents::default(),
        )
        .expect("materialize an empty ledger slot")
}

/// The storage of [`TestDbs`]: block references are `u64` (unused: no uncommitted overlays).
pub type TestStorage<S> = NomtProverStorage<S, u64>;

/// The state databases ([`DbGroup`], small settings: [`StateDbConfig::for_tests`]) in a
/// temporary directory, deleted on drop. Every method panics on a database error.
///
/// At most 3 exist at once in a process (the others wait): each holds several RocksDB and NOMT
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

    /// A crash during the commit of `change_set` (with an [`empty_slot`]): commits it with a
    /// fault at `point` (the commit must fail there, and poison the databases), then reopens the
    /// databases, which runs crash recovery ([`DbGroup::last_recovery`] says what it did).
    pub fn crash_at(mut self, point: CommitPoint, change_set: NomtChangeSet) -> Self {
        let ledger = self.empty_slot_for(&change_set);
        self.set_commit_hook(Some(fail_at(point)));
        let err = self
            .group
            .commit(change_set, ledger)
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

    /// The databases' directory.
    pub fn path(&self) -> &Path {
        self.dir.path()
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

    /// A reader of the committed ledger.
    pub fn ledger(&self) -> LedgerReader {
        self.group.ledger_reader().expect("a ledger reader")
    }

    /// An [`empty_slot`] for `change_set`.
    pub fn empty_slot_for(&self, change_set: &NomtChangeSet) -> LedgerChangeSet {
        empty_slot(&self.ledger(), change_set.version(), change_set.roots())
    }

    /// Commits a change set, with an [`empty_slot`].
    pub fn commit(&mut self, change_set: NomtChangeSet) {
        let ledger = self.empty_slot_for(&change_set);
        self.group.commit(change_set, ledger).expect("commit");
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

    /// Commits `user`, `kernel` and `accessory` (`None`: delete) as the next version, through a
    /// checkpoint over a new storage. Returns the new root.
    pub fn commit_writes(
        &mut self,
        user: Writes<'_>,
        kernel: Writes<'_>,
        accessory: Writes<'_>,
    ) -> StorageRoot<S> {
        self.commit_with(WitnessMode::Off, |checkpoint| {
            for (key, value) in user {
                let Ok(()) = write::<User, _>(checkpoint, key, value);
            }
            for (key, value) in kernel {
                let Ok(()) = write::<Kernel, _>(checkpoint, key, value);
            }
            for (key, value) in accessory {
                let Ok(()) = write::<Accessory, _>(checkpoint, key, value);
            }
        })
    }

    /// One pruning pass ([`DbGroup::prune`]).
    pub fn prune(
        &mut self,
        versions_to_keep: u64,
        max_keys_per_run: u64,
    ) -> anyhow::Result<crate::PruneStats> {
        let nonzero = |n: u64| core::num::NonZeroU64::new(n).expect("not zero");
        self.group
            .prune(nonzero(versions_to_keep), nonzero(max_keys_per_run))
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

// ---------------------------------------------------------------------------------------------
// The storage manager.

/// A DA block header for tests (no DA layer yet): its hash, its parent's hash and its height;
/// its time is its height in milliseconds.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TestHeader {
    /// The block's hash.
    pub hash: HexHash,
    /// The parent block's hash.
    pub prev: HexHash,
    /// The block's height.
    pub height: u64,
}

impl BlockHeaderTrait for TestHeader {
    type Hash = HexHash;

    fn prev_hash(&self) -> HexHash {
        self.prev
    }

    fn hash(&self) -> HexHash {
        self.hash
    }

    fn height(&self) -> u64 {
        self.height
    }

    fn time(&self) -> Time {
        Time::from_millis(i64::try_from(self.height).unwrap_or(i64::MAX))
    }
}

impl TestHeader {
    /// The fork of [`linear`](Self::linear) blocks.
    pub const MAIN_FORK: u64 = 1;

    /// Block `height` of fork `fork_id`, a child of block `height - 1` of fork `parent_fork`
    /// (hashes: [`block_hash`]).
    ///
    /// # Panics
    /// If `height` is 0 (use [`genesis`](Self::genesis)).
    pub fn new(fork_id: u64, height: u64, parent_fork: u64) -> Self {
        let parent_height = height.checked_sub(1).expect("height 0 has no parent here");
        Self {
            hash: block_hash(fork_id, height),
            prev: block_hash(parent_fork, parent_height),
            height,
        }
    }

    /// A genesis block of fork `fork_id` at `height`: its parent is block `height - 1` of fork
    /// 0, which no test executes (`height` 0: its parent is block 0 of fork 0).
    pub fn genesis(fork_id: u64, height: u64) -> Self {
        Self {
            hash: block_hash(fork_id, height),
            prev: block_hash(0, height.saturating_sub(1)),
            height,
        }
    }

    /// Block `height` of the main fork, on block `height - 1` of the main fork (`height` 0:
    /// the main fork's genesis block).
    pub fn linear(height: u64) -> Self {
        if height == 0 {
            Self::genesis(Self::MAIN_FORK, 0)
        } else {
            Self::new(Self::MAIN_FORK, height, Self::MAIN_FORK)
        }
    }

    /// A child of this block on fork `fork_id`.
    pub fn child(&self, fork_id: u64) -> Self {
        let height = self.height.checked_add(1).expect("height overflow");
        Self {
            hash: block_hash(fork_id, height),
            prev: self.hash,
            height,
        }
    }
}

/// A deterministic block hash: `fork_id` and `height`, big-endian, then zeros (upstream's
/// `get_block_hash`).
pub fn block_hash(fork_id: u64, height: u64) -> HexHash {
    let mut hash = [0u8; 32];
    hash[..8].copy_from_slice(&fork_id.to_be_bytes());
    hash[8..16].copy_from_slice(&height.to_be_bytes());
    HexHash::new(hash)
}

/// The ledger's DA block of `hdr`: its hash, height and time.
pub fn header_slot_info(hdr: &impl BlockHeaderTrait) -> SlotInfo {
    SlotInfo {
        da_hash: hdr.hash().into(),
        da_height: hdr.height(),
        timestamp: hdr.time(),
    }
}

/// The storage manager of [`TestManager`]: blocks are [`TestHeader`]s.
pub type TestStorageManager<S> = NomtStorageManager<S, TestHeader>;

/// The storage manager on state databases in a temporary directory, deleted on drop (it holds
/// one of the at most 3 test directories, like [`TestDbs`]). Dereferences to the manager. Every
/// method panics on a database error.
pub struct TestManager<S: MerkleProofSpec> {
    // Dropped (closed) before the directory.
    manager: TestStorageManager<S>,
    dir: TestDir,
    config: StorageManagerConfig,
}

impl<S: MerkleProofSpec> core::fmt::Debug for TestManager<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestManager")
            .field("path", &self.dir.path())
            .field("manager", &self.manager)
            .finish_non_exhaustive()
    }
}

impl<S: MerkleProofSpec> Default for TestManager<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: MerkleProofSpec> TestManager<S> {
    /// A manager on empty databases ([`StateDbConfig::for_tests`], witness off).
    pub fn new() -> Self {
        Self::with_config(|_| {})
    }

    /// A manager on empty databases, with the configuration changed by `f`.
    pub fn with_config(f: impl FnOnce(&mut StorageManagerConfig)) -> Self {
        Self::new_in(tempdir(), f)
    }

    /// A manager on empty databases in `dir`.
    pub(crate) fn new_in(dir: TestDir, f: impl FnOnce(&mut StorageManagerConfig)) -> Self {
        let mut config =
            StorageManagerConfig::new(StateDbConfig::for_tests(dir.path()), WitnessMode::Off);
        f(&mut config);
        let manager = NomtStorageManager::open(config.clone()).expect("open the storage manager");
        Self {
            manager,
            dir,
            config,
        }
    }

    /// Drops the manager (its unfinalized blocks are lost) and opens it again: crash recovery
    /// runs, and the finalized block comes from the ledger.
    pub fn reopen(self) -> Self {
        self.reopen_with(|_| {})
    }

    /// [`reopen`](Self::reopen) with the configuration changed by `f` (kept for later reopens).
    pub fn reopen_with(self, f: impl FnOnce(&mut StorageManagerConfig)) -> Self {
        let Self {
            manager,
            dir,
            mut config,
        } = self;
        drop(manager);
        f(&mut config);
        let manager = NomtStorageManager::open(config.clone()).expect("reopen the storage manager");
        Self {
            manager,
            dir,
            config,
        }
    }

    /// The databases' directory.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl<S: MerkleProofSpec> Deref for TestManager<S> {
    type Target = TestStorageManager<S>;

    fn deref(&self) -> &Self::Target {
        &self.manager
    }
}

impl<S: MerkleProofSpec> DerefMut for TestManager<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.manager
    }
}

/// One namespace's writes of a block (`None`: delete).
pub type Writes<'a> = &'a [(SlotKey, Option<SlotValue>)];

/// The changes of block `hdr` executed on `storage` (with `ledger`, both from `create_state_for`):
/// `user`, `kernel` and `accessory` written through a checkpoint, and an empty ledger slot for
/// `hdr`'s DA block ([`header_slot_info`]). Returns them with the root after the block.
pub fn block_changes<S: MerkleProofSpec, K: Clone + Eq + Hash>(
    storage: NomtProverStorage<S, K>,
    ledger: &LedgerReader,
    hdr: &impl BlockHeaderTrait,
    user: Writes<'_>,
    kernel: Writes<'_>,
    accessory: Writes<'_>,
) -> (NomtChangeSet, LedgerChangeSet, StorageRoot<S>) {
    let prev_root = storage.root().expect("the storage's root");
    let mut checkpoint = StateCheckpoint::new(storage);
    for (key, value) in user {
        let Ok(()) = write::<User, _>(&mut checkpoint, key, value);
    }
    for (key, value) in kernel {
        let Ok(()) = write::<Kernel, _>(&mut checkpoint, key, value);
    }
    for (key, value) in accessory {
        let Ok(()) = write::<Accessory, _>(&mut checkpoint, key, value);
    }
    let (root, mut update, accessory, _witness, storage) = checkpoint.materialize_update(prev_root);
    update.add_accessory_items(accessory.freeze());
    let change_set = storage.materialize_changes(update);
    let ledger_change_set = ledger
        .materialize_slot(
            change_set.version(),
            change_set.roots(),
            header_slot_info(hdr),
            SlotContents::default(),
        )
        .expect("materialize the block's ledger slot");
    (change_set, ledger_change_set, root)
}

fn write<N, St>(
    checkpoint: &mut StateCheckpoint<St>,
    key: &SlotKey,
    value: &Option<SlotValue>,
) -> Result<(), Infallible>
where
    St: Storage,
    N: selendra_state::namespaces::CompileTimeNamespace,
    StateCheckpoint<St>: StateWriter<N, Error = Infallible>,
{
    match value {
        Some(value) => StateWriter::<N>::set(checkpoint, key, value.clone()),
        None => StateWriter::<N>::delete(checkpoint, key),
    }
}

/// Executes block `hdr` on `manager` ([`block_changes`] on the state for it) and saves its
/// changes. Returns the root after it.
pub fn write_block<S: MerkleProofSpec>(
    manager: &mut TestStorageManager<S>,
    hdr: &TestHeader,
    user: Writes<'_>,
    kernel: Writes<'_>,
    accessory: Writes<'_>,
) -> StorageRoot<S> {
    let (storage, ledger) = manager
        .create_state_for(hdr)
        .expect("create the state for the block");
    let (change_set, ledger_change_set, root) =
        block_changes(storage, &ledger, hdr, user, kernel, accessory);
    manager
        .save_change_set(hdr, change_set, ledger_change_set)
        .expect("save the block's changes");
    root
}

/// Checks a proof of the user `key` from `storage` ([`NativeStorage::get_with_proof`]) and
/// returns its version and root: the version is the newest `storage` sees, the root is that
/// version's, the proof opens against it to `(key, expected)`, `fresh` (a storage at that
/// version) reads `expected` there and `accessory.1` at `accessory.0`, and the user and kernel
/// roots differ (tests write different values to them).
///
/// # Panics
/// If a check fails.
pub fn assert_proof_consistent<S: MerkleProofSpec, K: Clone + Eq + Hash>(
    storage: &NomtProverStorage<S, K>,
    fresh: &NomtProverStorage<S, K>,
    key: &SlotKey,
    expected: Option<&SlotValue>,
    accessory: (&SlotKey, Option<&SlotValue>),
) -> (SlotNumber, StorageRoot<S>) {
    let (proof, version, root) = storage
        .get_with_proof::<User>(key.clone())
        .expect("a proof");
    assert_eq!(
        version,
        storage.latest_version_unbound(),
        "the proof is of the newest version the storage sees"
    );
    assert_eq!(
        storage.get_root_hash_unbound(version),
        Some(root),
        "the proof's root is its version's"
    );
    assert_eq!(proof.value.as_ref(), expected, "the proven value");
    assert_eq!(
        NomtProverStorage::<S, K>::open_proof(root, proof).expect("the proof opens"),
        (key.clone(), expected.cloned())
    );
    assert_eq!(fresh.latest_version(), version, "`fresh` is at the version");
    assert_eq!(
        fresh
            .get_historical::<User>(key, Some(version), &Default::default())
            .expect("a historical read")
            .as_ref(),
        expected,
        "the value at the proof's version"
    );
    assert_eq!(
        fresh
            .get_accessory_historical(accessory.0, Some(version))
            .expect("a historical accessory read")
            .as_ref(),
        accessory.1,
        "the accessory value at the proof's version"
    );
    assert_ne!(
        root.user_root(),
        root.kernel_root(),
        "user and kernel roots"
    );
    (version, root)
}

// ---------------------------------------------------------------------------------------------
// Paused commits.

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
        let ledger = dbs.empty_slot_for(&change_set);
        let gate = Gate::new();
        dbs.set_commit_hook(Some(gate.hook_at(CommitPoint::BeforeArchival)));
        std::thread::scope(|scope| {
            let commit = scope.spawn(|| dbs.group.commit(change_set, ledger));
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
        let ledger = dbs.empty_slot_for(&change_set);
        let gate = Gate::with_timeout(Duration::from_millis(50));
        dbs.set_commit_hook(Some(gate.hook_at(CommitPoint::BeforeAccessory)));
        let err = dbs.group.commit(change_set, ledger).unwrap_err();
        assert!(format!("{err:#}").contains("timed out"), "{err:#}");
        assert!(gate.wait_reached(Duration::ZERO));
        assert!(dbs.group().is_poisoned());
        let dbs = dbs.reopen();
        assert_eq!(
            dbs.group().last_recovery().rolled_back,
            [RecoveryStep::UserNomt, RecoveryStep::Ledger]
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
                RecoveryStep::Ledger,
                RecoveryStep::Accessory,
                RecoveryStep::Archival
            ]
        );
        assert_eq!(dbs.root(), root);
        assert_eq!(dbs.commit_with(OFF, set(2)), next_root);
    }
}

//! A test harness: the state databases in a temporary directory, storages on them and commits
//! (test-only: `cfg(test)` or the `test-utils` feature).

use core::marker::PhantomData;
use std::path::Path;

use selendra_state::{MerkleProofSpec, StateCheckpoint, StateUpdate, Storage, StorageRoot};

use crate::test_utils::{TestDir, tempdir};
use crate::{DbGroup, NomtChangeSet, NomtProverStorage, StateDbConfig, WitnessMode};

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
        let dir = tempdir();
        let group = Self::open(dir.path());
        Self {
            group,
            dir,
            _spec: PhantomData,
        }
    }

    fn open(path: &Path) -> DbGroup<S::Hasher> {
        DbGroup::open(&StateDbConfig::for_tests(path)).expect("open the state databases")
    }

    /// Closes and reopens the databases.
    pub fn reopen(self) -> Self {
        let Self { group, dir, _spec } = self;
        // Closed first: the databases take file locks.
        drop(group);
        let group = Self::open(dir.path());
        Self { group, dir, _spec }
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

    /// Runs `f` on a checkpoint over a new storage, then commits its changes (accessory writes
    /// included) as the next version. Returns the new root.
    pub fn commit_with(
        &mut self,
        witness_mode: WitnessMode,
        f: impl FnOnce(&mut StateCheckpoint<TestStorage<S>>),
    ) -> StorageRoot<S> {
        let mut checkpoint = StateCheckpoint::new(self.storage(witness_mode));
        f(&mut checkpoint);
        let (root, mut update, accessory, _witness, storage) =
            checkpoint.materialize_update(self.root());
        update.add_accessory_items(accessory.freeze());
        self.commit(storage.materialize_changes(update));
        assert_eq!(
            self.root(),
            root,
            "the committed root is not the computed one"
        );
        root
    }
}

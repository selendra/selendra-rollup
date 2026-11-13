//! The flat value store ([`FlatStateDb`]): the raw key/value pairs of the user and kernel state,
//! versioned, in two RocksDB instances (live and archival). NOMT holds only hashes; every value
//! read goes through here.

use std::path::Path;
use std::sync::Arc;

use parking_lot::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};
use rockbound::cache::delta_reader::DeltaReader;
use rockbound::rocksdb::{self, ColumnFamilyDescriptor};
use rockbound::versioned_db::{
    CacheForVersionedDB, SchemaWithVersion, VersionedDB, VersionedDeltaReader, VersionedSchemaBatch,
};
use rockbound::{CacheForSchema, DB, Schema, SchemaBatch};
use selendra_interface::common::SlotNumber;

use crate::accessory::DbOptions;
use crate::faults::{CommitPoint, Faults};
use crate::historical::{
    HistoricalStateReader, KernelValues, StateChanges, UserValues, next_version_after,
};
use crate::nomt_state::NomtRoots;
use crate::schema::StateRootHashes;

/// The flat value store: for each provable namespace, rockbound's [`VersionedDB`] (one live
/// value per key plus its past values back to the pruning watermark: the pruner
/// ([`DbGroup::prune`](crate::DbGroup::prune)) deletes archival rows at or below its cutoff),
/// and the root of every version.
///
/// - The live DB (`state-db`) holds the live values, the committed version and the roots.
/// - The archival DB (`archival-state-db`) holds the past values, the keys written per version
///   (for pruning and rollback) and the roots.
///
/// A commit writes the archival DB first and the live DB last, so after a crash the live DB is
/// never ahead: the archival DB is at most one version ahead, and startup crash recovery
/// ([`DbGroup::open`](crate::DbGroup::open)) removes that version (as
/// [`validate_and_rollback_archival`](Self::validate_and_rollback_archival) does).
pub struct FlatStateDb {
    user: Arc<VersionedDB<UserValues, DbCache>>,
    kernel: Arc<VersionedDB<KernelValues, DbCache>>,
    live_db: Arc<DB>,
    archival_db: Arc<DB>,
    db_cache: DbCache,
}

impl core::fmt::Debug for FlatStateDb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FlatStateDb")
    }
}

/// What [`FlatStateDb::commit_internal`] writes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CommitMode {
    /// A version: archival, then live.
    Commit,
    /// Removes a version's archival rows (the live DB is not touched).
    RollbackArchival,
}

impl FlatStateDb {
    const LIVE_DB_NAME: &'static str = "state-live";
    pub(crate) const LIVE_DB_PATH_SUFFIX: &'static str = "state-db";
    const ARCHIVAL_DB_NAME: &'static str = "state-archival";
    pub(crate) const ARCHIVAL_DB_PATH_SUFFIX: &'static str = "archival-state-db";

    /// Opens (or creates) the store under `path`, with value caches of `user_cache_size` and
    /// `kernel_cache_size` bytes.
    pub fn new(
        path: &Path,
        user_cache_size: usize,
        kernel_cache_size: usize,
    ) -> anyhow::Result<Self> {
        let mut live_columns = vec![rockbound::default_cf_descriptor(
            StateRootHashes::COLUMN_FAMILY_NAME,
        )];
        VersionedDB::<UserValues, DbCache>::add_live_db_column_families(&mut live_columns)?;
        VersionedDB::<KernelValues, DbCache>::add_live_db_column_families(&mut live_columns)?;
        let live_db = Arc::new(
            Self::options(Self::LIVE_DB_NAME, Self::LIVE_DB_PATH_SUFFIX, live_columns)
                .open_in(path)?,
        );

        let mut archival_columns = vec![rockbound::default_cf_descriptor(
            StateRootHashes::COLUMN_FAMILY_NAME,
        )];
        VersionedDB::<UserValues, DbCache>::add_archival_db_column_families(&mut archival_columns)?;
        VersionedDB::<KernelValues, DbCache>::add_archival_db_column_families(
            &mut archival_columns,
        )?;
        let archival_db = Arc::new(
            Self::options(
                Self::ARCHIVAL_DB_NAME,
                Self::ARCHIVAL_DB_PATH_SUFFIX,
                archival_columns,
            )
            .open_in(path)?,
        );

        let db_cache = DbCache {
            inner: Arc::new(RwLock::new(Inner {
                user_cache: rockbound::new_cache_for_schema::<UserValues>(user_cache_size),
                kernel_cache: rockbound::new_cache_for_schema::<KernelValues>(kernel_cache_size),
            })),
        };
        let user = Arc::new(VersionedDB::from_dbs(
            live_db.clone(),
            archival_db.clone(),
            db_cache.clone(),
        )?);
        let kernel = Arc::new(VersionedDB::from_dbs(
            live_db.clone(),
            archival_db.clone(),
            db_cache.clone(),
        )?);
        Ok(Self {
            user,
            kernel,
            live_db,
            archival_db,
            db_cache,
        })
    }

    fn options(
        name: &'static str,
        path_suffix: &'static str,
        columns: Vec<ColumnFamilyDescriptor>,
    ) -> DbOptions {
        DbOptions {
            name,
            path_suffix,
            columns,
        }
    }

    /// The live DB.
    pub fn live_db(&self) -> &Arc<DB> {
        &self.live_db
    }

    /// The archival DB.
    pub fn archival_db(&self) -> &Arc<DB> {
        &self.archival_db
    }

    /// The versioned user values.
    pub fn user_db(&self) -> &Arc<VersionedDB<UserValues, DbCache>> {
        &self.user
    }

    /// The versioned kernel values.
    pub fn kernel_db(&self) -> &Arc<VersionedDB<KernelValues, DbCache>> {
        &self.kernel
    }

    /// The newest version committed to the live DB and its root (`None`: empty).
    pub fn latest_version_and_root_live(&self) -> anyhow::Result<Option<(SlotNumber, NomtRoots)>> {
        latest_root(&self.live_db)
    }

    /// The newest version in the archival DB and its root (`None`: empty). One version ahead of
    /// the live DB after a crash between the two writes.
    pub fn latest_version_and_root_archival(
        &self,
    ) -> anyhow::Result<Option<(SlotNumber, NomtRoots)>> {
        latest_root(&self.archival_db)
    }

    /// The root of exactly `version` in the archival DB.
    pub fn root_archival_at(&self, version: SlotNumber) -> anyhow::Result<Option<NomtRoots>> {
        let reader = DeltaReader::new(self.archival_db.clone(), Vec::new());
        Ok(
            HistoricalStateReader::get_root_hash_from_reader(&reader, version)?
                .filter(|(found, _)| *found == version)
                .map(|(_, root)| root),
        )
    }

    /// A reader of the committed store (no uncommitted snapshots) at its newest version.
    pub fn reader(&self) -> anyhow::Result<HistoricalStateReader> {
        let version = self
            .latest_version_and_root_live()?
            .map(|(version, _)| version.get());
        HistoricalStateReader::new(
            VersionedDeltaReader::new(self.user.clone(), version, Vec::new()),
            VersionedDeltaReader::new(self.kernel.clone(), version, Vec::new()),
            DeltaReader::new(self.live_db.clone(), Vec::new()),
        )
    }

    /// Commits one version's changes. `&mut`: commits must not race (each checks the version
    /// it appends to).
    ///
    /// # Errors
    /// If `changes` is not for the version after the newest committed one (genesis if the
    /// store is empty): upstream wrote the values at the next version whatever version the root
    /// was materialized for. Also on write errors; the value caches are then cleared, since
    /// they may hold values that were not written.
    pub fn commit(&mut self, changes: StateChanges) -> anyhow::Result<()> {
        self.commit_with_faults(&changes, &Faults::default())
    }

    /// [`commit`](Self::commit), calling `faults` between the archival and the live write
    /// ([`CommitPoint::BeforeLive`]).
    pub(crate) fn commit_with_faults(
        &mut self,
        changes: &StateChanges,
        faults: &Faults,
    ) -> anyhow::Result<()> {
        let latest = self.latest_version_and_root_live()?.map(|(v, _)| v);
        let expected = next_version_after(latest)?;
        anyhow::ensure!(
            changes.version == expected,
            "the state changes are for version {} but the flat store expects version {expected}",
            changes.version
        );
        self.commit_internal(changes, CommitMode::Commit, faults)
    }

    /// Writes `changes` at `changes.version` as `mode` says.
    fn commit_internal(
        &self,
        changes: &StateChanges,
        mode: CommitMode,
        faults: &Faults,
    ) -> anyhow::Result<()> {
        // Held while the caches and the DBs are updated. Only prefix iterators wait for it: a
        // point read that finds it taken reads the DBs themselves (the live DB is written last,
        // so it holds the previous version until then), and root reads take no lock.
        let inner = self.db_cache.inner.write();
        let written = self.write_under_lock(&inner, changes, mode, faults);
        if written.is_err() && mode != CommitMode::RollbackArchival {
            // The caches were updated with values that may not have been written.
            inner.user_cache.clear();
            inner.kernel_cache.clear();
        }
        drop(inner);
        written
    }

    fn write_under_lock(
        &self,
        inner: &Inner,
        changes: &StateChanges,
        mode: CommitMode,
        faults: &Faults,
    ) -> anyhow::Result<()> {
        let version = changes.version.get();
        let is_commit = mode != CommitMode::RollbackArchival;
        let mut live_batch = rocksdb::WriteBatch::default();
        let mut archival_batch = rocksdb::WriteBatch::default();
        VersionedDB::<KernelValues, DbCache>::update_versioned_db_batch(
            &mut live_batch,
            &mut archival_batch,
            &changes.kernel,
            version,
            &inner.kernel_cache,
            &self.live_db,
            &self.archival_db,
            is_commit,
        )?;
        VersionedDB::<UserValues, DbCache>::update_versioned_db_batch(
            &mut live_batch,
            &mut archival_batch,
            &changes.user,
            version,
            &inner.user_cache,
            &self.live_db,
            &self.archival_db,
            is_commit,
        )?;
        DB::update_db_batch_with_schema_data(
            &mut archival_batch,
            &changes.root_hash_batch,
            &self.archival_db,
        )?;
        DB::update_db_batch_with_schema_data(
            &mut live_batch,
            &changes.root_hash_batch,
            &self.live_db,
        )?;

        self.archival_db.write_db_batch(archival_batch)?;
        if mode == CommitMode::RollbackArchival {
            return Ok(());
        }
        // rockbound: before the live DB is written, so that readers of older versions read the
        // archival rows from now on. (Upstream also did this on a rollback, which sent readers
        // to the archival rows needlessly.)
        self.kernel.store_committed_archival_version(version);
        self.user.store_committed_archival_version(version);
        faults.hit(CommitPoint::BeforeLive)?;
        self.live_db.write_db_batch(live_batch)
    }

    /// Checks that the live and archival DBs are at the same version; if the archival DB is one
    /// version ahead (a crash between the two writes of a commit), removes that version from
    /// it. Startup crash recovery does the same for all the state databases
    /// ([`DbGroup::open`](crate::DbGroup::open)).
    ///
    /// # Errors
    /// If the two DBs are in any other state (they cannot be repaired automatically), or on
    /// read or write errors. Upstream panicked.
    pub fn validate_and_rollback_archival(&mut self) -> anyhow::Result<()> {
        if let Some((version, _)) = self.archival_ahead()? {
            self.rollback_archival(version)?;
        }
        Ok(())
    }

    /// The archival DB's newest version and roots if it is one version ahead of the live DB
    /// (and at the live DB's roots at its version); `None` if both are at the same version and
    /// roots. With an empty live DB, an archival DB at genesis is one ahead (a crash during the
    /// genesis commit; upstream refused it).
    ///
    /// # Errors
    /// If the two DBs are in any other state, or on read errors.
    pub(crate) fn archival_ahead(&self) -> anyhow::Result<Option<(SlotNumber, NomtRoots)>> {
        crate::recovery::one_ahead(
            "flat archival DB",
            self.latest_version_and_root_archival()?,
            self.latest_version_and_root_live()?,
            |version| self.root_archival_at(version),
        )
    }

    /// Removes `version` (every key written at it, and its root) from the archival DB.
    pub(crate) fn rollback_archival(&mut self, version: SlotNumber) -> anyhow::Result<()> {
        let user = keys_written_at(&self.user, version)?;
        let kernel = keys_written_at(&self.kernel, version)?;
        let mut root_hash_batch = SchemaBatch::default();
        root_hash_batch.delete::<StateRootHashes>(&version)?;
        let changes = StateChanges {
            user: Arc::new(user),
            kernel: Arc::new(kernel),
            root_hash_batch: Arc::new(root_hash_batch),
            version,
            // Unused by a rollback.
            root: NomtRoots::PRE_GENESIS,
        };
        self.commit_internal(&changes, CommitMode::RollbackArchival, &Faults::default())
    }
}

/// The newest version in `db` and its root.
fn latest_root(db: &Arc<DB>) -> anyhow::Result<Option<(SlotNumber, NomtRoots)>> {
    DeltaReader::new(db.clone(), Vec::new()).get_largest::<StateRootHashes>()
}

/// Every key written at `version`, as deletes (a rollback removes the version's row of each,
/// whatever was written).
fn keys_written_at<V>(
    db: &VersionedDB<V, DbCache>,
    version: SlotNumber,
) -> anyhow::Result<VersionedSchemaBatch<V>>
where
    V: SchemaWithVersion + Ord,
    DbCache: CacheForVersionedDB<V>,
{
    let mut batch = VersionedSchemaBatch::default();
    for key in db.iter_pruning_keys_at_version(version.get())? {
        let (key_version, key) = key?.version_and_key();
        anyhow::ensure!(
            key_version == version.get(),
            "DB corruption: the pruning keys of version {version} include version {key_version}"
        );
        batch.delete_versioned(key);
    }
    Ok(batch)
}

struct Inner {
    user_cache: CacheForSchema<UserValues>,
    kernel_cache: CacheForSchema<KernelValues>,
}

/// The value caches of the flat store (one per namespace, under one lock), shared by the
/// versioned DBs and their readers.
#[derive(Clone)]
pub struct DbCache {
    inner: Arc<RwLock<Inner>>,
}

impl core::fmt::Debug for DbCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DbCache")
    }
}

impl CacheForVersionedDB<UserValues> for DbCache {
    fn write(&self) -> MappedRwLockWriteGuard<'_, CacheForSchema<UserValues>> {
        RwLockWriteGuard::map(self.inner.write(), |c| &mut c.user_cache)
    }

    fn read(&self) -> MappedRwLockReadGuard<'_, CacheForSchema<UserValues>> {
        RwLockReadGuard::map(self.inner.read(), |c| &c.user_cache)
    }

    fn try_read(&self) -> Option<MappedRwLockReadGuard<'_, CacheForSchema<UserValues>>> {
        let lock = self.inner.try_read()?;
        Some(RwLockReadGuard::map(lock, |c| &c.user_cache))
    }
}

impl CacheForVersionedDB<KernelValues> for DbCache {
    fn write(&self) -> MappedRwLockWriteGuard<'_, CacheForSchema<KernelValues>> {
        RwLockWriteGuard::map(self.inner.write(), |c| &mut c.kernel_cache)
    }

    fn read(&self) -> MappedRwLockReadGuard<'_, CacheForSchema<KernelValues>> {
        RwLockReadGuard::map(self.inner.read(), |c| &c.kernel_cache)
    }

    fn try_read(&self) -> Option<MappedRwLockReadGuard<'_, CacheForSchema<KernelValues>>> {
        let lock = self.inner.try_read()?;
        Some(RwLockReadGuard::map(lock, |c| &c.kernel_cache))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use selendra_state::{SlotKey, SlotValue};

    use super::*;

    type Changes = Vec<(SlotKey, Option<SlotValue>)>;

    fn open(dir: &crate::test_utils::TestDir) -> FlatStateDb {
        FlatStateDb::new(dir.path(), 1_000_000, 1_000_000).unwrap()
    }

    fn root(version: u64) -> NomtRoots {
        NomtRoots::from_bytes([u8::try_from(version).unwrap(); 64])
    }

    impl FlatStateDb {
        /// Rolls back the newest archival version, whatever the live DB holds.
        fn rollback_archival_one_slot(&mut self) -> anyhow::Result<()> {
            let (version, _) = self.latest_version_and_root_archival()?.unwrap();
            self.root_archival_at(version.checked_sub(1).unwrap())?
                .unwrap();
            self.rollback_archival(version)
        }
    }

    #[test]
    fn test_rollback_crash_before_committing_archival() {
        test_rollback(false);
    }

    #[test]
    fn test_rollback_crash_before_committing_live() {
        test_rollback(true);
    }

    fn assert_key_value(key: &SlotKey, value: Option<SlotValue>, version: u64, flat: &FlatStateDb) {
        assert_eq!(
            flat.kernel.get_version_for_key(key, 99).unwrap(),
            Some(version)
        );
        assert_eq!(flat.kernel.get_historical_value(key, 99).unwrap(), value);
    }

    /// Commits version 0, then "crashes" during the commit of version 1 (before the archival
    /// write, or between the archival and live writes: a fault hook), reopens, and rolls the
    /// archival DB back. Upstream injected a panic through an environment variable.
    fn test_rollback(archival_written: bool) {
        let tempdir = crate::test_utils::tempdir();
        let data = data_to_insert_per_version();
        // Inserted at version 0, deleted at version 1.
        let kernel_key1 = &make_key("kernel_key1");
        // Inserted at version 0, overwritten at version 1.
        let kernel_key2 = &make_key("kernel_key2");

        {
            let mut flat = open(&tempdir);
            flat.commit(data.change_set(0)).unwrap();
            assert_flat_state(0, 0, &flat);
            assert_key_value(kernel_key1, Some(make_value("kernel_key1", 0)), 0, &flat);
            assert_key_value(kernel_key2, Some(make_value("kernel_key2", 0)), 0, &flat);
        }

        {
            let mut flat = open(&tempdir);
            // The crash: a fault injected before the archival write (nothing written) or
            // between the archival and the live write.
            if archival_written {
                let faults = Faults::new(Some(crate::faults::fail_at(CommitPoint::BeforeLive)));
                let err = flat
                    .commit_with_faults(&data.change_set(1), &faults)
                    .unwrap_err();
                assert!(err.to_string().contains("injected fault"), "{err}");
            }
            assert_flat_state(0, u64::from(archival_written), &flat);
        }

        {
            let mut flat = open(&tempdir);
            flat.validate_and_rollback_archival().unwrap();
            assert_flat_state(0, 0, &flat);
            for (k, v) in data.user(0) {
                assert_eq!(flat.user.get_historical_value(&k, 99).unwrap(), v);
            }
            for (k, v) in data.kernel(0) {
                assert_eq!(flat.kernel.get_historical_value(&k, 99).unwrap(), v);
            }
            assert_key_value(kernel_key1, Some(make_value("kernel_key1", 0)), 0, &flat);
            assert_key_value(kernel_key2, Some(make_value("kernel_key2", 0)), 0, &flat);
            // The store goes on from version 1.
            flat.commit(data.change_set(1)).unwrap();
            assert_flat_state(1, 1, &flat);
        }
    }

    /// A crash between the archival and the live write of the genesis commit leaves the
    /// archival DB at version 0 and the live DB empty: that is one version ahead, rolled back
    /// to empty (upstream refused: "remove the archival DB manually").
    #[test]
    fn rollback_of_an_interrupted_genesis_commit() {
        let tempdir = crate::test_utils::tempdir();
        let data = data_to_insert_per_version();
        let mut flat = open(&tempdir);
        let faults = Faults::new(Some(crate::faults::fail_at(CommitPoint::BeforeLive)));
        flat.commit_with_faults(&data.change_set(0), &faults)
            .unwrap_err();
        assert_eq!(flat.latest_version_and_root_live().unwrap(), None);
        assert_eq!(
            flat.latest_version_and_root_archival().unwrap(),
            Some((SlotNumber::GENESIS, root(0)))
        );
        drop(flat);

        let mut flat = open(&tempdir);
        flat.validate_and_rollback_archival().unwrap();
        assert_eq!(flat.latest_version_and_root_archival().unwrap(), None);
        for (k, _) in data.user(0) {
            assert_eq!(flat.user.get_historical_value(&k, 99).unwrap(), None);
        }
        assert_eq!(
            flat.user.iter_pruning_keys_at_version(0).unwrap().count(),
            0
        );
        flat.commit(data.change_set(0)).unwrap();
        assert_flat_state(0, 0, &flat);
    }

    /// Rolls back the archival DB regardless of the live DB's version.
    #[test]
    fn test_rollback_skip_validation() {
        let tempdir = crate::test_utils::tempdir();
        let data = data_to_insert_per_version();

        for version in 0..=2 {
            let mut flat = open(&tempdir);
            flat.commit(data.change_set(version)).unwrap();
            assert_flat_state(version, version, &flat);
        }

        {
            let mut flat = open(&tempdir);
            flat.rollback_archival_one_slot().unwrap();
            assert_flat_state(2, 1, &flat);
        }

        {
            let mut flat = open(&tempdir);
            flat.rollback_archival_one_slot().unwrap();
            assert_flat_state(2, 0, &flat);
            for (k, v) in data.user(0) {
                assert_eq!(flat.user.get_historical_value(&k, 99).unwrap(), v);
            }
            for (k, v) in data.kernel(0) {
                assert_eq!(flat.kernel.get_historical_value(&k, 99).unwrap(), v);
            }
            // The live DB is 2 versions ahead: not repairable.
            let err = flat.validate_and_rollback_archival().unwrap_err();
            assert!(err.to_string().contains("cannot be recovered"), "{err}");
        }
    }

    /// Pruning (which removes the oldest versions) and archival rollback (which removes the
    /// newest) coexist: pruned versions stay pruned, the rolled-back version is gone, the rest
    /// reads correctly.
    #[test]
    fn test_rollback_after_pruning_is_consistent() {
        let tempdir = crate::test_utils::tempdir();
        let user_hot = make_key("hot_user");
        let kernel_hot = make_key("hot_kernel");
        let last_version = 5u64;
        let keep = 2u64;

        for version in 0..=last_version {
            let mut flat = open(&tempdir);
            let user = vec![(user_hot.clone(), Some(make_value("hot_user", version)))];
            let kernel = vec![(kernel_hot.clone(), Some(make_value("hot_kernel", version)))];
            flat.commit(make_change_set(user, kernel, version)).unwrap();
            assert_flat_state(version, version, &flat);
        }

        // A pruning batch, as the pruner writes it.
        {
            let flat = open(&tempdir);
            let mut batch = flat.user.collect_pruning_batch(keep, None).unwrap().batch;
            batch.merge(flat.kernel.collect_pruning_batch(keep, None).unwrap().batch);
            flat.archival_db.write_schemas(&batch).unwrap();
        }

        // With the newest version 5 and 2 kept, the rows of versions 0, 1, 2 are gone.
        let oldest_available = last_version - keep;
        let mut flat = open(&tempdir);
        for version in 0..oldest_available {
            assert_eq!(
                flat.user.get_historical_value(&user_hot, version).unwrap(),
                None
            );
            assert_eq!(
                flat.kernel
                    .get_historical_value(&kernel_hot, version)
                    .unwrap(),
                None
            );
        }
        for version in oldest_available..=last_version {
            assert_eq!(
                flat.user.get_historical_value(&user_hot, version).unwrap(),
                Some(make_value("hot_user", version))
            );
        }

        flat.rollback_archival_one_slot().unwrap();
        assert_flat_state(last_version, last_version - 1, &flat);
        assert_eq!(
            flat.user
                .get_historical_value(&user_hot, last_version - 1)
                .unwrap(),
            Some(make_value("hot_user", last_version - 1))
        );
        for version in 0..oldest_available {
            assert_eq!(
                flat.user.get_historical_value(&user_hot, version).unwrap(),
                None
            );
        }
    }

    /// The values and the root are written at the version the changes were made for, or not
    /// at all (upstream wrote the values at the next version regardless).
    #[test]
    fn commit_checks_the_version() {
        let tempdir = crate::test_utils::tempdir();
        let data = data_to_insert_per_version();
        let mut flat = open(&tempdir);
        assert!(flat.commit(data.change_set(1)).is_err());
        assert_eq!(flat.latest_version_and_root_live().unwrap(), None);
        assert_eq!(flat.latest_version_and_root_archival().unwrap(), None);
        flat.commit(data.change_set(0)).unwrap();
        assert!(flat.commit(data.change_set(0)).is_err());
        assert!(flat.commit(data.change_set(2)).is_err());
        assert_flat_state(0, 0, &flat);
        flat.commit(data.change_set(1)).unwrap();
        assert_flat_state(1, 1, &flat);
    }

    #[test]
    fn corrupt_root_is_an_error() {
        let tempdir = crate::test_utils::tempdir();
        let flat = open(&tempdir);
        let mut batch = SchemaBatch::new();
        batch
            .put_raw::<StateRootHashes>(0u64.to_be_bytes().to_vec(), vec![1; 65])
            .unwrap();
        flat.live_db.write_schemas(&batch).unwrap();
        assert!(flat.latest_version_and_root_live().is_err());
        assert!(flat.reader().is_err());
    }

    #[test]
    fn readers_disagreeing_on_the_version_are_an_error() {
        let tempdir = crate::test_utils::tempdir();
        let mut flat = open(&tempdir);
        flat.commit(data_to_insert_per_version().change_set(0))
            .unwrap();
        let err = HistoricalStateReader::new(
            VersionedDeltaReader::new(flat.user.clone(), Some(0), Vec::new()),
            VersionedDeltaReader::new(flat.kernel.clone(), None, Vec::new()),
            DeltaReader::new(flat.live_db.clone(), Vec::new()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("different versions"), "{err}");
    }

    fn assert_flat_state(live_version: u64, archival_version: u64, flat: &FlatStateDb) {
        assert_eq!(
            flat.latest_version_and_root_live().unwrap(),
            Some((SlotNumber::new(live_version), root(live_version)))
        );
        assert_eq!(
            flat.latest_version_and_root_archival().unwrap(),
            Some((SlotNumber::new(archival_version), root(archival_version)))
        );
    }

    struct TestData {
        data: HashMap<u64, (Changes, Changes)>,
    }

    impl TestData {
        fn user(&self, version: u64) -> Changes {
            self.data[&version].0.clone()
        }

        fn kernel(&self, version: u64) -> Changes {
            self.data[&version].1.clone()
        }

        fn change_set(&self, version: u64) -> StateChanges {
            make_change_set(self.user(version), self.kernel(version), version)
        }
    }

    enum Op {
        Insert(&'static str),
        Delete(&'static str),
    }

    fn data_to_insert_per_version() -> TestData {
        use Op::{Delete, Insert};
        let versions = [
            (
                vec![
                    Insert("user_key1"),
                    Insert("user_key2"),
                    Insert("user_key3"),
                ],
                vec![Insert("kernel_key1"), Insert("kernel_key2")],
            ),
            (
                vec![Delete("user_key1"), Insert("user_key2")],
                vec![Delete("kernel_key1"), Insert("kernel_key2")],
            ),
            (
                vec![Delete("user_key1"), Insert("user_key2")],
                vec![Delete("kernel_key3"), Insert("kernel_key11")],
            ),
        ];
        let data = (0u64..)
            .zip(versions)
            .map(|(version, (user, kernel))| {
                (
                    version,
                    (make_data(user, version), make_data(kernel, version)),
                )
            })
            .collect();
        TestData { data }
    }

    fn make_key(key: &str) -> SlotKey {
        SlotKey::try_from_bytes(key.as_bytes()).unwrap()
    }

    fn make_value(key: &str, version: u64) -> SlotValue {
        SlotValue::from(format!("{key}_value_{version}").into_bytes())
    }

    fn make_data(ops: Vec<Op>, version: u64) -> Changes {
        ops.into_iter()
            .map(|op| match op {
                Op::Insert(key) => (make_key(key), Some(make_value(key, version))),
                Op::Delete(key) => (make_key(key), None),
            })
            .collect()
    }

    fn make_change_set(user: Changes, kernel: Changes, version: u64) -> StateChanges {
        HistoricalStateReader::materialize_values(
            user,
            kernel,
            root(version),
            SlotNumber::new(version),
        )
        .unwrap()
    }
}

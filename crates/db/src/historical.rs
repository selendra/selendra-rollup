//! Typed reads of the flat value store at a version ([`HistoricalStateReader`]) and the changes
//! of one version ([`StateChanges`]).

use std::sync::Arc;

use rockbound::SchemaBatch;
use rockbound::cache::delta_reader::DeltaReader;
use rockbound::versioned_db::{VersionedDeltaReader, VersionedSchemaBatch};
use selendra_interface::common::SlotNumber;
use selendra_state::namespaces::ProvableNamespace;
use selendra_state::{Kernel, SlotKey, SlotValue, User};

use crate::flat::DbCache;
use crate::nomt_state::NomtRoots;
use crate::pruner::VersionPin;
use crate::schema::{NomtStateValues, StateRootHashes};

/// A key and its value, as iterated.
pub type KvPair = (SlotKey, SlotValue);

/// The flat store of the user values.
pub(crate) type UserValues = NomtStateValues<User>;
/// The flat store of the kernel values.
pub(crate) type KernelValues = NomtStateValues<Kernel>;

/// Reads the flat value store (committed database plus uncommitted snapshots) as of one version.
///
/// *Bound* reads see the state as of this reader's version ([`last_version`](Self::last_version))
/// even after newer versions are committed: they then read the archival rows, which can fail
/// with [`HistoricalValueError::PrunedVersion`](crate::HistoricalValueError) once pruned.
/// *Unbound* reads (`*_unbound`) see the newest state: committed, or in this reader's snapshots
/// newer than the committed version.
///
/// Errors carry rockbound's [`HistoricalValueError`](crate::HistoricalValueError) where it
/// applies (use `downcast_ref`).
///
/// A reader built by [`DbGroup::readers`](crate::DbGroup::readers) or the storage manager pins
/// its base version (the newest committed version when it was built), so pruning keeps what its
/// bound reads need while it or a clone lives ([`pruner`](crate::pruner)).
#[derive(Clone)]
pub struct HistoricalStateReader {
    user: VersionedDeltaReader<UserValues, DbCache>,
    kernel: VersionedDeltaReader<KernelValues, DbCache>,
    root_hash_reader: DeltaReader,
    /// The version the next writes get. Reads are bound to the versions before it.
    next_version: SlotNumber,
    /// Keeps the base version from being pruned while this reader (or a clone) lives.
    _pin: Option<VersionPin>,
}

impl core::fmt::Debug for HistoricalStateReader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HistoricalStateReader")
            .field("next_version", &self.next_version)
            .finish_non_exhaustive()
    }
}

/// The changes of one version to the flat store: the user and kernel writes (`None`: delete) and
/// the version's root.
///
/// The batches are shared (`Arc`) so a storage manager can keep them as snapshots for readers
/// while they wait to be committed.
#[derive(Clone, Debug)]
pub struct StateChanges {
    pub(crate) user: Arc<VersionedSchemaBatch<UserValues>>,
    pub(crate) kernel: Arc<VersionedSchemaBatch<KernelValues>>,
    /// The root at `version` ([`StateRootHashes`]), written to every database that records
    /// versions.
    pub(crate) root_hash_batch: Arc<SchemaBatch>,
    pub(crate) version: SlotNumber,
    pub(crate) root: NomtRoots,
}

impl StateChanges {
    /// The version these changes are for.
    pub fn version(&self) -> SlotNumber {
        self.version
    }

    /// The root after these changes.
    pub fn root(&self) -> NomtRoots {
        self.root
    }
}

/// The version after `latest`, or genesis if nothing was committed.
pub(crate) fn next_version_after(latest: Option<SlotNumber>) -> anyhow::Result<SlotNumber> {
    match latest {
        Some(latest) => latest
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("state version overflow")),
        None => Ok(SlotNumber::GENESIS),
    }
}

impl HistoricalStateReader {
    /// A reader over the user and kernel value readers and the root-hash reader.
    ///
    /// # Errors
    /// If the three are not at the same version (upstream asserted).
    pub fn new(
        user: VersionedDeltaReader<UserValues, DbCache>,
        kernel: VersionedDeltaReader<KernelValues, DbCache>,
        root_hash_reader: DeltaReader,
    ) -> anyhow::Result<Self> {
        let user_version = user.latest_version()?;
        let kernel_version = kernel.latest_version()?;
        let root_version = Self::last_version_from_reader(&root_hash_reader)?.map(|v| v.get());
        anyhow::ensure!(
            user_version == kernel_version && user_version == root_version,
            "the flat store readers are at different versions: user {user_version:?}, kernel \
             {kernel_version:?}, roots {root_version:?}"
        );
        let next_version = next_version_after(user_version.map(SlotNumber::new))?;
        Ok(Self {
            user,
            kernel,
            root_hash_reader,
            next_version,
            _pin: None,
        })
    }

    /// This reader, holding `pin` (its base version's) while it or a clone lives.
    pub(crate) fn with_pin(self, pin: Option<VersionPin>) -> Self {
        Self { _pin: pin, ..self }
    }

    /// The version this reader pins (tests).
    #[cfg(test)]
    pub(crate) fn pinned_version(&self) -> Option<SlotNumber> {
        self._pin.as_ref().map(VersionPin::version)
    }

    /// The newest version with a root in `reader`.
    pub fn last_version_from_reader(reader: &DeltaReader) -> anyhow::Result<Option<SlotNumber>> {
        Ok(reader
            .get_largest::<StateRootHashes>()?
            .map(|(version, _)| version))
    }

    /// The version the next writes get (and the first version reads are not bound to).
    pub fn get_next_version(&self) -> SlotNumber {
        self.next_version
    }

    /// The newest version this reader sees, `None` if it sees an empty store.
    pub fn last_version(&self) -> Option<SlotNumber> {
        self.next_version.checked_sub(1)
    }

    /// The newest version this reader can see: the newest committed one, which can be newer
    /// than [`last_version`](Self::last_version) if more was committed since this reader was
    /// created, or the newest of this reader's uncommitted snapshots if newer. `None` if neither
    /// exists.
    ///
    /// Upstream returned genesis for an empty store too, the same as when version 0 is committed.
    pub fn last_version_unbound(&self) -> anyhow::Result<Option<SlotNumber>> {
        Self::last_version_from_reader(&self.root_hash_reader)
    }

    /// The newest version and its root (unbound: the newest committed version or a newer one
    /// of this reader's snapshots, like [`last_version_unbound`](Self::last_version_unbound)).
    pub fn latest_root_and_version_unbound(
        &self,
    ) -> anyhow::Result<Option<(SlotNumber, NomtRoots)>> {
        self.root_hash_reader.get_largest::<StateRootHashes>()
    }

    /// The value of `key` as of this reader's version (bound).
    pub fn get_value(
        &self,
        namespace: ProvableNamespace,
        key: &SlotKey,
    ) -> anyhow::Result<Option<SlotValue>> {
        match namespace {
            ProvableNamespace::User => self.user.get_latest_borrowed(key),
            ProvableNamespace::Kernel => self.kernel.get_latest_borrowed(key),
        }
    }

    /// The newest value of `key` (unbound): the newest committed one, or the newest of this
    /// reader's snapshots that are newer than the committed version. Never reads archival rows,
    /// so never fails with `PrunedVersion`.
    pub fn get_value_unbound(
        &self,
        namespace: ProvableNamespace,
        key: &SlotKey,
    ) -> anyhow::Result<Option<SlotValue>> {
        match namespace {
            ProvableNamespace::User => self.user.get_latest_borrowed_unbound(key),
            ProvableNamespace::Kernel => self.kernel.get_latest_borrowed_unbound(key),
        }
    }

    /// The value of `key` at `version`.
    ///
    /// # Errors
    /// `FutureVersion` if `version` is after this reader's version (also if the reader sees an
    /// empty store), and `PrunedVersion` if it was pruned.
    pub fn get_value_historical(
        &self,
        namespace: ProvableNamespace,
        key: &SlotKey,
        version: SlotNumber,
    ) -> anyhow::Result<Option<SlotValue>> {
        Ok(match namespace {
            ProvableNamespace::User => self.user.get_historical_borrowed(key, version.get())?,
            ProvableNamespace::Kernel => self.kernel.get_historical_borrowed(key, version.get())?,
        })
    }

    /// Iterates over the values whose key starts with `prefix`, in ascending key order, as of
    /// this reader's version, from `cursor` (inclusive) if given.
    ///
    /// The iterator holds the flat store's cache read lock until dropped: commits wait for it,
    /// and opening a second iterator on the same thread while a commit waits deadlocks. So does
    /// opening a NOMT session on the same thread while a storage manager finalizes (its commit
    /// holds the overlays lock the session waits for, and waits for the iterator).
    ///
    /// # Errors
    /// If the cursor does not start with `prefix`, or if a newer version has been committed
    /// (the live table no longer matches this reader). The iterator yields an error once and
    /// then ends if a read fails.
    pub fn iter_values_with_prefix(
        &self,
        namespace: ProvableNamespace,
        prefix: &SlotKey,
        cursor: Option<SlotKey>,
    ) -> anyhow::Result<Box<dyn Iterator<Item = anyhow::Result<KvPair>> + '_>> {
        Ok(match namespace {
            ProvableNamespace::User => Box::new(
                self.user
                    .iter_with_prefix_and_cursor(prefix.clone(), cursor)?,
            ),
            ProvableNamespace::Kernel => Box::new(
                self.kernel
                    .iter_with_prefix_and_cursor(prefix.clone(), cursor)?,
            ),
        })
    }

    /// The root at the newest version `<= version` and that version, or `None` if there is none.
    ///
    /// Unbound: `version` is not checked against this reader's version, so a version after the
    /// newest committed one gives the newest root. Check the version returned if you need the
    /// root of exactly `version`.
    pub fn get_root_hash(
        &self,
        version: SlotNumber,
    ) -> anyhow::Result<Option<(SlotNumber, NomtRoots)>> {
        Self::get_root_hash_from_reader(&self.root_hash_reader, version)
    }

    /// [`get_root_hash`](Self::get_root_hash) on `reader`.
    pub fn get_root_hash_from_reader(
        reader: &DeltaReader,
        version: SlotNumber,
    ) -> anyhow::Result<Option<(SlotNumber, NomtRoots)>> {
        reader.get_prev::<StateRootHashes>(&version)
    }

    /// Collects one version's changes: the user and kernel writes (`None`: delete) and `root`,
    /// the roots after them.
    ///
    /// A version may write only user keys (upstream required a kernel write whenever a user key
    /// was written, but nothing needs it: the versions of the two stay equal either way).
    pub fn materialize_values(
        user_changes: impl IntoIterator<Item = (SlotKey, Option<SlotValue>)>,
        kernel_changes: impl IntoIterator<Item = (SlotKey, Option<SlotValue>)>,
        root: NomtRoots,
        version: SlotNumber,
    ) -> anyhow::Result<StateChanges> {
        let (user_batch, kernel_batch) =
            Self::materialize_user_and_kernel_values(user_changes, kernel_changes);
        let mut root_hash_batch = SchemaBatch::default();
        root_hash_batch.put::<StateRootHashes>(&version, &root)?;
        Ok(StateChanges {
            user: Arc::new(user_batch),
            kernel: Arc::new(kernel_batch),
            root_hash_batch: Arc::new(root_hash_batch),
            version,
            root,
        })
    }

    /// The user and kernel writes as versioned batches (the last write of a key wins).
    pub fn materialize_user_and_kernel_values(
        user_changes: impl IntoIterator<Item = (SlotKey, Option<SlotValue>)>,
        kernel_changes: impl IntoIterator<Item = (SlotKey, Option<SlotValue>)>,
    ) -> (
        VersionedSchemaBatch<UserValues>,
        VersionedSchemaBatch<KernelValues>,
    ) {
        (
            VersionedSchemaBatch::from(user_changes),
            VersionedSchemaBatch::from(kernel_changes),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlatStateDb;
    use crate::HistoricalValueError;

    fn key(bytes: &[u8]) -> SlotKey {
        SlotKey::try_from_bytes(bytes).unwrap()
    }

    fn value(bytes: &[u8]) -> Option<SlotValue> {
        Some(SlotValue::from(bytes.to_vec()))
    }

    fn root(byte: u8) -> NomtRoots {
        NomtRoots::from_bytes([byte; 64])
    }

    fn open(dir: &crate::test_utils::TestDir) -> FlatStateDb {
        FlatStateDb::new(dir.path(), 1_000_000, 1_000_000).unwrap()
    }

    fn commit(
        flat: &mut FlatStateDb,
        version: u64,
        user: Vec<(SlotKey, Option<SlotValue>)>,
        kernel: Vec<(SlotKey, Option<SlotValue>)>,
    ) {
        let root = root(u8::try_from(version).unwrap());
        let changes =
            HistoricalStateReader::materialize_values(user, kernel, root, SlotNumber::new(version))
                .unwrap();
        flat.commit(changes).unwrap();
    }

    #[test]
    fn verify_last_version_bumped_properly() {
        let tempdir = crate::test_utils::tempdir();
        let mut flat = open(&tempdir);

        let writes = [
            (b"BBB", [1, 1, 1]),
            (b"AAA", [2, 2, 2]),
            (b"AAA", [3, 3, 3]),
            (b"AAA", [4, 4, 4]),
        ];
        for (idx, (k, v)) in writes.into_iter().enumerate() {
            let reader = flat.reader().unwrap();
            let slot_number = SlotNumber::new(u64::try_from(idx).unwrap());
            assert_eq!(slot_number.checked_sub(1), reader.last_version());
            assert_eq!(slot_number, reader.get_next_version());
            commit(
                &mut flat,
                slot_number.get(),
                vec![],
                vec![(key(k), value(&v))],
            );
        }
    }

    #[test]
    fn test_no_bound_on_passed_version() {
        let tempdir = crate::test_utils::tempdir();
        let mut flat = open(&tempdir);

        // Two independent readers on the same database.
        let reader1 = flat.reader().unwrap();
        let reader2 = flat.reader().unwrap();

        let version0 = SlotNumber::new(0);
        assert_eq!(reader1.get_next_version(), version0);
        assert_eq!(reader2.get_next_version(), version0);
        commit(&mut flat, 0, vec![], vec![(key(b"key1"), value(b"value1"))]);
        assert_eq!(reader1.get_next_version(), version0);
        assert_eq!(reader2.get_next_version(), version0);

        // Both readers see the new root.
        for reader in [&reader1, &reader2] {
            assert_eq!(
                reader.get_root_hash(version0).unwrap(),
                Some((version0, root(0)))
            );
        }

        let version1 = SlotNumber::new(1);
        commit(&mut flat, 1, vec![], vec![(key(b"key2"), value(b"value2"))]);
        assert_eq!(reader1.get_next_version(), version0);
        assert_eq!(reader2.get_next_version(), version0);

        // Both readers see the newer root, and still the older one.
        for reader in [&reader1, &reader2] {
            assert_eq!(
                reader.get_root_hash(version1).unwrap(),
                Some((version1, root(1)))
            );
            assert_eq!(
                reader.get_root_hash(version0).unwrap(),
                Some((version0, root(0)))
            );
            // A future version gives the newest root, labelled with its own version.
            assert_eq!(
                reader.get_root_hash(SlotNumber::new(7)).unwrap(),
                Some((version1, root(1)))
            );
        }
    }

    #[test]
    fn test_unbound_last_version() {
        let tempdir = crate::test_utils::tempdir();
        let mut flat = open(&tempdir);

        let reader1 = flat.reader().unwrap();
        let reader2 = flat.reader().unwrap();

        // Initially, nothing is committed.
        for reader in [&reader1, &reader2] {
            assert_eq!(reader.last_version(), None);
            assert_eq!(reader.last_version_unbound().unwrap(), None);
        }

        let version0 = SlotNumber::new(0);
        commit(&mut flat, 0, vec![], vec![(key(b"key1"), value(b"value1"))]);
        // The bound version stays the same, the unbound one sees the commit (upstream returned
        // genesis both before and after).
        for reader in [&reader1, &reader2] {
            assert_eq!(reader.last_version(), None);
            assert_eq!(reader.last_version_unbound().unwrap(), Some(version0));
        }

        let version1 = SlotNumber::new(1);
        commit(&mut flat, 1, vec![], vec![(key(b"key2"), value(b"value2"))]);
        for reader in [&reader1, &reader2] {
            assert_eq!(reader.last_version_unbound().unwrap(), Some(version1));
            assert_eq!(
                reader.latest_root_and_version_unbound().unwrap(),
                Some((version1, root(1)))
            );
            assert_eq!(reader.last_version(), None);
        }
    }

    /// A version that writes only user keys commits and reads back (upstream refused it).
    #[test]
    fn user_only_version() {
        let tempdir = crate::test_utils::tempdir();
        let mut flat = open(&tempdir);
        commit(&mut flat, 0, vec![(key(b"u1"), value(b"a"))], vec![]);
        commit(&mut flat, 1, vec![(key(b"u1"), value(b"b"))], vec![]);

        let reader = flat.reader().unwrap();
        assert_eq!(reader.last_version(), Some(SlotNumber::new(1)));
        assert_eq!(
            reader
                .get_value(ProvableNamespace::User, &key(b"u1"))
                .unwrap(),
            value(b"b")
        );
        assert_eq!(
            reader
                .get_value_historical(ProvableNamespace::User, &key(b"u1"), SlotNumber::new(0))
                .unwrap(),
            value(b"a")
        );
        assert_eq!(
            reader
                .get_value(ProvableNamespace::Kernel, &key(b"u1"))
                .unwrap(),
            None
        );
    }

    #[test]
    fn bound_and_unbound_reads() {
        let tempdir = crate::test_utils::tempdir();
        let mut flat = open(&tempdir);
        let k = key(b"k1");
        commit(&mut flat, 0, vec![(k.clone(), value(b"v0"))], vec![]);
        let stale = flat.reader().unwrap();
        commit(&mut flat, 1, vec![(k.clone(), value(b"v1"))], vec![]);
        let fresh = flat.reader().unwrap();

        let user = ProvableNamespace::User;
        // The stale reader still reads version 0 (through the archival rows)...
        assert_eq!(stale.get_value(user, &k).unwrap(), value(b"v0"));
        // ...unless unbound.
        assert_eq!(stale.get_value_unbound(user, &k).unwrap(), value(b"v1"));
        assert_eq!(fresh.get_value(user, &k).unwrap(), value(b"v1"));
        assert_eq!(
            fresh
                .get_value_historical(user, &k, SlotNumber::new(0))
                .unwrap(),
            value(b"v0")
        );
    }

    /// A historical read past the reader's version is an error, not "absent".
    #[test]
    fn future_version_is_an_error() {
        let tempdir = crate::test_utils::tempdir();
        let mut flat = open(&tempdir);
        let k = key(b"k1");
        let empty = flat.reader().unwrap();
        let err = empty
            .get_value_historical(ProvableNamespace::User, &k, SlotNumber::GENESIS)
            .unwrap_err();
        assert!(matches!(
            err.downcast_ref::<HistoricalValueError>(),
            Some(HistoricalValueError::FutureVersion { .. })
        ));

        commit(&mut flat, 0, vec![(k.clone(), value(b"v0"))], vec![]);
        let reader = flat.reader().unwrap();
        let err = reader
            .get_value_historical(ProvableNamespace::User, &k, SlotNumber::new(1))
            .unwrap_err();
        assert!(matches!(
            err.downcast_ref::<HistoricalValueError>(),
            Some(HistoricalValueError::FutureVersion { .. })
        ));
    }

    /// The `StateVec` case: `len` at `P`, element 0 at `P ‖ 0u64`. The historical and stale
    /// reads of `len` must not be shadowed by the longer key; an empty value is not a delete.
    #[test]
    fn prefix_keys_and_empty_values_read_back() {
        let tempdir = crate::test_utils::tempdir();
        let mut flat = open(&tempdir);
        let len_key = key(&[7, 1]);
        let elem_key = key(&[7, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        let unit_key = key(&[7, 2]);
        let empty = Some(SlotValue::from(vec![]));
        commit(
            &mut flat,
            0,
            vec![
                (len_key.clone(), value(&[1, 0, 0, 0])),
                (elem_key.clone(), value(b"e0")),
                (unit_key.clone(), empty.clone()),
            ],
            vec![],
        );
        let stale = flat.reader().unwrap();
        commit(
            &mut flat,
            1,
            vec![(elem_key.clone(), value(b"e0'"))],
            vec![],
        );

        let user = ProvableNamespace::User;
        let reader = flat.reader().unwrap();
        for version in [0, 1] {
            assert_eq!(
                reader
                    .get_value_historical(user, &len_key, SlotNumber::new(version))
                    .unwrap(),
                value(&[1, 0, 0, 0])
            );
            assert_eq!(
                reader
                    .get_value_historical(user, &unit_key, SlotNumber::new(version))
                    .unwrap(),
                empty
            );
        }
        assert_eq!(
            stale.get_value(user, &len_key).unwrap(),
            value(&[1, 0, 0, 0])
        );
        assert_eq!(stale.get_value(user, &unit_key).unwrap(), empty);
        assert_eq!(stale.get_value(user, &elem_key).unwrap(), value(b"e0"));
    }

    #[test]
    fn iteration_is_ascending_and_checks_its_arguments() {
        let tempdir = crate::test_utils::tempdir();
        let mut flat = open(&tempdir);
        let keys = [
            key(&[1, 1, 0xff]),
            key(&[1, 1]),
            key(&[1, 1, 0]),
            key(&[1, 2]),
            key(&[1, 1, 0, 0]),
        ];
        let empty = flat.reader().unwrap();
        commit(
            &mut flat,
            0,
            keys.iter()
                .map(|k| (k.clone(), value(k.as_ref())))
                .collect(),
            vec![],
        );
        // A reader of the empty store is stale once version 0 is committed (its point reads
        // still see nothing).
        assert_eq!(
            empty.get_value(ProvableNamespace::User, &keys[0]).unwrap(),
            None
        );
        for namespace in [ProvableNamespace::User, ProvableNamespace::Kernel] {
            assert!(
                empty
                    .iter_values_with_prefix(namespace, &key(&[1, 1]), None)
                    .is_err()
            );
        }
        let stale = flat.reader().unwrap();
        commit(&mut flat, 1, vec![(key(&[1, 1, 5]), value(b"x"))], vec![]);
        let reader = flat.reader().unwrap();

        let user = ProvableNamespace::User;
        let prefix = key(&[1, 1]);
        let read: Vec<SlotKey> = reader
            .iter_values_with_prefix(user, &prefix, None)
            .unwrap()
            .map(|item| item.unwrap().0)
            .collect();
        let expected = [
            key(&[1, 1]),
            key(&[1, 1, 0]),
            key(&[1, 1, 0, 0]),
            key(&[1, 1, 5]),
            key(&[1, 1, 0xff]),
        ];
        assert_eq!(read, expected);

        // From a cursor (inclusive).
        let read: Vec<SlotKey> = reader
            .iter_values_with_prefix(user, &prefix, Some(key(&[1, 1, 0, 0])))
            .unwrap()
            .map(|item| item.unwrap().0)
            .collect();
        assert_eq!(read, expected[2..]);

        // A cursor without the prefix, and a stale reader, are errors.
        assert!(
            reader
                .iter_values_with_prefix(user, &prefix, Some(key(&[1, 2])))
                .is_err()
        );
        assert!(stale.iter_values_with_prefix(user, &prefix, None).is_err());
        // The other namespace is empty.
        assert_eq!(
            reader
                .iter_values_with_prefix(ProvableNamespace::Kernel, &prefix, None)
                .unwrap()
                .count(),
            0
        );
    }
}

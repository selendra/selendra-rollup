//! The accessory store ([`AccessoryDb`]): state that is written by the state transition function
//! but not provable (module data for JSON-RPC). Also [`DbOptions`], how the state databases'
//! RocksDB instances are opened.

use std::path::Path;
use std::sync::Arc;

use rockbound::cache::delta_reader::DeltaReader;
use rockbound::rocksdb::ColumnFamilyDescriptor;
use rockbound::{SchemaBatch, rocksdb};
use selendra_interface::common::SlotNumber;
use selendra_state::{SlotKey, SlotValue};

use crate::nomt_state::NomtRoots;
use crate::schema::{
    ACCESSORY_TABLES, AccessoryKeysByVersion, ModuleAccessoryState, StateRootHashes,
};

/// How to open one RocksDB instance: its name (for logs), its directory (under a parent
/// directory) and its column families.
pub struct DbOptions {
    /// Name of the database (logs).
    pub name: &'static str,
    /// Sub-directory of the database.
    pub path_suffix: &'static str,
    /// The column families of the database.
    pub columns: Vec<ColumnFamilyDescriptor>,
}

impl DbOptions {
    /// Opens (or creates) the database in `parent/path_suffix`, with rockbound's default
    /// RocksDB options.
    pub fn open_in(self, parent: &Path) -> anyhow::Result<rockbound::DB> {
        let options = rockbound::gen_rocksdb_options(&Default::default(), false);
        rockbound::DB::open_with_cfds(
            &options,
            parent.join(self.path_suffix),
            self.name,
            self.columns,
        )
    }
}

/// A row of [`ModuleAccessoryState`]: `((key, version), value)`.
type AccessoryRow = ((Vec<u8>, SlotNumber), Option<SlotValue>);

/// Checks the result of a `get_prev` lookup of `(key, version)` in [`ModuleAccessoryState`]: the
/// row found (the largest at or below the seek key) belongs to `key` only if its key matches.
pub(crate) fn ensure_version_is_correct(
    key: &[u8],
    version: SlotNumber,
    found: Option<AccessoryRow>,
) -> anyhow::Result<Option<SlotValue>> {
    match found {
        Some(((found_key, found_version), value)) if found_key == key => {
            anyhow::ensure!(
                found_version <= version,
                "bug: the accessory lookup at version {version} returned version {found_version}"
            );
            Ok(value)
        }
        _ => Ok(None),
    }
}

/// A typed reader of the accessory store: the committed database plus uncommitted snapshots.
///
/// Every version of every key is kept (a delete is stored as `None`), so reads at a past version
/// are exact until pruned.
#[derive(Clone, Debug)]
pub struct AccessoryDb {
    db: DeltaReader,
}

impl AccessoryDb {
    const DB_PATH_SUFFIX: &'static str = "accessory";
    const DB_NAME: &'static str = "accessory-db";

    /// The options to open the accessory store with.
    pub fn options() -> DbOptions {
        DbOptions {
            name: Self::DB_NAME,
            path_suffix: Self::DB_PATH_SUFFIX,
            columns: ACCESSORY_TABLES
                .iter()
                .map(|cf| rockbound::default_cf_descriptor(*cf))
                .collect(),
        }
    }

    /// A reader over `reader` (the accessory database and its snapshots).
    pub fn with_reader(reader: DeltaReader) -> Self {
        Self { db: reader }
    }

    /// The value of `key` at `version`: the newest write at or below it (`None` if absent or
    /// deleted).
    pub fn get_value_option(
        &self,
        key: &SlotKey,
        version: SlotNumber,
    ) -> anyhow::Result<Option<SlotValue>> {
        ensure_version_is_correct(
            key.as_ref(),
            version,
            self.db
                .get_prev::<ModuleAccessoryState>(&(key.as_ref(), version))?,
        )
    }

    /// The writes of one version as a batch: every write is a put (a delete puts `None`, so
    /// history is kept), plus its row in the per-version index.
    pub fn materialize_values<K: AsRef<[u8]> + core::fmt::Debug>(
        key_value_pairs: impl IntoIterator<Item = (K, Option<SlotValue>)>,
        version: SlotNumber,
    ) -> anyhow::Result<SchemaBatch> {
        let mut batch = SchemaBatch::default();
        for (key, value) in key_value_pairs {
            let key = key.as_ref();
            batch.put::<ModuleAccessoryState>(&(key, version), &value)?;
            batch.put::<AccessoryKeysByVersion>(&(version, key), &())?;
        }
        Ok(batch)
    }

    /// The newest version committed to the accessory store and its root.
    pub fn latest_version_and_root(
        accessory_db: &Arc<rockbound::DB>,
    ) -> anyhow::Result<Option<(SlotNumber, NomtRoots)>> {
        DeltaReader::new(accessory_db.clone(), Vec::new()).get_largest::<StateRootHashes>()
    }

    /// Writes a version's accessory batch and its root batch in one RocksDB write batch.
    pub fn commit(
        accessory_db: &rockbound::DB,
        accessory_batch: &SchemaBatch,
        root_hash_batch: &SchemaBatch,
    ) -> anyhow::Result<()> {
        let mut db_batch = rocksdb::WriteBatch::default();
        rockbound::DB::update_db_batch_with_schema_data(
            &mut db_batch,
            accessory_batch,
            accessory_db,
        )?;
        rockbound::DB::update_db_batch_with_schema_data(
            &mut db_batch,
            root_hash_batch,
            accessory_db,
        )?;
        accessory_db.write_db_batch(db_batch)
    }

    /// Removes the newest version (its writes and its root) from the accessory store; does
    /// nothing if the store is empty. For crash recovery (not wired in yet).
    pub fn rollback(accessory_db: &Arc<rockbound::DB>) -> anyhow::Result<()> {
        let Some((version, _)) = Self::latest_version_and_root(accessory_db)? else {
            return Ok(());
        };
        let batch = Self::rollback_batch(accessory_db, version)?;
        accessory_db.write_schemas(&batch)
    }

    fn rollback_batch(db: &rockbound::DB, version: SlotNumber) -> anyhow::Result<SchemaBatch> {
        let mut batch = SchemaBatch::new();
        // The index rows of `version` are `[(version, []), (version + 1, []))`.
        let end = version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("slot number overflow"))?;
        let start: (SlotNumber, &[u8]) = (version, &[]);
        let end: (SlotNumber, &[u8]) = (end, &[]);
        let mut iter = db.iter_range::<AccessoryKeysByVersion>(&start, &end)?;
        iter.seek_to_first();

        let mut keys_deleted = 0usize;
        for entry in iter {
            let (slot_number, key) = entry?.key;
            anyhow::ensure!(
                slot_number == version,
                "DB corruption: the accessory index range of version {version} returned version {slot_number}"
            );
            batch.delete::<ModuleAccessoryState>(&(key.as_slice(), slot_number))?;
            batch.delete::<AccessoryKeysByVersion>(&(slot_number, key))?;
            keys_deleted = keys_deleted.saturating_add(1);
        }
        batch.delete::<StateRootHashes>(&version)?;

        tracing::info!(
            %version,
            keys_deleted,
            "Rolled back a version of the accessory database"
        );
        Ok(batch)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use selendra_interface::common::IntoSlotNumber;

    use super::*;

    fn open(dir: &crate::test_utils::TestDir) -> (Arc<rockbound::DB>, AccessoryDb) {
        let rocksdb = Arc::new(AccessoryDb::options().open_in(dir.path()).unwrap());
        let db = AccessoryDb::with_reader(DeltaReader::new(rocksdb.clone(), Vec::new()));
        (rocksdb, db)
    }

    fn slot_key(key: &[u8]) -> SlotKey {
        SlotKey::try_from_bytes(key).unwrap()
    }

    #[test]
    fn materialize_with_slot_value_round_trips() {
        let tempdir = crate::test_utils::tempdir();
        let (rocksdb, db) = open(&tempdir);

        let key = b"sv-key".to_vec();
        let value = SlotValue::from(vec![0x12, 0x34, 0x56, 0x78]);
        let changes = AccessoryDb::materialize_values(
            vec![(key.clone(), Some(value.clone()))],
            0.to_slot_number(),
        )
        .unwrap();
        rocksdb.write_schemas(&changes).unwrap();
        assert_eq!(
            db.get_value_option(&slot_key(&key), 0.to_slot_number())
                .unwrap(),
            Some(value)
        );
    }

    #[test]
    fn empty_value_is_not_a_delete() {
        let tempdir = crate::test_utils::tempdir();
        let (rocksdb, db) = open(&tempdir);

        let key = slot_key(b"unit");
        let empty = SlotValue::from(vec![]);
        let changes =
            AccessoryDb::materialize_values(vec![(&key, Some(empty.clone()))], SlotNumber::GENESIS)
                .unwrap();
        rocksdb.write_schemas(&changes).unwrap();
        assert_eq!(
            db.get_value_option(&key, SlotNumber::GENESIS).unwrap(),
            Some(empty)
        );
    }

    #[test]
    fn get_after_set() {
        let tempdir = crate::test_utils::tempdir();
        let (rocksdb, db) = open(&tempdir);

        let key = b"foo".to_vec();
        let value = SlotValue::from(b"bar".to_vec());
        let changes1 = AccessoryDb::materialize_values(
            vec![(key.clone(), Some(value.clone()))],
            0.to_slot_number(),
        )
        .unwrap();
        rocksdb.write_schemas(&changes1).unwrap();
        assert_eq!(
            db.get_value_option(&slot_key(&key), 0.to_slot_number())
                .unwrap(),
            Some(value.clone())
        );

        let value2 = SlotValue::from(b"baz".to_vec());
        let changes2 = AccessoryDb::materialize_values(
            vec![(key.clone(), Some(value2.clone()))],
            1.to_slot_number(),
        )
        .unwrap();
        rocksdb.write_schemas(&changes2).unwrap();
        assert_eq!(
            db.get_value_option(&slot_key(&key), 0.to_slot_number())
                .unwrap(),
            Some(value)
        );
        assert_eq!(
            db.get_value_option(&slot_key(&key), 1.to_slot_number())
                .unwrap(),
            Some(value2.clone())
        );
        assert_eq!(
            db.get_value_option(&slot_key(&key), SlotNumber::MAX)
                .unwrap(),
            Some(value2)
        );
    }

    #[test]
    fn get_after_delete() {
        let tempdir = crate::test_utils::tempdir();
        let (rocksdb, db) = open(&tempdir);

        let key = b"deleted".to_vec();
        let value = SlotValue::from(b"baz".to_vec());
        let changes1 = AccessoryDb::materialize_values(
            vec![(key.clone(), Some(value.clone()))],
            0.to_slot_number(),
        )
        .unwrap();
        rocksdb.write_schemas(&changes1).unwrap();
        assert_eq!(
            db.get_value_option(&slot_key(&key), 0.to_slot_number())
                .unwrap(),
            Some(value)
        );

        let changes2 =
            AccessoryDb::materialize_values(vec![(key.clone(), None)], 0.to_slot_number()).unwrap();
        rocksdb.write_schemas(&changes2).unwrap();
        assert_eq!(
            db.get_value_option(&slot_key(&key), 0.to_slot_number())
                .unwrap(),
            None
        );
    }

    #[test]
    fn get_nonexistent() {
        let tempdir = crate::test_utils::tempdir();
        let (_rocksdb, db) = open(&tempdir);
        assert_eq!(
            db.get_value_option(&slot_key(b"spam"), 0.to_slot_number())
                .unwrap(),
            None
        );
    }

    #[test]
    fn neighbouring_keys_are_not_returned() {
        let tempdir = crate::test_utils::tempdir();
        let (rocksdb, db) = open(&tempdir);
        // `ab` sorts between `a` and `abc` as raw bytes; with the length prefix none of them
        // is ever returned for another.
        let changes = AccessoryDb::materialize_values(
            vec![
                (b"ab".to_vec(), Some(SlotValue::from(vec![1]))),
                (b"abc".to_vec(), Some(SlotValue::from(vec![2]))),
            ],
            SlotNumber::GENESIS,
        )
        .unwrap();
        rocksdb.write_schemas(&changes).unwrap();
        for absent in [&b"aa"[..], b"abb", b"abcd", b"b0"] {
            assert_eq!(
                db.get_value_option(&slot_key(absent), SlotNumber::MAX)
                    .unwrap(),
                None
            );
        }
    }

    /// Commits slots 0, 1 and 2, then rolls back slots 2 and 1.
    #[test]
    fn rollback_accessory() {
        let tempdir = crate::test_utils::tempdir();
        let (rocksdb, db) = open(&tempdir);
        let data = TestData::new();

        for version in 0..=2 {
            let changes = AccessoryDb::materialize_values(
                data.for_version(version),
                version.to_slot_number(),
            )
            .unwrap();
            commit(&rocksdb, &changes, version).unwrap();
        }
        data.check_if_reverted(2, &db);

        for version in [1u64, 0] {
            AccessoryDb::rollback(&rocksdb).unwrap();
            let latest = AccessoryDb::latest_version_and_root(&rocksdb).unwrap();
            assert_eq!(
                latest,
                Some((version.to_slot_number(), root_from_version(version)))
            );
            data.check_if_reverted(version, &db);
        }
        AccessoryDb::rollback(&rocksdb).unwrap();
        assert_eq!(
            AccessoryDb::latest_version_and_root(&rocksdb).unwrap(),
            None
        );
        // An empty store: nothing to do.
        AccessoryDb::rollback(&rocksdb).unwrap();
    }

    #[test]
    fn corrupt_root_is_an_error() {
        let tempdir = crate::test_utils::tempdir();
        let (rocksdb, _db) = open(&tempdir);
        let mut batch = SchemaBatch::new();
        batch
            .put_raw::<StateRootHashes>(0u64.to_be_bytes().to_vec(), vec![0; 63])
            .unwrap();
        rocksdb.write_schemas(&batch).unwrap();
        let err = AccessoryDb::latest_version_and_root(&rocksdb).unwrap_err();
        assert!(format!("{err:#}").contains("64 bytes"), "{err:#}");
    }

    fn root_from_version(version: u64) -> NomtRoots {
        let byte = u8::try_from(version).unwrap();
        NomtRoots::from_bytes([byte; 64])
    }

    type Writes = Vec<(Vec<u8>, Option<SlotValue>)>;

    struct TestData {
        map: HashMap<u64, Writes>,
    }

    impl TestData {
        fn new() -> Self {
            let value = |bytes: &[u8]| Some(SlotValue::from(bytes.to_vec()));
            let mut map = HashMap::new();
            map.insert(0, vec![(b"key0".to_vec(), value(b"value0"))]);
            map.insert(
                1,
                vec![
                    (b"key1".to_vec(), value(b"value1")),
                    (b"key11".to_vec(), value(b"value11")),
                ],
            );
            map.insert(
                2,
                vec![
                    (b"key2".to_vec(), value(b"value12")),
                    (b"key11".to_vec(), value(b"value12")),
                    (b"key0".to_vec(), None),
                ],
            );
            Self { map }
        }

        fn check_if_reverted(&self, version: u64, db: &AccessoryDb) {
            for (k, v) in self.for_version(version) {
                assert_eq!(
                    db.get_value_option(&slot_key(&k), SlotNumber::MAX).unwrap(),
                    v
                );
            }
        }

        fn for_version(&self, version: u64) -> Writes {
            self.map.get(&version).unwrap().clone()
        }
    }

    fn commit(
        accessory_db: &rockbound::DB,
        accessory_batch: &SchemaBatch,
        version: u64,
    ) -> anyhow::Result<()> {
        let mut root_hash_batch = SchemaBatch::default();
        root_hash_batch
            .put::<StateRootHashes>(&version.to_slot_number(), &root_from_version(version))?;
        AccessoryDb::commit(accessory_db, accessory_batch, &root_hash_batch)
    }
}

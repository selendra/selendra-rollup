//! Regression tests for our fixes to upstream rockbound (see README.md):
//! - B1: a historical lookup returned `None` when it landed on a row of a longer (or shorter) key
//!   sharing its bytes;
//! - B2: an empty value was archived like a delete, so it read back as absent;
//! - B3: a RocksDB read error ended the iteration, so it read as "absent";
//! - rolling back a version with puts in it wrote the puts again;
//! - a reader of the empty DB iterated version 0's rows once version 0 was committed, instead
//!   of erroring as stale;
//! - B15: a reader's latest version (base version plus one per snapshot) was added unchecked;
//! - a reader read another fork's committed writes as its own once a block of the same version
//!   as one of its snapshots was committed;
//! - P1: pruning never removed delete markers, so a deleted key kept one archival row forever.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use proptest::prelude::*;
use rockbound::schema::{ColumnFamilyName, KeyDecoder, KeyEncoder, Schema, ValueCodec};
use rockbound::versioned_db::{
    CacheForVersionedDB, SchemaWithVersion, VersionedDB, VersionedDeltaReader, VersionedSchemaBatch,
};
use rockbound::{CacheForSchema, CodecError, DB, default_cf_descriptor, new_cache_for_schema};
use rocksdb::DEFAULT_COLUMN_FAMILY_NAME;
use tempfile::TempDir;

use super::TestKey;

/// A value of any length, the empty one included (like a `SlotValue`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Bytes(Vec<u8>);

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Default, Clone, PartialOrd, Ord, PartialEq, Eq)]
struct BytesSchema;

impl Schema for BytesSchema {
    type Key = TestKey;
    type Value = Bytes;
    const COLUMN_FAMILY_NAME: ColumnFamilyName = "BytesLiveCF";
}

impl SchemaWithVersion for BytesSchema {
    const HISTORICAL_COLUMN_FAMILY_NAME: ColumnFamilyName = "BytesHistoricalCF";
    const PRUNING_COLUMN_FAMILY_NAME: ColumnFamilyName = "BytesPruningCF";
    const VERSION_METADATA_COLUMN_FAMILY_NAME: ColumnFamilyName = "BytesVersionMetadataCF";
}

impl KeyEncoder<BytesSchema> for TestKey {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.as_ref().to_vec())
    }
}

impl KeyDecoder<BytesSchema> for TestKey {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        Ok(TestKey::from(data.to_vec()))
    }
}

impl ValueCodec<BytesSchema> for Bytes {
    fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.0.clone())
    }

    fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
        Ok(Self(data.to_vec()))
    }
}

/// The raw rows of the archival (historical) column family, to inspect and plant rows.
#[derive(Debug, Default)]
struct RawHistorical;

impl Schema for RawHistorical {
    type Key = Vec<u8>;
    type Value = Vec<u8>;
    const COLUMN_FAMILY_NAME: ColumnFamilyName = BytesSchema::HISTORICAL_COLUMN_FAMILY_NAME;
}

impl KeyEncoder<RawHistorical> for Vec<u8> {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.clone())
    }
}

impl KeyDecoder<RawHistorical> for Vec<u8> {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        Ok(data.to_vec())
    }
}

impl ValueCodec<RawHistorical> for Vec<u8> {
    fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.clone())
    }

    fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
        Ok(data.to_vec())
    }
}

#[derive(Debug)]
struct BytesCache(RwLock<CacheForSchema<BytesSchema>>);

impl CacheForVersionedDB<BytesSchema> for BytesCache {
    fn write(&self) -> parking_lot::MappedRwLockWriteGuard<'_, CacheForSchema<BytesSchema>> {
        RwLockWriteGuard::map(self.0.write(), |c| c)
    }

    fn read(&self) -> parking_lot::MappedRwLockReadGuard<'_, CacheForSchema<BytesSchema>> {
        RwLockReadGuard::map(self.0.read(), |c| c)
    }

    fn try_read(
        &self,
    ) -> Option<parking_lot::MappedRwLockReadGuard<'_, CacheForSchema<BytesSchema>>> {
        Some(RwLockReadGuard::map(self.0.try_read()?, |c| c))
    }
}

type Versioned = VersionedDB<BytesSchema, BytesCache>;

/// A versioned DB whose live and archival halves share one RocksDB instance (as in the other
/// tests here).
struct Fixture {
    raw: Arc<DB>,
    db: Arc<Versioned>,
}

impl Fixture {
    fn open(path: &Path) -> Self {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = [
            DEFAULT_COLUMN_FAMILY_NAME,
            BytesSchema::COLUMN_FAMILY_NAME,
            BytesSchema::HISTORICAL_COLUMN_FAMILY_NAME,
            BytesSchema::PRUNING_COLUMN_FAMILY_NAME,
            BytesSchema::VERSION_METADATA_COLUMN_FAMILY_NAME,
        ];
        let raw = Arc::new(
            DB::open_with_cfds(
                &opts,
                path,
                "fixes_test",
                cfs.into_iter().map(default_cf_descriptor),
            )
            .unwrap(),
        );
        let cache = BytesCache(RwLock::new(new_cache_for_schema::<BytesSchema>(1 << 20)));
        let db = Arc::new(Versioned::from_dbs(raw.clone(), raw.clone(), cache).unwrap());
        Self { raw, db }
    }

    fn commit(&self, version: u64, writes: &[(&[u8], Option<&[u8]>)]) {
        let mut batch = VersionedSchemaBatch::<BytesSchema>::default();
        for (key, value) in writes {
            let key = TestKey::from(key.to_vec());
            match value {
                Some(value) => batch.put_versioned(key, Bytes(value.to_vec())),
                None => batch.delete_versioned(key),
            }
        }
        self.db.commit(&batch, version).unwrap();
    }

    fn try_hist(&self, key: &[u8], version: u64) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .db
            .get_historical_value(&TestKey::from(key.to_vec()), version)?
            .map(|v| v.0))
    }

    fn hist(&self, key: &[u8], version: u64) -> Option<Vec<u8>> {
        self.try_hist(key, version).unwrap()
    }

    fn version_for(&self, key: &[u8], version: u64) -> Option<u64> {
        self.db
            .get_version_for_key(&TestKey::from(key.to_vec()), version)
            .unwrap()
    }

    fn raw_row(&self, key: &[u8], version: u64) -> Option<Vec<u8>> {
        let row_key = [key, &version.to_be_bytes()].concat();
        self.raw.get::<RawHistorical>(&row_key).unwrap()
    }

    /// A reader at `version` without in-memory snapshots, as a storage of that version sees
    /// the DB once later versions are committed (the stale-storage path).
    fn reader_at(&self, version: u64) -> VersionedDeltaReader<BytesSchema, BytesCache> {
        VersionedDeltaReader::new(self.db.clone(), Some(version), vec![])
    }
}

fn fixture() -> (TempDir, Fixture) {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::open(dir.path());
    (dir, fixture)
}

fn some(bytes: &[u8]) -> Option<Vec<u8>> {
    Some(bytes.to_vec())
}

// ---- B1 ----

/// A `StateVec`: its length at `P` and element 0 at `P ‖ [0; 8]`, which starts with the bytes
/// of `P`'s row at version 0. Upstream read the length as absent at every version after the
/// element's first write.
#[test]
fn historical_read_skips_rows_of_a_longer_key() {
    let (_dir, f) = fixture();
    let len_key: &[u8] = b"vP";
    let elem0 = [len_key, &[0; 8]].concat();
    f.commit(0, &[(len_key, Some(b"\x01")), (&elem0, Some(b"e0"))]);
    f.commit(1, &[(&elem0, Some(b"e1"))]);
    f.commit(2, &[]);

    for version in 0..=2 {
        assert_eq!(f.hist(len_key, version), some(b"\x01"), "version {version}");
        assert_eq!(
            f.version_for(len_key, version),
            Some(0),
            "version {version}"
        );
    }
    assert_eq!(f.hist(len_key, u64::MAX), some(b"\x01"));
    assert_eq!(f.hist(&elem0, 0), some(b"e0"));
    assert_eq!(f.hist(&elem0, 2), some(b"e1"));
    // The stale-storage path (`get_latest_borrowed` falls back to the archive) and the
    // watermark-aware historical read.
    assert_eq!(
        f.reader_at(1)
            .get_latest_borrowed(&TestKey::from(len_key.to_vec()))
            .unwrap(),
        Some(Bytes(vec![1]))
    );
    assert_eq!(
        f.reader_at(2)
            .get_historical_borrowed(&TestKey::from(len_key.to_vec()), 2)
            .unwrap(),
        Some(Bytes(vec![1]))
    );
}

/// `ab ‖ 5` (a row of the shorter key `ab`) starts with the key `ab\0\0` and sorts between that
/// key's rows and `ab\0\0 ‖ u64::MAX`.
#[test]
fn historical_read_skips_rows_of_a_shorter_key() {
    let (_dir, f) = fixture();
    let short: &[u8] = b"ab";
    let long: &[u8] = b"ab\0\0";
    f.commit(3, &[(long, Some(b"L"))]);
    f.commit(5, &[(short, Some(b"S"))]);

    assert_eq!(f.hist(long, u64::MAX), some(b"L"));
    assert_eq!(f.version_for(long, u64::MAX), Some(3));
    assert_eq!(f.hist(long, 5), some(b"L"));
    assert_eq!(f.hist(long, 2), None);
    assert_eq!(f.hist(short, u64::MAX), some(b"S"));
    assert_eq!(f.hist(short, 4), None);
}

/// The only row starting with the key is a shorter key's row at version 0, whose version bytes
/// are all zero: nothing of the key sorts below it.
#[test]
fn historical_read_of_a_key_with_only_a_shorter_keys_row() {
    let (_dir, f) = fixture();
    f.commit(0, &[(b"ab", Some(b"S"))]);
    assert_eq!(f.hist(b"ab\0\0", u64::MAX), None);
    assert_eq!(f.version_for(b"ab\0\0", u64::MAX), None);
    assert_eq!(f.hist(b"ab", u64::MAX), some(b"S"));
}

/// One committed version: the writes (key, value or delete) at that version.
type History = Vec<(u64, BTreeMap<Vec<u8>, Option<Vec<u8>>>)>;

fn history() -> impl Strategy<Value = History> {
    // Few distinct bytes and short keys, so keys are often prefixes of other keys and of their
    // rows (version bytes are mostly zeros); values may be empty (B2).
    let key = prop::collection::vec(prop::sample::select(vec![0x00u8, 0x01, 0xff]), 0..=3);
    let value = prop::option::of(prop::collection::vec(any::<u8>(), 0..=2));
    let version = prop_oneof![
        0..4u64,
        Just(0xff),
        Just(0x100),
        Just(0x1_0000_0000),
        Just(u64::MAX - 1),
        any::<u64>(),
    ];
    prop::collection::btree_map(
        version,
        prop::collection::btree_map(key, value, 0..=4),
        1..=6,
    )
    .prop_map(|history| history.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every historical read (and `get_version_for_key`) agrees with a model of the history.
    #[test]
    fn historical_reads_match_model(history in history()) {
        let (_dir, f) = fixture();
        for (version, writes) in &history {
            let writes: Vec<_> = writes
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_deref()))
                .collect();
            f.commit(*version, &writes);
        }
        let keys: std::collections::BTreeSet<&Vec<u8>> =
            history.iter().flat_map(|(_, writes)| writes.keys()).collect();
        let mut read_versions: Vec<u64> = vec![0, 1, 2, 0xff, 0x100, u64::MAX - 1, u64::MAX];
        for (version, _) in &history {
            read_versions.extend([version.saturating_sub(1), *version, version.saturating_add(1)]);
        }
        for key in keys {
            for &read_version in &read_versions {
                let last_write = history
                    .iter()
                    .rev()
                    .filter(|(version, _)| *version <= read_version)
                    .find_map(|(version, writes)| Some((*version, writes.get(key)?)));
                let expected_value = last_write.and_then(|(_, value)| value.clone());
                prop_assert_eq!(f.hist(key, read_version), expected_value, "key {:?} at {}", key, read_version);
                prop_assert_eq!(
                    f.version_for(key, read_version),
                    last_write.map(|(version, _)| version),
                    "key {:?} at {}", key, read_version
                );
            }
        }
    }
}

// ---- B2 ----

/// An empty value (e.g. the encoding of `()`) is a value, not a delete, in the live table, the
/// archive and through readers.
#[test]
fn empty_value_is_not_a_delete() {
    let (_dir, f) = fixture();
    let key: &[u8] = b"k";
    f.commit(0, &[(key, Some(b""))]);
    f.commit(1, &[(key, None)]);
    f.commit(2, &[(key, Some(b""))]);
    f.commit(3, &[(key, Some(b"x"))]);

    assert_eq!(f.hist(key, 0), some(b""));
    assert_eq!(f.hist(key, 1), None);
    assert_eq!(f.hist(key, 2), some(b""));
    assert_eq!(f.hist(key, 3), some(b"x"));
    assert_eq!(
        f.db.get_live_value(&TestKey::from(key.to_vec())).unwrap(),
        Some(Bytes(b"x".to_vec()))
    );

    // Readers of an older version: the archive serves them.
    let test_key = TestKey::from(key.to_vec());
    assert_eq!(
        f.reader_at(2).get_latest_borrowed(&test_key).unwrap(),
        Some(Bytes(vec![]))
    );
    assert_eq!(
        f.reader_at(3)
            .get_historical_borrowed(&test_key, 0)
            .unwrap(),
        Some(Bytes(vec![]))
    );
    assert_eq!(
        f.reader_at(3)
            .get_historical_borrowed(&test_key, 1)
            .unwrap(),
        None
    );

    // The live table and its iterator.
    f.commit(4, &[(key, Some(b""))]);
    assert_eq!(f.db.get_live_value(&test_key).unwrap(), Some(Bytes(vec![])));
    let items: Vec<_> = f
        .reader_at(4)
        .iter_with_prefix(TestKey::from(vec![]))
        .unwrap()
        .collect::<anyhow::Result<_>>()
        .unwrap();
    assert_eq!(items, vec![(test_key, Bytes(vec![]))]);
}

/// Pins the archival value format (module docs of `versioned_db`): `0x01 ‖ value` for a put,
/// `0x00` for a delete.
#[test]
fn archival_value_format() {
    let (_dir, f) = fixture();
    let key: &[u8] = b"k";
    f.commit(0, &[(key, Some(b"xy"))]);
    f.commit(1, &[(key, Some(b""))]);
    f.commit(2, &[(key, None)]);

    assert_eq!(f.raw_row(key, 0), Some(vec![0x01, b'x', b'y']));
    assert_eq!(f.raw_row(key, 1), Some(vec![0x01]));
    assert_eq!(f.raw_row(key, 2), Some(vec![0x00]));
}

/// A row that is neither (in particular upstream's untagged empty delete marker) is corruption.
#[test]
fn invalid_archival_value_is_an_error() {
    for row in [vec![], vec![0x00, 0x00], vec![0x02], vec![0x02, b'x']] {
        let (_dir, f) = fixture();
        f.commit(0, &[(b"k", Some(b"v"))]);
        f.raw
            .put::<RawHistorical>(&[b"k".as_slice(), &1_u64.to_be_bytes()].concat(), &row)
            .unwrap();
        assert!(f.try_hist(b"k", 1).is_err(), "row {row:?}");
        assert_eq!(f.hist(b"k", 0), some(b"v"));
    }
}

/// Rolling back a version (`update_versioned_db_batch` without `is_commit`) removes that
/// version's archival and pruning rows, for puts as well as deletes. (Upstream wrote puts again,
/// live table and cache included; its callers only rolled back with deletes.)
#[test]
fn rollback_removes_the_versions_rows() {
    let (_dir, f) = fixture();
    f.commit(0, &[(b"k", Some(b"v0")), (b"j", Some(b"j0"))]);
    f.commit(1, &[(b"k", Some(b"v1")), (b"j", None)]);

    let mut rollback = VersionedSchemaBatch::<BytesSchema>::default();
    rollback.put_versioned(TestKey::from(b"k".to_vec()), Bytes(b"v1".to_vec()));
    rollback.delete_versioned(TestKey::from(b"j".to_vec()));
    let mut live_batch = rocksdb::WriteBatch::default();
    let mut archival_batch = rocksdb::WriteBatch::default();
    let scratch_cache = new_cache_for_schema::<BytesSchema>(1 << 20);
    Versioned::update_versioned_db_batch(
        &mut live_batch,
        &mut archival_batch,
        &rollback,
        1,
        &scratch_cache,
        f.db.live_db(),
        f.db.archival_db(),
        false,
    )
    .unwrap();
    assert!(
        scratch_cache.is_empty(),
        "a rollback does not touch the cache"
    );
    f.db.archival_db().write_db_batch(archival_batch).unwrap();

    assert_eq!(f.raw_row(b"k", 1), None);
    assert_eq!(f.raw_row(b"j", 1), None);
    assert_eq!(f.hist(b"k", 1), some(b"v0"));
    assert_eq!(f.hist(b"j", 1), some(b"j0"));
    let pruning: Vec<_> =
        f.db.iter_pruning_keys_at_version(1)
            .unwrap()
            .collect::<anyhow::Result<_>>()
            .unwrap();
    assert!(pruning.is_empty());
}

/// A reader is stale, and its iterator an error, once a version newer than the reader's is
/// committed: the live table no longer matches it. That includes a reader of the empty DB once
/// version 0 is committed (upstream compared `0 > 0` there and iterated version 0's rows, while
/// the same reader's point reads still saw the empty DB).
#[test]
fn stale_reader_iteration_is_an_error() {
    let (_dir, f) = fixture();
    let key = TestKey::from(b"k".to_vec());
    let empty_reader = VersionedDeltaReader::new(f.db.clone(), None, vec![]);
    let items: Vec<_> = empty_reader
        .iter_with_prefix(TestKey::from(vec![]))
        .unwrap()
        .collect::<anyhow::Result<_>>()
        .unwrap();
    assert!(items.is_empty());

    f.commit(0, &[(b"k", Some(b"v0"))]);
    assert_eq!(empty_reader.get_latest_borrowed(&key).unwrap(), None);
    let err = empty_reader
        .iter_with_prefix(TestKey::from(vec![]))
        .err()
        .expect("a reader of the empty DB is stale once version 0 is committed");
    assert!(
        err.to_string().contains("Version on disk is newer"),
        "{err}"
    );
    assert!(
        empty_reader
            .iter_with_prefix_and_cursor(TestKey::from(vec![]), Some(key.clone()))
            .is_err()
    );

    // A reader at the committed version iterates; once it is stale, it errors.
    let items: Vec<_> = f
        .reader_at(0)
        .iter_with_prefix(TestKey::from(vec![]))
        .unwrap()
        .collect::<anyhow::Result<_>>()
        .unwrap();
    assert_eq!(items, vec![(key.clone(), Bytes(b"v0".to_vec()))]);
    f.commit(1, &[(b"k", Some(b"v1"))]);
    assert!(
        f.reader_at(0)
            .iter_with_prefix(TestKey::from(vec![]))
            .is_err()
    );
    assert!(
        f.reader_at(1)
            .iter_with_prefix(TestKey::from(vec![]))
            .is_ok()
    );
}

// ---- Snapshots of another fork ----

/// A reader on a snapshot of version 1 (writing `a`) after another block of version 1 (writing
/// `b` and `c`, from another fork) was committed: the reader keeps reading its own state, where
/// `b` has its version-0 value and `c` is absent. Upstream read the live table (and, in
/// historical reads, the archive at the snapshot's version), so it read the other block's
/// writes as its own. Readers on the empty DB read only their snapshots.
#[test]
fn reader_on_a_discarded_snapshot_reads_its_own_state() {
    let (_dir, f) = fixture();
    f.commit(0, &[(b"a", Some(b"a0")), (b"b", Some(b"b0"))]);
    let snapshot = |writes: &[(&[u8], &[u8])]| {
        let mut batch = VersionedSchemaBatch::<BytesSchema>::default();
        for (key, value) in writes {
            batch.put_versioned(TestKey::from(key.to_vec()), Bytes(value.to_vec()));
        }
        Arc::new(batch)
    };
    let ours = VersionedDeltaReader::new(f.db.clone(), Some(0), vec![snapshot(&[(b"a", b"a1")])]);
    let genesis = VersionedDeltaReader::new(f.db.clone(), None, vec![snapshot(&[(b"g", b"g0")])]);
    f.commit(1, &[(b"b", Some(b"b1-theirs")), (b"c", Some(b"c1-theirs"))]);

    let get = |reader: &VersionedDeltaReader<BytesSchema, BytesCache>, k: &[u8]| {
        reader
            .get_latest_borrowed(&TestKey::from(k.to_vec()))
            .unwrap()
            .map(|v| v.0)
    };
    let hist = |reader: &VersionedDeltaReader<BytesSchema, BytesCache>, k: &[u8], v| {
        reader
            .get_historical_borrowed(&TestKey::from(k.to_vec()), v)
            .unwrap()
            .map(|v| v.0)
    };
    assert_eq!(get(&ours, b"a"), some(b"a1"));
    assert_eq!(get(&ours, b"b"), some(b"b0"));
    assert_eq!(get(&ours, b"c"), None);
    assert_eq!(hist(&ours, b"a", 1), some(b"a1"));
    assert_eq!(hist(&ours, b"b", 1), some(b"b0"));
    assert_eq!(hist(&ours, b"c", 1), None);
    assert_eq!(hist(&ours, b"a", 0), some(b"a0"));
    assert_eq!(hist(&ours, b"b", 0), some(b"b0"));
    // Built on the empty DB: only its snapshot.
    assert_eq!(get(&genesis, b"g"), some(b"g0"));
    assert_eq!(get(&genesis, b"a"), None);
    assert_eq!(hist(&genesis, b"a", 0), None);
    // A reader of the committed version 1 reads it.
    assert_eq!(get(&f.reader_at(1), b"b"), some(b"b1-theirs"));
    assert_eq!(get(&f.reader_at(0), b"b"), some(b"b0"));
}

// ---- B15 ----

/// A reader whose base version plus its snapshots overflows a `u64`: every read is an `Err`
/// (upstream added unchecked, so the reads panicked on the overflow, or, without overflow
/// checks, saw a wrapped version). Readers that fit are unchanged, the empty DB's included.
#[test]
fn reader_version_overflow_is_an_error() {
    let (_dir, f) = fixture();
    let key = TestKey::from(b"k".to_vec());
    let snapshot = || {
        let mut batch = VersionedSchemaBatch::<BytesSchema>::default();
        batch.put_versioned(key.clone(), Bytes(b"v".to_vec()));
        Arc::new(batch)
    };
    let reader = VersionedDeltaReader::new(f.db.clone(), Some(u64::MAX), vec![snapshot()]);
    let err = reader.latest_version().unwrap_err();
    assert!(err.to_string().contains("version overflow"), "{err}");
    assert!(reader.get_latest_borrowed(&key).is_err());
    assert!(reader.get_latest_borrowed_unbound(&key).is_err());
    assert!(reader.get_historical_borrowed(&key, 0).is_err());
    assert!(reader.iter_with_prefix(TestKey::from(vec![])).is_err());

    let at = |base, snapshots: usize| {
        VersionedDeltaReader::new(
            f.db.clone(),
            base,
            (0..snapshots).map(|_| snapshot()).collect(),
        )
        .latest_version()
        .unwrap()
    };
    assert_eq!(at(Some(u64::MAX - 1), 1), Some(u64::MAX));
    assert_eq!(at(Some(u64::MAX), 0), Some(u64::MAX));
    assert_eq!(at(Some(3), 2), Some(5));
    assert_eq!(at(None, 0), None);
    assert_eq!(at(None, 3), Some(2));
}

// ---- B3 ----

/// Lists the SST files in `dir`.
fn sst_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sst"))
        .collect()
}

/// A corrupted data block makes RocksDB iterators fail: every read through them must be an
/// `Err`. Upstream ended the iteration instead, so historical reads returned `Ok(None)`,
/// pruning saw no keys and the prefix iterator ended early.
#[test]
fn iterator_read_errors_are_not_absent() {
    let dir = tempfile::tempdir().unwrap();
    {
        let f = Fixture::open(dir.path());
        f.commit(0, &[(b"k1", Some(b"v1")), (b"k2", Some(b"v2"))]);
        // Only these column families go to SST files; the version metadata stays in the WAL,
        // so `CommittedVersion` (a point read) is still readable after reopening.
        for cf in [
            BytesSchema::COLUMN_FAMILY_NAME,
            BytesSchema::HISTORICAL_COLUMN_FAMILY_NAME,
            BytesSchema::PRUNING_COLUMN_FAMILY_NAME,
        ] {
            f.raw.flush_cf(cf).unwrap();
        }
    }
    let ssts = sst_files(dir.path());
    assert_eq!(ssts.len(), 3, "one SST per flushed column family");
    for sst in ssts {
        // Each file holds a few rows: one data block at offset 0, checksummed. Flip its first
        // bytes (the file keeps its size, so opening the DB still succeeds).
        let mut bytes = std::fs::read(&sst).unwrap();
        for b in &mut bytes[..8] {
            *b ^= 0xff;
        }
        std::fs::write(&sst, bytes).unwrap();
    }

    let f = Fixture::open(dir.path());
    assert_eq!(f.db.get_committed_version_live_db().unwrap(), Some(0));
    assert!(f.try_hist(b"k1", 0).is_err());
    assert!(
        f.db.get_version_for_key(&TestKey::from(b"k1".to_vec()), 0)
            .is_err()
    );
    assert!(
        f.reader_at(0)
            .get_historical_borrowed(&TestKey::from(b"k1".to_vec()), 0)
            .is_err()
    );
    let pruning: Vec<_> = f.db.iter_pruning_keys_up_to_version(0).unwrap().collect();
    assert_eq!(pruning.len(), 1);
    assert!(pruning[0].is_err());
    let items: Vec<_> = f
        .reader_at(0)
        .iter_with_prefix(TestKey::from(b"k".to_vec()))
        .unwrap()
        .collect();
    assert_eq!(items.len(), 1);
    assert!(items[0].is_err());
}

// ---- P1 ----

/// The history of `pruning_collects_delete_markers`: `a` deleted at 1, `b` deleted at 2, `c`
/// deleted at 2 and written again at 3, `x` written after the cutoff.
fn deleted_keys_history(f: &Fixture) {
    f.commit(
        0,
        &[
            (b"a", Some(b"a0")),
            (b"b", Some(b"b0")),
            (b"c", Some(b"c0")),
        ],
    );
    f.commit(1, &[(b"a", None), (b"b", Some(b"b1"))]);
    f.commit(2, &[(b"b", None), (b"c", None)]);
    f.commit(3, &[(b"c", Some(b"c3"))]);
    f.commit(4, &[(b"x", Some(b"x4"))]);
    f.commit(5, &[(b"x", Some(b"x5"))]);
}

/// After pruning with cutoff 3 (newest version 5, 2 kept): the reads every version from the
/// cutoff on sees, the archival rows left, and the watermark `pruned`.
fn assert_deleted_keys_pruned(f: &Fixture, pruned: u64) {
    // Every row of `a` and `b` is gone, their delete markers included (upstream kept `a@1` and
    // `b@2` forever); `c` keeps its newest write, and its markers are gone too.
    for (key, version) in [(b"a", 0), (b"a", 1), (b"b", 0), (b"b", 1), (b"b", 2)] {
        assert_eq!(f.raw_row(key, version), None, "{key:?}@{version}");
    }
    assert_eq!(f.raw_row(b"c", 0), None);
    assert_eq!(f.raw_row(b"c", 2), None);
    assert_eq!(f.raw_row(b"c", 3), Some([&[0x01][..], b"c3"].concat()));
    assert_eq!(f.raw_row(b"x", 4), Some([&[0x01][..], b"x4"].concat()));
    assert_eq!(f.db.get_pruned_version().unwrap(), Some(pruned));
    // Reads at the cutoff and after it are unchanged: the deleted keys read as absent.
    for version in 3..=5 {
        let reader = f.reader_at(version);
        let read = |key: &[u8]| {
            reader
                .get_historical_borrowed(&TestKey::from(key.to_vec()), version)
                .unwrap()
                .map(|value| value.0)
        };
        assert_eq!(read(b"a"), None, "a@{version}");
        assert_eq!(read(b"b"), None, "b@{version}");
        assert_eq!(read(b"c"), some(b"c3"), "c@{version}");
        assert_eq!(f.hist(b"a", version), None);
        assert_eq!(f.hist(b"b", version), None);
    }
    // At and below the watermark, the reader reports the pruned versions.
    assert!(
        f.reader_at(5)
            .get_historical_borrowed(&TestKey::from(b"c".to_vec()), pruned)
            .is_err()
    );
    assert_eq!(f.version_for(b"a", 5), None);
    assert_eq!(f.version_for(b"b", 5), None);
    assert_eq!(f.version_for(b"c", 5), Some(3));
}

/// P1: a key's newest write at or before the cutoff survives pruning (its older rows are
/// deleted), even when it is a delete marker: upstream kept it, so every key ever deleted kept
/// one archival row forever. The marker is deleted now; every older row of the key is gone by
/// then, so reads find no row and the key still reads as absent.
#[test]
fn pruning_collects_delete_markers() {
    let (_dir, f) = fixture();
    deleted_keys_history(&f);
    let out = f.db.collect_pruning_batch(2, None).unwrap();
    assert!(!out.hit_size_limit);
    assert_eq!(out.keys_inspected, 8);
    // `a@0`, `b@0`, `b@1`, `c@0`, `c@2` (predecessors) and the markers `a@1`, `b@2`.
    assert_eq!(out.keys_to_prune, 7);
    assert_eq!(out.last_pruned_version, Some(2));
    f.db.archival_db().write_schemas(&out.batch).unwrap();
    assert_deleted_keys_pruned(&f, 2);

    // In passes of one index entry each: the same rows go. The marker `c@2` goes in the pass of
    // `(2, c)`, so the pass of `(3, c)` finds no predecessor left and the watermark stays at 1
    // (reads at version 2 are exact: every key written by then is deleted at 2).
    let (_dir, f) = fixture();
    deleted_keys_history(&f);
    let mut passes = 0;
    loop {
        let out = f.db.collect_pruning_batch(2, Some(1)).unwrap();
        f.db.archival_db().write_schemas(&out.batch).unwrap();
        passes += 1;
        if !out.hit_size_limit {
            break;
        }
    }
    assert_eq!(passes, 8);
    assert_deleted_keys_pruned(&f, 1);
    for key in [b"a", b"b", b"c"] {
        assert_eq!(
            f.reader_at(5)
                .get_historical_borrowed(&TestKey::from(key.to_vec()), 2)
                .unwrap(),
            None
        );
    }
}

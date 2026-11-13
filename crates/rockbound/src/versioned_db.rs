//! A database for versioned key-value pairs with one live value and N historical values.
//!
//! # On-disk format
//!
//! A [`SchemaWithVersion`] `S` uses two RocksDB instances (see [`VersionedDB`]). Keys are
//! the raw key bytes `K` ([`VersionedSchemaKeyMarker`]: no-op encoding) and versions are
//! `u64` big-endian (`V` below, 8 bytes).
//!
//! | DB | Column family | Key | Value |
//! |---|---|---|---|
//! | live | `S::COLUMN_FAMILY_NAME` | `K` | the value bytes (`AsRef<[u8]>`); a deleted key is absent |
//! | live | `S::VERSION_METADATA_COLUMN_FAMILY_NAME` | `[0]` (`CommittedVersion`) | `V` |
//! | archival | `S::HISTORICAL_COLUMN_FAMILY_NAME` | `K ‖ V` | `0x01 ‖ value` for a put, `0x00` for a delete |
//! | archival | `S::PRUNING_COLUMN_FAMILY_NAME` | `V ‖ K` | empty |
//! | archival | `S::VERSION_METADATA_COLUMN_FAMILY_NAME` | `[1]` (`PrunedVersion`) | `V` |
//!
//! The historical value is tagged so that an empty value (a legitimate value, e.g. the
//! encoding of `()`) is distinct from a delete. Upstream rockbound stored the raw value and
//! archived deletes as the empty string, so an empty value read back as deleted from the
//! archive. Any other historical value (including the empty string) is reported as
//! corruption. This format is not compatible with upstream rockbound databases.
//!
//! A historical read of `K` at version `v` returns the row `K ‖ V` with the largest
//! `V <= v`. Rows of other keys can start with the bytes of `K` (`K ‖ s ‖ V'` for a longer
//! key, or `K' ‖ V'` for a shorter key `K'`); those are skipped (see
//! `VersionedDB::get_versioned_internal`).

use std::{
    collections::{BTreeMap, btree_map},
    hash::Hash,
    iter::Peekable,
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::bail;
use parking_lot::{MappedRwLockReadGuard, MappedRwLockWriteGuard};
use quick_cache::sync::Cache;
use rocksdb::ColumnFamilyDescriptor;

use crate::{
    BasicWeighter, CacheForSchema, CfDescriptorBuilder, CodecError, DB, Schema, SchemaBatch,
    default_cf_descriptor_with,
    iterator::{RawDbIter, ScanDirection},
    schema::{ColumnFamilyName, KeyDecoder, KeyEncoder, ValueCodec},
    schema_batch::RangeDeleteKey,
};

#[derive(Debug, Default)]
pub(crate) struct VersionMetadata;

impl Schema for VersionMetadata {
    const COLUMN_FAMILY_NAME: ColumnFamilyName = "version_metadata";

    type Key = VersionedTableMetadataKey;
    type Value = u64;
}

/// A singleton key. Encodes to the empty vec.
#[derive(Debug, PartialEq, Clone, Ord, PartialOrd, Eq, Copy)]
pub enum VersionedTableMetadataKey {
    /// The latest version that has been committed.
    CommittedVersion,
    /// The newest version historical readers should treat as pruned.
    PrunedVersion,
}

const COMMITTED_VERSION: [u8; 1] = [0];
const PRUNED_VERSION: [u8; 1] = [1];

impl VersionedTableMetadataKey {
    /// Converts the key into a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            VersionedTableMetadataKey::CommittedVersion => &COMMITTED_VERSION,
            VersionedTableMetadataKey::PrunedVersion => &PRUNED_VERSION,
        }
    }

    /// Encodes the key into a byte vector.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.as_bytes().to_vec())
    }

    /// Decodes the key from a byte vector.
    pub fn decode(data: &[u8]) -> Result<Self, CodecError> {
        if data.len() != 1 {
            return Err(CodecError::InvalidKeyLength {
                expected: 1,
                got: data.len(),
            });
        }
        Ok(match data[0] {
            val if val == COMMITTED_VERSION[0] => VersionedTableMetadataKey::CommittedVersion,
            val if val == PRUNED_VERSION[0] => VersionedTableMetadataKey::PrunedVersion,
            _ => {
                return Err(CodecError::Wrapped(anyhow::anyhow!(
                    "Invalid versioned table metadata key: {}",
                    data[0]
                )));
            }
        })
    }
}

impl AsRef<VersionedTableMetadataKey> for VersionedTableMetadataKey {
    fn as_ref(&self) -> &VersionedTableMetadataKey {
        self
    }
}

impl KeyEncoder<VersionMetadata> for VersionedTableMetadataKey {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        self.encode()
    }
}

impl KeyDecoder<VersionMetadata> for VersionedTableMetadataKey {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        Self::decode(data)
    }
}

impl ValueCodec<VersionMetadata> for u64 {
    fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.to_be_bytes().to_vec())
    }

    fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
        Ok(u64::from_be_bytes(data.try_into().map_err(|_| {
            CodecError::InvalidKeyLength {
                expected: 8,
                got: data.len(),
            }
        })?))
    }
}

/// Cache for [`VersionedDB`].
pub trait CacheForVersionedDB<V: SchemaWithVersion> {
    /// Write lock.
    fn write(&self) -> MappedRwLockWriteGuard<'_, CacheForSchema<V>>;

    /// Read lock.
    fn read(&self) -> MappedRwLockReadGuard<'_, CacheForSchema<V>>;

    /// Attempt read lock.
    fn try_read(&self) -> Option<MappedRwLockReadGuard<'_, CacheForSchema<V>>>;
}

/// A versioned DB is a DB that stores data in a versioned column family.
///
/// Suppose the caller wants a versioned map from SlotKey to SlotValue. The implementation will generate several tables:
/// - A plain column family mapping SlotKey to SlotValue (the "live" column family). This can be cached.
/// - A historical column family mapping (SlotKey, Version) to SlotValue (the "historical" column family). Queries with an associated version retrieve the latest entry for that key whose value is less than or equal to the version.
///   Note that: pruning must leave at least one entry for each live key indicating at which version it was written.
/// - A pruning column family mapping Version => Vec<Key> telling us which entries were updated at each version
///
///
/// On each write, the implementation will:
/// - Put/delete the value in the live column family and its cache. (Note that range deletes are not yet supported.)
/// - Collect the keys and write them into the pruning column family
/// - (Open Question): Do we also duplicate the k/v pairs into the historical column family? or do we migrate them over to the historical column family?
///   - Suggested answer: We duplicate the keys into the other CF right away. This simplifies pruning and historical queries at the cost of maintaining two copies of the live data. We can have a config to disable the historical archive altogether, which should reduce space usage.
///
/// The alternative would be to use a more complicated multi-step commit where we...
/// - Read the current values of any keys to be modified from the live column family
/// - Modify the keys in the live column family
/// - Write the old values to the historical column family
///
/// One key problem with this approach is that we don't keep the record of when the column was written.
///
///
/// On each read, the implementation will:
/// - Read from the live column family
#[derive(Debug)]
pub struct VersionedDB<S: SchemaWithVersion, C: CacheForVersionedDB<S>> {
    /// Holds the live state and the committed versions metadata.
    ///
    /// # Warning
    /// This database *must* be written last so that we're in a consistent state on crash.
    /// When we recover, we'll read that version N-1 was the last committed version even if version N has been written
    /// to the archival DB - but that's fine because we'll reprocess block N and derive the same write set for archival state
    /// since the live_db is still correct. Conversely, if we were to commit archival state last then there would be no way to
    /// correctly re-execute the previous block..
    live_db: Arc<DB>,
    /// Holds *only* the archival and pruning data, inluding pruned version metadata.
    archival_db: Arc<DB>,
    versioned_db_cache: C,
    // The number of the *lowest* version that is guaranteed to be available in the live db. We increment this value when we *start* committing to the database,
    // so the cache may not be valid for versions below this value.
    committed_archival_version: AtomicU64,
    _schema: S,
}

fn decode_version_metadata_value(data: &[u8]) -> Result<u64, CodecError> {
    Ok(u64::from_be_bytes(data.try_into().map_err(|_| {
        CodecError::InvalidKeyLength {
            expected: 8,
            got: data.len(),
        }
    })?))
}

impl<S: SchemaWithVersion, C: CacheForVersionedDB<S>> VersionedDB<S, C>
// This where clause shouldn't be needed since it's implied by the Schema trait, but Rust intentionally doesn't elaborate these bounds.
{
    /// Returns the newest version historical readers should treat as pruned.
    ///
    /// Historical reads use `pruned_version + 1` as the oldest available version.
    pub fn get_pruned_version(&self) -> anyhow::Result<Option<u64>> {
        self.archival_db.get_raw_with_cf_and_decoder::<u64>(
            S::VERSION_METADATA_COLUMN_FAMILY_NAME,
            VersionedTableMetadataKey::PrunedVersion.as_bytes(),
            &decode_version_metadata_value,
        )
    }
    /// Returns the latest committed version in the live database.
    pub fn get_committed_version_live_db(&self) -> anyhow::Result<Option<u64>> {
        self.live_db.get_raw_with_cf_and_decoder::<u64>(
            S::VERSION_METADATA_COLUMN_FAMILY_NAME,
            VersionedTableMetadataKey::CommittedVersion.as_bytes(),
            &decode_version_metadata_value,
        )
    }
}

impl<S: SchemaWithVersion, C: CacheForVersionedDB<S>> VersionedDB<S, C> {
    /// Returns a reference to the live database.
    pub fn live_db(&self) -> &DB {
        &self.live_db
    }
    /// Returns a reference to the archival database.
    pub fn archival_db(&self) -> &DB {
        &self.archival_db
    }

    /// Triggers full compaction of the archival column families that pruning deletes from
    /// (historical + pruning), dropping the resulting tombstones and reclaiming disk.
    /// Intended to be called after committing a large pruning batch (e.g. a one-time
    /// startup prune). Heavy: only sensible when there is no live read/write traffic.
    ///
    /// The metadata CF and the live CF receive ~no deletes from pruning, so they are not
    /// compacted here.
    pub fn trigger_compaction(&self) -> anyhow::Result<()> {
        self.archival_db
            .compact_cf(S::HISTORICAL_COLUMN_FAMILY_NAME)?;
        self.archival_db.compact_cf(S::PRUNING_COLUMN_FAMILY_NAME)?;
        Ok(())
    }
}

/// A key *prefixed* with a version number for easy iteration by version.
#[derive(Debug)]
pub struct PrunableKey<S: SchemaWithVersion>(u64, S::Key, PhantomData<S>);
impl<S: SchemaWithVersion> PrunableKey<S> {
    /// Creates a new prunable key.
    pub fn new(version: u64, key: S::Key) -> Self {
        Self(version, key, PhantomData)
    }
}

impl<S: SchemaWithVersion> PrunableKey<S> {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        let len = data.len();
        if len < 8 {
            return Err(CodecError::InvalidKeyLength {
                expected: 8,
                got: len,
            });
        }
        let key = S::Key::decode_key(&data[8..])?;
        let version =
            u64::from_be_bytes(data[0..8].try_into().expect(
                "key length was just checked to be 8 bytes but no longer is. This is a bug.",
            ));
        Ok(Self::new(version, key))
    }

    /// Gets the underlying version and key.
    pub fn version_and_key(self) -> (u64, S::Key) {
        (self.0, self.1)
    }
}

#[derive(Debug, Clone)]
/// A batch of writes to a versioned schema.
pub struct VersionedSchemaBatch<S: Schema> {
    versioned_table_writes: BTreeMap<S::Key, Option<S::Value>>,
}

impl<S: Schema> Default for VersionedSchemaBatch<S> {
    fn default() -> Self {
        Self {
            versioned_table_writes: BTreeMap::new(),
        }
    }
}

impl<S: Schema, T: IntoIterator<Item = (S::Key, Option<S::Value>)>> From<T>
    for VersionedSchemaBatch<S>
where
    S::Key: Ord,
{
    fn from(iter: T) -> Self {
        Self {
            versioned_table_writes: iter.into_iter().collect(),
        }
    }
}

impl<S: Schema> VersionedSchemaBatch<S>
where
    S::Key: Ord,
{
    /// Puts a key-value pair into the batch.
    pub fn put_versioned(&mut self, key: S::Key, value: S::Value) {
        self.versioned_table_writes.insert(key, Some(value));
    }

    /// Deletes a key from the batch.
    pub fn delete_versioned(&mut self, key: S::Key) {
        self.versioned_table_writes.insert(key, None);
    }
}

/// The role of a versioned column family within a live or archival RocksDB instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionedColumnFamilyKind {
    /// The live key/value column family.
    Live,
    /// The historical versioned values column family.
    Historical,
    /// The pruning keys column family.
    Pruning,
    /// The version metadata column family.
    Metadata,
}

fn live_versioned_column_family_descriptor_with(
    name: &str,
    customize: impl FnOnce(&str, VersionedColumnFamilyKind, &mut CfDescriptorBuilder),
) -> ColumnFamilyDescriptor {
    default_cf_descriptor_with(name, |cf_name, builder| {
        // Use a 1GB block cache. TODO: Tune this value
        builder.optimize_for_point_lookup(1024);
        customize(cf_name, VersionedColumnFamilyKind::Live, builder);
    })
}

/// A marker trait showing that a type **HAS NOOP SERIALIZATION** implements `Clone` and `AsRef<[u8]>`, is cheaply cloneable.
/// No-op serialization means that key.encode_key() is the same as key.as_ref().to_vec()
pub trait VersionedSchemaKeyMarker: Clone + Ord + Hash + AsRef<[u8]> {}

/// A specialized schema for values which have one "live" version and wish to automatically store a
/// (possibly truncated) history of all versions over time.
pub trait SchemaWithVersion:
    Clone + Schema<Key: VersionedSchemaKeyMarker, Value: Clone + AsRef<[u8]>>
{
    /// The name of the column family for storing the historical values of the schema.
    const HISTORICAL_COLUMN_FAMILY_NAME: ColumnFamilyName;
    /// The name of the column family for storing the pruning keys of the schema.
    const PRUNING_COLUMN_FAMILY_NAME: ColumnFamilyName;
    /// The name of the column family for storing the version metadata of the schema.
    const VERSION_METADATA_COLUMN_FAMILY_NAME: ColumnFamilyName;
}

/// A value for a versioned schema.
#[derive(Debug, Clone)]
pub enum VersionedValue<V: SchemaWithVersion> {
    /// A value that is currently live
    Live(V::Value),
    /// A value that was written at a given version
    Historical(V::Value),
    /// A key was written at a given version and is to be pruned
    Pruning,
    /// Metadata about the versioned schema
    VersionMetadata(u64),
}

struct KeyWithVersionPrefixAndSuffix {
    version: u64,
    contents: Vec<u8>,
}

impl KeyWithVersionPrefixAndSuffix {
    pub fn new(version: u64) -> Self {
        Self {
            version,
            contents: version.to_be_bytes().to_vec(),
        }
    }

    pub fn set_key(&mut self, key: &[u8]) {
        self.contents.truncate(8);
        self.contents.extend_from_slice(key);
        self.contents.extend_from_slice(&self.version.to_be_bytes());
    }

    pub fn live_key(&self) -> &[u8] {
        let len = self.contents.len();
        &self.contents[8..len - 8]
    }

    pub fn archival_key(&self) -> &[u8] {
        let len = self.contents.len();
        &self.contents[8..len]
    }

    pub fn pruning_key(&self) -> &[u8] {
        let len = self.contents.len();
        &self.contents[0..len - 8]
    }
}

/// Encodes the historical/archival-CF key layout: `key` followed by the big-endian
/// `version`. Mirrors `KeyWithVersionPrefixAndSuffix::archival_key`.
fn encode_archival_key(key: &[u8], version: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(key.len() + 8);
    buf.extend_from_slice(key);
    buf.extend_from_slice(&version.to_be_bytes());
    buf
}

/// Archival value tag of a put: the row value is `ARCHIVAL_PUT_TAG ‖ value`.
const ARCHIVAL_PUT_TAG: u8 = 0x01;
/// Archival value of a delete: exactly this one byte.
const ARCHIVAL_DELETE: [u8; 1] = [0x00];

/// Encodes an archival put of `value` (`0x01 ‖ value`) into `buf`, replacing its contents.
fn encode_archival_put(buf: &mut Vec<u8>, value: &[u8]) {
    buf.clear();
    buf.reserve(1 + value.len());
    buf.push(ARCHIVAL_PUT_TAG);
    buf.extend_from_slice(value);
}

/// Decodes an archival value: `Some(value)` for a put, `None` for a delete.
///
/// Any other byte string (in particular the empty one, which is how upstream rockbound
/// archived deletes) is a corrupted or foreign database and an error.
fn decode_archival_value(data: &[u8]) -> Result<Option<&[u8]>, CodecError> {
    match data.split_first() {
        Some((&ARCHIVAL_PUT_TAG, value)) => Ok(Some(value)),
        Some((&tag, [])) if tag == ARCHIVAL_DELETE[0] => Ok(None),
        _ => Err(CodecError::Wrapped(anyhow::anyhow!(
            "DB corruption: invalid archival value (expected 0x01 ‖ value or 0x00, got {} bytes starting with {:?})",
            data.len(),
            data.first()
        ))),
    }
}

/// Encodes the pruning-CF key layout: the big-endian `version` followed by `key`.
/// Mirrors `KeyWithVersionPrefixAndSuffix::pruning_key`.
fn encode_pruning_key(version: u64, key: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + key.len());
    buf.extend_from_slice(&version.to_be_bytes());
    buf.extend_from_slice(key);
    buf
}

impl<V: SchemaWithVersion, C: CacheForVersionedDB<V>> VersionedDB<V, C>
where
    V::Key: Ord + Clone + std::hash::Hash + AsRef<[u8]>,
    V::Value: Clone + AsRef<[u8]>,
    V: Ord,
{
    /// Stores version in `committed_archival_version`.
    pub fn store_committed_archival_version(&self, version: u64) {
        self.committed_archival_version
            .store(version, Ordering::Release);
    }

    /// Adds the column families for the live db.
    pub fn add_live_db_column_families(
        existing_column_families: &mut Vec<ColumnFamilyDescriptor>,
    ) -> anyhow::Result<()> {
        Self::add_live_db_column_families_with(existing_column_families, |_, _, _| {})
    }

    /// Adds the column families for the live db, allowing callers to customize each descriptor.
    pub fn add_live_db_column_families_with(
        existing_column_families: &mut Vec<ColumnFamilyDescriptor>,
        mut customize: impl FnMut(&str, VersionedColumnFamilyKind, &mut CfDescriptorBuilder),
    ) -> anyhow::Result<()> {
        let live_column_family = V::COLUMN_FAMILY_NAME;
        let metadata_column_family = V::VERSION_METADATA_COLUMN_FAMILY_NAME;

        Self::validate_column_families(existing_column_families)?;

        existing_column_families.push(live_versioned_column_family_descriptor_with(
            live_column_family,
            |cf_name, kind, builder| customize(cf_name, kind, builder),
        ));
        existing_column_families.push(default_cf_descriptor_with(
            metadata_column_family,
            |cf_name, builder| customize(cf_name, VersionedColumnFamilyKind::Metadata, builder),
        ));
        Ok(())
    }

    /// Adds the column families for the archival db.
    pub fn add_archival_db_column_families(
        existing_column_families: &mut Vec<ColumnFamilyDescriptor>,
    ) -> anyhow::Result<()> {
        Self::add_archival_db_column_families_with(existing_column_families, |_, _, _| {})
    }

    /// Adds the column families for the archival db, allowing callers to customize each descriptor.
    pub fn add_archival_db_column_families_with(
        existing_column_families: &mut Vec<ColumnFamilyDescriptor>,
        mut customize: impl FnMut(&str, VersionedColumnFamilyKind, &mut CfDescriptorBuilder),
    ) -> anyhow::Result<()> {
        let historical_versioned_column_family = V::HISTORICAL_COLUMN_FAMILY_NAME;
        let pruning_column_family = V::PRUNING_COLUMN_FAMILY_NAME;
        let live_column_family = V::COLUMN_FAMILY_NAME;
        let metadata_column_family = V::VERSION_METADATA_COLUMN_FAMILY_NAME;

        Self::validate_column_families(existing_column_families)?;

        existing_column_families.push(default_cf_descriptor_with(
            historical_versioned_column_family,
            |cf_name, builder| customize(cf_name, VersionedColumnFamilyKind::Historical, builder),
        ));
        existing_column_families.push(default_cf_descriptor_with(
            pruning_column_family,
            |cf_name, builder| customize(cf_name, VersionedColumnFamilyKind::Pruning, builder),
        ));
        existing_column_families.push(live_versioned_column_family_descriptor_with(
            live_column_family,
            |cf_name, kind, builder| customize(cf_name, kind, builder),
        ));
        existing_column_families.push(default_cf_descriptor_with(
            metadata_column_family,
            |cf_name, builder| customize(cf_name, VersionedColumnFamilyKind::Metadata, builder),
        ));
        Ok(())
    }

    fn validate_column_families(
        existing_column_families: &Vec<ColumnFamilyDescriptor>,
    ) -> anyhow::Result<()> {
        let reserved = [
            V::HISTORICAL_COLUMN_FAMILY_NAME,
            V::PRUNING_COLUMN_FAMILY_NAME,
            V::COLUMN_FAMILY_NAME,
            V::VERSION_METADATA_COLUMN_FAMILY_NAME,
        ];

        for column in existing_column_families {
            if reserved.contains(&column.name()) {
                bail!("{} column name is reserved for internal use", column.name());
            }
        }

        Ok(())
    }

    /// Creates a new versioned DB from an existing DB.
    pub fn from_dbs(
        live_db: Arc<DB>,
        archival_db: Arc<DB>,
        versioned_db_cache: C,
    ) -> anyhow::Result<Self> {
        let version = Self::load_committed_version_from_disk(&live_db)?;
        let committed_archival_version = AtomicU64::new(version.unwrap_or(u64::MAX));

        Ok(Self {
            live_db,
            archival_db,
            versioned_db_cache,
            committed_archival_version,
            _schema: Default::default(),
        })
    }

    /// Returns an iterator over the pruning keys up to a given version.
    pub fn iter_pruning_keys_up_to_version(
        &self,
        version: u64,
    ) -> anyhow::Result<impl Iterator<Item = anyhow::Result<PrunableKey<V>>> + use<'_, V, C>> {
        // Because some keys are longer than 8 bytes, we use an exclusive range
        let first_version_to_keep = version.saturating_add(1);
        let range = ..first_version_to_keep.to_be_bytes().to_vec();
        self.iter_pruning_keys(range)
    }

    /// Returns an iterator over the pruning keys at a specific version.
    pub fn iter_pruning_keys_at_version(
        &self,
        version: u64,
    ) -> anyhow::Result<impl Iterator<Item = anyhow::Result<PrunableKey<V>>> + use<'_, V, C>> {
        let start = version.to_be_bytes().to_vec();
        let Some(end) = version.checked_add(1) else {
            anyhow::bail!("Unable to create iterator: upper bound overflow detected.")
        };

        let end = end.to_be_bytes().to_vec();

        let range = start..end;
        self.iter_pruning_keys(range)
    }

    /// Iterates over the pruning keys in `range`. Yields `Err` on a RocksDB error or an
    /// undecodable key (DB corruption; upstream panicked).
    fn iter_pruning_keys<R: std::ops::RangeBounds<Vec<u8>>>(
        &self,
        range: R,
    ) -> anyhow::Result<impl Iterator<Item = anyhow::Result<PrunableKey<V>>> + use<'_, V, C, R>>
    {
        let iter = self
            .archival_db
            .raw_iter_range_with_decode_fn_pruned::<V, Vec<u8>>(
                range,
                ScanDirection::Forward,
                &|(key, _value)| key.to_vec(),
            )?;
        Ok(iter.map(|key| {
            let key = key?;
            PrunableKey::decode_key(&key)
                .map_err(|e| anyhow::anyhow!("DB Corruption: Failed to decode pruning key: {e}"))
        }))
    }

    /// Collects a batch of deletes that prunes versioned data older than
    /// `last_committed - keep_versions`. The returned batch targets the `archival_db`:
    /// the caller commits it via `archival_db.write_schemas(&output.batch)`.
    ///
    /// On commit, the batch:
    /// - clears the pruning-CF entries `[V|K]` (`V <= cutoff`) collected this pass using
    ///   a single range tombstone. Every collected entry has its historical predecessor
    ///   delete emitted in this same batch, so the tombstone covers all of them; entries
    ///   beyond the `max_batch_size` cap stay in the pruning index for later passes.
    /// - deletes the historical-CF entry of the *previous* write of each collected K (so
    ///   the most recent write at or before `cutoff` survives, preserving the invariant
    ///   that every live key has at least one historical entry; see the doc on
    ///   [`VersionedDB`]). These stay point deletes; they are scattered per-key and not
    ///   safely range-able; their space is reclaimed by [`VersionedDB::trigger_compaction`].
    /// - also deletes that surviving entry when it is a delete marker: every older entry of
    ///   the key is gone by then, so reads at any version still find the key absent (a
    ///   deleted key is not live; upstream kept its marker forever).
    /// - writes [`VersionedTableMetadataKey::PrunedVersion`] = the greatest
    ///   `version - 1` for which this batch deleted a historical row, if any.
    ///
    /// A reader at a version `p >= cutoff` reads the same values before and after the batch:
    /// the newest entry at or below `p` of any key is never the predecessor of a collected
    /// entry (those are below a collected version `<= cutoff`), a deleted marker reads as
    /// absent like the marker, and the watermark stays below `cutoff`.
    ///
    /// `keep_versions` must be `>= 1`. `max_batch_size`, when set, must be `>= 1`;
    /// use `None` for an uncapped batch. If the database has no committed version yet,
    /// if `last_committed < keep_versions`, or if no pruning entries remain up to the
    /// cutoff, the returned batch is empty and `last_pruned_version` is `None`.
    ///
    /// When `max_batch_size` is set, at most that many pruning entries are collected per
    /// pass, so the batch holds at most twice that many historical-CF deletes (each entry
    /// contributes its predecessor and, last of its key's group, a delete marker);
    /// `hit_size_limit` is `true` when entries remain beyond the cap, and the caller should
    /// commit the batch and re-invoke to drain the rest.
    ///
    /// # Performance
    ///
    /// One sequential scan of the pruning index over the collected entries, plus at most
    /// one historical-CF seek and one point read (is the survivor a delete marker?) per
    /// *distinct key* in the pass: within a key's group of
    /// collected versions every predecessor is known from the group itself, and only the
    /// group's oldest version needs a lookup (for a survivor left by an earlier pass).
    /// An uncapped pass buffers all prunable entries in memory (the same order of
    /// magnitude as the returned batch itself); set `max_batch_size` to bound memory and
    /// commit size when pruning a large backlog.
    pub fn collect_pruning_batch(
        &self,
        keep_versions: u64,
        max_batch_size: Option<usize>,
    ) -> anyhow::Result<PruningBatchOutput> {
        if keep_versions == 0 {
            anyhow::bail!("keep_versions must be >= 1");
        }
        if max_batch_size == Some(0) {
            anyhow::bail!("max_batch_size must be >= 1 when set");
        }

        let mut batch = SchemaBatch::new();
        let mut keys_to_prune = 0usize;
        let mut hit_size_limit = false;
        let mut last_pruned_version = None;

        let Some(cutoff) = self
            .get_committed_version_live_db()?
            .and_then(|last_committed| last_committed.checked_sub(keep_versions))
        else {
            return Ok(PruningBatchOutput {
                batch,
                hit_size_limit,
                last_pruned_version,
                keys_inspected: 0,
                keys_to_prune,
            });
        };

        // Phase 1: collect up to `max_batch_size` pruning entries `[V|K]` with
        // `V <= cutoff`, in `[version_be || key]` order. Bounding the collection bounds
        // both this pass's memory and the number of deletes emitted below (each entry
        // contributes at most two historical deletes: its predecessor and a delete marker).
        let mut iter = self.iter_pruning_keys_up_to_version(cutoff)?;
        let mut collected: Vec<(u64, V::Key)> = Vec::new();
        for prunable in &mut iter {
            collected.push(prunable?.version_and_key());
            if max_batch_size.is_some_and(|m| collected.len() >= m) {
                // Peek whether entries remain so callers know to re-invoke.
                hit_size_limit = iter.next().transpose()?.is_some();
                break;
            }
        }
        let keys_inspected = collected.len();
        if collected.is_empty() {
            return Ok(PruningBatchOutput {
                batch,
                hit_size_limit,
                last_pruned_version,
                keys_inspected,
                keys_to_prune,
            });
        }

        // The pruning CF is keyed `[version_be || key]` and every collected entry has
        // `version <= cutoff`, so the collected set is one contiguous prefix range that we
        // clear with a single range tombstone instead of one point delete per entry. Every
        // collected entry is fully processed below (its historical predecessor delete is
        // emitted in this same batch), so the tombstone may cover all of them: when the
        // iterator was drained, the exclusive upper bound is `cutoff + 1`; when we stopped
        // at `max_batch_size`, it is the successor of the last collected entry.
        let pruning_cf_upper = if hit_size_limit {
            let (last_version, last_key) = collected
                .last()
                .expect("hit_size_limit implies at least one collected entry");
            encode_pruning_key(*last_version, last_key.as_ref()).range_delete_key_after()
        } else {
            cutoff.saturating_add(1).to_be_bytes().to_vec()
        };

        // Phase 2: group the collected entries per key, versions ascending within each
        // group. Sort by key *bytes* to match the column family's ordering.
        collected
            .sort_unstable_by(|(va, ka), (vb, kb)| ka.as_ref().cmp(kb.as_ref()).then(va.cmp(vb)));

        // Phase 3: walk each key's group `[V1 < V2 < ... < Vm]` and delete the historical
        // entry of each version's *previous* write, keeping the entry at `Vm` (the most
        // recent write at or before `cutoff`) intact, preserving the "at least one entry
        // per live key" invariant; see the doc on [`VersionedDB`].
        //
        // For `Vi` with `i >= 2` the previous write is `V(i-1)`, known from the group
        // itself. Only `V1` needs a historical-CF lookup: its previous write, if any, is a
        // survivor kept by an earlier pass. (A pre-redesign capped pass may also have left
        // `V1` lingering with its predecessor already deleted; the lookup then finds
        // nothing and emits nothing, so passes of either vintage compose safely.) When
        // `V1 == 0` there is nothing before it and the lookup is skipped.
        let mut prev_in_group: Option<(&[u8], u64)> = None;
        for (index, (version, key)) in collected.iter().enumerate() {
            // Deleting this entry's predecessor redirects historical queries in
            // `[predecessor, version - 1]`; `version == 0` has no predecessor.
            if let Some(query_version) = version.checked_sub(1) {
                let prev_version = match prev_in_group {
                    Some((prev_key, prev_version)) if prev_key == key.as_ref() => {
                        Some(prev_version)
                    }
                    _ => self.get_version_for_key(key, query_version)?,
                };
                if let Some(prev_version) = prev_version {
                    batch.delete_cf_raw(
                        V::HISTORICAL_COLUMN_FAMILY_NAME,
                        encode_archival_key(key.as_ref(), prev_version),
                    );
                    keys_to_prune += 1;
                    // The watermark must cover the highest redirected query version.
                    last_pruned_version = last_pruned_version.max(Some(query_version));
                }
            }
            prev_in_group = Some((key.as_ref(), *version));

            // The group's last entry is the key's newest write at or before the cutoff, and every
            // older row of the key is now deleted (by this pass or an earlier one: each entry
            // deletes its predecessor). Its row survives, unless it is a delete marker: a read of
            // any version then finds no row of the key, which reads as absent, like the marker.
            // (Upstream kept the marker, so a deleted key kept one row forever.) No read result
            // changes, so the watermark does not move.
            let last_of_group = collected
                .get(index + 1)
                .is_none_or(|(_, next_key)| next_key.as_ref() != key.as_ref());
            if last_of_group && self.is_archival_delete(key.as_ref(), *version)? {
                batch.delete_cf_raw(
                    V::HISTORICAL_COLUMN_FAMILY_NAME,
                    encode_archival_key(key.as_ref(), *version),
                );
                keys_to_prune += 1;
            }
        }

        if keys_inspected > 0 {
            // Clear the collected pruning entries with one range tombstone over
            // `[start-of-CF, pruning_cf_upper)`. `Vec::new()` sorts before all keys.
            batch.delete_range_cf_raw(V::PRUNING_COLUMN_FAMILY_NAME, Vec::new(), pruning_cf_upper);
        }

        if let Some(v) = last_pruned_version {
            batch.put_cf_raw(
                V::VERSION_METADATA_COLUMN_FAMILY_NAME,
                VersionedTableMetadataKey::PrunedVersion.as_bytes().to_vec(),
                v.to_be_bytes().to_vec(),
            );
        }

        Ok(PruningBatchOutput {
            batch,
            hit_size_limit,
            last_pruned_version,
            keys_inspected,
            keys_to_prune,
        })
    }

    /// Whether the archival row `key ‖ version` is a delete marker (`false` if absent).
    fn is_archival_delete(&self, key: &[u8], version: u64) -> anyhow::Result<bool> {
        let is_delete = self.archival_db.get_raw_with_cf_and_decoder(
            V::HISTORICAL_COLUMN_FAMILY_NAME,
            &encode_archival_key(key, version),
            &|data| Ok(decode_archival_value(data)?.is_none()),
        )?;
        Ok(is_delete == Some(true))
    }

    fn load_committed_version_from_disk(live_db: &DB) -> anyhow::Result<Option<u64>> {
        live_db.get_raw_with_cf_and_decoder::<u64>(
            V::VERSION_METADATA_COLUMN_FAMILY_NAME,
            VersionedTableMetadataKey::CommittedVersion.as_bytes(),
            &|data| {
                Ok(u64::from_be_bytes(data.try_into().map_err(|_| {
                    CodecError::InvalidKeyLength {
                        expected: 8,
                        got: data.len(),
                    }
                })?))
            },
        )
    }

    /// Name of the database that can be used for logging or metrics or tracing.
    #[inline]
    pub fn name(&self) -> &'static str {
        self.live_db.name()
    }

    /// Returns the value of a key in the live column family.
    pub fn get_live_value(&self, key: &V::Key) -> anyhow::Result<Option<V::Value>> {
        let lock = self.versioned_db_cache.try_read();
        if let Some(cache) = lock.as_ref() {
            let cache_result = cache.get(key);
            if let Some(result) = cache_result {
                return Ok(result);
            }
        }
        let result = self.live_db.get_raw::<V>(key.as_ref())?;
        // We can safely modify the cache while holding a read lock because we always hold a *write* lock while committing to the DB.
        // Since we're currently holding a read lock, that means that the DB is not currently changing - so the value we just read cannot
        // be invalidated by a concurrent write. This makes it safe to insert.
        //
        // Note that this analysis only holds because we've held the lock since the beginning of `get_live_value`. If we were to drop
        // the lock while we read from disk, this would not be sound.
        if let Some(cache) = lock {
            cache.insert(key.clone(), result.clone());
        }
        Ok(result)
    }

    /// Returns the latest committed version in the database from an atomic.
    pub fn fetch_latest_committed_archival_version(&self) -> Option<u64> {
        let value = self.committed_archival_version.load(Ordering::Acquire);
        // We use u64::MAX as a placeholder on startup to indicate that no version has been committed yet.
        if value == u64::MAX {
            return None;
        }
        Some(value)
    }

    /// Populates the `live_db_batch & archival_db_batch` using data from `batch`.
    ///
    /// With `is_commit`, this writes version `version`: live puts/deletes (and the cache), one
    /// archival row per key in the format described in the [module docs](self) (a tagged put
    /// or a delete marker), one pruning row per key, and the live `CommittedVersion`. Without
    /// `is_commit` it rolls back `version` in the archival DB: it removes that version's
    /// archival and pruning rows (the live DB is not rolled back).
    #[allow(clippy::too_many_arguments)]
    pub fn update_versioned_db_batch(
        live_db_batch: &mut rocksdb::WriteBatch,
        archival_db_batch: &mut rocksdb::WriteBatch,
        batch: &VersionedSchemaBatch<V>,
        version: u64,
        cache: &CacheForSchema<V>,
        live_db: &DB,
        archival_db: &DB,
        is_commit: bool,
    ) -> anyhow::Result<()> {
        // Optimization:
        // At various times we need the key *prefixed* with the version (for pruning), on its own (for live reads), and suffixed with the version (for archival reads).
        // To reduce allocations and memcopies, we create a single vector [version || key || version] and use it for all three cases, simply slicing the relevant subset.
        //
        // As a further optimization, we reuse a single `Vec` for all keys.
        let mut key_with_version = KeyWithVersionPrefixAndSuffix::new(version);
        // Reused buffer for the tagged archival value.
        let mut archival_value = Vec::new();

        let archival_cf_handle = archival_db.get_cf_handle(V::HISTORICAL_COLUMN_FAMILY_NAME)?;
        let pruning_cf_handle = archival_db.get_cf_handle(V::PRUNING_COLUMN_FAMILY_NAME)?;

        let live_cf_handle = live_db.get_cf_handle(V::COLUMN_FAMILY_NAME)?;
        let live_metadata_cf_handle =
            live_db.get_cf_handle(V::VERSION_METADATA_COLUMN_FAMILY_NAME)?;

        for (key, value) in batch.versioned_table_writes.iter() {
            key_with_version.set_key(key.as_ref());
            match value {
                Some(value) => {
                    if is_commit {
                        live_db_batch.put_cf(live_cf_handle, key_with_version.live_key(), value);
                        encode_archival_put(&mut archival_value, value.as_ref());
                        archival_db_batch.put_cf(
                            archival_cf_handle,
                            key_with_version.archival_key(),
                            &archival_value,
                        );
                        cache.insert(key.clone(), Some(value.clone()));
                    } else {
                        // We don't roll back live_db, and we remove data from HISTORICAL_COLUMN_FAMILY_NAME.
                        archival_db_batch
                            .delete_cf(archival_cf_handle, key_with_version.archival_key());
                    }
                }
                None => {
                    if is_commit {
                        live_db_batch.delete_cf(live_cf_handle, key);
                        cache.insert(key.clone(), None);
                        archival_db_batch.put_cf(
                            archival_cf_handle,
                            key_with_version.archival_key(),
                            ARCHIVAL_DELETE,
                        );
                    } else {
                        // We don't roll back live_db, and we remove data from HISTORICAL_COLUMN_FAMILY_NAME.
                        archival_db_batch
                            .delete_cf(archival_cf_handle, key_with_version.archival_key());
                    }
                }
            }

            if is_commit {
                archival_db_batch.put_cf(pruning_cf_handle, key_with_version.pruning_key(), []);
            } else {
                // On rollback we remove data from PRUNING_COLUMN_FAMILY_NAME)
                archival_db_batch.delete_cf(pruning_cf_handle, key_with_version.pruning_key());
            }
        }

        live_db_batch.put_cf(
            live_metadata_cf_handle,
            VersionedTableMetadataKey::CommittedVersion.as_bytes(),
            version.to_be_bytes(),
        );

        Ok(())
    }

    /// Returns the value of a key in the historical column family as of the given version.
    ///
    /// This is a raw archival lookup: it does not enforce
    /// [`VersionedTableMetadataKey::PrunedVersion`]. After pruning, some survivor rows are
    /// intentionally retained below the pruning watermark, so this method may return a
    /// value for a version that strict historical readers should treat as pruned. Use
    /// [`VersionedDeltaReader::get_historical_borrowed`] for watermark-aware reads.
    pub fn get_historical_value(
        &self,
        key_to_get: &impl KeyEncoder<V>,
        version: u64,
    ) -> anyhow::Result<Option<V::Value>> {
        self.get_historical_value_raw(key_to_get.encode_key()?, version)
    }

    /// Returns the value of a pre-encoded key in the historical column family as of the
    /// given version.
    ///
    /// This has the same raw archival semantics as [`Self::get_historical_value`]: it may
    /// return retained survivor rows below [`VersionedTableMetadataKey::PrunedVersion`].
    /// Use [`VersionedDeltaReader::get_historical_borrowed`] for watermark-aware reads.
    pub fn get_historical_value_raw(
        &self,
        pre_encoded_key_to_get: Vec<u8>,
        version: u64,
    ) -> anyhow::Result<Option<V::Value>> {
        let Some((value_bytes, _version)) =
            self.get_versioned_internal(pre_encoded_key_to_get, version)?
        else {
            return Ok(None);
        };
        match decode_archival_value(&value_bytes)? {
            Some(value_bytes) => Ok(Some(V::Value::decode_value(value_bytes)?)),
            None => Ok(None),
        }
    }

    /// Returns the latest version at which the given key was written.
    ///
    /// This is a raw archival lookup and does not enforce
    /// [`VersionedTableMetadataKey::PrunedVersion`]. After pruning, it may report retained
    /// survivor rows below the pruning watermark.
    pub fn get_version_for_key(
        &self,
        key_to_get: &impl KeyEncoder<V>,
        max_version: u64,
    ) -> anyhow::Result<Option<u64>> {
        let Some((_, version)) =
            self.get_versioned_internal(key_to_get.encode_key()?, max_version)?
        else {
            return Ok(None);
        };
        Ok(Some(version))
    }

    /// Finds the archival row `key_to_get ‖ v` with the largest `v <= max_version` and returns
    /// its raw (tagged) value and `v`.
    ///
    /// Rows of *other* keys can start with `key_to_get` too: those of a longer key
    /// `key_to_get ‖ s` (rows `key_to_get ‖ s ‖ v'`), and those of a shorter key `k'` whose
    /// version bytes continue with the rest of `key_to_get` (rows `k' ‖ v'` that start with
    /// `key_to_get` but are shorter than `key_to_get ‖ v`). All rows starting with
    /// `key_to_get` are contiguous, but such rows interleave with the rows of `key_to_get`
    /// itself, so the backward seek from `key_to_get ‖ max_version` can land on one of them.
    /// We then seek again from the largest possible row of `key_to_get` below it, so each
    /// re-seek skips a whole group of the other key's rows, not one row. (Upstream returned
    /// `None` as soon as it landed on such a row: e.g. a `StateVec` length at `P` read as
    /// absent once element 0, at `P ‖ [0; 8]`, had been written.)
    fn get_versioned_internal(
        &self,
        key_to_get: Vec<u8>,
        max_version: u64,
    ) -> anyhow::Result<Option<(Vec<u8>, u64)>> {
        let key_len = key_to_get.len();
        let row_len = key_len + 8;
        let mut seek_key = key_to_get;
        seek_key.extend_from_slice(&max_version.to_be_bytes());
        loop {
            let mut iterator = self
                .archival_db
                .raw_iter_cf_with_decode_fn::<(Vec<u8>, Vec<u8>)>(
                    V::HISTORICAL_COLUMN_FAMILY_NAME,
                    ..=&seek_key,
                    ScanDirection::Backward,
                    &|(key, value)| (key.to_vec(), value.to_vec()),
                )?;
            let Some((row_key, value_bytes)) = iterator.next().transpose()? else {
                return Ok(None);
            };
            if !row_key.starts_with(&seek_key[..key_len]) {
                return Ok(None);
            }
            match row_key.len().cmp(&row_len) {
                std::cmp::Ordering::Equal => {
                    let version = u64::from_be_bytes(
                        row_key[key_len..]
                            .try_into()
                            .expect("the row is the key plus 8 bytes"),
                    );
                    // Same length as `seek_key` and not greater than it.
                    debug_assert!(
                        version <= max_version,
                        "Unexpected version. Queried for less than or equal to version {max_version} but got version {version}"
                    );
                    return Ok(Some((value_bytes, version)));
                }
                // A longer key's row `key ‖ x` (`x` longer than 8 bytes): the largest row of
                // `key` not above it is `key ‖ x[..8]`.
                std::cmp::Ordering::Greater => seek_key.copy_from_slice(&row_key[..row_len]),
                // A shorter key's row `key ‖ t` (`t` shorter than 8 bytes): the largest row of
                // `key` below it is `key ‖ (t - 1) ‖ 0xff…`, and there is none if `t` is zero.
                std::cmp::Ordering::Less => {
                    let tail = &row_key[key_len..];
                    let mut suffix = [0xff; 8];
                    suffix[..tail.len()].copy_from_slice(tail);
                    if !decrement_be(&mut suffix[..tail.len()]) {
                        return Ok(None);
                    }
                    seek_key[key_len..].copy_from_slice(&suffix);
                }
            }
        }
    }
}

/// Decrements `bytes` as a big-endian integer. Returns `false` (and leaves `bytes` unchanged)
/// if it is zero, including when it is empty.
fn decrement_be(bytes: &mut [u8]) -> bool {
    let Some(last_non_zero) = bytes.iter().rposition(|b| *b != 0) else {
        return false;
    };
    bytes[last_non_zero] -= 1;
    for b in &mut bytes[last_non_zero + 1..] {
        *b = 0xff;
    }
    true
}

/// Output of [`VersionedDB::collect_pruning_batch`].
///
/// The caller commits `batch` via `archival_db.write_schemas(&output.batch)`.
#[derive(Debug)]
pub struct PruningBatchOutput {
    /// Multi-CF batch of deletes and the metadata write.
    pub batch: SchemaBatch,
    /// `true` if `max_batch_size` was reached with pruning entries still remaining.
    /// Caller should commit and re-invoke until this returns `false`.
    pub hit_size_limit: bool,
    /// The value recorded into [`VersionedTableMetadataKey::PrunedVersion`], or `None`
    /// when this batch deleted no historical rows.
    pub last_pruned_version: Option<u64>,
    /// Number of pruning-CF entries collected (and fully processed) this pass. For metrics.
    pub keys_inspected: usize,
    /// Number of historical-CF delete operations placed in the batch (predecessors and delete
    /// markers). For metrics.
    pub keys_to_prune: usize,
}

#[derive(Debug, Clone)]
/// A reader for a versioned schema.
pub struct VersionedDeltaReader<V: SchemaWithVersion, C: CacheForVersionedDB<V>> {
    db: Arc<VersionedDB<V, C>>,
    // The version of the underlying DB at the time this snapshot was taken.
    base_version: Option<u64>,
    // The snapshots to include in the reader, ordered from newest to oldest.
    snapshots: Vec<Arc<VersionedSchemaBatch<V>>>,
}

impl<V: SchemaWithVersion, C: CacheForVersionedDB<V>> VersionedDeltaReader<V, C>
where
    V::Key: Eq,
    V::Value: Clone,
{
    /// Creates a new versioned delta reader.
    ///
    /// Note that the snapshots are ordered from oldest to newest
    pub fn new(
        db: Arc<VersionedDB<V, C>>,
        base_version: Option<u64>,
        mut snapshots: Vec<Arc<VersionedSchemaBatch<V>>>,
    ) -> Self {
        // We keep the API consistent across the codebase (snapshots should be chronological),
        // But use reverse order internally so that iteration can always be done from newest to oldest.
        snapshots.reverse();
        Self {
            snapshots,
            db,
            base_version,
        }
    }

    /// Returns the latest version that is available in the reader: the base version plus one
    /// per snapshot (the snapshots are the versions after the base version, in order), or, on
    /// the empty DB (`None`), the number of snapshots minus one.
    ///
    /// # Errors
    /// If that version does not fit in a `u64` (upstream added unchecked: an overflow panic, or
    /// a wrapped version in builds without overflow checks).
    pub fn latest_version(&self) -> anyhow::Result<Option<u64>> {
        let snapshots = u64::try_from(self.snapshots.len())
            .map_err(|_| anyhow::anyhow!("more than u64::MAX snapshots"))?;
        match self.base_version {
            Some(base_version) => base_version
                .checked_add(snapshots)
                .map(Some)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "version overflow: base version {base_version} plus {snapshots} snapshots"
                    )
                }),
            None => Ok(snapshots.checked_sub(1)),
        }
    }

    /// Returns the version of the DB at the time this reader was created.
    pub fn base_version(&self) -> Option<u64> {
        self.base_version
    }
}

type MaybePeekableBtreeMapRange<'a, K, V> = Option<Peekable<btree_map::Range<'a, K, V>>>;

/// An iterator over the live key/value pairs in a VersionedDB, including the current snapshots.
///
/// Internally, this struct has to peek at each snapshot and the db to find the next smallest key and returns that result.
///
/// Keys come in ascending order. The snapshots are compared by the key's `Ord` and the DB by its
/// bytes, so the key's `Ord` must agree with the byte order of its encoding. Deleted keys are
/// skipped.
///
/// Yields `Err` once and then ends if the DB iterator fails or a stored key or value does not
/// decode. (Upstream ended the iteration silently on a RocksDB error and panicked on a decoding
/// error.)
pub struct VersionedDbIterator<'a, V: SchemaWithVersion> {
    // We hold a read lock over the db cache to prevent any writes to the table during iteration. If a key was written while we were iterating, we could get inconsistent results:
    //  - Iterator reads:  Key1 -> A,
    //  - Concurrent thread writes:: Key1 -> B, Key2 -> B
    //  - Iterator reads: Key2 -> B,
    // Now the caller sees a state of the world which never existed where Key1 -> A and Key2 -> B.
    _read_lock: MappedRwLockReadGuard<'a, Cache<V::Key, Option<V::Value>, BasicWeighter>>,
    // Borrow the snapshots to keep the lifetimes tied together. We could clone, but this makes it easier to reason about.
    snapshots: Vec<MaybePeekableBtreeMapRange<'a, V::Key, Option<V::Value>>>,
    db_iterator: Option<Peekable<RawDbIter<'a>>>,
    prefix: V::Key,
    encoded_prefix: Vec<u8>,
    /// Set after an error was returned.
    failed: bool,
}

enum LocationOfSmallestKey {
    Snapshot(usize),
    Db,
}

/// A trait for types that can be checked for a prefix.
pub trait HasPrefix<T = Self> {
    /// Checks if the current item has the given prefix.
    fn has_prefix(&self, prefix: &T) -> bool;
}

impl HasPrefix for Vec<u8> {
    fn has_prefix(&self, prefix: &Self) -> bool {
        self.starts_with(prefix)
    }
}

impl HasPrefix for Arc<Vec<u8>> {
    fn has_prefix(&self, prefix: &Self) -> bool {
        self.starts_with(prefix)
    }
}

impl<V: SchemaWithVersion<Key = K>, K> VersionedDbIterator<'_, V>
where
    K: Eq + std::hash::Hash + KeyEncoder<V> + KeyDecoder<V> + HasPrefix + Ord,
    V::Value: Clone,
{
    /// Decodes the key of the next DB entry, or `None` once the DB has no more entries with the
    /// prefix (and then drops the DB iterator).
    fn peek_db_key(&mut self) -> anyhow::Result<Option<K>> {
        let Some(iter) = self.db_iterator.as_mut() else {
            return Ok(None);
        };
        let has_prefix = match iter.peek() {
            None => return Ok(None),
            Some(Err(_)) => {
                return Err(iter
                    .next()
                    .expect("an entry was just peeked")
                    .expect_err("an error was just peeked"));
            }
            Some(Ok((key, _value))) => key.starts_with(&self.encoded_prefix),
        };
        if !has_prefix {
            self.db_iterator = None;
            return Ok(None);
        }
        match iter.peek() {
            Some(Ok((key, _value))) => Ok(Some(K::decode_key(key)?)),
            _ => unreachable!("an entry was just peeked"),
        }
    }

    fn next_impl(&mut self) -> anyhow::Result<Option<(K, V::Value)>> {
        // The body of this loop does two passes over the versioned DB contents (including all snapshots and the DB in each pass)
        // first pass: peek each iterator and find the smallest *key* available from any iterator.
        // second pass: advance each iterator whose peeked key is equal to the smallest key, keeping the first (newest) *value* that you find
        //
        // After these two passes, all iterators are consistent and we've saved the most recent value of the next key in lexicographic order into the variable `smallest_key`.
        // *but*, there's a wrinkle. Snapshots save deleted keys as `None`, while deleted keys are simply absent from the DB. To reflect this,
        // we don't want to return the k/v pair if the value is a `None` from a snapshot.
        //
        // To handle this, we simply run the core algorithm in a loop until we find a key/value pair whose value is not `None` and return it.
        loop {
            // Step 1: peek at each snapshot and the Db to find the global smallest key that matches our prefix.
            let mut smallest_key: Option<(LocationOfSmallestKey, K)> = None;
            // 1.1 Look at each snapshot
            for (idx, snapshot) in self.snapshots.iter_mut().enumerate() {
                if let Some((key, _value)) = snapshot.as_mut().and_then(|s| s.peek()) {
                    // If the next key from this snapsot doesn't match our prefix, ignore it
                    if !key.has_prefix(&self.prefix) {
                        continue;
                    }
                    // If this key is smaller than the current smallest key, update our view of the smallest key and remember which snapshot it came from.
                    if smallest_key
                        .as_ref()
                        .is_none_or(|(_smallest_idx, smallest_key)| *key < smallest_key)
                    {
                        smallest_key = Some((LocationOfSmallestKey::Snapshot(idx), (*key).clone()));
                    }
                }
            }
            // 1.2 Look at the Db, doing the same thing
            if let Some(key) = self.peek_db_key()?
                && smallest_key
                    .as_ref()
                    .is_none_or(|(_smallest_idx, smallest_key)| key < *smallest_key)
            {
                smallest_key = Some((LocationOfSmallestKey::Db, key));
            }

            // If we didn't find any keys that matches our prefix, we're done.
            let Some((smallest_idx, smallest_key)) = smallest_key else {
                return Ok(None);
            };

            // Step 2: advance the iterator that corresponds to the smallest key and get the value to return
            let value_to_return = match smallest_idx {
                LocationOfSmallestKey::Snapshot(idx) => {
                    let (_raw_key, value) = self.snapshots[idx].as_mut().and_then(|s| s.next()).expect("key went missing from snapshot while iterating. We just checked that `peek` returned a key and `next` failed. This is a bug.");
                    value.clone()
                }
                LocationOfSmallestKey::Db => {
                    let (_raw_key, value) = self.db_iterator.as_mut().and_then(|iter| iter.next()).expect("key went missing from DB while iterating. We just checked that `peek` returned a key and `next` failed. This is a bug.")?;
                    Some(V::Value::decode_value(&value)?)
                }
            };

            // Step 3: advance any iterators that are pointing to the same key we just returned. For example, if the newest snapshot contains key A and two of the older snapshots do as well,
            // we want to return the k/v pair from the newest snapshot and advance the other two iterators so that we don't return stale values of `A` on the next call to `next`.
            // Step 3.1: advance any snapshot iterators
            for snapshot in self.snapshots.iter_mut() {
                if let Some((key, _value)) = snapshot.as_mut().and_then(|s| s.peek())
                    && *key == &smallest_key
                {
                    let _ = snapshot.as_mut().and_then(|s| s.next());
                }
            }
            // Step 3.2 advance the db iterator
            if self.peek_db_key()?.as_ref() == Some(&smallest_key) {
                let _ = self.db_iterator.as_mut().and_then(|iter| iter.next());
            }

            if let Some(value) = value_to_return {
                return Ok(Some((smallest_key, value)));
            }
        }
    }
}

impl<V: SchemaWithVersion<Key = K>, K> Iterator for VersionedDbIterator<'_, V>
where
    K: Eq + std::hash::Hash + KeyEncoder<V> + KeyDecoder<V> + HasPrefix + Ord,
    V::Value: Clone,
{
    type Item = anyhow::Result<(K, V::Value)>;

    // Return the next key/value pair from the iterator.
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        match self.next_impl() {
            Ok(item) => item.map(Ok),
            Err(err) => {
                self.failed = true;
                Some(Err(err))
            }
        }
    }
}

impl<V: SchemaWithVersion<Key = K>, K> std::iter::FusedIterator for VersionedDbIterator<'_, V>
where
    K: Eq + std::hash::Hash + KeyEncoder<V> + KeyDecoder<V> + HasPrefix + Ord,
    V::Value: Clone,
{
}

impl<V: SchemaWithVersion, C: CacheForVersionedDB<V>> VersionedDeltaReader<V, C>
where
    V::Value: Clone + AsRef<[u8]>,
    V: Ord,
    V::Key: Eq
        + std::hash::Hash
        + KeyEncoder<V>
        + KeyDecoder<V>
        + HasPrefix
        + Ord
        + AsRef<[u8]>
        + std::fmt::Debug,
{
    /// Construct an iterator over the versioned DB with a given prefix.
    ///
    /// Note that the returned iterator holds a read lock over the DB, so no writes can complete while it is active.
    pub fn iter_with_prefix(&self, prefix: V::Key) -> anyhow::Result<VersionedDbIterator<'_, V>> {
        self.iter_with_prefix_and_cursor(prefix, None)
    }

    /// Construct an iterator over the versioned DB with a given prefix, skipping until the given key is reached. Note that
    /// any values exactly equal to the cursor *will* be included in the iterator.
    ///
    /// Note that the returned iterator holds a read lock over the DB, so no writes can complete while it is active.
    pub fn iter_with_prefix_and_cursor(
        &self,
        prefix: V::Key,
        skip_until: Option<V::Key>,
    ) -> anyhow::Result<VersionedDbIterator<'_, V>> {
        let read_lock = self.db.versioned_db_cache.read();
        let version_on_disk = self.db.get_committed_version_live_db()?;
        let encoded_prefix = prefix.encode_key()?;

        let (encoded_range, raw_range_start): (_, V::Key) = if let Some(skip_until) = skip_until {
            if !skip_until.has_prefix(&prefix) {
                return Err(anyhow::anyhow!(
                    "cursor must have appropriate prefix {:?}, got {:?}",
                    prefix,
                    skip_until
                ));
            }
            let encoded_skip_until = skip_until.encode_key()?;
            (encoded_skip_until.clone().., skip_until.clone())
        } else {
            (encoded_prefix.clone().., prefix.clone())
        };

        let latest_version = self.latest_version()?;
        // Compared as options: a reader of the empty DB (`None`) is older than any committed
        // version. (Upstream compared `v > latest_version.unwrap_or(0)`, so a reader taken
        // before version 0 was committed iterated version 0's rows.)
        if version_on_disk > latest_version {
            return Err(anyhow::anyhow!(
                "Version on disk is newer than the latest version in the reader. Cannot create an iterator which is guaranteed to be consistent with the version of this storage."
            ));
        }
        // Setup: get a list of all the in-memory snapshots that are newer than the version on disk.
        // Our goal is to provide a consistent view of the state in this reader to the caller - so for each key that we discover we'll take the version from the newest snapshot,
        // looking at disk last. Ensuring we don't have any stale snapshots in our list makes this simpler.
        let snapshots: Vec<_> = self
            .snapshots
            .iter()
            .enumerate()
            .take_while(|(idx, _snapshot)| {
                let snapshot_version = latest_version.and_then(|v| v.checked_sub(*idx as u64));
                let Some(snapshot_version) = snapshot_version else {
                    return false;
                };
                if version_on_disk.is_some_and(|v| v >= snapshot_version) {
                    return false;
                }
                true
            })
            .map(|(_, snapshot)| {
                Some(
                    snapshot
                        .versioned_table_writes
                        .range(raw_range_start.clone()..)
                        .peekable(),
                )
            })
            .collect();

        let db_iterator = Some(
            self.db
                .live_db
                .iter_range_allow_cached::<V>(&read_lock, encoded_range, ScanDirection::Forward)?
                .peekable(),
        );
        Ok(VersionedDbIterator {
            _read_lock: read_lock,
            snapshots,
            db_iterator,
            prefix,
            encoded_prefix,
            failed: false,
        })
    }

    /// Returns the latest value of a key in the reader: its newest write in the snapshots, else
    /// its value at the reader's base version.
    ///
    /// The snapshots hold every write after the base version, so a key they do not write keeps
    /// its base version's value: the live table's while the DB is still at the base version,
    /// else the archive's at the base version. (Upstream read the live table until the DB moved
    /// past the reader's newest version, on purpose: once another block of the same version as
    /// one of the snapshots was committed, from another fork, the reader read that block's
    /// writes as its own.) A reader built on the empty DB (no base version) reads only its
    /// snapshots.
    pub fn get_latest_borrowed(
        &self,
        key: &<V as Schema>::Key,
    ) -> anyhow::Result<Option<V::Value>> {
        // Checks that the reader's version fits.
        self.latest_version()?;
        for snapshot in self.snapshots.iter() {
            if let Some(value) = snapshot.versioned_table_writes.get(key) {
                return Ok(value.clone());
            }
        }
        let Some(base_version) = self.base_version else {
            return Ok(None);
        };
        // Whether the DB moved past the base version: the live table may then hold newer values
        // (also of another fork), and the base version's are in the archive.
        let moved = || {
            self.db
                .fetch_latest_committed_archival_version()
                .is_some_and(|v| v > base_version)
        };
        if moved() {
            tracing::trace!(
                base_version,
                "The DB moved past the reader's base version: reading the archive"
            );
            return Ok(self.get_historical_borrowed(key, base_version)?);
        }
        let live_value = self.db.get_live_value(key)?;
        // A commit during the live read: the read may be of the newer version.
        if moved() {
            tracing::trace!(
                base_version,
                "The DB moved past the reader's base version during the read: reading the archive"
            );
            Ok(self.get_historical_borrowed(key, base_version)?)
        } else {
            Ok(live_value)
        }
    }

    /// Returns the global latest value for the given key.
    pub fn get_latest_borrowed_unbound(
        &self,
        key: &<V as Schema>::Key,
    ) -> anyhow::Result<Option<V::Value>> {
        let live_table_version = self.db.get_committed_version_live_db()?;
        let latest_version = self.latest_version()?;
        // If the "live" table is ahead of this storage, fetch directly from the live table.
        let Some(latest_version) = latest_version else {
            return self.db.get_live_value(key);
        };
        if live_table_version.is_some_and(|v| v > latest_version) {
            return self.db.get_live_value(key);
        }
        // Otherwise, look through the snapshots
        for (idx, snapshot) in self.snapshots.iter().enumerate() {
            let snapshot_version = latest_version.saturating_sub(idx as u64);
            // If the snapshot is older than (or the same age as) the live table, we can stop looking.
            if live_table_version.is_some_and(|live_db_version| live_db_version >= snapshot_version)
            {
                break;
            }

            // Check the snapshot
            if let Some(value) = snapshot.versioned_table_writes.get(key) {
                return Ok(value.clone());
            }
        }
        // If we've looked through all the snapshots and not found the value, then the one in the db is newest. Take it.
        self.db.get_live_value(key)
    }

    /// Returns the value of a key in the historical column family as of the given version.
    pub fn get_historical_borrowed(
        &self,
        key: &<V as Schema>::Key,
        version: u64,
    ) -> Result<Option<V::Value>, HistoricalValueError> {
        let Some(newest_version) = self.latest_version()? else {
            return Err(HistoricalValueError::FutureVersion {
                requested_version: version,
                latest_version: None,
            });
        };
        if version > newest_version {
            return Err(HistoricalValueError::FutureVersion {
                requested_version: version,
                latest_version: Some(newest_version),
            });
        }

        let mut version_of_current_snapshot = newest_version;
        let mut must_have_been_last_iter = false;
        for snapshot in self.snapshots.iter() {
            assert!(
                !must_have_been_last_iter,
                "The number of snapshots is greater than the latest version + 1. This is a bug."
            );
            if version_of_current_snapshot > version {
                version_of_current_snapshot -= 1;
                continue;
            }
            if let Some(value) = snapshot.versioned_table_writes.get(key) {
                return Ok(value.clone());
            }
            version_of_current_snapshot = match version_of_current_snapshot.checked_sub(1) {
                Some(v) => v,
                None => {
                    must_have_been_last_iter = true;
                    0
                }
            };
        }
        // Not written by the snapshots up to `version`: the value at the base version if
        // `version` is after it (the snapshots hold every write after the base version; the DB's
        // rows after it may be another fork's, upstream read them), else at `version`. A reader
        // built on the empty DB reads only its snapshots.
        let Some(base_version) = self.base_version else {
            return Ok(None);
        };
        let db_version = version.min(base_version);
        let historical_value = self
            .db
            .get_historical_value_raw(key.as_ref().to_vec(), db_version)?;
        let oldest_available_version = self
            .db
            .get_pruned_version()?
            .and_then(|v| v.checked_add(1))
            .unwrap_or(0);
        if db_version < oldest_available_version {
            Err(HistoricalValueError::PrunedVersion {
                requested_version: db_version,
                oldest_available_version: Some(oldest_available_version),
            })
        } else {
            Ok(historical_value)
        }
    }
}

/// An error that occurs when querying for a historical value.
#[derive(Debug, thiserror::Error)]
pub enum HistoricalValueError {
    #[error(
        "The requested version {requested_version} is newer than the newest version in the reader {latest_version:?}"
    )]
    /// The requested version is newer than the latest version in the reader.
    FutureVersion {
        /// The requested version.
        requested_version: u64,
        /// The latest version in the reader.
        latest_version: Option<u64>,
    },
    #[error(
        "Version {requested_version} has been pruned. The oldest available version is {oldest_available_version:?}"
    )]
    /// The version to read in the database is older than the oldest available version.
    PrunedVersion {
        /// The version read in the database: the requested version, or, for a key that none of
        /// a reader's snapshots writes, the reader's base version if the requested one is newer
        /// (the key is read there, see `VersionedDeltaReader::get_historical_borrowed`).
        requested_version: u64,
        /// The oldest available version.
        oldest_available_version: Option<u64>,
    },
    /// Any other error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[cfg(feature = "test-utils")]
impl<V: SchemaWithVersion, C: CacheForVersionedDB<V>> VersionedDB<V, C>
where
    V::Key: Ord + Clone + std::hash::Hash + AsRef<[u8]>,
    V::Value: Clone + AsRef<[u8]>,
    V: Ord,
{
    /// This method is used nly for integration tests.
    /// Commits a batch of versioned writes to the database.
    pub fn commit(&self, batch: &VersionedSchemaBatch<V>, version: u64) -> anyhow::Result<()>
    where
        V::Value: AsRef<[u8]>,
        V::Key: AsRef<[u8]>,
    {
        // Update the next version to commit if relevant.
        // Block any readers while the DB isn't fully consistent
        let cache = self.versioned_db_cache.write();

        let mut live_db_batch = rocksdb::WriteBatch::default();
        let mut archival_db_batch = rocksdb::WriteBatch::default();

        let live_db = &self.live_db;
        let archival_db = &self.archival_db;

        Self::update_versioned_db_batch(
            &mut live_db_batch,
            &mut archival_db_batch,
            batch,
            version,
            &cache,
            live_db,
            archival_db,
            true,
        )?;

        crate::with_error_logging(
            || archival_db.write_opt(archival_db_batch, &crate::default_write_options()),
            "write_versioned_schemas::write_archival_opt",
        )?;

        // Danger: This function is coupled with `get_historical_value`.
        self.store_committed_archival_version(version);

        crate::with_error_logging(
            || live_db.write_opt(live_db_batch, &crate::default_write_options()),
            "write_versioned_schemas::write_live_opt",
        )?;

        drop(cache);

        Ok(())
    }

    /// Sets the cache size for the DB.
    pub fn set_cache_size(&self, estimated_size: usize, weight_capacity: u64) {
        *self.versioned_db_cache.write() =
            Cache::with_weighter(estimated_size, weight_capacity, BasicWeighter);
    }

    /// Returns the number of cache hits.
    pub fn cache_hits(&self) -> u64 {
        self.versioned_db_cache.read().hits()
    }

    /// Returns the number of cache misses.
    pub fn cache_misses(&self) -> u64 {
        self.versioned_db_cache.read().misses()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the on-disk key layouts: the free `encode_*` helpers used on the pruning
    /// path must stay byte-identical to `KeyWithVersionPrefixAndSuffix`, which defines
    /// the canonical archival (`key || version_be`) and pruning (`version_be || key`)
    /// layouts at write time. If either drifts, historical deletes and pruning-range
    /// bounds silently target the wrong bytes.
    #[test]
    fn encode_helpers_match_key_with_version_layout() {
        let cases: &[(&[u8], u64)] = &[
            (b"k", 0),
            (b"k", 1),
            (b"k", u64::MAX),
            (b"multi-byte-key", 42),
            (&[0xff, 0x00, 0xff], u64::MAX),
            (&[], 7),
        ];

        for &(key, version) in cases {
            let mut key_with_version = KeyWithVersionPrefixAndSuffix::new(version);
            key_with_version.set_key(key);

            assert_eq!(
                encode_archival_key(key, version),
                key_with_version.archival_key(),
                "archival layout mismatch for key={key:?} version={version}",
            );
            assert_eq!(
                encode_pruning_key(version, key),
                key_with_version.pruning_key(),
                "pruning layout mismatch for key={key:?} version={version}",
            );
            // `live_key` must round-trip the original key out of the shared buffer.
            assert_eq!(
                key_with_version.live_key(),
                key,
                "live_key round-trip mismatch for key={key:?} version={version}",
            );
        }
    }
}

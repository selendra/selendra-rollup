//! The RocksDB tables (rockbound schemas) of the state databases and their encodings.
//!
//! | Table | DB | Key | Value |
//! |---|---|---|---|
//! | [`NomtStateValues<User>`] / [`NomtStateValues<Kernel>`] | flat (live + archival) | the raw [`SlotKey`] bytes | the raw [`SlotValue`] bytes (archival rows tagged by rockbound) |
//! | [`StateRootHashes`] | flat live, flat archival, accessory | slot number, `u64` big-endian | the 64 root bytes `user ‖ kernel` ([`NomtRoots`]) |
//! | [`ModuleAccessoryState`] | accessory | borsh `Vec<u8>` key ‖ slot number `u64` big-endian | borsh `Option<Vec<u8>>` (`None`: deleted) |
//! | [`AccessoryKeysByVersion`] | accessory | slot number `u64` big-endian ‖ borsh `Vec<u8>` key | empty |
//! | [`DbMetadata`] | accessory | a [`MetadataKey`]'s name (ASCII) | its bytes (per key) |
//! | [`SlotByNumber`] | ledger | slot number | borsh [`StoredSlot`] |
//! | [`SlotByHash`] | ledger | DA block hash (32 bytes) | slot number |
//! | [`BatchByNumber`] / [`TxByNumber`] / [`EventByNumber`] / [`DiscardedBlobByNumber`] | ledger | item number | borsh [`StoredBatch`] / [`StoredTransaction`] / [`StoredEvent`] / [`StoredDiscardedBlob`] |
//! | [`BatchByHash`] / [`TxByHash`] / [`DiscardedBlobByHash`] | ledger | hash ‖ item number | empty |
//! | [`EventByKey`] | ledger | `u16` key length ‖ event key ‖ transaction number ‖ event number | empty |
//! | [`EventCountByKey`] | ledger | the raw event key | `u64` |
//! | [`AggregatedProofBySlot`] | ledger | slot number ‖ `u32` index | the proof bytes |
//! | [`ProofReceiptBySlot`] | ledger | slot number ‖ `u32` index | borsh `([u8; 32], Vec<u8>)`: blob hash, receipt |
//! | [`ProofReceiptByHash`] | ledger | blob hash ‖ slot number ‖ `u32` index | empty |
//! | [`StfInfoBySlot`] | ledger | slot number | the STF info bytes |
//!
//! Numbers in keys and values are big-endian (8 bytes for `u64`, 4 for `u32`), so byte order is
//! number order. Every decoder rejects bytes that are not exactly an encoding (wrong length,
//! trailing bytes, inverted ranges): stored data that does not decode is an error, never a
//! panic.

use core::fmt;
use core::marker::PhantomData;

use rockbound::schema::{ColumnFamilyName, KeyDecoder, KeyEncoder, ValueCodec};
use rockbound::versioned_db::SchemaWithVersion;
use rockbound::{CodecError, Schema, SeekKeyEncoder};
use selendra_interface::common::SlotNumber;
use selendra_interface::stf::{EventKey, StoredEvent};
use selendra_state::{Kernel, Prefix, ProvableCompileTimeNamespace, SlotKey, SlotValue, User};

use crate::ledger::{
    BatchNumber, DiscardedBlobNumber, EventNumber, StoredBatch, StoredDiscardedBlob, StoredSlot,
    StoredTransaction, TxNumber,
};
use crate::nomt_state::NomtRoots;

/// A provable namespace with its own versioned value table in the flat store: the four
/// column-family names rockbound's versioned DB uses for it.
///
/// Implemented for [`User`] and [`Kernel`]. (Upstream's `Namespace` trait; renamed, since
/// `selendra_state::Namespace` is the namespace enum. The column-family names are new: the chain
/// starts fresh, so upstream's legacy `*_jmt_values` names are not kept.)
pub trait VersionedNamespace: ProvableCompileTimeNamespace + Default {
    /// The live values (`key → value`), in the live DB.
    const STATE_VALUES_TABLE_NAME: ColumnFamilyName;
    /// The keys written per version (`version ‖ key`), in the archival DB.
    const PRUNING_COLUMN_FAMILY: ColumnFamilyName;
    /// The committed and pruned versions, in both DBs.
    const VERSION_METADATA_COLUMN: ColumnFamilyName;
    /// The values per version (`key ‖ version`), in the archival DB.
    const HISTORICAL_COLUMN_FAMILY: ColumnFamilyName;
}

impl VersionedNamespace for User {
    const STATE_VALUES_TABLE_NAME: ColumnFamilyName = "user_state_values";
    const PRUNING_COLUMN_FAMILY: ColumnFamilyName = "user_state_pruning";
    const VERSION_METADATA_COLUMN: ColumnFamilyName = "user_state_version_metadata";
    const HISTORICAL_COLUMN_FAMILY: ColumnFamilyName = "user_state_historical_values";
}

impl VersionedNamespace for Kernel {
    const STATE_VALUES_TABLE_NAME: ColumnFamilyName = "kernel_state_values";
    const PRUNING_COLUMN_FAMILY: ColumnFamilyName = "kernel_state_pruning";
    const VERSION_METADATA_COLUMN: ColumnFamilyName = "kernel_state_version_metadata";
    const HISTORICAL_COLUMN_FAMILY: ColumnFamilyName = "kernel_state_historical_values";
}

/// The versioned state values of namespace `N` in the flat store: [`SlotKey`] → [`SlotValue`].
///
/// The key and value codecs are no-ops (the raw bytes): rockbound writes `as_ref()` directly and
/// iterates by the encoded prefix, so the encoding must be the bytes themselves.
pub struct NomtStateValues<N>(PhantomData<fn() -> N>);

// Hand-written: derives would require the bounds on `N`, which is only a marker. rockbound needs
// `Clone`, `Debug`, `Default` and `Ord`.
impl<N> Clone for NomtStateValues<N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<N> Copy for NomtStateValues<N> {}

impl<N> Default for NomtStateValues<N> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<N> PartialEq for NomtStateValues<N> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<N> Eq for NomtStateValues<N> {}

impl<N> PartialOrd for NomtStateValues<N> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<N> Ord for NomtStateValues<N> {
    fn cmp(&self, _other: &Self) -> core::cmp::Ordering {
        core::cmp::Ordering::Equal
    }
}

impl<N: VersionedNamespace> fmt::Debug for NomtStateValues<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NomtStateValues({})", N::STATE_VALUES_TABLE_NAME)
    }
}

impl<N: VersionedNamespace> Schema for NomtStateValues<N> {
    const COLUMN_FAMILY_NAME: ColumnFamilyName = N::STATE_VALUES_TABLE_NAME;

    type Key = SlotKey;
    type Value = SlotValue;
}

impl<N: VersionedNamespace> SchemaWithVersion for NomtStateValues<N> {
    const HISTORICAL_COLUMN_FAMILY_NAME: ColumnFamilyName = N::HISTORICAL_COLUMN_FAMILY;
    const PRUNING_COLUMN_FAMILY_NAME: ColumnFamilyName = N::PRUNING_COLUMN_FAMILY;
    const VERSION_METADATA_COLUMN_FAMILY_NAME: ColumnFamilyName = N::VERSION_METADATA_COLUMN;
}

impl<N: VersionedNamespace> KeyEncoder<NomtStateValues<N>> for SlotKey {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.as_ref().to_vec())
    }
}

impl<N: VersionedNamespace> KeyDecoder<NomtStateValues<N>> for SlotKey {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        SlotKey::try_from_bytes(data).map_err(|e| CodecError::InvalidKeyLength {
            expected: Prefix::LENGTH,
            got: e.0,
        })
    }
}

impl<N: VersionedNamespace> ValueCodec<NomtStateValues<N>> for SlotValue {
    fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.as_ref().to_vec())
    }

    fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
        Ok(SlotValue::from(data.to_vec()))
    }
}

/// The length of an encoded slot number.
const SLOT_NUMBER_LEN: usize = 8;

fn encode_slot_number(slot: SlotNumber) -> [u8; SLOT_NUMBER_LEN] {
    slot.get().to_be_bytes()
}

fn decode_slot_number(data: &[u8]) -> Result<SlotNumber, CodecError> {
    let bytes: [u8; SLOT_NUMBER_LEN] =
        data.try_into().map_err(|_| CodecError::InvalidKeyLength {
            expected: SLOT_NUMBER_LEN,
            got: data.len(),
        })?;
    Ok(SlotNumber::new(u64::from_be_bytes(bytes)))
}

/// Defines a unit struct implementing [`Schema`] with the given column-family name.
macro_rules! define_table {
    ($(#[$docs:meta])* $name:ident, $cf:literal, $key:ty => $value:ty) => {
        $(#[$docs])*
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl Schema for $name {
            const COLUMN_FAMILY_NAME: ColumnFamilyName = $cf;
            type Key = $key;
            type Value = $value;
        }
    };
}

define_table!(
    /// The state root committed at each slot number. In the flat live and archival DBs and in
    /// the accessory DB, so each can tell which version it holds.
    StateRootHashes, "state_root_hashes", SlotNumber => NomtRoots
);

impl KeyEncoder<StateRootHashes> for SlotNumber {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        Ok(encode_slot_number(*self).to_vec())
    }
}

impl KeyDecoder<StateRootHashes> for SlotNumber {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        decode_slot_number(data)
    }
}

impl SeekKeyEncoder<StateRootHashes> for SlotNumber {
    fn encode_seek_key(&self) -> Result<Vec<u8>, CodecError> {
        <Self as KeyEncoder<StateRootHashes>>::encode_key(self)
    }
}

impl ValueCodec<StateRootHashes> for NomtRoots {
    fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.to_bytes().to_vec())
    }

    fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
        let bytes: [u8; NomtRoots::LENGTH] = data.try_into().map_err(|_| {
            CodecError::Wrapped(anyhow::anyhow!(
                "DB corruption: a state root must be {} bytes, got {}",
                NomtRoots::LENGTH,
                data.len()
            ))
        })?;
        Ok(NomtRoots::from_bytes(bytes))
    }
}

define_table!(
    /// Accessory state (not provable, for JSON-RPC): every version of every key.
    ///
    /// The key is borsh `Vec<u8>` (`u32` little-endian length, then the bytes) followed by the
    /// slot number big-endian, so the rows of one key are contiguous and ordered by version:
    /// [`AccessoryDb`](crate::AccessoryDb) reads with `get_prev` (the newest row at or below a
    /// version) and checks the key. Because of the length prefix, RocksDB order is not key
    /// order: prefix iteration over accessory keys is impossible with this layout.
    ModuleAccessoryState, "module_accessory_state", (Vec<u8>, SlotNumber) => Option<SlotValue>
);

define_table!(
    /// Index of the accessory keys written at each slot number (for rollback).
    AccessoryKeysByVersion, "accessory_keys_by_version", (SlotNumber, Vec<u8>) => ()
);

/// Appends borsh `Vec<u8>`: `u32` little-endian length, then the bytes.
fn encode_borsh_bytes(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), CodecError> {
    let len = u32::try_from(bytes.len()).map_err(|_| {
        CodecError::Wrapped(anyhow::anyhow!(
            "an accessory key is at most u32::MAX bytes, got {}",
            bytes.len()
        ))
    })?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Splits borsh `Vec<u8>` off the front of `data`.
fn decode_borsh_bytes(data: &[u8]) -> Result<(Vec<u8>, &[u8]), CodecError> {
    let invalid = || CodecError::Wrapped(anyhow::anyhow!("DB corruption: invalid accessory key"));
    let (len, rest) = data.split_first_chunk::<4>().ok_or_else(invalid)?;
    let len = usize::try_from(u32::from_le_bytes(*len)).map_err(|_| invalid())?;
    if rest.len() < len {
        return Err(invalid());
    }
    let (bytes, rest) = rest.split_at(len);
    Ok((bytes.to_vec(), rest))
}

impl<K: AsRef<[u8]> + fmt::Debug> KeyEncoder<ModuleAccessoryState> for (K, SlotNumber) {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        let key = self.0.as_ref();
        let mut out = Vec::with_capacity(4 + key.len() + SLOT_NUMBER_LEN);
        encode_borsh_bytes(key, &mut out)?;
        out.extend_from_slice(&encode_slot_number(self.1));
        Ok(out)
    }
}

impl<K: AsRef<[u8]> + fmt::Debug> SeekKeyEncoder<ModuleAccessoryState> for (K, SlotNumber) {
    fn encode_seek_key(&self) -> Result<Vec<u8>, CodecError> {
        <Self as KeyEncoder<ModuleAccessoryState>>::encode_key(self)
    }
}

impl KeyDecoder<ModuleAccessoryState> for (Vec<u8>, SlotNumber) {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        let (key, rest) = decode_borsh_bytes(data)?;
        Ok((key, decode_slot_number(rest)?))
    }
}

impl ValueCodec<ModuleAccessoryState> for Option<SlotValue> {
    fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
        borsh::to_vec(self).map_err(CodecError::from)
    }

    fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
        // `from_slice` rejects trailing bytes.
        borsh::from_slice(data).map_err(CodecError::from)
    }
}

impl<K: AsRef<[u8]> + fmt::Debug> KeyEncoder<AccessoryKeysByVersion> for (SlotNumber, K) {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        let key = self.1.as_ref();
        let mut out = Vec::with_capacity(SLOT_NUMBER_LEN + 4 + key.len());
        out.extend_from_slice(&encode_slot_number(self.0));
        encode_borsh_bytes(key, &mut out)?;
        Ok(out)
    }
}

impl<K: AsRef<[u8]> + fmt::Debug> SeekKeyEncoder<AccessoryKeysByVersion> for (SlotNumber, K) {
    fn encode_seek_key(&self) -> Result<Vec<u8>, CodecError> {
        <Self as KeyEncoder<AccessoryKeysByVersion>>::encode_key(self)
    }
}

impl KeyDecoder<AccessoryKeysByVersion> for (SlotNumber, Vec<u8>) {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        let (slot, rest) =
            data.split_at_checked(SLOT_NUMBER_LEN)
                .ok_or(CodecError::InvalidKeyLength {
                    expected: SLOT_NUMBER_LEN,
                    got: data.len(),
                })?;
        let (key, rest) = decode_borsh_bytes(rest)?;
        if !rest.is_empty() {
            return Err(CodecError::Wrapped(anyhow::anyhow!(
                "DB corruption: {} trailing bytes after an accessory key",
                rest.len()
            )));
        }
        Ok((decode_slot_number(slot)?, key))
    }
}

impl ValueCodec<AccessoryKeysByVersion> for () {
    fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
        Ok(Vec::new())
    }

    fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
        if data.is_empty() {
            Ok(())
        } else {
            Err(CodecError::Wrapped(anyhow::anyhow!(
                "DB corruption: an accessory index row must be empty, got {} bytes",
                data.len()
            )))
        }
    }
}

define_table!(
    /// Facts about the state databases as a whole, one row per [`MetadataKey`] (not versioned:
    /// written outside the commits, never rolled back).
    DbMetadata, "db_metadata", MetadataKey => Vec<u8>
);

/// A row of [`DbMetadata`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataKey {
    /// The tag of the hasher `H` the state databases were created with:
    /// `H(b"SELENDRA/state-hasher/v1")` (32 bytes), written by the first
    /// [`DbGroup::open`](crate::DbGroup::open) of empty databases and checked by every later
    /// one.
    StateHasher,
}

impl MetadataKey {
    /// Every key (decoding looks the stored name up here).
    const ALL: [Self; 1] = [Self::StateHasher];

    /// The stored key bytes.
    fn name(self) -> &'static [u8] {
        match self {
            Self::StateHasher => b"state_hasher",
        }
    }
}

impl KeyEncoder<DbMetadata> for MetadataKey {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.name().to_vec())
    }
}

impl KeyDecoder<DbMetadata> for MetadataKey {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        Self::ALL
            .into_iter()
            .find(|key| key.name() == data)
            .ok_or_else(|| {
                CodecError::Wrapped(anyhow::anyhow!(
                    "DB corruption: unknown metadata key {:?}",
                    String::from_utf8_lossy(data)
                ))
            })
    }
}

impl ValueCodec<DbMetadata> for Vec<u8> {
    fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.clone())
    }

    fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
        Ok(data.to_vec())
    }
}

/// The tables of the accessory DB.
pub(crate) const ACCESSORY_TABLES: [ColumnFamilyName; 4] = [
    ModuleAccessoryState::COLUMN_FAMILY_NAME,
    AccessoryKeysByVersion::COLUMN_FAMILY_NAME,
    StateRootHashes::COLUMN_FAMILY_NAME,
    DbMetadata::COLUMN_FAMILY_NAME,
];

// ---------------------------------------------------------------------------------------------
// The ledger DB.

/// The longest event key the ledger stores, in bytes. Longer keys are refused (`Err`) when a
/// slot is materialized and by the key encoders, so `event_by_key` keys stay exact-length
/// prefixed (a `u16`).
pub const MAX_EVENT_KEY_LEN: usize = 256;

/// The length of an encoded hash.
const HASH_LEN: usize = 32;

/// An encoded `u64`, big-endian (so byte order is number order).
fn encode_u64(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

/// Splits a big-endian `u64` off the front of `data`.
fn take_u64(data: &[u8]) -> Result<(u64, &[u8]), CodecError> {
    let (bytes, rest) = data
        .split_first_chunk::<8>()
        .ok_or(CodecError::InvalidKeyLength {
            expected: 8,
            got: data.len(),
        })?;
    Ok((u64::from_be_bytes(*bytes), rest))
}

/// Splits a 32-byte hash off the front of `data`.
fn take_hash(data: &[u8]) -> Result<([u8; HASH_LEN], &[u8]), CodecError> {
    let (bytes, rest) =
        data.split_first_chunk::<HASH_LEN>()
            .ok_or(CodecError::InvalidKeyLength {
                expected: HASH_LEN,
                got: data.len(),
            })?;
    Ok((*bytes, rest))
}

/// Splits a big-endian `u32` off the front of `data`.
fn take_u32(data: &[u8]) -> Result<(u32, &[u8]), CodecError> {
    let (bytes, rest) = data
        .split_first_chunk::<4>()
        .ok_or(CodecError::InvalidKeyLength {
            expected: 4,
            got: data.len(),
        })?;
    Ok((u32::from_be_bytes(*bytes), rest))
}

/// Fails unless the whole key was decoded.
fn ensure_consumed(rest: &[u8], expected: usize, got: usize) -> Result<(), CodecError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(CodecError::InvalidKeyLength { expected, got })
    }
}

/// Fails if an event key is longer than [`MAX_EVENT_KEY_LEN`].
fn check_event_key_len(len: usize) -> Result<(), CodecError> {
    if len > MAX_EVENT_KEY_LEN {
        return Err(CodecError::Wrapped(anyhow::anyhow!(
            "an event key is at most {MAX_EVENT_KEY_LEN} bytes, got {len}"
        )));
    }
    Ok(())
}

/// Decodes borsh, rejecting trailing bytes (upstream's `deserialize_reader` ignored them).
fn decode_borsh<T: borsh::BorshDeserialize>(data: &[u8]) -> Result<T, CodecError> {
    borsh::from_slice(data).map_err(CodecError::from)
}

/// Implements the key codecs of a table keyed by a `u64` number type (`new`/`get`), 8 bytes
/// big-endian.
macro_rules! number_key {
    ($table:ty, $number:ty) => {
        impl KeyEncoder<$table> for $number {
            fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
                Ok(encode_u64(self.get()).to_vec())
            }
        }

        impl KeyDecoder<$table> for $number {
            fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
                let (n, rest) = take_u64(data)?;
                ensure_consumed(rest, 8, data.len())?;
                Ok(<$number>::new(n))
            }
        }

        impl SeekKeyEncoder<$table> for $number {
            fn encode_seek_key(&self) -> Result<Vec<u8>, CodecError> {
                <Self as KeyEncoder<$table>>::encode_key(self)
            }
        }
    };
}

/// Implements the key codecs of an index keyed by `hash ‖ number` (32 + 8 bytes).
macro_rules! hash_number_key {
    ($table:ty, $number:ty) => {
        impl KeyEncoder<$table> for ([u8; HASH_LEN], $number) {
            fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
                let mut out = Vec::with_capacity(HASH_LEN + 8);
                out.extend_from_slice(&self.0);
                out.extend_from_slice(&encode_u64(self.1.get()));
                Ok(out)
            }
        }

        impl KeyDecoder<$table> for ([u8; HASH_LEN], $number) {
            fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
                let (hash, rest) = take_hash(data)?;
                let (n, rest) = take_u64(rest)?;
                ensure_consumed(rest, HASH_LEN + 8, data.len())?;
                Ok((hash, <$number>::new(n)))
            }
        }

        impl SeekKeyEncoder<$table> for ([u8; HASH_LEN], $number) {
            fn encode_seek_key(&self) -> Result<Vec<u8>, CodecError> {
                <Self as KeyEncoder<$table>>::encode_key(self)
            }
        }
    };
}

/// Implements the empty value codec of an index table.
macro_rules! empty_value {
    ($table:ty) => {
        impl ValueCodec<$table> for () {
            fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
                Ok(Vec::new())
            }

            fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
                if data.is_empty() {
                    Ok(())
                } else {
                    Err(CodecError::Wrapped(anyhow::anyhow!(
                        "DB corruption: an index row must be empty, got {} bytes",
                        data.len()
                    )))
                }
            }
        }
    };
}

/// Implements a borsh value codec (strict: no trailing bytes), checking the decoded value with
/// `$check` (`fn(&T) -> anyhow::Result<()>`).
macro_rules! borsh_value {
    ($table:ty, $value:ty $(, $check:path)?) => {
        impl ValueCodec<$table> for $value {
            fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
                borsh::to_vec(self).map_err(CodecError::from)
            }

            fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
                let value: $value = decode_borsh(data)?;
                $($check(&value).map_err(CodecError::Wrapped)?;)?
                Ok(value)
            }
        }
    };
}

/// Implements a raw-bytes value codec (the value is the bytes).
macro_rules! bytes_value {
    ($table:ty) => {
        impl ValueCodec<$table> for Vec<u8> {
            fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
                Ok(self.clone())
            }

            fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
                Ok(data.to_vec())
            }
        }
    };
}

/// Implements the key codecs of a table keyed by `slot ‖ u32 index` (8 + 4 bytes).
macro_rules! slot_index_key {
    ($table:ty) => {
        impl KeyEncoder<$table> for (SlotNumber, u32) {
            fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
                let mut out = Vec::with_capacity(SLOT_NUMBER_LEN + 4);
                out.extend_from_slice(&encode_slot_number(self.0));
                out.extend_from_slice(&self.1.to_be_bytes());
                Ok(out)
            }
        }

        impl KeyDecoder<$table> for (SlotNumber, u32) {
            fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
                let (slot, rest) = take_u64(data)?;
                let (index, rest) = take_u32(rest)?;
                ensure_consumed(rest, SLOT_NUMBER_LEN + 4, data.len())?;
                Ok((SlotNumber::new(slot), index))
            }
        }

        impl SeekKeyEncoder<$table> for (SlotNumber, u32) {
            fn encode_seek_key(&self) -> Result<Vec<u8>, CodecError> {
                <Self as KeyEncoder<$table>>::encode_key(self)
            }
        }
    };
}

define_table!(
    /// The ledger's slots by slot number. The largest is the ledger's newest slot: its version
    /// (the state version it was committed with) and roots.
    SlotByNumber, "slot_by_number", SlotNumber => StoredSlot
);
number_key!(SlotByNumber, SlotNumber);
borsh_value!(SlotByNumber, StoredSlot, StoredSlot::check);

define_table!(
    /// The slot of each DA block hash (unique on a chain).
    SlotByHash, "slot_by_hash", [u8; 32] => SlotNumber
);

impl KeyEncoder<SlotByHash> for [u8; HASH_LEN] {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        Ok(self.to_vec())
    }
}

impl KeyDecoder<SlotByHash> for [u8; HASH_LEN] {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        data.try_into().map_err(|_| CodecError::InvalidKeyLength {
            expected: HASH_LEN,
            got: data.len(),
        })
    }
}

impl ValueCodec<SlotByHash> for SlotNumber {
    fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
        Ok(encode_slot_number(*self).to_vec())
    }

    fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
        decode_slot_number(data)
    }
}

define_table!(
    /// The ledger's batches by number.
    BatchByNumber, "batch_by_number", BatchNumber => StoredBatch
);
number_key!(BatchByNumber, BatchNumber);
borsh_value!(BatchByNumber, StoredBatch, StoredBatch::check);

define_table!(
    /// Index of the batches by hash: `hash ‖ number` (several batches may have one hash;
    /// upstream keyed by the hash alone, so a repeated hash overwrote the older row).
    BatchByHash, "batch_by_hash", ([u8; 32], BatchNumber) => ()
);
hash_number_key!(BatchByHash, BatchNumber);
empty_value!(BatchByHash);

define_table!(
    /// The ledger's transactions by number.
    TxByNumber, "tx_by_number", TxNumber => StoredTransaction
);
number_key!(TxByNumber, TxNumber);
borsh_value!(TxByNumber, StoredTransaction, StoredTransaction::check);

define_table!(
    /// Index of the transactions by hash: `hash ‖ number`.
    TxByHash, "tx_by_hash", ([u8; 32], TxNumber) => ()
);
hash_number_key!(TxByHash, TxNumber);
empty_value!(TxByHash);

define_table!(
    /// The ledger's events by number.
    EventByNumber, "event_by_number", EventNumber => StoredEvent
);
number_key!(EventByNumber, EventNumber);
borsh_value!(EventByNumber, StoredEvent);

define_table!(
    /// Index of the events by key: `u16 length ‖ key ‖ transaction number ‖ event number`, so
    /// the events of one key are contiguous and ordered by transaction (exact-key scans; the
    /// length prefix rules out key-prefix scans, which `event_count_by_key` serves).
    EventByKey, "event_by_key", (EventKey, TxNumber, EventNumber) => ()
);

impl KeyEncoder<EventByKey> for (EventKey, TxNumber, EventNumber) {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        let key = self.0.inner();
        check_event_key_len(key.len())?;
        let len = u16::try_from(key.len()).map_err(|_| CodecError::InvalidKeyLength {
            expected: MAX_EVENT_KEY_LEN,
            got: key.len(),
        })?;
        let mut out = Vec::with_capacity(2 + key.len() + 16);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&encode_u64(self.1.get()));
        out.extend_from_slice(&encode_u64(self.2.get()));
        Ok(out)
    }
}

impl KeyDecoder<EventByKey> for (EventKey, TxNumber, EventNumber) {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        let (len, rest) = data
            .split_first_chunk::<2>()
            .ok_or(CodecError::InvalidKeyLength {
                expected: 2,
                got: data.len(),
            })?;
        let len = usize::from(u16::from_be_bytes(*len));
        check_event_key_len(len)?;
        let (key, rest) = rest
            .split_at_checked(len)
            .ok_or(CodecError::InvalidKeyLength {
                expected: 2 + len,
                got: data.len(),
            })?;
        let (tx, rest) = take_u64(rest)?;
        let (event, rest) = take_u64(rest)?;
        ensure_consumed(rest, 2 + len + 16, data.len())?;
        Ok((
            EventKey::new(key),
            TxNumber::new(tx),
            EventNumber::new(event),
        ))
    }
}

impl SeekKeyEncoder<EventByKey> for (EventKey, TxNumber, EventNumber) {
    fn encode_seek_key(&self) -> Result<Vec<u8>, CodecError> {
        <Self as KeyEncoder<EventByKey>>::encode_key(self)
    }
}

empty_value!(EventByKey);

define_table!(
    /// How many events of each key the ledger holds. The key is the raw event-key bytes, so
    /// the rows are in key order (a key-prefix scan finds every key with a prefix); the value
    /// is a `u64` big-endian. A key whose count drops to 0 has no row.
    EventCountByKey, "event_count_by_key", EventKey => u64
);

impl KeyEncoder<EventCountByKey> for EventKey {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        check_event_key_len(self.inner().len())?;
        Ok(self.inner().clone())
    }
}

impl KeyDecoder<EventCountByKey> for EventKey {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        check_event_key_len(data.len())?;
        Ok(EventKey::new(data))
    }
}

impl SeekKeyEncoder<EventCountByKey> for EventKey {
    fn encode_seek_key(&self) -> Result<Vec<u8>, CodecError> {
        <Self as KeyEncoder<EventCountByKey>>::encode_key(self)
    }
}

impl ValueCodec<EventCountByKey> for u64 {
    fn encode_value(&self) -> Result<Vec<u8>, CodecError> {
        Ok(encode_u64(*self).to_vec())
    }

    fn decode_value(data: &[u8]) -> Result<Self, CodecError> {
        let bytes: [u8; 8] = data.try_into().map_err(|_| {
            CodecError::Wrapped(anyhow::anyhow!(
                "DB corruption: an event count must be 8 bytes, got {}",
                data.len()
            ))
        })?;
        Ok(u64::from_be_bytes(bytes))
    }
}

define_table!(
    /// The ledger's discarded blobs by number.
    DiscardedBlobByNumber, "discarded_blob_by_number", DiscardedBlobNumber => StoredDiscardedBlob
);
number_key!(DiscardedBlobByNumber, DiscardedBlobNumber);
borsh_value!(DiscardedBlobByNumber, StoredDiscardedBlob);

define_table!(
    /// Index of the discarded blobs by hash: `hash ‖ number` (upstream keyed the blobs
    /// themselves by hash, so a repeated hash overwrote the older blob).
    DiscardedBlobByHash, "discarded_blob_by_hash", ([u8; 32], DiscardedBlobNumber) => ()
);
hash_number_key!(DiscardedBlobByHash, DiscardedBlobNumber);
empty_value!(DiscardedBlobByHash);

define_table!(
    /// The aggregated proofs accepted in each slot, by `slot ‖ u32 index` (opaque bytes;
    /// upstream kept a single proof, always at id 0, which a rollback never removed).
    AggregatedProofBySlot, "aggregated_proof_by_slot", (SlotNumber, u32) => Vec<u8>
);
slot_index_key!(AggregatedProofBySlot);
bytes_value!(AggregatedProofBySlot);

define_table!(
    /// The proof receipts of each slot, by `slot ‖ u32 index`: the proof blob's hash and the
    /// receipt (borsh `([u8; 32], Vec<u8>)`; the receipt is opaque bytes).
    ProofReceiptBySlot, "proof_receipt_by_slot", (SlotNumber, u32) => ([u8; 32], Vec<u8>)
);
slot_index_key!(ProofReceiptBySlot);
borsh_value!(ProofReceiptBySlot, ([u8; 32], Vec<u8>));

define_table!(
    /// Index of the proof receipts by proof blob hash: `hash ‖ slot ‖ u32 index`.
    ProofReceiptByHash, "proof_receipt_by_hash", ([u8; 32], SlotNumber, u32) => ()
);

impl KeyEncoder<ProofReceiptByHash> for ([u8; HASH_LEN], SlotNumber, u32) {
    fn encode_key(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::with_capacity(HASH_LEN + SLOT_NUMBER_LEN + 4);
        out.extend_from_slice(&self.0);
        out.extend_from_slice(&encode_slot_number(self.1));
        out.extend_from_slice(&self.2.to_be_bytes());
        Ok(out)
    }
}

impl KeyDecoder<ProofReceiptByHash> for ([u8; HASH_LEN], SlotNumber, u32) {
    fn decode_key(data: &[u8]) -> Result<Self, CodecError> {
        let (hash, rest) = take_hash(data)?;
        let (slot, rest) = take_u64(rest)?;
        let (index, rest) = take_u32(rest)?;
        ensure_consumed(rest, HASH_LEN + SLOT_NUMBER_LEN + 4, data.len())?;
        Ok((hash, SlotNumber::new(slot), index))
    }
}

impl SeekKeyEncoder<ProofReceiptByHash> for ([u8; HASH_LEN], SlotNumber, u32) {
    fn encode_seek_key(&self) -> Result<Vec<u8>, CodecError> {
        <Self as KeyEncoder<ProofReceiptByHash>>::encode_key(self)
    }
}

empty_value!(ProofReceiptByHash);

define_table!(
    /// The STF info of each slot (opaque bytes).
    StfInfoBySlot, "stf_info_by_slot", SlotNumber => Vec<u8>
);
number_key!(StfInfoBySlot, SlotNumber);
bytes_value!(StfInfoBySlot);

/// The tables of the ledger DB.
pub(crate) const LEDGER_TABLES: [ColumnFamilyName; 15] = [
    SlotByNumber::COLUMN_FAMILY_NAME,
    SlotByHash::COLUMN_FAMILY_NAME,
    BatchByNumber::COLUMN_FAMILY_NAME,
    BatchByHash::COLUMN_FAMILY_NAME,
    TxByNumber::COLUMN_FAMILY_NAME,
    TxByHash::COLUMN_FAMILY_NAME,
    EventByNumber::COLUMN_FAMILY_NAME,
    EventByKey::COLUMN_FAMILY_NAME,
    EventCountByKey::COLUMN_FAMILY_NAME,
    DiscardedBlobByNumber::COLUMN_FAMILY_NAME,
    DiscardedBlobByHash::COLUMN_FAMILY_NAME,
    AggregatedProofBySlot::COLUMN_FAMILY_NAME,
    ProofReceiptBySlot::COLUMN_FAMILY_NAME,
    ProofReceiptByHash::COLUMN_FAMILY_NAME,
    StfInfoBySlot::COLUMN_FAMILY_NAME,
];

#[cfg(test)]
mod tests {
    use super::*;

    type UserValues = NomtStateValues<User>;

    #[test]
    fn column_family_names_are_distinct() {
        let mut names = vec![
            <NomtStateValues<User> as Schema>::COLUMN_FAMILY_NAME,
            <NomtStateValues<User> as SchemaWithVersion>::HISTORICAL_COLUMN_FAMILY_NAME,
            <NomtStateValues<User> as SchemaWithVersion>::PRUNING_COLUMN_FAMILY_NAME,
            <NomtStateValues<User> as SchemaWithVersion>::VERSION_METADATA_COLUMN_FAMILY_NAME,
            <NomtStateValues<Kernel> as Schema>::COLUMN_FAMILY_NAME,
            <NomtStateValues<Kernel> as SchemaWithVersion>::HISTORICAL_COLUMN_FAMILY_NAME,
            <NomtStateValues<Kernel> as SchemaWithVersion>::PRUNING_COLUMN_FAMILY_NAME,
            <NomtStateValues<Kernel> as SchemaWithVersion>::VERSION_METADATA_COLUMN_FAMILY_NAME,
        ];
        names.extend(ACCESSORY_TABLES);
        names.extend(LEDGER_TABLES);
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn state_value_codecs_are_the_raw_bytes() {
        let key = SlotKey::try_from_bytes(&[1, 2, 3]).unwrap();
        assert_eq!(
            <SlotKey as KeyEncoder<UserValues>>::encode_key(&key).unwrap(),
            [1, 2, 3]
        );
        assert_eq!(
            <SlotKey as KeyDecoder<UserValues>>::decode_key(&[1, 2, 3]).unwrap(),
            key
        );
        assert!(<SlotKey as KeyDecoder<UserValues>>::decode_key(&[1]).is_err());
        let value = SlotValue::from(vec![]);
        assert!(
            <SlotValue as ValueCodec<UserValues>>::encode_value(&value)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            <SlotValue as ValueCodec<UserValues>>::decode_value(&[]).unwrap(),
            value
        );
    }

    #[test]
    fn root_hash_table_encoding() {
        let slot = SlotNumber::new(0x0102);
        let encoded = <SlotNumber as KeyEncoder<StateRootHashes>>::encode_key(&slot).unwrap();
        assert_eq!(encoded, [0, 0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(
            <SlotNumber as KeyDecoder<StateRootHashes>>::decode_key(&encoded).unwrap(),
            slot
        );
        assert!(<SlotNumber as KeyDecoder<StateRootHashes>>::decode_key(&encoded[1..]).is_err());
        assert!(<SlotNumber as KeyDecoder<StateRootHashes>>::decode_key(&[0; 9]).is_err());

        let roots = NomtRoots {
            user: [1; 32],
            kernel: [2; 32],
        };
        let bytes = roots.encode_value().unwrap();
        assert_eq!(bytes, [[1u8; 32], [2; 32]].concat());
        assert_eq!(NomtRoots::decode_value(&bytes).unwrap(), roots);
        assert!(NomtRoots::decode_value(&bytes[1..]).is_err());
        assert!(NomtRoots::decode_value(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn accessory_key_encodings_are_pinned() {
        let key = (b"ab".to_vec(), SlotNumber::new(3));
        let encoded = <_ as KeyEncoder<ModuleAccessoryState>>::encode_key(&key).unwrap();
        assert_eq!(encoded, [2, 0, 0, 0, b'a', b'b', 0, 0, 0, 0, 0, 0, 0, 3]);
        assert_eq!(
            <(Vec<u8>, SlotNumber) as KeyDecoder<ModuleAccessoryState>>::decode_key(&encoded)
                .unwrap(),
            key
        );
        for bad in [
            &encoded[..13],
            &[encoded.as_slice(), &[0]].concat(),
            &[9, 0, 0, 0],
        ] {
            assert!(
                <(Vec<u8>, SlotNumber) as KeyDecoder<ModuleAccessoryState>>::decode_key(bad)
                    .is_err()
            );
        }

        let index = (SlotNumber::new(3), b"ab".to_vec());
        let encoded = <_ as KeyEncoder<AccessoryKeysByVersion>>::encode_key(&index).unwrap();
        assert_eq!(encoded, [0, 0, 0, 0, 0, 0, 0, 3, 2, 0, 0, 0, b'a', b'b']);
        assert_eq!(
            <(SlotNumber, Vec<u8>) as KeyDecoder<AccessoryKeysByVersion>>::decode_key(&encoded)
                .unwrap(),
            index
        );
        for bad in [
            &encoded[..13],
            &[encoded.as_slice(), &[0]].concat(),
            &encoded[..7],
        ] {
            assert!(
                <(SlotNumber, Vec<u8>) as KeyDecoder<AccessoryKeysByVersion>>::decode_key(bad)
                    .is_err()
            );
        }
        assert!(<() as ValueCodec<AccessoryKeysByVersion>>::decode_value(&[0]).is_err());
    }

    #[test]
    fn metadata_key_encoding_is_pinned() {
        let encoded = <_ as KeyEncoder<DbMetadata>>::encode_key(&MetadataKey::StateHasher).unwrap();
        assert_eq!(encoded, b"state_hasher");
        for key in MetadataKey::ALL {
            let encoded = <_ as KeyEncoder<DbMetadata>>::encode_key(&key).unwrap();
            assert_eq!(
                <MetadataKey as KeyDecoder<DbMetadata>>::decode_key(&encoded).unwrap(),
                key
            );
        }
        for bad in [&b"state_hashe"[..], b"state_hasher\0", b""] {
            assert!(<MetadataKey as KeyDecoder<DbMetadata>>::decode_key(bad).is_err());
        }
        let value = vec![1, 2, 3];
        assert_eq!(
            <Vec<u8> as ValueCodec<DbMetadata>>::encode_value(&value).unwrap(),
            value
        );
        assert_eq!(
            <Vec<u8> as ValueCodec<DbMetadata>>::decode_value(&value).unwrap(),
            value
        );
    }

    fn hex(bytes: &[u8]) -> String {
        selendra_interface::common::HexString(bytes).to_string()
    }

    /// The ledger's key bytes (big-endian numbers: byte order is number order) and value bytes,
    /// pinned against bytes computed with Python's `struct` (`<` borsh little-endian, `>` key
    /// big-endian).
    #[test]
    fn ledger_encodings_are_pinned() {
        let n = 0x0102;
        let be = [0, 0, 0, 0, 0, 0, 1, 2];
        assert_eq!(
            <_ as KeyEncoder<SlotByNumber>>::encode_key(&SlotNumber::new(n)).unwrap(),
            be
        );
        assert_eq!(
            <_ as KeyEncoder<StfInfoBySlot>>::encode_key(&SlotNumber::new(n)).unwrap(),
            be
        );
        assert_eq!(
            <_ as KeyEncoder<BatchByNumber>>::encode_key(&BatchNumber::new(n)).unwrap(),
            be
        );
        assert_eq!(
            <_ as KeyEncoder<TxByNumber>>::encode_key(&TxNumber::new(n)).unwrap(),
            be
        );
        assert_eq!(
            <_ as KeyEncoder<EventByNumber>>::encode_key(&EventNumber::new(n)).unwrap(),
            be
        );
        assert_eq!(
            <_ as KeyEncoder<DiscardedBlobByNumber>>::encode_key(&DiscardedBlobNumber::new(n))
                .unwrap(),
            be
        );
        let hash = [0xAB; 32];
        assert_eq!(
            <_ as KeyEncoder<SlotByHash>>::encode_key(&hash).unwrap(),
            hash
        );
        assert_eq!(
            <SlotNumber as ValueCodec<SlotByHash>>::encode_value(&SlotNumber::new(n)).unwrap(),
            be
        );
        let hash_then_be = [hash.as_slice(), &be].concat();
        assert_eq!(
            <_ as KeyEncoder<BatchByHash>>::encode_key(&(hash, BatchNumber::new(n))).unwrap(),
            hash_then_be
        );
        assert_eq!(
            <_ as KeyEncoder<TxByHash>>::encode_key(&(hash, TxNumber::new(n))).unwrap(),
            hash_then_be
        );
        assert_eq!(
            <_ as KeyEncoder<DiscardedBlobByHash>>::encode_key(&(
                hash,
                DiscardedBlobNumber::new(n)
            ))
            .unwrap(),
            hash_then_be
        );
        assert_eq!(
            hex(&<_ as KeyEncoder<EventByKey>>::encode_key(&(
                EventKey::new(b"ab"),
                TxNumber::new(1),
                EventNumber::new(2)
            ))
            .unwrap()),
            "0x0002616200000000000000010000000000000002"
        );
        assert_eq!(
            <_ as KeyEncoder<EventCountByKey>>::encode_key(&EventKey::new(b"ab")).unwrap(),
            b"ab"
        );
        assert_eq!(
            <u64 as ValueCodec<EventCountByKey>>::encode_value(&n).unwrap(),
            be
        );
        let slot_index = [0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 4, 5];
        assert_eq!(
            <_ as KeyEncoder<AggregatedProofBySlot>>::encode_key(&(SlotNumber::new(3), 0x0405))
                .unwrap(),
            slot_index
        );
        assert_eq!(
            <_ as KeyEncoder<ProofReceiptBySlot>>::encode_key(&(SlotNumber::new(3), 0x0405))
                .unwrap(),
            slot_index
        );
        assert_eq!(
            hex(&<_ as KeyEncoder<ProofReceiptByHash>>::encode_key(&(
                hash,
                SlotNumber::new(3),
                0x0405
            ))
            .unwrap()),
            "0xabababababababababababababababababababababababababababababababab000000000000000300000405"
        );
        assert_eq!(
            hex(&<_ as ValueCodec<ProofReceiptBySlot>>::encode_value(&([1; 32], vec![9])).unwrap()),
            "0x01010101010101010101010101010101010101010101010101010101010101010100000009"
        );
        assert_eq!(
            <Vec<u8> as ValueCodec<AggregatedProofBySlot>>::encode_value(&vec![7, 8]).unwrap(),
            [7, 8]
        );

        let slot = StoredSlot {
            da_hash: [0x11; 32],
            da_height: n,
            roots: NomtRoots {
                user: [0x22; 32],
                kernel: [0x33; 32],
            },
            timestamp: selendra_interface::da::Time::from_millis(-2),
            batches: BatchNumber::new(1)..BatchNumber::new(2),
            txs: TxNumber::new(3)..TxNumber::new(4),
            events: EventNumber::new(5)..EventNumber::new(6),
            discarded_blobs: DiscardedBlobNumber::new(7)..DiscardedBlobNumber::new(8),
        };
        let bytes = <_ as ValueCodec<SlotByNumber>>::encode_value(&slot).unwrap();
        assert_eq!(
            hex(&bytes),
            "0x1111111111111111111111111111111111111111111111111111111111111111020100000000000022\
             222222222222222222222222222222222222222222222222222222222222223333333333333333333333\
             333333333333333333333333333333333333333333feffffffffffffff01000000000000000200000000\
             000000030000000000000004000000000000000500000000000000060000000000000007000000000000\
             000800000000000000"
        );
        assert_eq!(
            <StoredSlot as ValueCodec<SlotByNumber>>::decode_value(&bytes).unwrap(),
            slot
        );
        let tx = StoredTransaction {
            hash: [0x44; 32],
            events: EventNumber::new(1)..EventNumber::new(3),
            body: Some(vec![0xAA]),
            receipt: vec![0xBB, 0xCC],
            batch: BatchNumber::new(9),
        };
        assert_eq!(
            hex(&<_ as ValueCodec<TxByNumber>>::encode_value(&tx).unwrap()),
            "0x4444444444444444444444444444444444444444444444444444444444444444010000000000000003\
             000000000000000101000000aa02000000bbcc0900000000000000"
        );
    }

    #[test]
    fn accessory_value_encoding() {
        let value = Some(SlotValue::from(vec![7]));
        let encoded = <_ as ValueCodec<ModuleAccessoryState>>::encode_value(&value).unwrap();
        assert_eq!(encoded, [1, 1, 0, 0, 0, 7]);
        assert_eq!(
            <Option<SlotValue> as ValueCodec<ModuleAccessoryState>>::decode_value(&encoded)
                .unwrap(),
            value
        );
        assert_eq!(
            <Option<SlotValue> as ValueCodec<ModuleAccessoryState>>::decode_value(&[0]).unwrap(),
            None
        );
        assert!(
            <Option<SlotValue> as ValueCodec<ModuleAccessoryState>>::decode_value(&[0, 0]).is_err()
        );
    }
}

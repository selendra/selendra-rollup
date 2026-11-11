//! The RocksDB tables (rockbound schemas) of the state databases and their encodings.
//!
//! | Table | DB | Key | Value |
//! |---|---|---|---|
//! | [`NomtStateValues<User>`] / [`NomtStateValues<Kernel>`] | flat (live + archival) | the raw [`SlotKey`] bytes | the raw [`SlotValue`] bytes (archival rows tagged by rockbound) |
//! | [`StateRootHashes`] | flat live, flat archival, accessory | slot number, `u64` big-endian | the 64 root bytes `user ‖ kernel` ([`NomtRoots`]) |
//! | [`ModuleAccessoryState`] | accessory | borsh `Vec<u8>` key ‖ slot number `u64` big-endian | borsh `Option<Vec<u8>>` (`None`: deleted) |
//! | [`AccessoryKeysByVersion`] | accessory | slot number `u64` big-endian ‖ borsh `Vec<u8>` key | empty |
//! | [`DbMetadata`] | accessory | a [`MetadataKey`]'s name (ASCII) | its bytes (per key) |
//!
//! Every decoder rejects bytes that are not exactly an encoding (wrong length, trailing bytes):
//! stored data that does not decode is an error, never a panic.

use core::fmt;
use core::marker::PhantomData;

use rockbound::schema::{ColumnFamilyName, KeyDecoder, KeyEncoder, ValueCodec};
use rockbound::versioned_db::SchemaWithVersion;
use rockbound::{CodecError, Schema, SeekKeyEncoder};
use selendra_interface::common::SlotNumber;
use selendra_state::{Kernel, Prefix, ProvableCompileTimeNamespace, SlotKey, SlotValue, User};

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

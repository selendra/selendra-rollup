//! Storage keys ([`SlotKey`], built from a [`Prefix`]) and values ([`SlotValue`]).

use core::fmt;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::{HexString, hex_string_serde};

use crate::codec::EncodeLike;

/// A prefix prepended to each key before insertion and retrieval from the storage.
///
/// Every state item (a container in a module) gets its own prefix: `module` identifies the
/// module, `item` the container within it. Two items with the same prefix would read each
/// other's bytes, so prefixes must be unique (the module macros assign them in Phase 5).
///
/// borsh: the two bytes `[module, item]`. String and JSON: `0x` + 4 lowercase hex digits.
#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord, BorshSerialize, BorshDeserialize,
)]
pub struct Prefix {
    module: u8,
    item: u8,
}

impl Prefix {
    /// The length of a prefix in bytes.
    pub const LENGTH: usize = 2;

    /// Returns a new [`Prefix`] with the given module and item discriminants.
    pub const fn new(module: u8, item: u8) -> Self {
        Self { module, item }
    }

    /// Returns the module short id of the [`Prefix`].
    pub const fn module(&self) -> u8 {
        self.module
    }

    /// Returns the item id of the [`Prefix`].
    pub const fn item(&self) -> u8 {
        self.item
    }

    /// Returns the bytes `[module, item]`, which start every key with this prefix.
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        [self.module, self.item]
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", HexString(self.to_bytes()))
    }
}

impl serde::Serialize for Prefix {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&HexString(self.to_bytes()), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Prefix {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let HexString([module, item]) =
            <HexString<[u8; Self::LENGTH]> as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self::new(module, item))
    }
}

/// Error returned when bytes are too short to be a [`SlotKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a slot key must be at least {min} bytes (its prefix), got {0}", min = Prefix::LENGTH)]
pub struct SlotKeyTooShort(pub usize);

/// The key under which a value is stored: a [`Prefix`] followed by the encoded item key (empty
/// for a single value). Cheap to clone.
///
/// Invariant: the bytes are at least [`Prefix::LENGTH`] long. Every constructor either starts
/// from a [`Prefix`] or checks the length ([`SlotKey::try_from_bytes`]).
///
/// borsh and serde encode the bytes including the prefix: borsh like a `Vec<u8>`, JSON as a
/// `0x`-prefixed lowercase hex string. Decoding rejects fewer than 2 bytes. [`fmt::Display`]
/// prints the same hex string.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotKey(Arc<[u8]>);

impl SlotKey {
    /// Creates the key that is just a prefix (used by single values such as `StateValue`).
    pub fn singleton(prefix: &Prefix) -> Self {
        Self(Arc::from(prefix.to_bytes()))
    }

    /// Creates the key `prefix || key_bytes`.
    pub fn from_parts(prefix: &Prefix, key_bytes: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(Prefix::LENGTH.saturating_add(key_bytes.len()));
        bytes.extend_from_slice(&prefix.to_bytes());
        bytes.extend_from_slice(key_bytes);
        Self(Arc::from(bytes))
    }

    /// Creates the key `prefix || encode(key)`, encoding `key` as if it were a `K` with `codec`.
    pub fn new<K, Q, KC>(prefix: &Prefix, key: &Q, codec: &KC) -> Self
    where
        KC: EncodeLike<Q, K>,
        Q: ?Sized,
    {
        let mut bytes = prefix.to_bytes().to_vec();
        codec.encode_like(key, &mut bytes);
        Self(Arc::from(bytes))
    }

    /// Creates a key from its bytes, including the prefix.
    ///
    /// # Errors
    /// If `bytes` is shorter than [`Prefix::LENGTH`].
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, SlotKeyTooShort> {
        if bytes.len() < Prefix::LENGTH {
            return Err(SlotKeyTooShort(bytes.len()));
        }
        Ok(Self(Arc::from(bytes)))
    }

    /// Returns the prefix of the key.
    pub fn prefix(&self) -> Prefix {
        // In bounds: the key is at least `Prefix::LENGTH` bytes (type invariant).
        Prefix::new(self.0[0], self.0[1])
    }

    /// Returns the bytes of this key excluding the prefix.
    pub fn without_prefix(&self) -> &[u8] {
        // In bounds: the key is at least `Prefix::LENGTH` bytes (type invariant).
        &self.0[Prefix::LENGTH..]
    }

    /// Returns the bytes of this key including the prefix (same as [`AsRef::as_ref`]).
    pub fn with_prefix(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length of the key including the prefix.
    // `is_empty` would always return false because of the prefix, so it isn't provided.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns a new key containing the first `length_excluding_prefix` bytes after the prefix,
    /// or `None` if the key is shorter than that.
    pub fn truncate_to(&self, length_excluding_prefix: usize) -> Option<Self> {
        let key = self.without_prefix().get(..length_excluding_prefix)?;
        Some(Self::from_parts(&self.prefix(), key))
    }
}

impl AsRef<[u8]> for SlotKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for SlotKey {
    type Error = SlotKeyTooShort;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl TryFrom<Vec<u8>> for SlotKey {
    type Error = SlotKeyTooShort;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() < Prefix::LENGTH {
            return Err(SlotKeyTooShort(bytes.len()));
        }
        Ok(Self(Arc::from(bytes)))
    }
}

impl fmt::Display for SlotKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", HexString(&self.0))
    }
}

impl fmt::Debug for SlotKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlotKey({self})")
    }
}

impl BorshSerialize for SlotKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // Same encoding as `Vec<u8>`.
        BorshSerialize::serialize(&*self.0, writer)
    }
}

impl BorshDeserialize for SlotKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes = Vec::<u8>::deserialize_reader(reader)?;
        Self::try_from(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

impl serde::Serialize for SlotKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        hex_string_serde::serialize(&self.0, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SlotKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = hex_string_serde::deserialize(deserializer)?;
        Self::try_from(bytes).map_err(serde::de::Error::custom)
    }
}

/// A serialized value suitable for storing. Internally uses an [`Arc<Vec<u8>>`] for cheap
/// cloning.
///
/// borsh encodes it like a `Vec<u8>`; JSON as a `0x`-prefixed lowercase hex string.
#[derive(Clone, PartialEq, Eq, Default, Hash)]
pub struct SlotValue {
    value: Arc<Vec<u8>>,
}

impl SlotValue {
    /// Creates a value by encoding `value` as if it were a `V` with `codec`.
    pub fn new<V, Vq, VC>(value: &Vq, codec: &VC) -> Self
    where
        Vq: ?Sized,
        VC: EncodeLike<Vq, V>,
    {
        codec.encode_to_vec_like(value).into()
    }

    /// Get the bytes of this value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// The size of the value in bytes.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Whether the value is zero bytes long (e.g. the borsh encoding of `()`).
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl From<Vec<u8>> for SlotValue {
    fn from(value: Vec<u8>) -> Self {
        Self {
            value: Arc::new(value),
        }
    }
}

#[cfg(test)]
impl From<&str> for SlotValue {
    fn from(value: &str) -> Self {
        value.as_bytes().to_vec().into()
    }
}

impl AsRef<[u8]> for SlotValue {
    fn as_ref(&self) -> &[u8] {
        &self.value
    }
}

impl fmt::Debug for SlotValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlotValue({})", HexString(self.value()))
    }
}

impl BorshSerialize for SlotValue {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(self.value.as_slice(), writer)
    }
}

impl BorshDeserialize for SlotValue {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        Vec::<u8>::deserialize_reader(reader).map(Self::from)
    }
}

impl serde::Serialize for SlotValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        hex_string_serde::serialize(self.value(), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SlotValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        hex_string_serde::deserialize::<D, Vec<u8>>(deserializer).map(Self::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::BorshCodec;

    fn build_key(prefix: Prefix, key: &[u8]) -> SlotKey {
        SlotKey::from_parts(&prefix, key)
    }

    #[test]
    fn test_as_ref() {
        let prefix = Prefix::new(1, 2);
        let key = build_key(prefix, b"hello");
        let key_ref = key.as_ref();
        assert_eq!(key_ref, b"\x01\x02hello");
        assert_eq!(key.with_prefix(), key_ref);
        assert_eq!(key.without_prefix(), b"hello");
        assert_eq!(key.len(), 7);
    }

    #[test]
    fn test_borsh_roundtrip() {
        let prefix = Prefix::new(1, 2);
        let key = build_key(prefix, b"hello");
        let serialized = borsh::to_vec(&key).unwrap();
        assert_eq!(
            serialized,
            borsh::to_vec(&b"\x01\x02hello".to_vec()).unwrap()
        );
        let key2: SlotKey = borsh::from_slice(&serialized).unwrap();

        assert_eq!(key.prefix(), prefix);
        assert_eq!(key.prefix(), key2.prefix());
        assert_eq!(key, key2);
    }

    #[test]
    fn test_serde_roundtrip() {
        let prefix = Prefix::new(1, 2);
        let key = build_key(prefix, b"hello");
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, r#""0x010268656c6c6f""#);
        let key2: SlotKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key.prefix(), prefix);
        assert_eq!(key.prefix(), key2.prefix());
        assert_eq!(key, key2);

        let binary = postcard::to_allocvec(&key).unwrap();
        assert_eq!(postcard::from_bytes::<SlotKey>(&binary).unwrap(), key);
    }

    #[test]
    fn test_comparison() {
        let prefix = Prefix::new(1, 2);
        let key1 = build_key(prefix, b"hello");
        let key2 = build_key(prefix, b"goodbye");
        assert!(key1 != key2);
        assert!(key1 > key2);

        let key3 = build_key(Prefix::new(1, 2), &[0u8; 500]);
        let key4 = build_key(Prefix::new(1, 2), &[1]);

        assert!(key3 != key4);
        assert!(key3 < key4);
        assert!(key3 < key1);

        let key5 = build_key(Prefix::new(1, 2), b"hello");
        assert!(key5 == key1);

        let lowest_key = build_key(Prefix::new(0, 0), b"xylophone");
        assert!(lowest_key < key2);
        assert!(lowest_key < key3);
    }

    #[test]
    fn test_truncate_to() {
        let key = build_key(Prefix::new(1, 2), b"hello");
        let long = build_key(Prefix::new(1, 2), b"helloworld");
        assert_eq!(long.truncate_to(5).unwrap(), key);
        assert_eq!(long.truncate_to(10).unwrap(), long);
        assert_eq!(long.truncate_to(11), None);
        assert_eq!(
            long.truncate_to(0).unwrap(),
            SlotKey::singleton(&Prefix::new(1, 2))
        );

        let key = build_key(Prefix::new(1, 2), &[2u8; 500]);
        let key2 = build_key(Prefix::new(1, 2), &[2u8; 7]);
        assert_eq!(key.truncate_to(7).unwrap(), key2);
    }

    #[test]
    fn test_to_vec_and_back() {
        for len in [0, 3, 100] {
            let key = build_key(Prefix::new(9, 8), &vec![1; len]);
            let vec = key.as_ref().to_vec();
            assert_eq!(SlotKey::try_from_bytes(&vec).unwrap(), key);
            assert_eq!(SlotKey::try_from(vec).unwrap(), key);
        }
    }

    #[test]
    fn keys_from_codec_and_singleton() {
        let prefix = Prefix::new(1, 2);
        assert_eq!(SlotKey::singleton(&prefix).as_ref(), [1, 2]);
        let key = SlotKey::new::<u64, _, _>(&prefix, &5u64, &BorshCodec);
        assert_eq!(key.as_ref(), [1, 2, 5, 0, 0, 0, 0, 0, 0, 0]);
        // A slice is encoded like a `Vec`.
        let key = SlotKey::new::<Vec<u8>, [u8], _>(&prefix, &[7u8, 8][..], &BorshCodec);
        assert_eq!(key.as_ref(), [1, 2, 2, 0, 0, 0, 7, 8]);
    }

    #[test]
    fn short_keys_are_rejected() {
        assert_eq!(SlotKey::try_from_bytes(&[]), Err(SlotKeyTooShort(0)));
        assert_eq!(SlotKey::try_from_bytes(&[1]), Err(SlotKeyTooShort(1)));
        assert_eq!(SlotKey::try_from(vec![1]), Err(SlotKeyTooShort(1)));
        assert_eq!(SlotKey::try_from_bytes(&[1, 2]).unwrap().as_ref(), [1, 2]);

        assert!(borsh::from_slice::<SlotKey>(&[0, 0, 0, 0]).is_err());
        assert!(borsh::from_slice::<SlotKey>(&[1, 0, 0, 0, 7]).is_err());
        assert!(borsh::from_slice::<SlotKey>(&[2, 0, 0, 0, 7, 8]).is_ok());
        assert!(serde_json::from_str::<SlotKey>(r#""0x""#).is_err());
        assert!(serde_json::from_str::<SlotKey>(r#""0x01""#).is_err());
        assert!(postcard::from_bytes::<SlotKey>(&postcard::to_allocvec(&[1u8]).unwrap()).is_err());
    }

    #[test]
    fn non_canonical_encodings_are_rejected() {
        // borsh: trailing bytes, length prefix too long.
        assert!(borsh::from_slice::<SlotKey>(&[2, 0, 0, 0, 7, 8, 9]).is_err());
        assert!(borsh::from_slice::<SlotKey>(&[3, 0, 0, 0, 7, 8]).is_err());
        assert!(borsh::from_slice::<SlotValue>(&[1, 0, 0, 0, 7, 8]).is_err());
        // JSON: the hex string must be `0x` + lowercase.
        assert!(serde_json::from_str::<SlotKey>(r#""0x0A0B""#).is_err());
        assert!(serde_json::from_str::<SlotKey>(r#""0a0b""#).is_err());
        assert!(serde_json::from_str::<SlotKey>("[10,11]").is_err());
        assert!(serde_json::from_str::<SlotValue>(r#""0xAB""#).is_err());
        assert!(serde_json::from_str::<Prefix>(r#""0x0A0B""#).is_err());
        assert!(serde_json::from_str::<Prefix>(r#""0x0a""#).is_err());
        assert!(serde_json::from_str::<Prefix>(r#""0x0a0b0c""#).is_err());
        assert!(serde_json::from_str::<Prefix>(r#"{"module":10,"item":11}"#).is_err());
    }

    #[test_strategy::proptest]
    fn slot_key_encodings_roundtrip_canonically(module: u8, item: u8, key: Vec<u8>) {
        let key = SlotKey::from_parts(&Prefix::new(module, item), &key);
        let borsh_bytes = borsh::to_vec(&key).unwrap();
        assert_eq!(borsh_bytes, borsh::to_vec(&key.as_ref().to_vec()).unwrap());
        let decoded: SlotKey = borsh::from_slice(&borsh_bytes).unwrap();
        assert_eq!(borsh::to_vec(&decoded).unwrap(), borsh_bytes);
        assert_eq!(decoded, key);

        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, format!("\"{key}\""));
        assert_eq!(serde_json::from_str::<SlotKey>(&json).unwrap(), key);
        let binary = postcard::to_allocvec(&key).unwrap();
        assert_eq!(postcard::from_bytes::<SlotKey>(&binary).unwrap(), key);
    }

    #[test_strategy::proptest]
    fn slot_value_encodings_roundtrip(bytes: Vec<u8>) {
        let value = SlotValue::from(bytes.clone());
        assert_eq!(value.value(), bytes.as_slice());
        assert_eq!(value.len(), bytes.len());
        let borsh_bytes = borsh::to_vec(&value).unwrap();
        assert_eq!(borsh_bytes, borsh::to_vec(&bytes).unwrap());
        assert_eq!(borsh::from_slice::<SlotValue>(&borsh_bytes).unwrap(), value);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<SlotValue>(&json).unwrap(), value);
        let binary = postcard::to_allocvec(&value).unwrap();
        assert_eq!(postcard::from_bytes::<SlotValue>(&binary).unwrap(), value);
    }

    #[test]
    fn prefix_encodings() {
        let prefix = Prefix::new(1, 0xab);
        assert_eq!(prefix.to_string(), "0x01ab");
        assert_eq!(borsh::to_vec(&prefix).unwrap(), [1, 0xab]);
        assert_eq!(borsh::from_slice::<Prefix>(&[1, 0xab]).unwrap(), prefix);
        assert!(borsh::from_slice::<Prefix>(&[1]).is_err());
        assert!(borsh::from_slice::<Prefix>(&[1, 2, 3]).is_err());
        assert_eq!(serde_json::to_string(&prefix).unwrap(), r#""0x01ab""#);
        assert_eq!(
            serde_json::from_str::<Prefix>(r#""0x01ab""#).unwrap(),
            prefix
        );
        let binary = postcard::to_allocvec(&prefix).unwrap();
        assert_eq!(postcard::from_bytes::<Prefix>(&binary).unwrap(), prefix);
    }

    #[test]
    fn display_and_debug_are_lowercase_hex() {
        let key = SlotKey::from_parts(&Prefix::new(0xab, 0xcd), &[0xef]);
        assert_eq!(key.to_string(), "0xabcdef");
        assert_eq!(format!("{key:?}"), "SlotKey(0xabcdef)");
        assert_eq!(format!("{:?}", SlotValue::from("A")), "SlotValue(0x41)");
    }
}

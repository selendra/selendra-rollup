use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::ser::SerializeSeq;

use super::safe_vec::cautious_size_hint;
use super::{ConsensusType, SafeVec};
use crate::da::BlockHashTrait;

/// A [`hex`]-encoded 32-byte hash. Note, this is not necessarily a transaction
/// hash, rather a generic hash.
pub type HexHash = HexString<[u8; 32]>;

/// A [`serde`]-compatible newtype wrapper around [`Vec<u8>`] or other
/// bytes-like types, which is serialized as a 0x-prefixed hex string.
///
/// Parsing accepts only the form [`Display`] produces: a `0x` prefix followed by lowercase
/// hex digits, so every value has exactly one string encoding. Every decoder rejects more than
/// [`HexBytes::MAX_LEN`] bytes before decoding them or allocating for them.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, derive_more::AsRef)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
pub struct HexString<T = Vec<u8>>(pub T)
where
    T: AsRef<[u8]>;

/// A bytes type a [`HexString`] decodes into (`Vec<u8>`, [`Bytes`](bytes::Bytes), `[u8; N]`,
/// [`SafeVec<u8, N>`]), with the most bytes it holds: every `HexString` decoder rejects a longer
/// input before decoding it or allocating for it.
pub trait HexBytes: AsRef<[u8]> + TryFrom<Vec<u8>> {
    /// The most bytes a value holds (`usize::MAX`: unbounded).
    const MAX_LEN: usize;
}

impl HexBytes for Vec<u8> {
    const MAX_LEN: usize = usize::MAX;
}

impl HexBytes for bytes::Bytes {
    const MAX_LEN: usize = usize::MAX;
}

impl<const N: usize> HexBytes for [u8; N] {
    const MAX_LEN: usize = N;
}

impl<const N: usize> HexBytes for SafeVec<u8, N> {
    const MAX_LEN: usize = N;
}

impl schemars::JsonSchema for HexString {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "HexString".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^0x(?:[a-f0-9]{2})*$",
            "description": "A `0x`-prefixed lowercase hexadecimal string of variable length, with an even number of hex digits.",
        })
    }
}

// Useful for representing Ethereum addresses
impl<const N: usize> schemars::JsonSchema for HexString<[u8; N]> {
    // One name per length: schemars stores schemas by name, so a shared name would make every
    // length use whichever pattern was generated first.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        match N {
            32 => "HexHash".into(),
            _ => format!("HexBytes{N}").into(),
        }
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": format!("^0x[a-f0-9]{{{}}}$", N * 2),
            "description": format!("{} bytes in lowercase hexadecimal format, with `0x` prefix.", N),
        })
    }
}

/// At most `N` bytes. One name per `N`, like the fixed-length schemas above.
impl<const N: usize> schemars::JsonSchema for HexString<SafeVec<u8, N>> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("HexBytesMax{N}").into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": format!("^0x(?:[a-f0-9]{{2}}){{0,{N}}}$"),
            "description": format!("At most {N} bytes in lowercase hexadecimal format, with `0x` prefix."),
        })
    }
}

/// The encodings are those of the inner bytes type.
impl<T: AsRef<[u8]> + ConsensusType> ConsensusType for HexString<T> {}

impl<T: AsRef<[u8]>> HexString<T> {
    /// Creates a new [`HexString`] from its inner contents.
    pub const fn new(bytes: T) -> Self {
        Self(bytes)
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for HexString<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<HexHash> for [u8; 32] {
    fn from(hash: HexHash) -> Self {
        hash.0
    }
}

impl<T: AsRef<[u8]>> From<T> for HexString<T> {
    fn from(bytes: T) -> Self {
        Self(bytes)
    }
}

impl<T> Display for HexString<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

impl<T> Debug for HexString<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

impl<T> serde::Serialize for HexString<T>
where
    T: AsRef<[u8]>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let inner_ref = self.0.as_ref();
            let mut seq = serializer.serialize_seq(Some(inner_ref.len()))?;
            for element in inner_ref {
                seq.serialize_element(element)?;
            }
            seq.end()
        }
    }
}

impl<'de, T: HexBytes> serde::Deserialize<'de> for HexString<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            deserializer.deserialize_str(HexStrVisitor::<T>(PhantomData))?
        } else {
            deserializer.deserialize_seq(HexSeqVisitor::<T>(PhantomData))?
        };

        Ok(HexString(bytes.try_into().map_err(|_| {
            serde::de::Error::custom("Invalid hex string length")
        })?))
    }
}

/// Decodes the hex string a human-readable format hands over, rejecting more than
/// `T::MAX_LEN` bytes before decoding (and so before allocating for them).
struct HexStrVisitor<T>(PhantomData<T>);

impl<T: HexBytes> serde::de::Visitor<'_> for HexStrVisitor<T> {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a 0x-prefixed lowercase hex string")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        parse_vec_u8(v, T::MAX_LEN).map_err(E::custom)
    }

    // Like `String`: UTF-8 bytes are accepted as a string.
    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        let string = std::str::from_utf8(v)
            .map_err(|_| E::invalid_value(serde::de::Unexpected::Bytes(v), &self))?;
        self.visit_str(string)
    }
}

/// Decodes the byte sequence a binary format hands over, rejecting a claimed length over
/// `T::MAX_LEN` before allocating for it; the claimed length only sizes the first allocation.
struct HexSeqVisitor<T>(PhantomData<T>);

impl<'de, T: HexBytes> serde::de::Visitor<'de> for HexSeqVisitor<T> {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "a sequence of at most {} bytes", T::MAX_LEN)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        use serde::de::Error;

        let hint = seq.size_hint().unwrap_or(0);
        if hint > T::MAX_LEN {
            return Err(A::Error::invalid_length(hint, &self));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve(cautious_size_hint::<u8>(hint))
            .map_err(|_| A::Error::custom("out of memory"))?;
        while let Some(byte) = seq.next_element::<u8>()? {
            if bytes.len() >= T::MAX_LEN {
                return Err(A::Error::invalid_length(
                    T::MAX_LEN.saturating_add(1),
                    &self,
                ));
            }
            bytes.push(byte);
        }
        Ok(bytes)
    }
}

impl<T: BorshSerialize + AsRef<[u8]>> BorshSerialize for HexString<T> {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.serialize(writer)
    }
}

impl<T: BorshDeserialize + AsRef<[u8]>> BorshDeserialize for HexString<T> {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        T::deserialize_reader(reader).map(Self)
    }
}

impl<T: HexBytes> FromStr for HexString<T> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = parse_vec_u8(s, T::MAX_LEN)?;
        Ok(HexString(bytes.try_into().map_err(|_| {
            anyhow::anyhow!("Invalid hex string length")
        })?))
    }
}

impl BlockHashTrait for HexHash {}

/// [`serde`] (de)serialization functions for [`HexString`], to be used with
/// `#[serde(with = "...")]`.
pub mod hex_string_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{HexBytes, HexString};

    /// Serializes `data` as hex string using lowercase characters and prefixing with '0x'.
    ///
    /// Lowercase characters are used (e.g. `f9b4ca`). The resulting string's length
    /// is always even, each byte in data is always encoded using two hex digits.
    /// Thus, the resulting string contains exactly twice as many bytes as the input
    /// data.
    pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        HexString::<T>::new(data).serialize(serializer)
    }

    /// Deserializes a hex string into raw bytes.
    ///
    /// The input must be `0x`-prefixed lowercase hex, as produced by [`serialize`].
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: HexBytes,
    {
        HexString::<T>::deserialize(deserializer).map(|s| s.0)
    }
}

/// Parses the canonical form only: `0x` followed by an even number of lowercase hex digits,
/// encoding at most `max_len` bytes (checked before decoding).
fn parse_vec_u8(s: &str, max_len: usize) -> anyhow::Result<Vec<u8>> {
    let digits = s
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("hex string must start with 0x"))?;
    if digits.len() / 2 > max_len {
        anyhow::bail!("hex string encodes more than {max_len} bytes");
    }
    if digits.bytes().any(|b| b.is_ascii_uppercase()) {
        anyhow::bail!("hex string must be lowercase");
    }
    hex::decode(digits).map_err(|e| anyhow::anyhow!("Failed to decode hex string: {e}"))
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::str::FromStr;

    use super::*;

    /// Serializes, then deserializes a value with [`serde_json`], then asserts
    /// equality.
    fn test_serialization_roundtrip_equality_json<T>(item: T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + Debug,
    {
        let serialized = serde_json::to_string(&item).unwrap();
        let deserialized: T = serde_json::from_str(&serialized).unwrap();
        assert_eq!(item, deserialized);
    }

    fn test_serialization_roundtrip_equality_binary<T>(item: T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + Debug,
    {
        let serialized = postcard::to_allocvec(&item).unwrap();
        let deserialized: T = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(item, deserialized);
    }

    fn test_str_roundtrip(item: HexString) {
        let s = item.to_string();
        let restored = HexString::from_str(&s).expect("HexString::from_str should pass");
        assert_eq!(item, restored);
    }

    #[test_strategy::proptest]
    fn hex_string_serialization_roundtrip(item: HexString) {
        test_serialization_roundtrip_equality_json(item.clone());
        test_serialization_roundtrip_equality_binary(item);
    }

    #[test_strategy::proptest]
    fn hex_string_str_roundtrip(item: HexString) {
        test_str_roundtrip(item);
    }

    #[test]
    fn only_the_canonical_string_is_accepted() {
        assert_eq!(HexString::from_str("0x").unwrap(), HexString(vec![]));
        assert_eq!(HexString::from_str("0xab").unwrap(), HexString(vec![0xab]));
        for bad in ["", "ab", "0xAB", "0xAb", "0Xab", "0xabc", "0x0g", " 0xab"] {
            assert!(HexString::<Vec<u8>>::from_str(bad).is_err(), "{bad:?}");
            assert!(
                serde_json::from_str::<HexString>(&format!("\"{bad}\"")).is_err(),
                "{bad:?}"
            );
        }
        assert!(HexString::<[u8; 1]>::from_str("0x").is_err());
    }

    #[test]
    fn fixed_length_schemas_do_not_collide() {
        #[derive(schemars::JsonSchema)]
        #[allow(dead_code)]
        struct Both {
            a: HexString<[u8; 20]>,
            b: HexString<[u8; 32]>,
        }
        let schema = serde_json::to_value(schemars::schema_for!(Both)).unwrap();
        assert_eq!(schema["$defs"]["HexBytes20"]["pattern"], "^0x[a-f0-9]{40}$");
        assert_eq!(schema["$defs"]["HexHash"]["pattern"], "^0x[a-f0-9]{64}$");
    }

    // Regressions of upstream's `HexString` schema bugs

    /// P5-04: every `HexString<SafeVec<u8, N>>` schema (like every `HexString<[u8; N]>` one,
    /// fixed in Phase 3) was named `HexHash`, so schemas of different caps collided and used
    /// whichever pattern was generated first; the patterns also allowed uppercase digits,
    /// which parsing rejects.
    #[test]
    fn safe_vec_hex_schema_names_are_distinct() {
        #[derive(schemars::JsonSchema)]
        #[allow(dead_code)]
        struct All {
            a: HexString<SafeVec<u8, 4>>,
            b: HexString<SafeVec<u8, 32>>,
            c: HexString<[u8; 32]>,
            d: HexString<[u8; 4]>,
        }
        let schema = serde_json::to_value(schemars::schema_for!(All)).unwrap();
        let defs = schema["$defs"].as_object().unwrap();
        assert_eq!(defs.len(), 4, "{defs:?}");
        assert_eq!(defs["HexBytesMax4"]["pattern"], "^0x(?:[a-f0-9]{2}){0,4}$");
        assert_eq!(
            defs["HexBytesMax32"]["pattern"],
            "^0x(?:[a-f0-9]{2}){0,32}$"
        );
        assert_eq!(defs["HexHash"]["pattern"], "^0x[a-f0-9]{64}$");
        assert_eq!(defs["HexBytes4"]["pattern"], "^0x[a-f0-9]{8}$");
        for def in defs.values() {
            let pattern = def["pattern"].as_str().unwrap();
            assert!(!pattern.contains("A-F"), "{pattern}");
        }
    }

    #[test]
    fn safe_vec_hex_string_is_capped() {
        type Capped = HexString<SafeVec<u8, 2>>;
        let value = Capped::from_str("0xabcd").unwrap();
        assert_eq!(value.to_string(), "0xabcd");
        assert_eq!(serde_json::to_string(&value).unwrap(), "\"0xabcd\"");
        assert_eq!(serde_json::from_str::<Capped>("\"0xabcd\"").unwrap(), value);
        assert_eq!(Capped::from_str("0x").unwrap().0.len(), 0);
        assert!(Capped::from_str("0xabcdef").is_err());
        assert!(serde_json::from_str::<Capped>("\"0xabcdef\"").is_err());
        assert!(Capped::from_str("0xABCD").is_err());
        let bytes = borsh::to_vec(&value).unwrap();
        assert_eq!(bytes, [2, 0, 0, 0, 0xab, 0xcd]);
        assert_eq!(borsh::from_slice::<Capped>(&bytes).unwrap(), value);
        assert!(borsh::from_slice::<Capped>(&[3, 0, 0, 0, 1, 2, 3]).is_err());
    }

    /// The cap is checked before the hex digits are decoded (or allocated for): a string over
    /// the cap is rejected for its length even when malformed further on (before, it was
    /// decoded first). `tests/decode_allocations.rs` checks what the decoders allocate.
    #[test]
    fn cap_is_checked_before_decoding() {
        type Capped = HexString<SafeVec<u8, 2>>;
        let over = "0xabcdefzz";
        let err = Capped::from_str(over).unwrap_err().to_string();
        assert!(err.contains("more than 2 bytes"), "{err}");
        let err = serde_json::from_str::<Capped>(&format!("\"{over}\""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("more than 2 bytes"), "{err}");
        // A fixed-length inner type is capped the same way.
        let err = HexString::<[u8; 2]>::from_str(over)
            .unwrap_err()
            .to_string();
        assert!(err.contains("more than 2 bytes"), "{err}");
        // An odd number of digits within the cap is still an error.
        assert!(Capped::from_str("0xabc").is_err());

        // Binary formats: over the cap is rejected, within it unchanged.
        let three = postcard::to_allocvec(&HexString(vec![1u8, 2, 3])).unwrap();
        assert_eq!(
            postcard::from_bytes::<Capped>(&three),
            Err(postcard::Error::SerdeDeCustom)
        );
        assert!(postcard::from_bytes::<Capped>(&three[..3]).is_err());
        let two = postcard::to_allocvec(&HexString(vec![1u8, 2])).unwrap();
        assert_eq!(
            postcard::from_bytes::<Capped>(&two).unwrap().as_ref(),
            [1, 2]
        );
        assert_eq!(
            postcard::from_bytes::<HexString<[u8; 2]>>(&two).unwrap(),
            HexString([1, 2])
        );
        let one = postcard::to_allocvec(&HexString(vec![1u8])).unwrap();
        assert!(postcard::from_bytes::<HexString<[u8; 2]>>(&one).is_err());
    }

    #[test]
    fn schema_matches_serialized_form() {
        let schema = serde_json::to_value(schemars::schema_for!(HexString)).unwrap();
        assert_eq!(schema["pattern"], "^0x(?:[a-f0-9]{2})*$");
        // The serializer's output (including empty bytes) matches the pattern.
        for bytes in [vec![], vec![0xab], vec![0, 0xff, 0x10]] {
            let s = HexString(bytes).to_string();
            assert!(s.starts_with("0x") && s.len() % 2 == 0);
            assert!(
                s[2..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
        }
        let schema = serde_json::to_value(schemars::schema_for!(HexString<[u8; 2]>)).unwrap();
        assert_eq!(schema["pattern"], "^0x[a-f0-9]{4}$");
    }
}

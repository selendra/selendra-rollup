use std::fmt::{Debug, Display};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::ser::SerializeSeq;

use crate::da::BlockHashTrait;

/// A [`hex`]-encoded 32-byte hash. Note, this is not necessarily a transaction
/// hash, rather a generic hash.
pub type HexHash = HexString<[u8; 32]>;

/// A [`serde`]-compatible newtype wrapper around [`Vec<u8>`] or other
/// bytes-like types, which is serialized as a 0x-prefixed hex string.
///
/// Parsing accepts only the form [`Display`] produces: a `0x` prefix followed by lowercase
/// hex digits, so every value has exactly one string encoding.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, derive_more::AsRef)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
pub struct HexString<T = Vec<u8>>(pub T)
where
    T: AsRef<[u8]>;

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

impl<'de, T> serde::Deserialize<'de> for HexString<T>
where
    T: TryFrom<Vec<u8>> + AsRef<[u8]>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let string: String = serde::Deserialize::deserialize(deserializer)?;
            parse_vec_u8(&string).map_err(serde::de::Error::custom)?
        } else {
            serde::Deserialize::deserialize(deserializer)?
        };

        Ok(HexString(bytes.try_into().map_err(|_| {
            serde::de::Error::custom("Invalid hex string length")
        })?))
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

impl<T: TryFrom<Vec<u8>> + AsRef<[u8]>> FromStr for HexString<T> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = parse_vec_u8(s)?;
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

    use super::HexString;

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
        T: TryFrom<Vec<u8>> + AsRef<[u8]>,
    {
        HexString::<T>::deserialize(deserializer).map(|s| s.0)
    }
}

/// Parses the canonical form only: `0x` followed by an even number of lowercase hex digits.
fn parse_vec_u8(s: &str) -> anyhow::Result<Vec<u8>> {
    let digits = s
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("hex string must start with 0x"))?;
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

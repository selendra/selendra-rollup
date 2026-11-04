//! Common types used throughout Selendra.

mod hex_string;
mod slot_numbering;

pub use hex_string::*;
pub use slot_numbering::*;

/// Deserializes a struct, accepting only the object form in human-readable formats.
///
/// Use it from a hand-written `Deserialize` impl on a derived helper struct (usually with
/// `#[serde(deny_unknown_fields)]`).
///
/// Derived struct impls also accept a JSON array of the field values (`[[1,2]]` for
/// `{"data":[1,2]}`), which would give one value two JSON encodings. Binary formats such as
/// postcard encode structs as sequences, so they keep the derived behavior.
pub fn deserialize_object_only<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    struct ObjectOnly<T>(std::marker::PhantomData<T>);

    impl<'de, T: serde::Deserialize<'de>> serde::de::Visitor<'de> for ObjectOnly<T> {
        type Value = T;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }

    if deserializer.is_human_readable() {
        deserializer.deserialize_map(ObjectOnly(std::marker::PhantomData))
    } else {
        T::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    /// Maps and sets in consensus types rely on borsh's `de_strict_order` feature: keys must be
    /// strictly increasing, so each map has exactly one encoding.
    #[test]
    fn borsh_maps_require_strictly_increasing_keys() {
        let sorted = [2, 0, 0, 0, 1, 8, 2, 9];
        let map: BTreeMap<u8, u8> = borsh::from_slice(&sorted).unwrap();
        assert_eq!(borsh::to_vec(&map).unwrap(), sorted);

        let unsorted = [2, 0, 0, 0, 2, 9, 1, 8];
        let duplicate = [2, 0, 0, 0, 1, 7, 1, 8];
        assert!(borsh::from_slice::<BTreeMap<u8, u8>>(&unsorted).is_err());
        assert!(borsh::from_slice::<BTreeMap<u8, u8>>(&duplicate).is_err());
        assert!(borsh::from_slice::<BTreeSet<u8>>(&[2, 0, 0, 0, 2, 1]).is_err());
        assert!(borsh::from_slice::<BTreeSet<u8>>(&[2, 0, 0, 0, 1, 1]).is_err());
    }
}

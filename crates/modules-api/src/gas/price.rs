//! [`GasPrice`]: the price of multi-dimensional gas.

use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};

use super::GAS_DIMENSIONS;
use super::impl_macros::impl_gas_array;
use crate::Amount;

/// A gas price: a token [`Amount`] per unit of gas, one per dimension.
///
/// - borsh: the `N` amounts, each a `u128` little-endian (no length prefix);
/// - serde: as `[Amount; N]` (JSON: an array of `N` canonical decimal strings, e.g.
///   `["10","10"]`);
/// - JSON schema `GasPrice{N}`: an array of exactly `N` amounts (upstream's schema said
///   numbers, while the JSON holds strings);
/// - `Display`/`Debug`: `GasPrice[10, 10]`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct GasPrice<const N: usize> {
    value: [Amount; N],
}

impl<const N: usize> selendra_interface::common::ConsensusType for GasPrice<N> {}

impl<const N: usize> GasPrice<N> {
    /// The price with these amounts per dimension.
    pub const fn from_dimensions(dimensions: [Amount; N]) -> Self {
        Self { value: dimensions }
    }

    /// The amounts per dimension.
    pub const fn dimensions(&self) -> [Amount; N] {
        self.value
    }
}

impl_gas_array!(GasPrice<GAS_DIMENSIONS>, Amount);

impl<const N: usize> From<[Amount; N]> for GasPrice<N> {
    fn from(dimensions: [Amount; N]) -> Self {
        Self::from_dimensions(dimensions)
    }
}

impl<const N: usize> From<GasPrice<N>> for [Amount; N] {
    fn from(price: GasPrice<N>) -> Self {
        price.value
    }
}

impl<const N: usize> AsRef<[Amount; N]> for GasPrice<N> {
    fn as_ref(&self) -> &[Amount; N] {
        &self.value
    }
}

impl<const N: usize> fmt::Display for GasPrice<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GasPrice{:?}", self.value)
    }
}

impl<const N: usize> fmt::Debug for GasPrice<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<const N: usize> serde::Serialize for GasPrice<N>
where
    [Amount; N]: serde::Serialize,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.value, serializer)
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for GasPrice<N>
where
    [Amount; N]: serde::Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <[Amount; N] as serde::Deserialize>::deserialize(deserializer).map(Self::from_dimensions)
    }
}

impl<const N: usize> schemars::JsonSchema for GasPrice<N> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("GasPrice{N}").into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "array",
            "minItems": N,
            "maxItems": N,
            "items": generator.subschema_for::<Amount>(),
            "description": format!("A gas price: {N} token amounts per unit of gas, one per dimension"),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, const N: usize> arbitrary::Arbitrary<'a> for GasPrice<N> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        <[Amount; N]>::arbitrary(u).map(Self::from_dimensions)
    }
}

#[cfg(feature = "arbitrary")]
impl<const N: usize> proptest::arbitrary::Arbitrary for GasPrice<N>
where
    [Amount; N]: proptest::arbitrary::Arbitrary,
{
    type Parameters = <[Amount; N] as proptest::arbitrary::Arbitrary>::Parameters;
    type Strategy = proptest::strategy::Map<
        <[Amount; N] as proptest::arbitrary::Arbitrary>::Strategy,
        fn([Amount; N]) -> Self,
    >;

    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        proptest::strategy::Strategy::prop_map(
            <[Amount; N] as proptest::arbitrary::Arbitrary>::arbitrary_with(args),
            Self::from_dimensions as fn([Amount; N]) -> Self,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GasArray;

    const GAS_PRICE: GasPrice<2> = GasPrice::from_dimensions([Amount::new(10), Amount::new(10)]);

    #[test]
    fn test_gas_price_serde_json() {
        let serialized = serde_json::to_string(&GAS_PRICE).unwrap();
        assert_eq!(serialized, r#"["10","10"]"#);
        let deserialized: GasPrice<2> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, GAS_PRICE);
        for rejected in [
            r#"[10,10]"#,
            r#"["10"]"#,
            r#"["10","10","10"]"#,
            r#"["+10","10"]"#,
        ] {
            assert!(
                serde_json::from_str::<GasPrice<2>>(rejected).is_err(),
                "{rejected}"
            );
        }
    }

    #[test]
    fn test_gas_price_serde_binary() {
        let serialized = postcard::to_allocvec(&GAS_PRICE).unwrap();
        let deserialized: GasPrice<2> = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, GAS_PRICE);
    }

    #[test]
    fn test_gas_price_display() {
        assert_eq!("GasPrice[10, 10]", GAS_PRICE.to_string());
    }

    #[test]
    fn gas_price_borsh_known_answer() {
        let price = GasPrice::<2>::from([Amount::new(1), Amount::new(u128::MAX)]);
        let mut expected = vec![1];
        expected.extend([0; 15]);
        expected.extend([0xff; 16]);
        assert_eq!(borsh::to_vec(&price).unwrap(), expected);
        assert_eq!(borsh::from_slice::<GasPrice<2>>(&expected).unwrap(), price);
    }

    #[test]
    fn gas_price_arithmetic() {
        let price = GasPrice::<2>::from([Amount::new(10), Amount::new(3)]);
        assert_eq!(
            price.checked_scalar_product(Amount::new(2)),
            Some(GasPrice::from([Amount::new(20), Amount::new(6)]))
        );
        assert_eq!(price.checked_scalar_product(Amount::MAX), None);
        assert_eq!(GasPrice::<2>::MAX.checked_combine(price), None);
        assert_eq!(GasPrice::<2>::ZEROED.checked_sub(price), None);
    }

    /// The schema's items are amounts (decimal strings), like the JSON.
    #[test]
    fn gas_price_schema_items_are_amounts() {
        let schema = serde_json::to_value(schemars::schema_for!(GasPrice<2>)).unwrap();
        assert_eq!(schema["title"], "GasPrice2");
        assert_eq!(schema["items"]["$ref"], "#/$defs/Amount");
        assert_eq!(schema["$defs"]["Amount"]["type"], "string");
    }
}

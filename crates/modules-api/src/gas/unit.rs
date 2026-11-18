//! [`GasUnit`]: an amount of multi-dimensional gas.

use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_state::metered::StateGas;

use super::impl_macros::{impl_gas_array, map_checked, zip_checked};
use super::{GAS_DIMENSIONS, Gas, GasPrice};
use crate::Amount;

/// An amount of gas: one `u64` per dimension.
///
/// - borsh: the `N` values, each a `u64` little-endian (no length prefix);
/// - serde: as `[u64; N]` (JSON: an array of `N` numbers, nothing else);
/// - JSON schema `GasUnit{N}`: an array of exactly `N` non-negative integers;
/// - `Display`/`Debug`: `GasUnit[1, 2]`.
///
/// The field is private: build one with [`GasUnit::from_dimensions`] (a `const fn`) or
/// `From<[u64; N]>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct GasUnit<const N: usize> {
    value: [u64; N],
}

impl<const N: usize> selendra_interface::common::ConsensusType for GasUnit<N> {}

impl<const N: usize> GasUnit<N> {
    /// The gas with these values per dimension.
    pub const fn from_dimensions(dimensions: [u64; N]) -> Self {
        Self { value: dimensions }
    }

    /// The values per dimension.
    pub const fn dimensions(&self) -> [u64; N] {
        self.value
    }
}

impl_gas_array!(GasUnit<GAS_DIMENSIONS>, u64);

impl Gas for GasUnit<GAS_DIMENSIONS> {
    type Price = GasPrice<GAS_DIMENSIONS>;

    fn checked_value(self, price: Self::Price) -> Option<Amount> {
        self.value
            .iter()
            .zip(price.dimensions())
            .try_fold(Amount::ZERO, |total, (gas, price)| {
                total.checked_add(Amount::new(u128::from(*gas)).checked_mul(price)?)
            })
    }
}

/// The gas the metered state accessors charge.
impl<const N: usize> StateGas for GasUnit<N> {
    const ZERO: Self = Self::from_dimensions([0; N]);

    fn checked_add(self, rhs: Self) -> Option<Self> {
        zip_checked(self.value, rhs.value, u64::checked_add).map(Self::from_dimensions)
    }

    fn checked_scale(self, n: u32) -> Option<Self> {
        map_checked(self.value, u64::from(n), u64::checked_mul).map(Self::from_dimensions)
    }
}

impl<const N: usize> From<[u64; N]> for GasUnit<N> {
    fn from(dimensions: [u64; N]) -> Self {
        Self::from_dimensions(dimensions)
    }
}

impl<const N: usize> From<GasUnit<N>> for [u64; N] {
    fn from(gas: GasUnit<N>) -> Self {
        gas.value
    }
}

impl<const N: usize> AsRef<[u64; N]> for GasUnit<N> {
    fn as_ref(&self) -> &[u64; N] {
        &self.value
    }
}

impl<const N: usize> fmt::Display for GasUnit<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GasUnit{:?}", self.value)
    }
}

impl<const N: usize> fmt::Debug for GasUnit<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<const N: usize> serde::Serialize for GasUnit<N>
where
    [u64; N]: serde::Serialize,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.value, serializer)
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for GasUnit<N>
where
    [u64; N]: serde::Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <[u64; N] as serde::Deserialize>::deserialize(deserializer).map(Self::from_dimensions)
    }
}

impl<const N: usize> schemars::JsonSchema for GasUnit<N> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("GasUnit{N}").into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "array",
            "minItems": N,
            "maxItems": N,
            "items": generator.subschema_for::<u64>(),
            "description": format!("Gas: {N} non-negative integers, one per dimension"),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, const N: usize> arbitrary::Arbitrary<'a> for GasUnit<N> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        <[u64; N]>::arbitrary(u).map(Self::from_dimensions)
    }
}

#[cfg(feature = "arbitrary")]
impl<const N: usize> proptest::arbitrary::Arbitrary for GasUnit<N>
where
    [u64; N]: proptest::arbitrary::Arbitrary,
{
    type Parameters = <[u64; N] as proptest::arbitrary::Arbitrary>::Parameters;
    type Strategy = proptest::strategy::Map<
        <[u64; N] as proptest::arbitrary::Arbitrary>::Strategy,
        fn([u64; N]) -> Self,
    >;

    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        proptest::strategy::Strategy::prop_map(
            <[u64; N] as proptest::arbitrary::Arbitrary>::arbitrary_with(args),
            Self::from_dimensions as fn([u64; N]) -> Self,
        )
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;
    use crate::GasArray;

    macro_rules! gas {
        ($a:expr, $b:expr) => {
            GasUnit::<2>::from([$a, $b])
        };
    }

    const TEST_GAS: GasUnit<2> = GasUnit::from_dimensions([100, 50]);

    #[test]
    fn test_dim_is_less_than() {
        let cases = [
            (gas!(10, 20), gas!(20, 30), true),
            (gas!(10, 40), gas!(20, 30), false),
            (gas!(40, 40), gas!(20, 30), false),
            (gas!(40, 40), gas!(20, 50), false),
            (gas!(10, 20), gas!(10, 30), false),
            (gas!(10, 30), gas!(20, 30), false),
        ];
        for (a, b, expected) in cases {
            assert_eq!(a.dim_is_less_than(b), expected);
        }
    }

    #[test]
    fn test_dim_is_less_or_eq() {
        let cases = [
            (gas!(10, 20), gas!(20, 30), true),
            (gas!(20, 30), gas!(20, 30), true),
            (gas!(10, 20), gas!(10, 30), true),
            (gas!(10, 30), gas!(20, 30), true),
            (gas!(10, 40), gas!(20, 30), false),
            (gas!(40, 40), gas!(20, 30), false),
            (gas!(40, 40), gas!(20, 50), false),
        ];
        for (a, b, expected) in cases {
            assert_eq!(a.dim_is_less_or_eq(b), expected);
        }
    }

    #[test]
    fn calculate_min_test() {
        let cases = [
            (gas!(10, 20), gas!(20, 30), gas!(10, 20)),
            (gas!(20, 30), gas!(10, 20), gas!(10, 20)),
            (gas!(10, 20), gas!(10, 5), gas!(10, 5)),
            (gas!(10, 20), gas!(5, 30), gas!(5, 20)),
            (gas!(10, 20), gas!(10, 20), gas!(10, 20)),
        ];
        for (a, b, expected) in cases {
            assert_eq!(GasUnit::calculate_min(a, b), expected);
        }
    }

    #[test]
    fn checked_scalar_product_test() {
        let cases = [
            (gas!(10, 20), 10, Some(gas!(100, 200))),
            (gas!(u64::MAX, 20), 10, None),
            (gas!(10, u64::MAX), 10, None),
            (gas!(u64::MAX, u64::MAX), 10, None),
            (gas!(u64::MAX, u64::MAX), 0, Some(gas!(0, 0))),
        ];
        for (gas, scalar, expected) in cases {
            assert_eq!(gas.checked_scalar_product(scalar), expected);
        }
    }

    #[test]
    fn checked_combine_test() {
        let cases = [
            (gas!(10, 20), gas!(10, 20), Some(gas!(20, 40))),
            (gas!(u64::MAX, 20), gas!(10, 20), None),
            (gas!(20, 20), gas!(10, u64::MAX), None),
            (gas!(u64::MAX, u64::MAX), gas!(10, 20), None),
            (gas!(u64::MAX, u64::MAX), gas!(u64::MAX, u64::MAX), None),
        ];
        for (a, b, expected) in cases {
            assert_eq!(a.checked_combine(b), expected);
        }
    }

    /// Checked arithmetic per dimension: an overflow or underflow in any one dimension is
    /// `None`, never a wrap or a panic.
    #[test]
    fn gas_unit_checked_arithmetic() {
        assert_eq!(gas!(10, 20).checked_sub(gas!(10, 5)), Some(gas!(0, 15)));
        assert_eq!(gas!(10, 20).checked_sub(gas!(11, 5)), None);
        assert_eq!(gas!(10, 20).checked_sub(gas!(1, 21)), None);
        assert_eq!(gas!(10, 21).checked_scalar_division(10), Some(gas!(1, 2)));
        assert_eq!(gas!(10, 21).checked_scalar_division(0), None);
        assert_eq!(
            StateGas::checked_add(gas!(u64::MAX, 0), gas!(0, 1)),
            Some(gas!(u64::MAX, 1))
        );
        assert_eq!(StateGas::checked_add(gas!(u64::MAX, 0), gas!(1, 0)), None);
        assert_eq!(
            gas!(3, 4).checked_scale(u32::MAX),
            Some(gas!(3 * 4_294_967_295, 4 * 4_294_967_295))
        );
        assert_eq!(gas!(u64::MAX, 0).checked_scale(2), None);
        assert_eq!(gas!(0, u64::MAX).checked_scale(2), None);
        assert_eq!(gas!(5, 5).checked_scale(0), Some(gas!(0, 0)));
        assert_eq!(<GasUnit<2> as StateGas>::ZERO, GasUnit::<2>::ZEROED);
        assert_eq!(GasUnit::<2>::zero(), gas!(0, 0));
        assert_eq!(GasUnit::<2>::max(), gas!(u64::MAX, u64::MAX));
    }

    #[test]
    fn human_readable_serde_roundtrip() {
        let gas = gas!(1, 2);
        let json = serde_json::to_string(&gas).unwrap();
        assert_eq!(json, "[1,2]");
        assert_eq!(serde_json::from_str::<GasUnit<2>>(&json).unwrap(), gas);
        for rejected in [
            "[1]",
            "[1,2,3]",
            "[-1,2]",
            "[\"1\",2]",
            "{\"value\":[1,2]}",
            "[1.5,2]",
        ] {
            assert!(
                serde_json::from_str::<GasUnit<2>>(rejected).is_err(),
                "{rejected} accepted"
            );
        }
    }

    #[test]
    fn binary_serde_roundtrip() {
        let gas = gas!(50, 2);
        let bytes = postcard::to_allocvec(&gas).unwrap();
        assert_eq!(bytes, postcard::to_allocvec(&[50u64, 2]).unwrap());
        assert_eq!(postcard::from_bytes::<GasUnit<2>>(&bytes).unwrap(), gas);
    }

    #[test]
    fn gas_unit_borsh_known_answer() {
        let gas = gas!(0x0102_0304_0506_0708, 9);
        assert_eq!(
            borsh::to_vec(&gas).unwrap(),
            [8, 7, 6, 5, 4, 3, 2, 1, 9, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(borsh::from_slice::<GasUnit<2>>(&[0; 15]).is_err());
        assert!(borsh::from_slice::<GasUnit<2>>(&[0; 17]).is_err());
    }

    #[test]
    fn test_gas_unit_display() {
        assert_eq!("GasUnit[100, 50]", TEST_GAS.to_string());
        assert_eq!("GasUnit[100, 50]", format!("{TEST_GAS:?}"));
    }

    #[test]
    fn gas_unit_schema() {
        let schema = serde_json::to_value(schemars::schema_for!(GasUnit<2>)).unwrap();
        assert_eq!(schema["title"], "GasUnit2");
        assert_eq!(schema["minItems"], 2);
        assert_eq!(schema["maxItems"], 2);
        assert_eq!(schema["items"]["type"], "integer");
        assert_eq!(schema["items"]["minimum"], 0);
    }

    #[proptest]
    fn gas_unit_round_trips(dimensions: [u64; 2]) {
        let gas = GasUnit::<2>::from(dimensions);
        let json = serde_json::to_string(&gas).unwrap();
        assert_eq!(serde_json::from_str::<GasUnit<2>>(&json).unwrap(), gas);
        assert_eq!(
            borsh::from_slice::<GasUnit<2>>(&borsh::to_vec(&gas).unwrap()).unwrap(),
            gas
        );
        assert_eq!(<[u64; 2]>::from(gas), dimensions);
    }
}

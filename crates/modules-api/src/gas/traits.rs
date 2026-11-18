//! The gas traits: [`GasArray`] (a value per gas dimension), [`Gas`] (gas amounts, priced by
//! [`Gas::Price`]), and [`Fraction`].

use core::fmt::{Debug, Display};
use core::hash::Hash;

use borsh::{BorshDeserialize, BorshSerialize};
use schemars::JsonSchema;
use selendra_interface::common::ConsensusType;
use selendra_state::metered::StateGas;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Amount;

/// The number of gas dimensions (expected: native execution and zk proving; Phase 6 confirms
/// and documents them). A plain constant: upstream read it from `constants.toml`.
pub const GAS_DIMENSIONS: usize = 2;

/// A value per gas dimension: [`GasUnit`](crate::GasUnit) (gas, `u64`s) and
/// [`GasPrice`](crate::GasPrice) (token amounts per unit of gas).
///
/// All arithmetic is checked per dimension; every operation returns a new value.
pub trait GasArray:
    'static
    + Debug
    + Display
    + Clone
    + Copy
    + Send
    + Sync
    + Unpin
    + PartialEq
    + Eq
    + Hash
    + JsonSchema
    + Serialize
    + DeserializeOwned
    + BorshSerialize
    + BorshDeserialize
    + ConsensusType
    + From<[Self::Scalar; GAS_DIMENSIONS]>
    + Into<[Self::Scalar; GAS_DIMENSIONS]>
    + AsRef<[Self::Scalar; GAS_DIMENSIONS]>
{
    /// The value of one dimension (`u64` for gas, [`Amount`] for prices).
    type Scalar: Copy + Ord + Debug;

    /// Zero in every dimension.
    const ZEROED: Self;

    /// The largest value in every dimension.
    const MAX: Self;

    /// `self + rhs` in every dimension, or `None` if one overflows.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn checked_combine(self, rhs: Self) -> Option<Self>;

    /// `self - rhs` in every dimension, or `None` if one underflows.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn checked_sub(self, rhs: Self) -> Option<Self>;

    /// `self · scalar` in every dimension, or `None` if one overflows.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn checked_scalar_product(self, scalar: Self::Scalar) -> Option<Self>;

    /// `self / scalar` (rounded down) in every dimension, or `None` if `scalar` is zero.
    /// (Upstream's `scalar_division` returned zero for a zero divisor.)
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn checked_scalar_division(self, scalar: Self::Scalar) -> Option<Self>;

    /// Whether `self < rhs` in every dimension.
    #[must_use = "comparisons are pure and do not modify either value"]
    fn dim_is_less_than(self, rhs: Self) -> bool;

    /// Whether `self <= rhs` in every dimension.
    #[must_use = "comparisons are pure and do not modify either value"]
    fn dim_is_less_or_eq(self, rhs: Self) -> bool;

    /// The smaller value of each dimension.
    #[must_use = "this returns the computed minimum without modifying either value"]
    fn calculate_min(lhs: Self, rhs: Self) -> Self;
}

/// A gas amount, one `u64` per dimension.
///
/// It is also the gas the metered state accessors charge
/// ([`StateGas`](selendra_state::metered::StateGas)).
pub trait Gas: GasArray<Scalar = u64> + StateGas {
    /// The price of gas: token amounts per unit, one per dimension.
    type Price: GasArray<Scalar = Amount>;

    /// The value of this gas at `price`: the sum over the dimensions of `gas · price`, or
    /// `None` on overflow. (Upstream also had a saturating `value`; a saturated fee is a wrong
    /// amount, so there is only this one.)
    #[must_use = "this returns the computed value without modifying the original"]
    fn checked_value(self, price: Self::Price) -> Option<Amount>;

    /// Zero gas in every dimension.
    #[must_use]
    fn zero() -> Self {
        Self::ZEROED
    }

    /// The largest gas in every dimension.
    #[must_use]
    fn max() -> Self {
        Self::MAX
    }
}

/// A fraction `numerator / denominator` of at most one, with a nonzero denominator (checked
/// by [`Fraction::new`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fraction {
    numerator: u32,
    denominator: u32,
}

impl Fraction {
    /// `numerator / denominator`, or `None` unless `0 < denominator` and
    /// `numerator <= denominator`. (Upstream's fields were public, with the bound in a comment.)
    pub const fn new(numerator: u32, denominator: u32) -> Option<Self> {
        if denominator == 0 || numerator > denominator {
            return None;
        }
        Some(Self {
            numerator,
            denominator,
        })
    }

    /// The numerator.
    pub const fn numerator(self) -> u32 {
        self.numerator
    }

    /// The denominator (nonzero).
    pub const fn denominator(self) -> u32 {
        self.denominator
    }

    /// This fraction of `gas` in every dimension: `gas / denominator · numerator`, rounded
    /// down (the division first, like upstream). Never overflows: the result is at most `gas`.
    #[must_use]
    pub fn of<G: GasArray<Scalar = u64>>(self, gas: G) -> G {
        let dimensions: [u64; GAS_DIMENSIONS] = gas.into();
        G::from(
            dimensions.map(|value| value / u64::from(self.denominator) * u64::from(self.numerator)),
        )
    }
}

/// The share of a slot's gas (and of its data) the preferred sequencer may use: 9/10. The rest
/// stays for other sequencers and forced (emergency) registrations, so the preferred sequencer
/// cannot fill a slot alone.
pub const PREFERRED_DATA_FRACTION: Fraction = match Fraction::new(9, 10) {
    Some(fraction) => fraction,
    None => panic!("9/10 is a valid fraction"),
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GasPrice, GasUnit};

    #[test]
    fn checked_value_test() {
        let gas = GasUnit::<2>::from([10, 20]);
        let gas_price = GasPrice::<2>::from([Amount::new(3), Amount::new(5)]);
        assert_eq!(gas.checked_value(gas_price).unwrap(), 130);

        let gas = GasUnit::<2>::from([u64::MAX, 20]);
        assert_eq!(
            gas.checked_value(gas_price).unwrap(),
            u128::from(u64::MAX) * 3 + 100
        );

        let gas_price = GasPrice::<2>::from([
            Amount::new(u128::from(u64::MAX))
                .checked_mul(Amount::new(3))
                .unwrap(),
            Amount::new(5),
        ]);
        assert!(gas.checked_value(gas_price).is_none());

        let gas = GasUnit::<2>::from([u64::MAX, u64::MAX]);
        let gas_price = GasPrice::<2>::from([Amount::from(u64::MAX); 2]);
        assert!(gas.checked_value(gas_price).is_none());

        let gas = GasUnit::<2>::from([0, 10]);
        let gas_price = GasPrice::<2>::from([Amount::MAX, Amount::new(20)]);
        assert_eq!(gas.checked_value(gas_price).unwrap(), 200);
    }

    #[test]
    fn fractions_are_checked() {
        assert_eq!(Fraction::new(1, 0), None);
        assert_eq!(Fraction::new(0, 0), None);
        assert_eq!(Fraction::new(11, 10), None);
        assert!(Fraction::new(10, 10).is_some());
        assert!(Fraction::new(0, 1).is_some());
        assert_eq!(PREFERRED_DATA_FRACTION.numerator(), 9);
        assert_eq!(PREFERRED_DATA_FRACTION.denominator(), 10);

        let gas = GasUnit::<2>::from([100, 205]);
        assert_eq!(PREFERRED_DATA_FRACTION.of(gas), GasUnit::from([90, 180]));
        let max = GasUnit::<2>::MAX;
        assert_eq!(
            PREFERRED_DATA_FRACTION.of(max),
            GasUnit::from([u64::MAX / 10 * 9; 2])
        );
        assert_eq!(Fraction::new(1, 1).unwrap().of(max), max);
    }
}

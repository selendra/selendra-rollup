//! Fee fields of transactions: [`PriorityFeeBips`].

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Amount;

/// A priority fee in basis points (1/100 of a percent) of the transaction's gas value: `100` is
/// 1%, `10_000` is 100%. (Upstream's docs said `1%` is `10_000`, and the `TxDetails` field docs
/// that `100_000` is 10%: both off by 100×.)
///
/// borsh: the `u64`. JSON: a number.
#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
pub struct PriorityFeeBips(pub u64);

selendra_interface::impl_consensus_type!(PriorityFeeBips);

/// Applying the priority fee overflows `u128`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Applying the priority fee to this quantity causes an overflow")]
pub struct PriorityFeeApplyOverflowError;

impl PriorityFeeBips {
    /// No priority fee: the sequencer gets no tip.
    pub const ZERO: Self = Self(0);

    /// Basis points in 100%.
    pub const BASIS_POINTS: u64 = 10_000;

    /// `percentage`% (`from_percentage(1)` is `PriorityFeeBips(100)`), or `None` if it does not
    /// fit (upstream multiplied unchecked: a panic with overflow checks, a wrong fee without).
    #[must_use]
    pub const fn from_percentage(percentage: u64) -> Option<Self> {
        match percentage.checked_mul(100) {
            Some(bips) => Some(Self(bips)),
            None => None,
        }
    }

    /// `quantity · self / 10_000`, rounded down: the fee on `quantity`.
    ///
    /// Exact for every `quantity`: computed on the two 64-bit halves of `quantity` with the
    /// remainders carried (upstream dropped the low half's remainder, so above `2^64` the
    /// result could be one less than the rounded-down fee).
    ///
    /// # Errors
    /// If the fee does not fit in a `u128` (only possible above 100%).
    pub fn apply(&self, quantity: Amount) -> Result<Amount, PriorityFeeApplyOverflowError> {
        const BASIS_POINTS: u128 = PriorityFeeBips::BASIS_POINTS as u128;
        let quantity = quantity.get();
        let bips = u128::from(self.0);
        let high = quantity >> 64;
        let low = quantity & u128::from(u64::MAX);
        // Both products fit: each factor is below 2^64.
        let (high_quotient, high_remainder) = div_rem(high * bips, BASIS_POINTS);
        let (low_quotient, low_remainder) = div_rem(low * bips, BASIS_POINTS);
        // quantity · bips = (high_quotient · 10_000 + high_remainder) · 2^64
        //                 + low_quotient · 10_000 + low_remainder,
        // so the fee is high_quotient · 2^64 + low_quotient
        //             + ⌊(high_remainder · 2^64 + low_remainder) / 10_000⌋,
        // where high_remainder · 2^64 + low_remainder < 10_000 · 2^64 + 10_000 fits.
        let carried = ((high_remainder << 64) + low_remainder) / BASIS_POINTS;
        let high_part = u64::try_from(high_quotient).map_err(|_| PriorityFeeApplyOverflowError)?;
        (u128::from(high_part) << 64)
            .checked_add(low_quotient)
            .and_then(|fee| fee.checked_add(carried))
            .map(Amount::new)
            .ok_or(PriorityFeeApplyOverflowError)
    }
}

fn div_rem(numerator: u128, denominator: u128) -> (u128, u128) {
    (numerator / denominator, numerator % denominator)
}

impl From<u64> for PriorityFeeBips {
    fn from(bips: u64) -> Self {
        Self(bips)
    }
}

impl From<PriorityFeeBips> for u64 {
    fn from(fee: PriorityFeeBips) -> Self {
        fee.0
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;

    // Regressions of upstream's `PriorityFeeBips` bugs

    /// P5-40 (regression): `from_percentage` multiplied unchecked (a panic in debug and
    /// overflow-checked release builds).
    #[test]
    fn priority_fee_from_percentage_overflow() {
        assert_eq!(PriorityFeeBips::from_percentage(u64::MAX), None);
        assert_eq!(PriorityFeeBips::from_percentage(u64::MAX / 100 + 1), None);
        assert_eq!(
            PriorityFeeBips::from_percentage(u64::MAX / 100),
            Some(PriorityFeeBips(u64::MAX / 100 * 100))
        );
        assert_eq!(
            PriorityFeeBips::from_percentage(1),
            Some(PriorityFeeBips(100))
        );
        assert_eq!(
            PriorityFeeBips::from_percentage(100),
            Some(PriorityFeeBips(PriorityFeeBips::BASIS_POINTS))
        );
        const TEN_PERCENT: Option<PriorityFeeBips> = PriorityFeeBips::from_percentage(10);
        assert_eq!(TEN_PERCENT, Some(PriorityFeeBips(1_000)));
    }

    /// Found now (no plan ID; regression): `apply` rounded the fee down twice above `2^64` (upstream dropped the low half's
    /// remainder): a fee could be one unit short. Known answers computed independently
    /// (Python integers): `⌊(2^64 + 9999) · 1 / 10_000⌋ = 1844674407370956` (upstream:
    /// `1844674407370955`).
    #[test]
    fn priority_fee_apply_is_exact() {
        let quantity = Amount::new((1u128 << 64) + 9999);
        assert_eq!(
            PriorityFeeBips(1).apply(quantity),
            Ok(Amount::new(1_844_674_407_370_956))
        );
        assert_eq!(
            PriorityFeeBips(2_500).apply(Amount::new(
                123_456_789_012_345_678_901_234_567_890_123_456_789
            )),
            Ok(Amount::new(
                30_864_197_253_086_419_725_308_641_972_530_864_197
            ))
        );
        assert_eq!(PriorityFeeBips(10_000).apply(Amount::MAX), Ok(Amount::MAX));
        assert_eq!(
            PriorityFeeBips(10_001).apply(Amount::MAX),
            Err(PriorityFeeApplyOverflowError)
        );
        assert_eq!(
            PriorityFeeBips(u64::MAX).apply(Amount::MAX),
            Err(PriorityFeeApplyOverflowError)
        );
        assert_eq!(PriorityFeeBips::ZERO.apply(Amount::MAX), Ok(Amount::ZERO));
        assert_eq!(
            PriorityFeeBips(100).apply(Amount::new(250)),
            Ok(Amount::new(2))
        );
    }

    /// Wherever `quantity · bips` fits a `u128`, `apply` equals the direct computation
    /// `⌊quantity · bips / 10_000⌋` (quantities up to `2^72`, so the high half is exercised).
    #[proptest]
    fn priority_fee_apply_matches_direct_computation(quantity: u64, bips: u64, high: u8) {
        let quantity = (u128::from(high) << 64) | u128::from(quantity);
        let expected = quantity
            .checked_mul(u128::from(bips))
            .map(|product| product / 10_000);
        if let Some(expected) = expected {
            assert_eq!(
                PriorityFeeBips(bips).apply(Amount::new(quantity)),
                Ok(Amount::new(expected))
            );
        }
    }

    #[test]
    fn priority_fee_encodings() {
        assert_eq!(
            borsh::to_vec(&PriorityFeeBips(0x0102)).unwrap(),
            [2, 1, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(serde_json::to_string(&PriorityFeeBips(250)).unwrap(), "250");
        assert_eq!(
            serde_json::from_str::<PriorityFeeBips>("250").unwrap(),
            PriorityFeeBips(250)
        );
        for rejected in ["\"250\"", "-1", "2.5", "1e2"] {
            assert!(serde_json::from_str::<PriorityFeeBips>(rejected).is_err());
        }
        assert_eq!(u64::from(PriorityFeeBips::from(7)), 7);
    }
}

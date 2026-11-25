//! A transaction's details ([`TxDetails`]: fees, gas limit, runtime version) and the
//! authenticated form the hooks receive ([`AuthenticatedTransactionData`]); the priority fee
//! ([`PriorityFeeBips`]).

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{Amount, BasicGasMeter, ConsensusType, Gas, GasArray, Spec};

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
    ConsensusType,
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
pub struct PriorityFeeBips(pub u64);

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

/// A transaction's fee and gas details, and the runtime version it was signed for.
///
/// borsh: the fields in order (`max_priority_fee_bips` `u64`, `max_fee` `u128`, `gas_limit` an
/// option of the spec's gas, `runtime_version` `u32`, all little-endian). JSON: an object with
/// exactly these four fields (`gas_limit` may be `null` but not missing; unknown fields are
/// rejected), `max_fee` a decimal string, `gas_limit` the spec's gas (an array of numbers for
/// [`GasUnit`](crate::GasUnit)) or `null`, the other two numbers. A consensus type.
///
/// `runtime_version` selects an entry of the runtime's version table (the spec version and
/// schema hash the signing payload commits to; Phase 5's transaction formats). It replaces
/// upstream's `chain_hash_fragment` (64 bits of the UniversalWallet chain hash).
///
/// Phase 6 adds the fee token and fee payer (a pre-genesis format change).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(bound = "S: Spec", deny_unknown_fields)]
pub struct TxDetails<S: Spec> {
    /// The most the sequencer may be tipped, in basis points of the gas value
    /// ([`PriorityFeeBips`]: `100` is 1%).
    pub max_priority_fee_bips: PriorityFeeBips,
    /// The most the transaction may pay in fees, in gas token base units.
    pub max_fee: Amount,
    /// The most gas the transaction may use, per dimension; at most the block's limit. With
    /// the gas price it must not cost more than `max_fee`. `None`: the block's limit.
    #[serde(deserialize_with = "required_option")]
    pub gas_limit: Option<S::Gas>,
    /// The runtime version the transaction was signed for.
    pub runtime_version: u32,
}

/// Every field is a consensus type.
impl<S: Spec> ConsensusType for TxDetails<S> {}

/// An `Option` field that must be present (`null` for `None`): one JSON form per value. (Serde's
/// derive treats a missing `Option` field as `None` unless the field has its own
/// deserializer.)
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// A transaction's details after authentication: what the authenticator returns and the
/// transaction hooks receive.
///
/// Nothing at the type level proves it was authenticated: authenticators in other crates (the
/// EVM's, Phase 7) build it too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedTransactionData<S: Spec>(pub TxDetails<S>);

impl<S: Spec> From<TxDetails<S>> for AuthenticatedTransactionData<S> {
    fn from(details: TxDetails<S>) -> Self {
        Self(details)
    }
}

impl<S: Spec> AuthenticatedTransactionData<S> {
    /// The transaction's meter: the smaller of its gas limit and `slot_gas_limit` in each
    /// dimension (`slot_gas_limit` without a gas limit), at `gas_price`, with `max_fee` as its
    /// funds budget.
    pub fn gas_meter(
        &self,
        gas_price: <S::Gas as Gas>::Price,
        slot_gas_limit: S::Gas,
    ) -> BasicGasMeter<S> {
        let gas_limit = self.0.gas_limit.map_or(slot_gas_limit, |gas_limit| {
            S::Gas::calculate_min(gas_limit, slot_gas_limit)
        });
        BasicGasMeter::new_with_funds_and_gas(self.0.max_fee, gas_limit, gas_price)
    }
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

    type S = crate::test_utils::TestSpec;

    fn details(gas_limit: Option<[u64; 2]>) -> TxDetails<S> {
        TxDetails {
            max_priority_fee_bips: PriorityFeeBips(0x0102),
            max_fee: Amount::new(1000),
            gas_limit: gas_limit.map(crate::GasUnit::from),
            runtime_version: 0x0102_0304,
        }
    }

    /// Known answers computed independently (`python3 -I -c 'import struct …'`: `<Q`, 16-byte
    /// LE, option tag, `<Q` per dimension, `<I`).
    #[test]
    fn tx_details_borsh_known_answers() {
        let bytes = borsh::to_vec(&details(Some([5, 0x0607]))).unwrap();
        assert_eq!(
            bytes,
            [
                2, 1, 0, 0, 0, 0, 0, 0, 232, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 5, 0,
                0, 0, 0, 0, 0, 0, 7, 6, 0, 0, 0, 0, 0, 0, 4, 3, 2, 1
            ]
        );
        assert_eq!(
            borsh::from_slice::<TxDetails<S>>(&bytes).unwrap(),
            details(Some([5, 0x0607]))
        );
        let none = TxDetails::<S> {
            max_priority_fee_bips: PriorityFeeBips::ZERO,
            max_fee: Amount::MAX,
            gas_limit: None,
            runtime_version: 0,
        };
        let bytes = borsh::to_vec(&none).unwrap();
        let mut expected = vec![0u8; 8];
        expected.extend([255; 16]);
        expected.extend([0; 5]);
        assert_eq!(bytes, expected);
        assert_eq!(borsh::from_slice::<TxDetails<S>>(&bytes).unwrap(), none);

        // Trailing bytes, a truncated encoding and an option tag other than 0/1 are rejected.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(borsh::from_slice::<TxDetails<S>>(&trailing).is_err());
        assert!(borsh::from_slice::<TxDetails<S>>(&bytes[..bytes.len() - 1]).is_err());
        // The tag is flipped in the `Some` encoding: every byte a decoder taking any nonzero tag
        // as `Some` would read is present, so only the tag check can reject it.
        let mut bad_tag = borsh::to_vec(&details(Some([5, 0x0607]))).unwrap();
        assert_eq!(bad_tag[24], 1);
        bad_tag[24] = 2;
        assert!(borsh::from_slice::<TxDetails<S>>(&bad_tag).is_err());
    }

    /// JSON: exactly the four fields, `gas_limit` present (`null` for none), no unknown fields.
    #[test]
    fn tx_details_json() {
        let json = serde_json::to_string(&details(Some([5, 6]))).unwrap();
        assert_eq!(
            json,
            r#"{"max_priority_fee_bips":258,"max_fee":"1000","gas_limit":[5,6],"runtime_version":16909060}"#
        );
        assert_eq!(
            serde_json::from_str::<TxDetails<S>>(&json).unwrap(),
            details(Some([5, 6]))
        );
        let json = serde_json::to_string(&details(None)).unwrap();
        assert_eq!(
            json,
            r#"{"max_priority_fee_bips":258,"max_fee":"1000","gas_limit":null,"runtime_version":16909060}"#
        );
        assert_eq!(
            serde_json::from_str::<TxDetails<S>>(&json).unwrap(),
            details(None)
        );
        for rejected in [
            // `gas_limit` missing (serde's derive would read it as `None`).
            r#"{"max_priority_fee_bips":258,"max_fee":"1000","runtime_version":1}"#,
            // An unknown field.
            r#"{"max_priority_fee_bips":258,"max_fee":"1000","gas_limit":null,"runtime_version":1,"x":0}"#,
            // `max_fee` as a number, `runtime_version` above `u32::MAX`.
            r#"{"max_priority_fee_bips":258,"max_fee":1000,"gas_limit":null,"runtime_version":1}"#,
            r#"{"max_priority_fee_bips":258,"max_fee":"1000","gas_limit":null,"runtime_version":4294967296}"#,
            // The upstream field.
            r#"{"max_priority_fee_bips":258,"max_fee":"1000","gas_limit":null,"chain_hash_fragment":"1"}"#,
        ] {
            assert!(
                serde_json::from_str::<TxDetails<S>>(rejected).is_err(),
                "{rejected}"
            );
        }
        let binary = postcard::to_allocvec(&details(Some([1, 2]))).unwrap();
        assert_eq!(
            postcard::from_bytes::<TxDetails<S>>(&binary).unwrap(),
            details(Some([1, 2]))
        );
    }

    /// Every value round-trips through borsh, JSON and postcard.
    #[proptest]
    fn tx_details_round_trip(
        fee: u64,
        max_fee: u128,
        gas_limit: Option<[u64; 2]>,
        runtime_version: u32,
    ) {
        let details = TxDetails::<S> {
            max_priority_fee_bips: PriorityFeeBips(fee),
            max_fee: Amount::new(max_fee),
            gas_limit: gas_limit.map(crate::GasUnit::from),
            runtime_version,
        };
        let bytes = borsh::to_vec(&details).unwrap();
        assert_eq!(bytes.len(), if gas_limit.is_some() { 45 } else { 29 });
        assert_eq!(borsh::from_slice::<TxDetails<S>>(&bytes).unwrap(), details);
        let json = serde_json::to_string(&details).unwrap();
        assert_eq!(
            serde_json::from_str::<TxDetails<S>>(&json).unwrap(),
            details
        );
        let binary = postcard::to_allocvec(&details).unwrap();
        assert_eq!(
            postcard::from_bytes::<TxDetails<S>>(&binary).unwrap(),
            details
        );
    }

    /// The meter takes the smaller limit per dimension, the block's without a gas limit, and
    /// `max_fee` as its budget.
    #[test]
    fn authenticated_tx_gas_meter() {
        let price = crate::GasPrice::from([Amount::new(2), Amount::new(3)]);
        let slot = crate::GasUnit::from([100, 10]);
        let tx = AuthenticatedTransactionData::from(details(Some([50, 20])));
        let meter = tx.gas_meter(price, slot);
        assert_eq!(meter.remaining_gas(), crate::GasUnit::from([50, 10]));
        assert_eq!(meter.remaining_funds(), Some(Amount::new(1000)));
        assert_eq!(meter.gas_price(), price);

        let tx = AuthenticatedTransactionData(details(None));
        let meter = tx.gas_meter(price, slot);
        assert_eq!(meter.remaining_gas(), slot);
        assert_eq!(meter.initial_gas(), slot);
        assert_eq!(tx.0, details(None));
    }
}

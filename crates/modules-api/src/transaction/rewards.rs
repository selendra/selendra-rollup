//! What a transaction's fees pay: [`TransactionConsumption`], split into the prover's reward
//! ([`ProverReward`]), the sequencer's ([`SequencerReward`]) and the refund
//! ([`RemainingFunds`]).
//!
//! These values move tokens (the capabilities pay them out, Phase 5 S11 and Phase 6), so they
//! can only be computed from a transaction's gas meter: their fields are private, the reward
//! types have no public constructor (other than [`SequencerReward::ZERO`]) and nothing here
//! decodes. Upstream documented them as buildable only from the working set, but the reward
//! types' fields were `pub`, `SequencerReward` decoded (borsh and serde) and `TransactionConsumption` decoded
//! (serde) and had a public `new` (P5-41). None of these compiles outside this crate (a
//! consumption's fields cannot be set, so it cannot be built either):
//!
//! ```compile_fail,E0423
//! use selendra_modules_api::Amount;
//! use selendra_modules_api::transaction::RemainingFunds;
//!
//! let refund = RemainingFunds(Amount::new(1_000_000));
//! ```
//!
//! ```compile_fail,E0423
//! use selendra_modules_api::Amount;
//! use selendra_modules_api::transaction::ProverReward;
//!
//! let reward = ProverReward(Amount::new(1_000_000));
//! ```
//!
//! ```compile_fail,E0423
//! use selendra_modules_api::Amount;
//! use selendra_modules_api::transaction::SequencerReward;
//!
//! let reward = SequencerReward(Amount::new(1_000_000));
//! ```
//!
//! ```compile_fail,E0616
//! use selendra_modules_api::transaction::TransactionConsumption;
//! use selendra_modules_api::{Amount, GasUnit};
//!
//! let mut consumption = TransactionConsumption::<GasUnit<2>>::ZERO;
//! consumption.remaining_funds = Amount::new(1_000_000);
//! ```
//!
//! ```compile_fail,E0616
//! use selendra_modules_api::transaction::TransactionConsumption;
//! use selendra_modules_api::{Amount, GasUnit};
//!
//! let mut consumption = TransactionConsumption::<GasUnit<2>>::ZERO;
//! consumption.base_fee_value = Amount::new(1_000_000);
//! ```
//!
//! ```compile_fail,E0616
//! use selendra_modules_api::transaction::TransactionConsumption;
//! use selendra_modules_api::{Amount, GasUnit};
//!
//! let mut consumption = TransactionConsumption::<GasUnit<2>>::ZERO;
//! consumption.priority_fee = Amount::new(1_000_000);
//! ```
//!
//! ```compile_fail,E0616
//! use selendra_modules_api::transaction::TransactionConsumption;
//! use selendra_modules_api::GasUnit;
//!
//! let mut consumption = TransactionConsumption::<GasUnit<2>>::ZERO;
//! consumption.base_fee = GasUnit::from([1, 1]);
//! ```
//!
//! ```compile_fail,E0616
//! use selendra_modules_api::transaction::TransactionConsumption;
//! use selendra_modules_api::{Amount, GasPrice, GasUnit};
//!
//! let mut consumption = TransactionConsumption::<GasUnit<2>>::ZERO;
//! consumption.gas_price = GasPrice::from([Amount::new(1), Amount::new(1)]);
//! ```
//!
//! ```compile_fail,E0599
//! use selendra_modules_api::transaction::TransactionConsumption;
//! use selendra_modules_api::{Amount, GasPrice, GasUnit};
//!
//! let consumption = TransactionConsumption::<GasUnit<2>>::new(
//!     Amount::new(1_000_000),
//!     GasUnit::from([0, 0]),
//!     Amount::ZERO,
//!     Amount::ZERO,
//!     GasPrice::from([Amount::ZERO, Amount::ZERO]),
//! );
//! ```
//!
//! ```compile_fail,E0277
//! use selendra_modules_api::transaction::SequencerReward;
//!
//! let reward: SequencerReward = borsh::from_slice(&[0xff; 16]).unwrap();
//! ```
//!
//! ```compile_fail,E0277
//! use selendra_modules_api::transaction::SequencerReward;
//!
//! let reward: SequencerReward = serde_json::from_str("\"1000000\"").unwrap();
//! ```
//!
//! ```compile_fail,E0277
//! use selendra_modules_api::transaction::TransactionConsumption;
//! use selendra_modules_api::GasUnit;
//!
//! let consumption: TransactionConsumption<GasUnit<2>> = serde_json::from_str("{}").unwrap();
//! ```
//!
//! They are computed from a meter instead (the compiling twin), and serialize (for display):
//!
//! ```
//! use selendra_modules_api::test_utils::TestSpec;
//! use selendra_modules_api::transaction::{SequencerReward, TransactionConsumption};
//! use selendra_modules_api::{Amount, BasicGasMeter, GasPrice, GasUnit, PriorityFeeBips};
//!
//! let meter = BasicGasMeter::<TestSpec>::new_with_funds_and_gas(
//!     Amount::new(100),
//!     GasUnit::from([1_000, 1_000]),
//!     GasPrice::from([Amount::new(1), Amount::new(1)]),
//! );
//! let consumption: TransactionConsumption<GasUnit<2>> =
//!     TransactionConsumption::from_meter(&meter, PriorityFeeBips::ZERO);
//! assert_eq!(consumption.remaining_funds().amount(), Amount::new(100));
//! assert_eq!(consumption.base_fee_value().amount(), Amount::ZERO);
//! assert_eq!(consumption.priority_fee().amount(), Amount::ZERO);
//! let mut total = SequencerReward::ZERO;
//! total.accumulate(consumption.priority_fee());
//! assert_eq!(total, SequencerReward::ZERO);
//! assert!(serde_json::to_string(&consumption).is_ok());
//! assert!(serde_json::to_string(&total).is_ok());
//! // An amount itself decodes: only the reward types do not.
//! let amount: Amount = borsh::from_slice(&[0xff; 16]).unwrap();
//! assert_eq!(amount, Amount::new(u128::MAX));
//! let amount: Amount = serde_json::from_str("\"1000000\"").unwrap();
//! assert_eq!(amount, Amount::new(1_000_000));
//! ```

use core::fmt;

use crate::{Amount, BasicGasMeter, Gas, GasArray, PriorityFeeBips, Spec};

/// The resources a transaction consumed and what its fees pay: the base fee (to the prover),
/// the priority fee (to the sequencer) and the funds left to refund.
///
/// Computed from the transaction's meter ([`from_meter`](Self::from_meter)) at the end of the
/// transaction; serialized only for display.
#[derive(PartialEq, Eq, Debug, Clone, Copy, serde::Serialize)]
#[serde(bound = "GU: serde::Serialize")]
pub struct TransactionConsumption<GU: Gas> {
    remaining_funds: Amount,
    base_fee: GU,
    base_fee_value: Amount,
    priority_fee: Amount,
    gas_price: GU::Price,
}

impl<GU: Gas> fmt::Display for TransactionConsumption<GU> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl<GU: Gas> TransactionConsumption<GU> {
    /// Nothing consumed, nothing paid (an ignored transaction).
    pub const ZERO: Self = Self {
        remaining_funds: Amount::ZERO,
        base_fee: GU::ZEROED,
        base_fee_value: Amount::ZERO,
        priority_fee: Amount::ZERO,
        gas_price: <GU::Price as GasArray>::ZEROED,
    };

    /// What a transaction metered by `meter` consumed, with at most `max_priority_fee_bips` of
    /// the base fee as the sequencer's tip:
    /// - the base fee is the gas used, worth its value at the meter's price;
    /// - the tip is `max_priority_fee_bips` of that value (rounded down), at most the funds
    ///   left;
    /// - the funds left are the meter's funds minus the tip. A meter without a funds budget
    ///   reserved nothing: no tip, nothing to refund.
    ///
    /// The meter keeps the value of the gas used computable and at most its funds, so nothing
    /// here overflows (upstream recomputed the value and `expect`ed it).
    pub fn from_meter<S: Spec<Gas = GU>>(
        meter: &BasicGasMeter<S>,
        max_priority_fee_bips: PriorityFeeBips,
    ) -> Self {
        let info = meter.gas_info();
        let funds_left = meter.remaining_funds().unwrap_or(Amount::ZERO);
        // A tip too large to compute would be capped by the funds left anyway.
        let tip = max_priority_fee_bips
            .apply(info.gas_value)
            .unwrap_or(funds_left);
        let priority_fee = core::cmp::min(tip, funds_left);
        Self {
            remaining_funds: funds_left.saturating_sub(priority_fee),
            base_fee: info.gas_used,
            base_fee_value: info.gas_value,
            priority_fee,
            gas_price: info.gas_price,
        }
    }

    /// The base fee: the gas used, per dimension.
    pub const fn base_fee(&self) -> &GU {
        &self.base_fee
    }

    /// The gas price the transaction paid.
    pub fn gas_price(&self) -> GU::Price {
        self.gas_price
    }

    /// The base fee's value in gas tokens: the prover's reward.
    pub const fn base_fee_value(&self) -> ProverReward {
        ProverReward(self.base_fee_value)
    }

    /// The priority fee: the sequencer's reward.
    pub const fn priority_fee(&self) -> SequencerReward {
        SequencerReward(self.priority_fee)
    }

    /// The funds left: refunded to the payer.
    pub const fn remaining_funds(&self) -> RemainingFunds {
        RemainingFunds(self.remaining_funds)
    }
}

/// The prover's reward: a transaction's base fee value
/// ([`TransactionConsumption::base_fee_value`]).
#[derive(Copy, Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProverReward(Amount);

/// The funds a transaction did not spend, refunded to its payer
/// ([`TransactionConsumption::remaining_funds`]).
#[derive(Copy, Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RemainingFunds(Amount);

/// The sequencer's reward: a transaction's priority fee
/// ([`TransactionConsumption::priority_fee`]), or the sum of several
/// ([`accumulate`](Self::accumulate)).
///
/// Upstream's also decoded (borsh and serde), so a value could be built from any bytes.
#[derive(Copy, Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SequencerReward(Amount);

impl ProverReward {
    /// The amount.
    pub const fn amount(&self) -> Amount {
        self.0
    }
}

impl RemainingFunds {
    /// The amount.
    pub const fn amount(&self) -> Amount {
        self.0
    }
}

impl SequencerReward {
    /// No reward: the start of a sum.
    pub const ZERO: Self = Self(Amount::ZERO);

    /// The amount.
    pub const fn amount(&self) -> Amount {
        self.0
    }

    /// Adds `other` to this reward (saturating: the sum of a block's priority fees is at most
    /// the funds its transactions reserved).
    pub fn accumulate(&mut self, other: Self) {
        self.0 = self.0.saturating_add(other.0);
    }
}

impl fmt::Display for ProverReward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProverReward({})", self.0)
    }
}

impl fmt::Display for RemainingFunds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RemainingFunds({})", self.0)
    }
}

impl fmt::Display for SequencerReward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SequencerReward({})", self.0)
    }
}

impl From<ProverReward> for Amount {
    fn from(reward: ProverReward) -> Self {
        reward.0
    }
}

impl From<RemainingFunds> for Amount {
    fn from(funds: RemainingFunds) -> Self {
        funds.0
    }
}

impl From<SequencerReward> for Amount {
    fn from(reward: SequencerReward) -> Self {
        reward.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestSpec;
    use crate::{GasPrice, GasUnit};

    const REMAINING_FUNDS: u64 = 100;

    fn meter(funds: u64, used: [u64; 2]) -> BasicGasMeter<TestSpec> {
        let mut meter = BasicGasMeter::<TestSpec>::new_with_funds_and_gas(
            Amount::from(funds),
            GasUnit::from([1_000, 1_000]),
            GasPrice::from([Amount::new(1); 2]),
        );
        meter.charge_gas(GasUnit::from(used)).unwrap();
        meter
    }

    /// Upstream: `test_compute_transaction_reward_consume_all_gas`. All the funds go to gas:
    /// the reward is the base fee, no tip.
    #[test]
    fn consume_all_gas() {
        let consumption = TransactionConsumption::from_meter(
            &meter(REMAINING_FUNDS, [REMAINING_FUNDS / 2; 2]),
            PriorityFeeBips::from_percentage(10).unwrap(),
        );
        assert_eq!(
            consumption,
            TransactionConsumption {
                remaining_funds: Amount::ZERO,
                base_fee: GasUnit::from([REMAINING_FUNDS / 2; 2]),
                base_fee_value: Amount::from(REMAINING_FUNDS),
                priority_fee: Amount::ZERO,
                gas_price: GasPrice::from([Amount::new(1); 2])
            }
        );
        assert_eq!(
            consumption.base_fee_value().amount(),
            Amount::from(REMAINING_FUNDS)
        );
    }

    /// Upstream: `test_compute_transaction_reward_consume_not_all_gas`. Half the funds go to
    /// gas, a 100% tip takes the other half.
    #[test]
    fn consume_not_all_gas() {
        let consumption = TransactionConsumption::from_meter(
            &meter(REMAINING_FUNDS, [REMAINING_FUNDS / 4; 2]),
            PriorityFeeBips::from_percentage(100).unwrap(),
        );
        assert_eq!(
            consumption,
            TransactionConsumption {
                remaining_funds: Amount::ZERO,
                base_fee: GasUnit::from([REMAINING_FUNDS / 4; 2]),
                base_fee_value: Amount::new(50),
                priority_fee: Amount::new(50),
                gas_price: GasPrice::from([Amount::new(1); 2])
            }
        );
        // A 10% tip: 5 of the 50 left; 45 refunded.
        let consumption = TransactionConsumption::from_meter(
            &meter(REMAINING_FUNDS, [REMAINING_FUNDS / 4; 2]),
            PriorityFeeBips::from_percentage(10).unwrap(),
        );
        assert_eq!(consumption.priority_fee().amount(), Amount::new(5));
        assert_eq!(consumption.remaining_funds().amount(), Amount::new(45));
        assert_eq!(consumption.base_fee(), &GasUnit::from([25, 25]));
        assert_eq!(consumption.gas_price(), GasPrice::from([Amount::new(1); 2]));
    }

    /// A tip too large to compute is capped by the funds left; a meter without funds tips and
    /// refunds nothing.
    #[test]
    fn tip_is_capped_by_the_funds_left() {
        let consumption =
            TransactionConsumption::from_meter(&meter(1_000, [10, 10]), PriorityFeeBips(u64::MAX));
        assert_eq!(consumption.priority_fee().amount(), Amount::new(980));
        assert_eq!(consumption.remaining_funds().amount(), Amount::ZERO);

        let mut unfunded = BasicGasMeter::<TestSpec>::new_with_gas(
            GasUnit::from([1_000, 1_000]),
            GasPrice::from([Amount::new(1); 2]),
        );
        unfunded.charge_gas(GasUnit::from([5, 5])).unwrap();
        let consumption = TransactionConsumption::from_meter(
            &unfunded,
            PriorityFeeBips::from_percentage(10).unwrap(),
        );
        assert_eq!(consumption.base_fee_value().amount(), Amount::new(10));
        assert_eq!(consumption.priority_fee(), SequencerReward::ZERO);
        assert_eq!(consumption.remaining_funds().amount(), Amount::ZERO);
        assert_eq!(
            TransactionConsumption::<GasUnit<2>>::ZERO
                .base_fee_value()
                .amount(),
            Amount::ZERO
        );
    }

    /// Upstream: `test_display_transaction_reward` (with the base fee value).
    #[test]
    fn display_transaction_consumption() {
        let consumption = TransactionConsumption::<GasUnit<2>> {
            remaining_funds: Amount::new(10),
            base_fee: GasUnit::from([100; 2]),
            base_fee_value: Amount::new(200),
            priority_fee: Amount::new(50),
            gas_price: GasPrice::from([Amount::new(1); 2]),
        };
        assert_eq!(
            format!("{consumption}"),
            "TransactionConsumption { remaining_funds: 10, base_fee: GasUnit[100, 100], \
             base_fee_value: 200, priority_fee: 50, gas_price: GasPrice[1, 1] }"
        );
    }

    /// Upstream: `test_display_sequencer_reward`, `test_display_prover_reward`,
    /// `test_display_remaining_funds`.
    #[test]
    fn display_rewards() {
        assert_eq!(
            SequencerReward(Amount::new(100)).to_string(),
            "SequencerReward(100)"
        );
        assert_eq!(
            ProverReward(Amount::new(100)).to_string(),
            "ProverReward(100)"
        );
        assert_eq!(
            RemainingFunds(Amount::new(100)).to_string(),
            "RemainingFunds(100)"
        );
        let mut sum = SequencerReward::ZERO;
        sum.accumulate(SequencerReward(Amount::new(7)));
        sum.accumulate(SequencerReward(Amount::MAX));
        assert_eq!(Amount::from(sum), Amount::MAX);
        assert_eq!(Amount::from(ProverReward(Amount::new(3))), Amount::new(3));
        assert_eq!(Amount::from(RemainingFunds(Amount::new(4))), Amount::new(4));
    }
}

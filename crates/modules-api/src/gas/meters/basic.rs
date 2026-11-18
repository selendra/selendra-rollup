//! [`BasicGasMeter`]: a transaction's gas meter.

use selendra_state::metered::StateGasMeter;

use crate::{Amount, Gas, GasArray, GasMeteringError, Spec};

/// The gas used by a meter and its value at the meter's price.
///
/// `gas_value == gas_used.checked_value(gas_price)` (the meter refuses a charge that would make
/// it overflow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasInfo<GU: Gas> {
    /// `gas_used · gas_price`, in tokens.
    pub gas_value: Amount,
    /// The gas used, per dimension.
    pub gas_used: GU,
    /// The gas price, per dimension.
    pub gas_price: GU::Price,
}

/// A gas meter with a gas limit and, optionally, a budget of funds (the transaction's
/// `max_fee`): a charge must fit in both.
///
/// The fields are private (upstream's were `pub`, and `GasMeter::try_as_basic_gas_meter` handed
/// any module a `&mut` to them: a module could mint itself gas, or make `remaining > initial`,
/// which crashed `gas_info` with an `expect`; P5-16). The meter changes only through
/// [`charge_gas`](Self::charge_gas)/[`charge_linear_gas`](Self::charge_linear_gas), which are
/// atomic: a refused charge changes nothing. So `remaining_gas + gas_used == initial_gas` in
/// every dimension, always.
///
/// ```compile_fail,E0616
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_modules_api::*;
///
/// let mut meter = BasicGasMeter::<TestSpec>::new_with_gas(GasUnit::from([10, 10]), GasPrice::ZEROED);
/// meter.remaining_gas = GasUnit::MAX;
/// ```
///
/// The crate root's traits are all in scope (`*`), so neither an inherent method nor a method of
/// any exported trait (S6's module-facing `GasMeter`, upstream's home of the method) can bring it
/// back unnoticed:
///
/// ```compile_fail,E0599
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_modules_api::*;
///
/// let mut meter = BasicGasMeter::<TestSpec>::new_with_gas(GasUnit::from([10, 10]), GasPrice::ZEROED);
/// let _ = meter.try_as_basic_gas_meter();
/// ```
///
/// What it offers instead, read-only:
///
/// ```
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_modules_api::*;
///
/// let mut meter = BasicGasMeter::<TestSpec>::new_with_gas(GasUnit::from([10, 10]), GasPrice::ZEROED);
/// meter.charge_gas(GasUnit::from([3, 4])).unwrap();
/// assert_eq!(meter.remaining_gas(), GasUnit::from([7, 6]));
/// assert_eq!(meter.gas_used(), GasUnit::from([3, 4]));
/// ```
#[derive(Debug, Clone)]
pub struct BasicGasMeter<S: Spec> {
    initial_gas: S::Gas,
    remaining_gas: S::Gas,
    gas_used: S::Gas,
    gas_value: Amount,
    remaining_funds: Option<Amount>,
    gas_price: <S::Gas as Gas>::Price,
}

impl<S: Spec> BasicGasMeter<S> {
    /// A meter with `remaining_gas` and no funds budget.
    pub fn new_with_gas(remaining_gas: S::Gas, gas_price: <S::Gas as Gas>::Price) -> Self {
        Self {
            initial_gas: remaining_gas,
            remaining_gas,
            gas_used: S::Gas::ZEROED,
            gas_value: Amount::ZERO,
            remaining_funds: None,
            gas_price,
        }
    }

    /// A meter with `remaining_gas` and a budget of `remaining_funds`.
    pub fn new_with_funds_and_gas(
        remaining_funds: Amount,
        remaining_gas: S::Gas,
        gas_price: <S::Gas as Gas>::Price,
    ) -> Self {
        Self {
            remaining_funds: Some(remaining_funds),
            ..Self::new_with_gas(remaining_gas, gas_price)
        }
    }

    /// The gas the meter started with.
    pub fn initial_gas(&self) -> S::Gas {
        self.initial_gas
    }

    /// The gas left.
    pub fn remaining_gas(&self) -> S::Gas {
        self.remaining_gas
    }

    /// The gas charged so far.
    pub fn gas_used(&self) -> S::Gas {
        self.gas_used
    }

    /// The funds left, if the meter has a budget.
    pub fn remaining_funds(&self) -> Option<Amount> {
        self.remaining_funds
    }

    /// The meter's gas price.
    pub fn gas_price(&self) -> <S::Gas as Gas>::Price {
        self.gas_price
    }

    /// The gas used and its value.
    pub fn gas_info(&self) -> GasInfo<S::Gas> {
        GasInfo {
            gas_value: self.gas_value,
            gas_used: self.gas_used,
            gas_price: self.gas_price,
        }
    }

    /// Charges `amount`.
    ///
    /// # Errors
    /// [`GasMeteringError::OutOfFunds`] if its value exceeds the remaining funds,
    /// [`GasMeteringError::OutOfGas`] if it exceeds the remaining gas in some dimension, and
    /// [`GasMeteringError::Overflow`] if a value cannot be computed. Nothing changes then.
    pub fn charge_gas(&mut self, amount: S::Gas) -> Result<(), GasMeteringError<S::Gas>> {
        let remaining_funds = match self.remaining_funds {
            Some(funds) => {
                let value = amount.checked_value(self.gas_price).ok_or_else(|| {
                    GasMeteringError::Overflow(
                        "Charge Funds: Unable to charge gas, because the calculation overflows"
                            .to_string(),
                    )
                })?;
                Some(
                    funds
                        .checked_sub(value)
                        .ok_or(GasMeteringError::OutOfFunds {
                            amount_to_charge: value,
                            remaining_funds: funds,
                            gas_price: self.gas_price,
                        })?,
                )
            }
            None => None,
        };

        let remaining_gas =
            self.remaining_gas
                .checked_sub(amount)
                .ok_or(GasMeteringError::OutOfGas {
                    gas_to_charge: amount,
                    gas_price: self.gas_price,
                    initial_gas: self.initial_gas,
                    remaining_gas: self.remaining_gas,
                })?;

        // The value of all the gas used must stay computable, so it can always be converted to
        // tokens after execution. (`gas_used + amount <= initial_gas` here, so the sum cannot
        // overflow; the error is only for completeness.)
        let overflow = || {
            GasMeteringError::Overflow(
                "Charge Gas: Unable to charge gas, because the calculation overflows".to_string(),
            )
        };
        let gas_used = self.gas_used.checked_combine(amount).ok_or_else(overflow)?;
        let gas_value = gas_used
            .checked_value(self.gas_price)
            .ok_or_else(overflow)?;

        self.remaining_funds = remaining_funds;
        self.remaining_gas = remaining_gas;
        self.gas_used = gas_used;
        self.gas_value = gas_value;
        Ok(())
    }

    /// Charges `amount · parameter` in every dimension (e.g. a per-byte cost times a length).
    ///
    /// # Errors
    /// As [`charge_gas`](Self::charge_gas), and [`GasMeteringError::Overflow`] if the product
    /// overflows. Nothing changes then.
    pub fn charge_linear_gas(
        &mut self,
        amount: S::Gas,
        parameter: u32,
    ) -> Result<(), GasMeteringError<S::Gas>> {
        let total = amount
            .checked_scalar_product(u64::from(parameter))
            .ok_or_else(|| {
                GasMeteringError::Overflow(format!(
                    "Unable to charge gas. The product of {amount} to {parameter} is overflowing"
                ))
            })?;
        self.charge_gas(total)
    }
}

/// The metered state accessors charge this meter.
impl<S: Spec> StateGasMeter for BasicGasMeter<S> {
    type Gas = S::Gas;
    type Error = GasMeteringError<S::Gas>;

    fn charge(&mut self, gas: S::Gas) -> Result<(), Self::Error> {
        self.charge_gas(gas)
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;
    use crate::test_utils::TestSpec;
    use crate::{GasPrice, GasUnit};

    type S = TestSpec;

    const STANDARD_GAS_PRICE: GasPrice<2> =
        GasPrice::from_dimensions([Amount::new(1), Amount::new(1)]);
    const MAX_GAS_PRICE: GasPrice<2> = GasPrice::from_dimensions([Amount::MAX, Amount::MAX]);

    fn assert_charge_succeeds(meter: &mut BasicGasMeter<S>, gas: GasUnit<2>) {
        assert!(
            meter.charge_gas(gas).is_ok(),
            "It should be possible to charge gas"
        );
    }

    fn assert_charge_fails(meter: &mut BasicGasMeter<S>, gas: GasUnit<2>) {
        assert!(
            meter.charge_gas(gas).is_err(),
            "The gas meter should not be able to charge gas if there is not enough gas reserved"
        );
    }

    fn assert_gas_used_equals(meter: &BasicGasMeter<S>, expected: GasUnit<2>) {
        assert_eq!(meter.gas_info().gas_used, expected);
    }

    #[test]
    fn test_charge_gas_fails_with_zeroed_gas() {
        let mut gas_meter = BasicGasMeter::<S>::new_with_gas(GasUnit::ZEROED, STANDARD_GAS_PRICE);
        assert_charge_fails(&mut gas_meter, GasUnit::from([100; 2]));
    }

    #[test]
    fn test_charge_gas_fails_when_partial_gas_insufficient() {
        let mut gas_meter =
            BasicGasMeter::<S>::new_with_gas(GasUnit::from([1000, 99]), STANDARD_GAS_PRICE);
        assert_charge_fails(&mut gas_meter, GasUnit::from([100; 2]));
    }

    #[test]
    fn test_charge_with_funds_tracks_usage() {
        const REMAINING_FUNDS: u64 = 100;
        let mut gas_meter = BasicGasMeter::<S>::new_with_funds_and_gas(
            Amount::from(REMAINING_FUNDS),
            GasUnit::MAX,
            STANDARD_GAS_PRICE,
        );
        assert_charge_succeeds(&mut gas_meter, GasUnit::from([REMAINING_FUNDS / 2; 2]));
        assert_gas_used_equals(&gas_meter, GasUnit::from([REMAINING_FUNDS / 2; 2]));
        assert_eq!(gas_meter.gas_info().gas_price, STANDARD_GAS_PRICE);
        assert_eq!(gas_meter.gas_info().gas_value, Amount::new(100));
        assert_eq!(gas_meter.remaining_funds(), Some(Amount::ZERO));
        assert!(matches!(
            gas_meter.charge_gas(GasUnit::from([1; 2])),
            Err(GasMeteringError::OutOfFunds { .. })
        ));
    }

    #[test]
    fn test_charge_without_funds_tracks_usage() {
        let remaining_gas = GasUnit::from([100; 2]);
        let mut gas_meter = BasicGasMeter::<S>::new_with_gas(remaining_gas, STANDARD_GAS_PRICE);
        assert_charge_succeeds(&mut gas_meter, remaining_gas);
        assert_gas_used_equals(&gas_meter, remaining_gas);
        assert!(matches!(
            gas_meter.charge_gas(GasUnit::from([1; 2])),
            Err(GasMeteringError::OutOfGas { .. })
        ));
    }

    #[test]
    fn test_charge_gas_prevents_gas_value_overflow() {
        let mut gas_meter = BasicGasMeter::<S>::new_with_gas(GasUnit::MAX, MAX_GAS_PRICE);
        assert_eq!(
            gas_meter.charge_gas(GasUnit::from([2; 2])),
            Err(GasMeteringError::Overflow(
                "Charge Gas: Unable to charge gas, because the calculation overflows".to_string()
            ))
        );
        assert_eq!(gas_meter.gas_used(), GasUnit::ZEROED);
    }

    #[test]
    fn test_charge_gas_prevents_funds_value_overflow() {
        let mut gas_meter = BasicGasMeter::<S>::new_with_funds_and_gas(
            Amount::new(u128::from(u64::MAX)),
            GasUnit::MAX,
            MAX_GAS_PRICE,
        );
        assert_eq!(
            gas_meter.charge_gas(GasUnit::from([2; 2])),
            Err(GasMeteringError::Overflow(
                "Charge Funds: Unable to charge gas, because the calculation overflows".to_string()
            ))
        );
    }

    #[test]
    fn test_charge_gas_atomic_update_on_failure() {
        let remaining_gas = GasUnit::from([5, 5]);
        let remaining_funds = Amount::new(1_000_000);
        let gas_price = GasPrice::<2>::from([Amount::new(10); 2]);
        let mut gas_meter =
            BasicGasMeter::<S>::new_with_funds_and_gas(remaining_funds, remaining_gas, gas_price);

        // Enough funds, not enough gas.
        assert!(gas_meter.charge_gas(GasUnit::from([10; 2])).is_err());
        assert_eq!(gas_meter.remaining_funds(), Some(remaining_funds));
        assert_eq!(gas_meter.remaining_gas(), remaining_gas);
    }

    #[test]
    fn test_charge_linear_gas() {
        let mut gas_meter =
            BasicGasMeter::<S>::new_with_gas(GasUnit::from([1000; 2]), STANDARD_GAS_PRICE);
        assert!(
            gas_meter
                .charge_linear_gas(GasUnit::from([10; 2]), 5)
                .is_ok()
        );
        assert_gas_used_equals(&gas_meter, GasUnit::from([50; 2]));
        assert!(
            gas_meter
                .charge_linear_gas(GasUnit::from([10; 2]), 0)
                .is_ok()
        );
        assert_gas_used_equals(&gas_meter, GasUnit::from([50; 2]));
        // 10 · 100 = 1000 > 950 left.
        assert!(matches!(
            gas_meter.charge_linear_gas(GasUnit::from([10; 2]), 100),
            Err(GasMeteringError::OutOfGas { .. })
        ));
        assert!(matches!(
            gas_meter.charge_linear_gas(GasUnit::MAX, 2),
            Err(GasMeteringError::Overflow(_))
        ));
        assert_gas_used_equals(&gas_meter, GasUnit::from([50; 2]));
    }

    #[test]
    fn state_gas_meter_charges_the_same() {
        let mut meter =
            BasicGasMeter::<S>::new_with_gas(GasUnit::from([10; 2]), STANDARD_GAS_PRICE);
        StateGasMeter::charge(&mut meter, GasUnit::from([4, 6])).unwrap();
        assert_eq!(meter.remaining_gas(), GasUnit::from([6, 4]));
        assert!(StateGasMeter::charge(&mut meter, GasUnit::from([0, 5])).is_err());
        assert_eq!(meter.remaining_gas(), GasUnit::from([6, 4]));
    }

    // Regressions of upstream's `BasicGasMeter` bugs

    /// P5-16 (regression, invariant): the invariant upstream's public fields let a module break (after which
    /// `gas_info` panicked): whatever is charged, a refused charge changes nothing and
    /// `remaining <= initial` (with `remaining + used == initial`) always holds. The regression
    /// tests of the fix itself are the `compile_fail` doctests on [`BasicGasMeter`] (E0616,
    /// E0599).
    #[proptest]
    fn remaining_never_exceeds_initial(
        initial: [u64; 2],
        funds: Option<u128>,
        price: [u128; 2],
        charges: Vec<([u64; 2], u32)>,
    ) {
        let price = GasPrice::<2>::from(price.map(Amount::new));
        let initial = GasUnit::<2>::from(initial);
        let mut meter = match funds {
            Some(funds) => {
                BasicGasMeter::<S>::new_with_funds_and_gas(Amount::new(funds), initial, price)
            }
            None => BasicGasMeter::<S>::new_with_gas(initial, price),
        };
        for (gas, parameter) in charges {
            let before = meter.clone();
            let result = if parameter % 2 == 0 {
                meter.charge_gas(GasUnit::from(gas))
            } else {
                meter.charge_linear_gas(GasUnit::from(gas), parameter % 4)
            };
            if result.is_err() {
                assert_eq!(meter.remaining_gas(), before.remaining_gas());
                assert_eq!(meter.gas_used(), before.gas_used());
                assert_eq!(meter.remaining_funds(), before.remaining_funds());
                assert_eq!(meter.gas_info(), before.gas_info());
            }
            assert!(meter.remaining_gas().dim_is_less_or_eq(meter.initial_gas()));
            assert_eq!(
                meter.remaining_gas().checked_combine(meter.gas_used()),
                Some(meter.initial_gas())
            );
            assert_eq!(
                meter.gas_used().checked_value(meter.gas_price()),
                Some(meter.gas_info().gas_value)
            );
        }
    }
}

//! [`SlotGasMeter`]: a slot's (rollup block's) gas meter.

use selendra_interface::da::DaSpec;

use crate::{GasArray, GasMeteringError, PREFERRED_DATA_FRACTION, SlotOutOfGasDetails, Spec};

/// The gas of one slot, shared by its batches and proofs.
///
/// The preferred sequencer may use at most [`PREFERRED_DATA_FRACTION`] of the slot's gas; its
/// charges count against both its own budget and the slot's, other sequencers' charges against
/// the slot's only. So the preferred sequencer cannot use up a slot alone (other sequencers and
/// forced registrations keep the rest).
///
/// The limit is a value, not a constant: the block gas limit is runtime state (Phase 6's
/// `fee-params`).
#[derive(Debug, Clone)]
pub struct SlotGasMeter<S: Spec> {
    preferred_sequencer: Option<<S::Da as DaSpec>::Address>,
    initial_slot_gas: S::Gas,
    remaining_preferred_slot_gas: S::Gas,
    remaining_total_slot_gas: S::Gas,
    total_gas_used: S::Gas,
}

impl<S: Spec> SlotGasMeter<S> {
    /// A meter for a slot with `slot_gas_limit`, whose preferred sequencer (if any) may use
    /// [`PREFERRED_DATA_FRACTION`] of it.
    pub fn new(
        slot_gas_limit: S::Gas,
        preferred_sequencer: Option<<S::Da as DaSpec>::Address>,
    ) -> Self {
        Self {
            preferred_sequencer,
            initial_slot_gas: slot_gas_limit,
            remaining_preferred_slot_gas: PREFERRED_DATA_FRACTION.of(slot_gas_limit),
            remaining_total_slot_gas: slot_gas_limit,
            total_gas_used: S::Gas::ZEROED,
        }
    }

    /// The slot's gas limit.
    pub fn initial_slot_gas(&self) -> S::Gas {
        self.initial_slot_gas
    }

    /// The gas `sequencer` may still use: the preferred sequencer's budget for it, the slot's
    /// for anyone else.
    pub fn remaining_slot_gas(&self, sequencer: &<S::Da as DaSpec>::Address) -> S::Gas {
        if self.is_preferred(sequencer) {
            self.remaining_preferred_slot_gas
        } else {
            self.remaining_total_slot_gas
        }
    }

    /// The preferred sequencer's remaining budget.
    pub fn remaining_preferred_slot_gas(&self) -> S::Gas {
        self.remaining_preferred_slot_gas
    }

    /// The gas used in the slot so far.
    pub fn total_gas_used(&self) -> S::Gas {
        self.total_gas_used
    }

    /// Charges `gas` for `sequencer`.
    ///
    /// # Errors
    /// [`GasMeteringError::SlotOutOfGas`] if the preferred sequencer's budget or the slot's gas
    /// is too small. A refused charge changes neither budget (upstream took the preferred
    /// sequencer's share before checking the slot's, and kept it when that check failed).
    pub fn charge_gas(
        &mut self,
        gas: S::Gas,
        sequencer: &<S::Da as DaSpec>::Address,
    ) -> Result<(), GasMeteringError<S::Gas>> {
        let remaining_preferred_slot_gas = if self.is_preferred(sequencer) {
            self.remaining_preferred_slot_gas
                .checked_sub(gas)
                .ok_or_else(|| self.gas_error(gas, true))?
        } else {
            self.remaining_preferred_slot_gas
        };
        let remaining_total_slot_gas = self
            .remaining_total_slot_gas
            .checked_sub(gas)
            .ok_or_else(|| self.gas_error(gas, false))?;
        // `total_gas_used + gas <= initial_slot_gas` here, so this cannot overflow.
        let total_gas_used = self.total_gas_used.checked_combine(gas).ok_or_else(|| {
            GasMeteringError::Overflow("Slot gas: the gas used overflows".to_string())
        })?;

        self.remaining_preferred_slot_gas = remaining_preferred_slot_gas;
        self.remaining_total_slot_gas = remaining_total_slot_gas;
        self.total_gas_used = total_gas_used;
        Ok(())
    }

    fn is_preferred(&self, sequencer: &<S::Da as DaSpec>::Address) -> bool {
        self.preferred_sequencer.as_ref() == Some(sequencer)
    }

    fn gas_error(&self, gas_to_charge: S::Gas, is_preferred: bool) -> GasMeteringError<S::Gas> {
        GasMeteringError::SlotOutOfGas(Box::new(SlotOutOfGasDetails {
            initial_slot_gas: self.initial_slot_gas,
            gas_to_charge,
            remaining_preferred_slot_gas: self.remaining_preferred_slot_gas,
            remaining_total_slot_gas: self.remaining_total_slot_gas,
            is_preferred,
        }))
    }
}

#[cfg(test)]
mod tests {
    use selendra_mock_da::MockAddress;

    use super::*;
    use crate::GasUnit;
    use crate::test_utils::TestSpec;

    type S = TestSpec;

    fn assert_charge_succeeds(
        meter: &mut SlotGasMeter<S>,
        gas: GasUnit<2>,
        sequencer: &MockAddress,
    ) {
        assert!(
            meter.charge_gas(gas, sequencer).is_ok(),
            "It should be possible to charge gas"
        );
    }

    #[test]
    fn test_charge_gas_without_preferred_sequencer() {
        let mut slot_gas_meter = SlotGasMeter::<S>::new(GasUnit::from([100, 200]), None);
        let sequencer = MockAddress::new([10; 32]);
        assert_charge_succeeds(&mut slot_gas_meter, GasUnit::from([10, 20]), &sequencer);
        assert_eq!(
            slot_gas_meter.remaining_slot_gas(&sequencer),
            GasUnit::from([90, 180])
        );
        assert_eq!(slot_gas_meter.total_gas_used(), GasUnit::from([10, 20]));
    }

    #[test]
    fn test_charge_gas_from_preferred_sequencer() {
        let preferred_sequencer = MockAddress::new([10; 32]);
        let mut slot_gas_meter =
            SlotGasMeter::<S>::new(GasUnit::from([100, 200]), Some(preferred_sequencer));
        assert_charge_succeeds(
            &mut slot_gas_meter,
            GasUnit::from([10, 20]),
            &preferred_sequencer,
        );
        let expected_preferred_gas = GasUnit::from([80, 160]);
        assert_eq!(
            slot_gas_meter.remaining_slot_gas(&preferred_sequencer),
            expected_preferred_gas
        );
        assert_eq!(
            slot_gas_meter.remaining_preferred_slot_gas(),
            expected_preferred_gas
        );
        assert_eq!(
            slot_gas_meter.remaining_slot_gas(&MockAddress::new([1; 32])),
            GasUnit::from([90, 180])
        );
    }

    #[test]
    fn test_charge_gas_from_non_preferred_does_not_affect_preferred() {
        let preferred_sequencer = MockAddress::new([10; 32]);
        let mut slot_gas_meter =
            SlotGasMeter::<S>::new(GasUnit::from([100, 200]), Some(preferred_sequencer));
        // 90% of 100 = 90, 90% of 200 = 180.
        let initial_preferred_gas = slot_gas_meter.remaining_preferred_slot_gas();
        assert_eq!(initial_preferred_gas, GasUnit::from([90, 180]));

        let other_sequencer = MockAddress::new([33; 32]);
        assert_charge_succeeds(
            &mut slot_gas_meter,
            GasUnit::from([20, 30]),
            &other_sequencer,
        );
        assert_eq!(
            slot_gas_meter.remaining_slot_gas(&other_sequencer),
            GasUnit::from([80, 170])
        );
        assert_eq!(
            slot_gas_meter.remaining_preferred_slot_gas(),
            initial_preferred_gas
        );
    }

    // Regressions of upstream's `SlotGasMeter` bugs

    /// P5-18 (regression): `charge_gas` was not atomic. After other sequencers used most of the
    /// slot, a preferred charge that fit its own budget but not the slot's was refused, yet the
    /// preferred budget had already been reduced.
    #[test]
    fn slot_gas_meter_failed_charge_changes_nothing() {
        let preferred = MockAddress::new([10; 32]);
        let other = MockAddress::new([33; 32]);
        let mut meter = SlotGasMeter::<S>::new(GasUnit::from([100, 100]), Some(preferred));
        assert_charge_succeeds(&mut meter, GasUnit::from([50, 50]), &other);
        // Preferred: 90 left; slot: 50 left.
        let err = meter
            .charge_gas(GasUnit::from([60, 60]), &preferred)
            .unwrap_err();
        assert!(matches!(
            err,
            GasMeteringError::SlotOutOfGas(details) if !details.is_preferred
        ));
        assert_eq!(
            meter.remaining_preferred_slot_gas(),
            GasUnit::from([90, 90])
        );
        assert_eq!(meter.remaining_slot_gas(&other), GasUnit::from([50, 50]));
        assert_eq!(meter.total_gas_used(), GasUnit::from([50, 50]));

        // Refused by the preferred budget: nothing changes either.
        let err = meter
            .charge_gas(GasUnit::from([91, 0]), &preferred)
            .unwrap_err();
        assert!(matches!(
            err,
            GasMeteringError::SlotOutOfGas(details) if details.is_preferred
        ));
        assert_eq!(
            meter.remaining_preferred_slot_gas(),
            GasUnit::from([90, 90])
        );
        assert_eq!(meter.remaining_slot_gas(&other), GasUnit::from([50, 50]));
    }
}

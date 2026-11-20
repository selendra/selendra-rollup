//! The module-facing gas meter ([`GasMeter`]): what module code charges, through the state
//! accessor it was given, and the meters such an accessor can charge ([`TxMeter`]).

use selendra_state::metered::{Metered, StateGas, StateGasMeter};

use crate::state::TxStateError;
use crate::{
    Amount, BasicGasMeter, Gas, GasArray, GasInfo, GasMeteringError, Spec, UnlimitedGasMeter,
};

/// A gas meter a transaction's state accessor charges: a [`StateGasMeter`] with the spec's gas
/// and errors, plus read-only information for [`GasMeter`]'s getters.
///
/// Implemented by [`BasicGasMeter`] (the transaction meters) and [`UnlimitedGasMeter`].
pub trait TxMeter<S: Spec>: StateGasMeter<Gas = S::Gas, Error = GasMeteringError<S::Gas>> {
    /// The gas used so far, its price and its value.
    fn gas_info(&self) -> GasInfo<S::Gas>;

    /// The gas left.
    fn remaining_gas(&self) -> S::Gas;
}

impl<S: Spec> TxMeter<S> for BasicGasMeter<S> {
    fn gas_info(&self) -> GasInfo<S::Gas> {
        BasicGasMeter::gas_info(self)
    }

    fn remaining_gas(&self) -> S::Gas {
        BasicGasMeter::remaining_gas(self)
    }
}

/// Records nothing: no gas used, at a zero price, and the most gas left in every dimension.
impl<S: Spec> TxMeter<S> for UnlimitedGasMeter<S> {
    fn gas_info(&self) -> GasInfo<S::Gas> {
        GasInfo {
            gas_value: Amount::ZERO,
            gas_used: S::Gas::ZEROED,
            gas_price: <S::Gas as Gas>::Price::ZEROED,
        }
    }

    fn remaining_gas(&self) -> S::Gas {
        S::Gas::MAX
    }
}

/// The gas meter module code charges, through its state accessor ([`TxState`](crate::TxState),
/// the pre-execution state): computation, hashing, decoding, anything the state accessors do
/// not charge themselves.
///
/// It has exactly one implementation, a blanket impl over every [`Metered`] accessor whose
/// meter is a [`TxMeter`]: a charge goes to the meter of the metered phase the accessor runs in,
/// and a refused charge **poisons** that phase like a refused state access (every later access
/// fails, and the phase is reverted whatever the module returns). Upstream's `GasMeter` had
/// default bodies that charged nothing, so an accessor that did not override them was free
/// (P5-17); this trait has no default bodies, and another impl for a metered accessor conflicts
/// with the blanket impl (E0119):
///
/// ```compile_fail,E0119
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
///
/// struct Free<'a>(&'a mut WorkingSet<TestSpec>);
///
/// impl Metered for Free<'_> {
/// #   type Storage = <WorkingSet<TestSpec> as Metered>::Storage;
/// #   type Meter = <WorkingSet<TestSpec> as Metered>::Meter;
/// #   type Rights = <WorkingSet<TestSpec> as Metered>::Rights;
/// #   fn metered(&mut self) -> MeteredRef<'_, Self::Storage, Self::Meter, Self::Rights> { self.0.metered() }
/// #   fn metered_view(&self) -> MeteredView<'_, Self::Meter> { self.0.metered_view() }
///     // … forwards to the working set
/// }
///
/// impl GasMeter<TestSpec> for Free<'_> {
///     fn charge_gas(&mut self, _: GasUnit<2>) -> Result<(), TxStateError<TestSpec>> { Ok(()) }
/// #   fn charge_linear_gas(&mut self, _: GasUnit<2>, _: u32) -> Result<(), TxStateError<TestSpec>> { Ok(()) }
/// #   fn gas_info(&self) -> GasInfo<GasUnit<2>> { unimplemented!() }
/// #   fn remaining_gas(&self) -> GasUnit<2> { unimplemented!() }
/// #   fn gas_price(&self) -> GasPrice<2> { unimplemented!() }
///     // …
/// }
/// ```
///
/// The same forwarding accessor without the hand-written impl compiles, and charges the
/// working set's meter:
///
/// ```
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
///
/// struct Forward<'a>(&'a mut WorkingSet<TestSpec>);
///
/// impl Metered for Forward<'_> {
/// #   type Storage = <WorkingSet<TestSpec> as Metered>::Storage;
/// #   type Meter = <WorkingSet<TestSpec> as Metered>::Meter;
/// #   type Rights = <WorkingSet<TestSpec> as Metered>::Rights;
/// #   fn metered(&mut self) -> MeteredRef<'_, Self::Storage, Self::Meter, Self::Rights> { self.0.metered() }
/// #   fn metered_view(&self) -> MeteredView<'_, Self::Meter> { self.0.metered_view() }
///     // … forwards to the working set
/// }
///
/// fn charge(state: &mut Forward<'_>) -> Result<(), TxStateError<TestSpec>> {
///     state.charge_gas(GasUnit::from([1, 1]))
/// }
/// ```
///
/// The meter itself is out of reach: no method hands out the [`BasicGasMeter`] (upstream's
/// `try_as_basic_gas_meter` gave any module a `&mut` to it, to mint gas; P5-16), only the
/// read-only getters below, which read it from `&self` through
/// [`Metered::metered_view`].
pub trait GasMeter<S: Spec>: Metered<Meter: TxMeter<S>> {
    /// Charges `amount`.
    ///
    /// # Errors
    /// The meter refused it ([`StateAccessError::OutOfGas`](selendra_state::StateAccessError)),
    /// or the phase was already poisoned (`Poisoned`). A refusal poisons the phase.
    fn charge_gas(&mut self, amount: S::Gas) -> Result<(), TxStateError<S>>;

    /// Charges `amount · parameter` in every dimension (e.g. a per-byte cost times a length).
    ///
    /// # Errors
    /// As [`charge_gas`](Self::charge_gas), and `GasOverflow` if the product overflows. A
    /// failure poisons the phase.
    fn charge_linear_gas(&mut self, amount: S::Gas, parameter: u32) -> Result<(), TxStateError<S>>;

    /// The gas used so far by the phase, its price and its value.
    fn gas_info(&self) -> GasInfo<S::Gas>;

    /// The gas the phase has left.
    fn remaining_gas(&self) -> S::Gas;

    /// The phase's gas price (upstream `GetGasPrice::gas_price`).
    fn gas_price(&self) -> <S::Gas as Gas>::Price;
}

impl<S: Spec, T> GasMeter<S> for T
where
    T: Metered<Meter: TxMeter<S>>,
{
    fn charge_gas(&mut self, amount: S::Gas) -> Result<(), TxStateError<S>> {
        self.metered().charge(amount)
    }

    fn charge_linear_gas(&mut self, amount: S::Gas, parameter: u32) -> Result<(), TxStateError<S>> {
        self.metered()
            .charge_linear(S::Gas::ZERO, amount, u64::from(parameter))
    }

    fn gas_info(&self) -> GasInfo<S::Gas> {
        self.metered_view().meter().gas_info()
    }

    fn remaining_gas(&self) -> S::Gas {
        self.metered_view().meter().remaining_gas()
    }

    fn gas_price(&self) -> <S::Gas as Gas>::Price {
        self.metered_view().meter().gas_info().gas_price
    }
}

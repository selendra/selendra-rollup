//! [`GasMeteringError`]: why a gas meter refused a charge.

use thiserror::Error;

use crate::{Amount, Gas};

/// Why a gas meter refused a charge. A refused charge changes nothing in the meter.
///
/// The variants holding several gas values keep them in a [`Box`] (`…Details`), so the error
/// stays small (32 bytes on x86-64 for [`GasUnit`](crate::GasUnit)) while keeping every value
/// and message. Every metered state access of a module returns it inside
/// [`TxStateError`](crate::TxStateError), and an error of 128 bytes or more makes clippy's
/// `result_large_err` fire on every function returning it; upstream's unboxed variants made
/// `TxStateError` 128 bytes. A meter creates the error only when it refuses a charge, never on
/// a successful one, so the allocation (one small [`Box`] per refused charge) costs nothing
/// that matters. Gas errors are not encoded (no borsh or serde): their shape is no wire or
/// state format.
///
/// ```
/// use selendra_modules_api::{Amount, GasMeteringError, GasPrice, GasUnit, OutOfFundsDetails};
///
/// let price = GasPrice::from_dimensions([Amount::new(10), Amount::new(11)]);
/// let error = GasMeteringError::<GasUnit<2>>::OutOfFunds(Box::new(OutOfFundsDetails {
///     amount_to_charge: Amount::new(158),
///     remaining_funds: Amount::new(12),
///     gas_price: price,
/// }));
/// let GasMeteringError::OutOfFunds(details) = &error else {
///     unreachable!()
/// };
/// assert_eq!(details.remaining_funds, Amount::new(12));
/// assert_eq!(
///     error.to_string(),
///     "The amount to charge is greater than the funds available in the meter. \
///      Amount to charge 158, remaining_funds 12, price GasPrice[10, 11]"
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GasMeteringError<GU: Gas> {
    /// The gas or its value cannot be computed (overflow).
    #[error("Gas calculation overflow: {0}")]
    Overflow(String),
    /// The slot's gas is exhausted.
    #[error(
        "The slot gas limit has been exhausted. Initial slot gas: {}, gas to charge {}, remaining total slot gas {}, remaining preferred slot gas {}, is preferred {}",
        .0.initial_slot_gas,
        .0.gas_to_charge,
        .0.remaining_total_slot_gas,
        .0.remaining_preferred_slot_gas,
        .0.is_preferred
    )]
    SlotOutOfGas(Box<SlotOutOfGasDetails<GU>>),
    /// Data to charge for has an invalid length.
    #[error("Unable to deserialize data due to invalid length: {0}")]
    InvalidLength(String),
    /// The meter has less gas left than the charge, in some dimension.
    #[error(
        "The gas to charge is greater than the funds available in the meter. Gas to charge {}, gas price {}, initial_gas {}, remaining gas {}",
        .0.gas_to_charge,
        .0.gas_price,
        .0.initial_gas,
        .0.remaining_gas
    )]
    OutOfGas(Box<OutOfGasDetails<GU>>),
    /// The meter has fewer funds left than the charge's value.
    #[error(
        "The amount to charge is greater than the funds available in the meter. Amount to charge {}, remaining_funds {}, price {}",
        .0.amount_to_charge,
        .0.remaining_funds,
        .0.gas_price
    )]
    OutOfFunds(Box<OutOfFundsDetails<GU>>),
    /// A refund is larger than the gas used.
    #[error(
        "The gas to refund is greater than the gas used. Gas to refund {}, gas used {}",
        .0.gas_to_refund,
        .0.gas_used
    )]
    ImpossibleToRefundGas(Box<ImpossibleToRefundGasDetails<GU>>),
}

/// [`GasMeteringError::SlotOutOfGas`]'s values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotOutOfGasDetails<GU: Gas> {
    /// The slot's gas limit.
    pub initial_slot_gas: GU,
    /// The gas to charge.
    pub gas_to_charge: GU,
    /// The preferred sequencer's remaining gas.
    pub remaining_preferred_slot_gas: GU,
    /// The slot's remaining gas.
    pub remaining_total_slot_gas: GU,
    /// Whether the charge was for the preferred sequencer.
    pub is_preferred: bool,
}

/// [`GasMeteringError::OutOfGas`]'s values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutOfGasDetails<GU: Gas> {
    /// The gas to charge.
    pub gas_to_charge: GU,
    /// The meter's gas price.
    pub gas_price: GU::Price,
    /// The meter's initial gas.
    pub initial_gas: GU,
    /// The meter's remaining gas.
    pub remaining_gas: GU,
}

/// [`GasMeteringError::OutOfFunds`]'s values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutOfFundsDetails<GU: Gas> {
    /// The charge's value.
    pub amount_to_charge: Amount,
    /// The meter's remaining funds.
    pub remaining_funds: Amount,
    /// The meter's gas price.
    pub gas_price: GU::Price,
}

/// [`GasMeteringError::ImpossibleToRefundGas`]'s values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpossibleToRefundGasDetails<GU: Gas> {
    /// The gas to refund.
    pub gas_to_refund: GU,
    /// The gas used so far.
    pub gas_used: GU,
}

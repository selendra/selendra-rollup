//! [`GasMeteringError`]: why a gas meter refused a charge.

use thiserror::Error;

use crate::{Amount, Gas};

/// Why a gas meter refused a charge. A refused charge changes nothing in the meter.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GasMeteringError<GU: Gas> {
    /// The gas or its value cannot be computed (overflow).
    #[error("Gas calculation overflow: {0}")]
    Overflow(String),
    /// The slot's gas is exhausted.
    #[error(
        "The slot gas limit has been exhausted. Initial slot gas: {initial_slot_gas}, gas to charge {gas_to_charge}, remaining total slot gas {remaining_total_slot_gas}, remaining preferred slot gas {remaining_preferred_slot_gas}, is preferred {is_preferred}"
    )]
    SlotOutOfGas {
        /// The slot's gas limit.
        initial_slot_gas: GU,
        /// The gas to charge.
        gas_to_charge: GU,
        /// The preferred sequencer's remaining gas.
        remaining_preferred_slot_gas: GU,
        /// The slot's remaining gas.
        remaining_total_slot_gas: GU,
        /// Whether the charge was for the preferred sequencer.
        is_preferred: bool,
    },
    /// Data to charge for has an invalid length.
    #[error("Unable to deserialize data due to invalid length: {0}")]
    InvalidLength(String),
    /// The meter has less gas left than the charge, in some dimension.
    #[error(
        "The gas to charge is greater than the funds available in the meter. Gas to charge {gas_to_charge}, gas price {gas_price}, initial_gas {initial_gas}, remaining gas {remaining_gas}"
    )]
    OutOfGas {
        /// The gas to charge.
        gas_to_charge: GU,
        /// The meter's gas price.
        gas_price: GU::Price,
        /// The meter's initial gas.
        initial_gas: GU,
        /// The meter's remaining gas.
        remaining_gas: GU,
    },
    /// The meter has fewer funds left than the charge's value.
    #[error(
        "The amount to charge is greater than the funds available in the meter. Amount to charge {amount_to_charge}, remaining_funds {remaining_funds}, price {gas_price}"
    )]
    OutOfFunds {
        /// The charge's value.
        amount_to_charge: Amount,
        /// The meter's remaining funds.
        remaining_funds: Amount,
        /// The meter's gas price.
        gas_price: GU::Price,
    },
    /// A refund is larger than the gas used.
    #[error(
        "The gas to refund is greater than the gas used. Gas to refund {gas_to_refund}, gas used {gas_used}"
    )]
    ImpossibleToRefundGas {
        /// The gas to refund.
        gas_to_refund: GU,
        /// The gas used so far.
        gas_used: GU,
    },
}

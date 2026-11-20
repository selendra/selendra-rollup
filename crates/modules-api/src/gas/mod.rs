//! Gas: multi-dimensional gas amounts and prices ([`GasUnit`], [`GasPrice`]), the meters that
//! count them ([`BasicGasMeter`], [`SlotGasMeter`], [`UnlimitedGasMeter`]) and a block's gas
//! record ([`BlockGasInfo`]).
//!
//! All gas arithmetic is checked: an overflow is an error or `None`, never a wrap or a panic.
//! The meters are also what the metered state accessors charge
//! ([`StateGasMeter`](selendra_state::metered::StateGasMeter)), with costs from the spec's
//! [`GasSchedule`](crate::GasSchedule). Module code charges through its state accessor
//! ([`GasMeter`]), and hashes, reads and decodes with the metered utilities ([`MeteredHasher`],
//! [`MeteredReader`], [`MeteredBorshDeserialize`]).

mod block_info;
mod error;
pub(crate) mod impl_macros;
mod meter;
mod metered_reader;
mod metered_utils;
mod meters;
mod price;
mod traits;
mod unit;

#[cfg(test)]
mod tests;

pub use block_info::BlockGasInfo;
pub use error::{
    GasMeteringError, ImpossibleToRefundGasDetails, OutOfFundsDetails, OutOfGasDetails,
    SlotOutOfGasDetails,
};
pub use meter::{GasMeter, TxMeter};
pub use metered_reader::MeteredReader;
pub use metered_utils::{MeteredBorshDeserialize, MeteredBorshDeserializeError, MeteredHasher};
pub use meters::{BasicGasMeter, GasInfo, SlotGasMeter, UnlimitedGasMeter};
pub use price::GasPrice;
pub use traits::{Fraction, GAS_DIMENSIONS, Gas, GasArray, PREFERRED_DATA_FRACTION};
pub use unit::GasUnit;

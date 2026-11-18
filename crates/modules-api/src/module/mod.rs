//! The [`Spec`] every module is generic over, the chain's [`SelendraSpec`] with its
//! [`GasSchedule`], and how accounts are derived from credentials ([`Credential`],
//! [`AccountAddress`]).

mod credential;
mod gas_schedule;
mod spec;

pub use credential::{AccountAddress, Credential};
pub use gas_schedule::{GasSchedule, SELENDRA_GAS_SCHEDULE, SchemeCosts};
pub use spec::{CryptoSpecExt, SelendraSpec, Spec};

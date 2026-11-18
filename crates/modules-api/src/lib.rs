//! The Selendra module system's API: what modules, the runtime and the state transition function
//! are written against.
//!
//! So far:
//! - [`gas`]: multi-dimensional gas ([`GasUnit`], [`GasPrice`]), the meters ([`BasicGasMeter`]
//!   for one transaction, [`SlotGasMeter`] for a block, [`UnlimitedGasMeter`]) and a block's gas
//!   record ([`BlockGasInfo`]);
//! - [`module`]: the [`Spec`] trait every module is generic over, the chain's [`SelendraSpec`],
//!   its per-operation [`GasSchedule`], and how an account is derived from the key that signs
//!   ([`Credential`], [`AccountAddress`]);
//! - [`common`]: token amounts ([`Amount`]), 32-byte ids shown as bech32m ([`hash32_id!`],
//!   [`ModuleId`]), module errors ([`ModuleError`], [`ErrorDetail`]) and the cryptography
//!   bounds of the module system ([`PublicKeyExt`], [`SignatureExt`]);
//! - [`runtime`] ([`OperatingMode`]) and [`transaction`] ([`PriorityFeeBips`]).
//!
//! Every type that is stored or signed is a consensus type
//! ([`ConsensusType`](selendra_interface::common::ConsensusType)); encodings are in
//! `docs/serialization.md`, "Module system types".
//!
//! # Features
//! - `native`: node-only code, never compiled into the zk guest (`PrivateKeyExt`).
//! - `arbitrary`: `arbitrary::Arbitrary` and proptest strategies for this crate's types.
//! - `test-utils`: `test_utils`, spec aliases over the mock DA, the mock zkVM and
//!   `selendra-state`'s in-memory `TestStorage`. Never in a node or guest build.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// The module system's derives (Phase 5's `selendra-macros`) name this crate by its path; this
// lets them be used inside it too.
extern crate self as selendra_modules_api;

pub mod common;
mod consensus_types;
pub mod gas;
pub mod module;
pub mod runtime;
#[cfg(feature = "test-utils")]
pub mod test_utils;
pub mod transaction;

// `selendra-interface/native` marks a node build, where this crate's node-only items are
// expected too. Cargo cannot make the first imply the second (the dependency points the other
// way), so say what to do instead of failing later with missing items.
#[cfg(not(feature = "native"))]
selendra_interface::__if_native! {
    compile_error!(
        "`selendra-interface/native` is enabled but `selendra-modules-api/native` is not: enable both"
    );
}

#[cfg(feature = "native")]
pub use common::PrivateKeyExt;
pub use common::{
    Amount, CoreModuleError, ErrorContext, ErrorDetail, ErrorDetailError, InvalidIdLength,
    ModuleError, ModuleId, NotInstantiable, ParseAmountError, PublicKeyExt, SequencerType,
    SignatureExt, to_json_object,
};
pub use gas::{
    BasicGasMeter, BlockGasInfo, Fraction, GAS_DIMENSIONS, Gas, GasArray, GasInfo,
    GasMeteringError, GasPrice, GasUnit, PREFERRED_DATA_FRACTION, SlotGasMeter, UnlimitedGasMeter,
};
pub use module::{
    AccountAddress, Credential, CryptoSpecExt, GasSchedule, SchemeCosts, SelendraSpec, Spec,
};
pub use runtime::OperatingMode;
pub use transaction::{PriorityFeeApplyOverflowError, PriorityFeeBips};

/// What the macros of this crate (and the module system's derives) expand to. Not public API.
#[doc(hidden)]
pub mod __private {
    #[cfg(feature = "arbitrary")]
    pub use arbitrary;
    #[cfg(feature = "arbitrary")]
    pub use proptest;
    pub use selendra_interface::common::ConsensusType;
    pub use selendra_primitives::bech32;
    pub use {borsh, schemars, serde, serde_json};
}

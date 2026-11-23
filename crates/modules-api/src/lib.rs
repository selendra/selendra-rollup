//! The Selendra module system's API: what modules, the runtime and the state transition function
//! are written against.
//!
//! So far:
//! - [`gas`]: multi-dimensional gas ([`GasUnit`], [`GasPrice`]), the meters ([`BasicGasMeter`]
//!   for one transaction, [`SlotGasMeter`] for a block, [`UnlimitedGasMeter`]), a block's gas
//!   record ([`BlockGasInfo`]), the gas meter module code charges ([`GasMeter`]) and the
//!   metered utilities ([`MeteredHasher`], [`MeteredReader`], [`MeteredBorshDeserialize`]);
//! - [`state`]: the state module code runs on: the transaction accessors ([`WorkingSet`],
//!   [`PreExecWorkingSet`], [`RevertableTxState`], [`GenesisStateAccessor`]), the block hooks'
//!   [`BlockState`], the traits module code is written against ([`TxState`], [`GenesisState`],
//!   [`StateAccessor`]) and events ([`EventContainer`], [`TypeErasedEvent`]);
//! - [`module`]: the traits a module implements ([`ModuleInfo`], [`Module`], with its hooks) and
//!   those built on them ([`Genesis`], [`EventEmitter`]), its calls and events ([`CallMessage`],
//!   [`ModuleEvent`]), what a runtime implements over its modules ([`DispatchCall`],
//!   [`EncodeCall`], [`RuntimeEventProcessor`]), the [`Context`] a call runs with; the [`Spec`]
//!   trait every module is generic over, the chain's [`SelendraSpec`], its per-operation
//!   [`GasSchedule`], and how an account is derived from the key that signs ([`Credential`],
//!   [`AccountAddress`]);
//! - [`hooks`]: a runtime's hooks ([`TxHooks`], [`BlockHooks`], [`FinalizeHook`]);
//! - [`sort_values_by_modules_dependencies`]: the order of the modules' genesis (dependencies
//!   first, [`ModuleDescriptor`]);
//! - [`common`]: token amounts ([`Amount`]), 32-byte ids shown as bech32m ([`hash32_id!`],
//!   [`ModuleId`]), module errors ([`ModuleError`], [`ErrorDetail`]) and the cryptography
//!   bounds of the module system ([`PublicKeyExt`], [`SignatureExt`]);
//! - [`runtime`] ([`OperatingMode`]) and [`transaction`] ([`TxDetails`],
//!   [`AuthenticatedTransactionData`], [`PriorityFeeBips`]).
//!
//! Every type that is stored or signed is a consensus type
//! ([`ConsensusType`](selendra_interface::common::ConsensusType)); encodings are in
//! `docs/serialization.md`, "Module system types".
//!
//! # Features
//! - `native`: node-only code, never compiled into the zk guest (`PrivateKeyExt`), and it keeps
//!   the events module code emits (without it they are charged the same gas, then dropped: the
//!   zk guest keeps none, so a build that reads events needs it).
//! - `arbitrary`: `arbitrary::Arbitrary` and proptest strategies for this crate's types.
//! - `test-utils`: `test_utils`, spec aliases over the mock DA, the mock zkVM and
//!   `selendra-state`'s in-memory `TestStorage`, a spec whose gas costs are all distinct, and a
//!   mock kernel. Never in a node or guest build.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// The module system's derives (Phase 5's `selendra-macros`) name this crate by its path; this
// lets them be used inside it too.
extern crate self as selendra_modules_api;

pub mod common;
mod consensus_types;
mod dependencies;
pub mod gas;
pub mod hooks;
pub mod module;
pub mod runtime;
pub mod state;
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
pub use dependencies::{
    DependencyError, ModuleDescriptor, ModuleKey, sort_values_by_modules_dependencies,
};
pub use gas::{
    BasicGasMeter, BlockGasInfo, Fraction, GAS_DIMENSIONS, Gas, GasArray, GasInfo, GasMeter,
    GasMeteringError, GasPrice, GasUnit, ImpossibleToRefundGasDetails, MeteredBorshDeserialize,
    MeteredBorshDeserializeError, MeteredHasher, MeteredReader, OutOfFundsDetails, OutOfGasDetails,
    PREFERRED_DATA_FRACTION, SlotGasMeter, SlotOutOfGasDetails, TxMeter, UnlimitedGasMeter,
};
pub use hooks::{BlockHooks, FinalizeHook, TxHooks};
pub use module::{
    AccountAddress, CallMessage, Context, Credential, CryptoSpecExt, DispatchCall, EncodeCall,
    EventEmitter, GasSchedule, Genesis, Module, ModuleEvent, ModuleInfo, ModuleMessage,
    RuntimeEventProcessor, SchemeCosts, SelendraSpec, Spec, StateItem,
};
pub use runtime::OperatingMode;
// Where a transaction runs, for `Context` (`selendra-interface`).
pub use selendra_interface::stf::ExecutionContext;
// The metered state access the accessors are built on, for module code (`selendra-state`).
pub use selendra_state::metered::{
    MAX_EVENT_KEY_LEN, Metered, MeteredRef, MeteredView, PhaseOutcome, RevertReason, ScopeEnd,
    StateAccessError, TxRights,
};
pub use selendra_state::{
    AccessoryStateReaderAndWriter, StateReader, StateReaderAndWriter, StateWriter, VersionReader,
};
pub use state::{
    BlockState, EventContainer, FinalizedGenesis, FinalizedPreExec, FinalizedWorkingSet,
    GenesisState, GenesisStateAccessor, InfallibleKernelStateAccessor, InfallibleStateAccessor,
    NotAtGenesis, PreExecWorkingSet, PrivilegedKernelAccessor, RevertableTxState, SpecCheckpoint,
    StateAccessor, TxOutcome, TxState, TxStateError, TypeErasedEvent, WorkingSet,
};
pub use transaction::{
    AuthenticatedTransactionData, PriorityFeeApplyOverflowError, PriorityFeeBips, TxDetails,
};

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

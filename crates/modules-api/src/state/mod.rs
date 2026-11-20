//! The state module code runs on: the transaction accessors ([`WorkingSet`],
//! [`PreExecWorkingSet`], [`RevertableTxState`], [`GenesisStateAccessor`]) and the block hooks'
//! [`BlockState`], the traits module code is written against ([`TxState`], [`GenesisState`],
//! [`StateAccessor`], …), and events ([`EventContainer`], [`TypeErasedEvent`]).
//!
//! # Layers
//! Built on `selendra-state`'s metered state access (`selendra_state::metered`), each layer with
//! one owner that decides whether its writes are kept:
//! 1. the block's [`StateCheckpoint`](selendra_state::StateCheckpoint) (the state transition
//!    function; block hooks get a [`BlockState`] over it);
//! 2. a transaction's [`TxScratchpad`](selendra_state::TxScratchpad) (the state transition
//!    function: pre-execution results, the gas reservation and its settlement);
//! 3. a metered phase: [`PreExecWorkingSet`] (pre-execution) and [`WorkingSet`] (the call and
//!    its hooks), each finalized with its result: committed into the scratchpad only if no
//!    access failed **and** the result is `Ok`;
//! 4. nested scopes: [`RevertableTxState`] ([`TxState::to_revertable`]).
//!
//! Every transaction accessor is [`Metered`](selendra_state::Metered): its readers and writers
//! are `selendra-state`'s blanket impls, which charge gas for every access, and a failed access
//! poisons its phase. Its gas meter ([`GasMeter`](crate::GasMeter)) is a blanket impl too, and
//! events are charged ([`events`]).

mod block;
pub mod events;
mod genesis;
mod pre_exec;
mod revertable;
mod traits;
mod working_set;

#[cfg(test)]
mod tests;

pub use block::BlockState;
pub use events::{EventContainer, TypeErasedEvent};
pub use genesis::{FinalizedGenesis, GenesisStateAccessor, NotAtGenesis};
pub use pre_exec::{FinalizedPreExec, PreExecWorkingSet};
pub use revertable::RevertableTxState;
pub use traits::{
    GenesisState, InfallibleKernelStateAccessor, InfallibleStateAccessor, PrivilegedKernelAccessor,
    SpecCheckpoint, StateAccessor, TxState, TxStateError,
};
pub use working_set::{FinalizedWorkingSet, TxOutcome, WorkingSet};

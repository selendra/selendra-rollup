//! Modules: the traits a module implements ([`ModuleInfo`], [`Module`]) and the ones built on
//! them ([`Genesis`], [`EventEmitter`]); what a runtime implements over its modules
//! ([`DispatchCall`], [`EncodeCall`], [`RuntimeEventProcessor`]); what a transaction's call runs
//! with ([`Context`]); the [`Spec`] every module is generic over, the chain's [`SelendraSpec`]
//! with its [`GasSchedule`], and how accounts are derived from credentials ([`Credential`],
//! [`AccountAddress`]).

mod call;
mod context;
mod credential;
mod dispatch;
mod event;
mod gas_schedule;
mod spec;

#[cfg(test)]
mod tests;

use selendra_interface::da::DaSpec;
use selendra_state::{AccessoryStateReaderAndWriter, Prefix, Storage};

pub use call::CallMessage;
pub use context::Context;
pub use credential::{AccountAddress, Credential};
pub use dispatch::{DispatchCall, EncodeCall, ModuleMessage};
pub use event::{ModuleEvent, RuntimeEventProcessor};
pub use gas_schedule::{GasSchedule, SELENDRA_GAS_SCHEDULE, SchemeCosts};
pub use spec::{CryptoSpecExt, SelendraSpec, Spec};

use crate::state::{EventContainer, TxStateError};
use crate::transaction::AuthenticatedTransactionData;
use crate::{BlockState, GenesisState, ModuleError, ModuleId, TxState};

/// One state item of a module (a `#[state]` field): its item id and its field name. Its state
/// lives under the prefix `(module discriminant, item)` ([`StateItem::prefix`]).
///
/// A module's items are listed in [`ModuleInfo::STATE_LAYOUT`]; each module pins that list in a
/// known-answer test, so renaming, renumbering or dropping an item (a change of the stored data)
/// fails a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateItem {
    item: u8,
    name: &'static str,
}

impl StateItem {
    /// The item `item`, a field named `name`.
    pub const fn new(item: u8, name: &'static str) -> Self {
        Self { item, name }
    }

    /// The item id: the second byte of the item's prefix.
    pub const fn item(&self) -> u8 {
        self.item
    }

    /// The field name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The prefix of this item in the module with discriminant `module`.
    pub const fn prefix(&self, module: u8) -> Prefix {
        Prefix::new(module, self.item)
    }
}

/// A module's identity and state layout: what the runtime, its derives and the state
/// transition function need to know about a module without running it. Derived by
/// `#[derive(ModuleInfo)]` (with `#[module_info(discriminant = …, name = "…")]`).
///
/// - [`DISCRIMINANT`](Self::DISCRIMINANT) numbers the module, once for everything: the first
///   byte of every state prefix of the module, and the tag of its calls and events in the
///   runtime's call and event encodings. Never `0` (reserved); unique within a runtime. Ranges
///   (`docs/serialization.md`, "Module discriminants"): 1–127 Selendra's runtime modules,
///   128–223 other modules, 224–255 test modules.
/// - [`NAME`](Self::NAME) is the module's stable name (`^[a-z][a-z0-9_]{0,31}$`), unique within
///   a runtime: the key of the module's calls and events in JSON, the first half of its event
///   keys, and what its [`ModuleId`] is derived from ([`ModuleId::from_name`]). Moving or
///   renaming the Rust type changes none of these.
/// - [`DEPENDENCIES`](Self::DEPENDENCIES) are the `(DISCRIMINANT, NAME)` of the modules this
///   one holds and calls (its `#[module]` fields). Their genesis runs first
///   ([`sort_values_by_modules_dependencies`](crate::sort_values_by_modules_dependencies)), and
///   each must be a module of the runtime, with that discriminant and that name (a nested
///   module with another discriminant would write under another module's prefixes).
/// - [`STATE_LAYOUT`](Self::STATE_LAYOUT) lists the module's state items.
///
/// The derive checks these rules, the runtime derive checks the runtime's modules together. A
/// hand-written impl must keep them, and its [`id`](Self::id) must be
/// `ModuleId::from_name(Self::NAME)`.
///
/// Upstream's `ModuleInfo` numbered a module three ways (the state prefix from its Rust path,
/// the call tag from its position in the runtime, the discriminant from `constants.toml`;
/// P5-25), derived its id from its Rust path (P5-27), and had `is_safe_for_sequencer`, which
/// comes back with the sequencer (Phase 11).
pub trait ModuleInfo {
    /// The spec the module runs with.
    type Spec: Spec;

    /// The module's number: the first byte of its state prefixes and the tag of its calls and
    /// events. Never `0`.
    const DISCRIMINANT: u8;

    /// The module's stable name, `^[a-z][a-z0-9_]{0,31}$`.
    const NAME: &'static str;

    /// The `(DISCRIMINANT, NAME)` of each module this one depends on.
    const DEPENDENCIES: &'static [(u8, &'static str)];

    /// The module's state items.
    const STATE_LAYOUT: &'static [StateItem];

    /// The module's id: `ModuleId::from_name(Self::NAME)`.
    fn id(&self) -> &ModuleId;

    /// The ids of the modules this one depends on (from [`DEPENDENCIES`](Self::DEPENDENCIES)).
    fn dependencies(&self) -> Vec<ModuleId> {
        Self::DEPENDENCIES
            .iter()
            .map(|&(_, name)| ModuleId::from_name(name))
            .collect()
    }
}

/// A module: its genesis, the calls it takes, the events it emits, and its hooks.
///
/// Every module is also a [`ModuleInfo`] (usually derived), whose [`Spec`](ModuleInfo::Spec)
/// it runs with.
///
/// # Determinism
/// A module's methods must change state and emit events the same way on every node and in the
/// zk guest: no network access, randomness, clocks, or iteration over hash collections (this
/// crate bans `HashMap`/`HashSet`; every call message, event and stored value is a consensus
/// type, which keeps them out of consensus data). Code that is not part of the state
/// transition (a secondary index for an API, say) is `native`-only, and writes only
/// Accessory state.
///
/// # Gas
/// State accesses are charged by the state accessor; a module charges anything else it does
/// that costs (computation, memory, hashing: [`GasMeter`](crate::GasMeter), the metered
/// utilities). Any failed access or charge reverts the whole call, whatever the module
/// returns: a module cannot catch an out-of-gas error and keep its writes.
///
/// # Hooks
/// The hook methods ([`begin_rollup_block_hook`](Self::begin_rollup_block_hook),
/// [`end_rollup_block_hook`](Self::end_rollup_block_hook),
/// [`pre_dispatch_tx_hook`](Self::pre_dispatch_tx_hook),
/// [`post_dispatch_tx_hook`](Self::post_dispatch_tx_hook),
/// [`finalize_hook`](Self::finalize_hook)) do nothing unless the module overrides them. The
/// runtime calls every module's hooks, in the order of its fields
/// ([`TxHooks`](crate::TxHooks), [`BlockHooks`](crate::BlockHooks),
/// [`FinalizeHook`](crate::FinalizeHook)). A hook is overridden in the module's one `impl
/// Module`, so it runs for every spec the module runs with. Upstream's hooks were separate
/// traits with a fallback impl for every module, so an impl for one concrete spec was silently
/// skipped by a runtime generic over the spec (P5-31); here such an impl leaves the module
/// without an `impl Module` for the other specs, which fails to compile in a runtime generic
/// over the spec (E0277):
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_state::Storage;
/// # #[derive(Clone)]
/// # struct Clock<S>(ModuleId, core::marker::PhantomData<S>);
/// # impl<S: Spec> ModuleInfo for Clock<S> {
/// #     type Spec = S;
/// #     const DISCRIMINANT: u8 = 231;
/// #     const NAME: &'static str = "clock";
/// #     const DEPENDENCIES: &'static [(u8, &'static str)] = &[];
/// #     const STATE_LAYOUT: &'static [StateItem] = &[];
/// #     fn id(&self) -> &ModuleId { &self.0 }
/// # }
///
/// // `Clock<S>` is a `ModuleInfo` for every spec (hidden above); its hook is for one spec.
/// impl Module for Clock<TestSpec> {
/// #   type Config = ();
/// #   type CallMessage = NotInstantiable;
/// #   type Event = NotInstantiable;
/// #   type Error = anyhow::Error;
/// #   fn call(&mut self, m: NotInstantiable, _: &Context<TestSpec>, _: &mut impl TxState<TestSpec>) -> anyhow::Result<()> { match m {} }
///     fn end_rollup_block_hook(&mut self, _state: &mut BlockState<'_, TestSpec>) {
///         // …
///     }
/// }
///
/// struct Runtime<S: Spec>(Clock<S>);
///
/// impl<S: Spec> BlockHooks for Runtime<S> {
///     type Spec = S;
/// #   fn begin_rollup_block_hook(&mut self, root: &<S::Storage as Storage>::Root, state: &mut BlockState<'_, S>) {
/// #       <Clock<S> as Module>::begin_rollup_block_hook(&mut self.0, root, state);
/// #   }
///     fn end_rollup_block_hook(&mut self, state: &mut BlockState<'_, S>) {
///         <Clock<S> as Module>::end_rollup_block_hook(&mut self.0, state);
///     }
/// }
/// ```
///
/// With the `impl Module` for every spec, it compiles and the hook runs for every spec:
///
/// ```
/// use selendra_modules_api::*;
/// use selendra_state::Storage;
/// # #[derive(Clone)]
/// # struct Clock<S>(ModuleId, core::marker::PhantomData<S>);
/// # impl<S: Spec> ModuleInfo for Clock<S> {
/// #     type Spec = S;
/// #     const DISCRIMINANT: u8 = 231;
/// #     const NAME: &'static str = "clock";
/// #     const DEPENDENCIES: &'static [(u8, &'static str)] = &[];
/// #     const STATE_LAYOUT: &'static [StateItem] = &[];
/// #     fn id(&self) -> &ModuleId { &self.0 }
/// # }
///
/// impl<S: Spec> Module for Clock<S> {
/// #   type Config = ();
/// #   type CallMessage = NotInstantiable;
/// #   type Event = NotInstantiable;
/// #   type Error = anyhow::Error;
/// #   fn call(&mut self, m: NotInstantiable, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> { match m {} }
///     fn end_rollup_block_hook(&mut self, _state: &mut BlockState<'_, S>) {
///         // …
///     }
/// }
///
/// struct Runtime<S: Spec>(Clock<S>);
///
/// impl<S: Spec> BlockHooks for Runtime<S> {
///     type Spec = S;
/// #   fn begin_rollup_block_hook(&mut self, root: &<S::Storage as Storage>::Root, state: &mut BlockState<'_, S>) {
/// #       <Clock<S> as Module>::begin_rollup_block_hook(&mut self.0, root, state);
/// #   }
///     fn end_rollup_block_hook(&mut self, state: &mut BlockState<'_, S>) {
///         <Clock<S> as Module>::end_rollup_block_hook(&mut self.0, state);
///     }
/// }
/// ```
///
/// Block hooks and the finalize hook are not metered: their work must be bounded per block
/// (e.g. a fixed number of items, or the items touched in the block), never by the size of the
/// state.
pub trait Module: ModuleInfo + Clone {
    /// The configuration of the module's genesis.
    type Config;

    /// The calls the module takes ([`CallMessage`]; a module that takes none uses
    /// [`NotInstantiable`](crate::NotInstantiable)).
    type CallMessage: CallMessage;

    /// The events the module emits ([`ModuleEvent`]; a module that emits none uses
    /// [`NotInstantiable`](crate::NotInstantiable)). A consensus type, like everything that
    /// leaves a call.
    type Event: ModuleEvent
        + selendra_interface::common::ConsensusType
        + borsh::BorshSerialize
        + borsh::BorshDeserialize
        + serde::Serialize
        + serde::de::DeserializeOwned
        + schemars::JsonSchema
        + core::fmt::Debug
        + Clone
        + PartialEq
        + Send
        + Sync
        + 'static;

    /// The error of [`call`](Self::call) and the transaction hooks. The runtime returns it as a
    /// [`ModuleError`], with its [`ErrorDetail`](crate::ErrorDetail) for clients.
    type Error: crate::ErrorDetail + Send + Sync + 'static;

    /// Initializes the module's state, once, when the rollup starts. Expensive work is fine
    /// here, but it must be deterministic.
    ///
    /// # Errors
    /// If the configuration is invalid or a state access fails: the rollup does not start.
    fn genesis(
        &mut self,
        _genesis_rollup_header: &<<Self::Spec as Spec>::Da as DaSpec>::BlockHeader,
        _config: &Self::Config,
        _state: &mut impl GenesisState<Self::Spec>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// Executes a call: changes the module's state and emits events. `context` says who sent
    /// it and which sequencer included it.
    ///
    /// # Errors
    /// The call is rejected: none of its writes and events are kept (nor if a state access
    /// failed and the module returned `Ok` anyway).
    fn call(
        &mut self,
        message: Self::CallMessage,
        context: &Context<Self::Spec>,
        state: &mut impl TxState<Self::Spec>,
    ) -> Result<(), Self::Error>;

    /// Charges `gas` (at the transaction's gas price) on `state`'s meter, for work the state
    /// accessor does not charge for.
    ///
    /// # Errors
    /// Out of gas, or an earlier access failed. Either way the call is reverted.
    fn charge_gas(
        &self,
        state: &mut impl TxState<Self::Spec>,
        gas: <Self::Spec as Spec>::Gas,
    ) -> Result<(), TxStateError<Self::Spec>> {
        state.charge_gas(gas)
    }

    /// Runs at the beginning of each rollup block, before its transactions. Not metered (see
    /// the trait docs).
    ///
    /// `visible_hash` is a root that storage proofs can be checked against: its user half is
    /// the pre-state root of the rollup block `STATE_ROOT_DELAY_BLOCKS` before this one, its
    /// kernel half the pre-state root of that block's visible slot.
    fn begin_rollup_block_hook(
        &mut self,
        _visible_hash: &<<Self::Spec as Spec>::Storage as Storage>::Root,
        _state: &mut BlockState<'_, Self::Spec>,
    ) {
    }

    /// Runs at the end of each rollup block, after its transactions. Not metered (see the
    /// trait docs).
    fn end_rollup_block_hook(&mut self, _state: &mut BlockState<'_, Self::Spec>) {}

    /// Runs before each transaction's call is dispatched, metered as part of the call.
    ///
    /// # Errors
    /// The transaction is reverted (the hooks of the modules after this one do not run).
    fn pre_dispatch_tx_hook<T: TxState<Self::Spec>>(
        &mut self,
        _tx: &AuthenticatedTransactionData<Self::Spec>,
        _state: &mut T,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Runs after each transaction's call, metered as part of the call.
    ///
    /// # Errors
    /// The transaction is reverted (the hooks of the modules after this one do not run).
    fn post_dispatch_tx_hook<T: TxState<Self::Spec>>(
        &mut self,
        _tx: &AuthenticatedTransactionData<Self::Spec>,
        _context: &Context<Self::Spec>,
        _state: &mut T,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Runs after a block's state changes are computed, with the new root: for post-processing
    /// of Accessory state only (the root is fixed). Called only natively, never in the zk guest,
    /// which is safe because nothing provable reads Accessory state. Not metered (see the trait
    /// docs).
    fn finalize_hook(
        &mut self,
        _root_hash: &<<Self::Spec as Spec>::Storage as Storage>::Root,
        _state: &mut impl AccessoryStateReaderAndWriter,
    ) {
    }
}

/// Runs a module's (or a runtime's) genesis: implemented for every [`Module`] (its
/// [`Module::genesis`], the error as a [`ModuleError`]) and by the runtime's derive (every
/// module's, dependencies first).
pub trait Genesis {
    /// The spec.
    type Spec: Spec;

    /// The genesis configuration.
    type Config;

    /// Initializes the state.
    ///
    /// # Errors
    /// If the configuration is invalid or a state access fails.
    fn genesis(
        &mut self,
        genesis_rollup_header: &<<Self::Spec as Spec>::Da as DaSpec>::BlockHeader,
        config: &Self::Config,
        state: &mut impl GenesisState<Self::Spec>,
    ) -> Result<(), ModuleError>;
}

impl<T: Module> Genesis for T {
    type Spec = <T as ModuleInfo>::Spec;
    type Config = <T as Module>::Config;

    fn genesis(
        &mut self,
        genesis_rollup_header: &<<Self::Spec as Spec>::Da as DaSpec>::BlockHeader,
        config: &Self::Config,
        state: &mut impl GenesisState<Self::Spec>,
    ) -> Result<(), ModuleError> {
        <T as Module>::genesis(self, genesis_rollup_header, config, state)
            .map_err(ModuleError::from)
    }
}

/// How a module emits its events: implemented for every [`Module`], and only by this blanket
/// impl, so an event always carries the emitting module's own
/// [`DISCRIMINANT`](ModuleInfo::DISCRIMINANT), which the runtime maps it back to the module by.
///
/// Each event is charged gas ([`EventContainer::add_event`]), the same natively and in the zk
/// guest, and kept only natively. Its key is `"{NAME}/{event_name}"` (e.g. `"bank/Transfer"`),
/// from the event's [`ModuleEvent::event_name`]: upstream parsed it out of the event's `Debug`
/// output (P5-32), so a hand-written `Debug` changed it.
///
/// A key, derived or custom, is at most [`MAX_EVENT_KEY_LEN`](crate::MAX_EVENT_KEY_LEN) (256)
/// bytes: a longer one fails with
/// [`StateAccessError::EventKeyTooLong`](crate::StateAccessError::EventKeyTooLong), charges
/// nothing for the event and reverts the call (the node's ledger stores no longer key).
///
/// A module cannot override it (another impl conflicts with the blanket impl; E0119):
///
/// ```compile_fail,E0119
/// use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # #[derive(Clone)]
/// # struct Quiet(ModuleId);
/// # impl ModuleInfo for Quiet {
/// #     type Spec = TestSpec;
/// #     const DISCRIMINANT: u8 = 230;
/// #     const NAME: &'static str = "quiet";
/// #     const DEPENDENCIES: &'static [(u8, &'static str)] = &[];
/// #     const STATE_LAYOUT: &'static [StateItem] = &[];
/// #     fn id(&self) -> &ModuleId { &self.0 }
/// # }
/// # impl Module for Quiet {
/// #     type Config = ();
/// #     type CallMessage = NotInstantiable;
/// #     type Event = NotInstantiable;
/// #     type Error = anyhow::Error;
/// #     fn call(&mut self, m: NotInstantiable, _: &Context<TestSpec>, _: &mut impl TxState<TestSpec>) -> anyhow::Result<()> { match m {} }
/// # }
/// // `Quiet` is a module (hidden above).
/// impl EventEmitter for Quiet {
///     fn emit_event(&self, _: &mut impl EventContainer<TestSpec>, _: NotInstantiable) -> Result<(), TxStateError<TestSpec>> {
///         Ok(())
///     }
/// #   fn emit_event_with_custom_key(&self, _: &mut impl EventContainer<TestSpec>, _: &str, _: NotInstantiable) -> Result<(), TxStateError<TestSpec>> { Ok(()) }
/// }
/// ```
///
/// A module emits through it:
///
/// ```
/// use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # #[derive(Clone)]
/// # struct Quiet(ModuleId);
/// # impl ModuleInfo for Quiet {
/// #     type Spec = TestSpec;
/// #     const DISCRIMINANT: u8 = 230;
/// #     const NAME: &'static str = "quiet";
/// #     const DEPENDENCIES: &'static [(u8, &'static str)] = &[];
/// #     const STATE_LAYOUT: &'static [StateItem] = &[];
/// #     fn id(&self) -> &ModuleId { &self.0 }
/// # }
/// # impl Module for Quiet {
/// #     type Config = ();
/// #     type CallMessage = NotInstantiable;
/// #     type Event = NotInstantiable;
/// #     type Error = anyhow::Error;
/// #     fn call(&mut self, m: NotInstantiable, _: &Context<TestSpec>, _: &mut impl TxState<TestSpec>) -> anyhow::Result<()> { match m {} }
/// # }
/// // `Quiet` is a module (hidden above).
/// fn emit(module: &Quiet, state: &mut impl EventContainer<TestSpec>, event: NotInstantiable) -> Result<(), TxStateError<TestSpec>> {
///     module.emit_event(state, event)
/// }
/// ```
///
/// Module code could still call [`EventContainer::add_event`] itself with another module's
/// discriminant (modules are trusted code, compiled into the runtime): it should not, and a
/// review rejects it.
pub trait EventEmitter: Module {
    /// Emits `event` with the key `"{NAME}/{event_name}"`.
    ///
    /// # Errors
    /// As [`EventContainer::add_event`]: the key is longer than
    /// [`MAX_EVENT_KEY_LEN`](crate::MAX_EVENT_KEY_LEN) bytes, out of gas, or an earlier access
    /// failed. Either way the call is reverted.
    fn emit_event(
        &self,
        state: &mut impl EventContainer<Self::Spec>,
        event: Self::Event,
    ) -> Result<(), TxStateError<Self::Spec>>;

    /// Emits `event` with the key `key`, of at most
    /// [`MAX_EVENT_KEY_LEN`](crate::MAX_EVENT_KEY_LEN) bytes.
    ///
    /// # Errors
    /// As [`emit_event`](Self::emit_event).
    fn emit_event_with_custom_key(
        &self,
        state: &mut impl EventContainer<Self::Spec>,
        key: &str,
        event: Self::Event,
    ) -> Result<(), TxStateError<Self::Spec>>;
}

impl<T: Module> EventEmitter for T {
    fn emit_event(
        &self,
        state: &mut impl EventContainer<Self::Spec>,
        event: Self::Event,
    ) -> Result<(), TxStateError<Self::Spec>> {
        let key = event_key::<T>(&event);
        state.add_event(T::DISCRIMINANT, &key, event)
    }

    fn emit_event_with_custom_key(
        &self,
        state: &mut impl EventContainer<Self::Spec>,
        key: &str,
        event: Self::Event,
    ) -> Result<(), TxStateError<Self::Spec>> {
        state.add_event(T::DISCRIMINANT, key, event)
    }
}

/// The key of `event` emitted by `M`: `"{NAME}/{event_name}"`.
fn event_key<M: Module>(event: &M::Event) -> String {
    format!("{}/{}", M::NAME, event.event_name())
}

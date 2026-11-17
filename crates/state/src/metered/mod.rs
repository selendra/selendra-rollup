//! Metered state access for transactions: the transaction journal ([`TxScratchpad`]), metered
//! phases ([`MeteredTx`]) with nested scopes ([`ScopeToken`]), and the hook ([`Metered`])
//! through which every transaction accessor gets its readers and writers
//! ([`StateReader`](crate::StateReader), [`StateWriter`](crate::StateWriter)), which charge
//! gas on every access.
//!
//! # Layers
//! Each layer has one owner that decides whether its writes are kept:
//! 1. [`StateCheckpoint`](crate::StateCheckpoint): the block (the state transition function).
//! 2. [`TxScratchpad`]: one transaction, a journal over the checkpoint (the state transition
//!    function): the transaction-level writes, such as the gas reservation and its
//!    settlement. [`commit`](TxScratchpad::commit) or [`revert`](TxScratchpad::revert).
//! 3. [`MeteredTx`]: one metered phase (pre-execution, or the call), in a base scope of the
//!    journal. [`finalize`](MeteredTx::finalize) commits it into the scratchpad only if no
//!    access failed and the module returned `Ok`.
//! 4. Nested scopes ([`MeteredRef::open_scope`]; upstream `RevertableTxState`), committed into
//!    their parent or reverted by their owner.
//!
//! # The hook
//! Transaction accessors (`selendra-modules-api`'s working sets) implement [`Metered`] by
//! lending the [`MeteredRef`] of the [`MeteredTx`] they own, and get their readers and writers
//! ([`StateReader`](crate::StateReader), [`StateWriter`](crate::StateWriter)) for the
//! namespaces their [`rights`] grant, and [`VersionReader`](crate::VersionReader), from blanket
//! impls in this crate. So every
//! accessor is metered in one place, and module code cannot reach storage without paying:
//! - the raw reads and writes are crate-private methods of [`MeteredRef`], called only by the
//!   blanket impls, and [`MeteredRef`], [`MeteredView`], [`MeteredTx`] and [`ScopeToken`] have
//!   private fields;
//! - a [`Metered`] type cannot also implement a reader or writer by hand (E0119: the blanket
//!   impls cover it);
//! - an accessor cannot widen its rights: [`Metered::metered`] must return a [`MeteredRef`]
//!   with its own `Rights`, which only a [`MeteredTx`] built with them lends. A wrapper that
//!   forwards another accessor's [`MeteredRef`] charges the real meter;
//! - [`MeteredTx::new`] needs a [`TxScratchpad`], built only from an owned checkpoint, which
//!   modules never hold.
//!
//! Upstream sealed its raw-access trait (`UniversalStateAccessor`) as a supertrait of the
//! accessor traits, and supertrait methods resolve through a generic bound without the trait
//! being nameable: any module could read and write any namespace unmetered, Accessory reads
//! included (`containers/vec.rs`'s `push_accessory` did).
//!
//! Generic code takes `T: Metered<Rights = TxRights, ..>` (`selendra-modules-api`'s `TxState`
//! lists it as a supertrait), and gets `T: StateReader<User>` and the others from the blanket
//! impls:
//!
//! ```
//! use selendra_state::metered::{Metered, TxRights};
//! use selendra_state::{BorshCodec, KernelStateValue, Prefix, StateMap, StateValue};
//!
//! fn call<T: Metered<Rights = TxRights>>(state: &mut T) -> Result<(), String> {
//!     let mut count = StateValue::<u64>::with_codec(Prefix::new(1, 0), BorshCodec);
//!     let mut balances = StateMap::<u64, u64>::with_codec(Prefix::new(1, 1), BorshCodec);
//!     let height = KernelStateValue::<u64>::with_codec(Prefix::new(2, 0), BorshCodec);
//!     let n = count.get(state).map_err(|e| e.to_string())?.unwrap_or(0);
//!     count.set(&(n + 1), state).map_err(|e| e.to_string())?;
//!     balances.set(&n, &7, state).map_err(|e| e.to_string())?;
//!     let _ = height.get(state).map_err(|e| e.to_string())?;
//!     Ok(())
//! }
//! ```
//!
//! P5-11: the raw operations are not methods of an accessor (E0599)...
//!
//! ```compile_fail,E0599
//! use selendra_state::metered::Metered;
//! use selendra_state::{ProvableNamespace, SlotKey};
//!
//! fn raw<T: Metered>(state: &mut T, key: &SlotKey) {
//!     let _ = state.read(ProvableNamespace::User, key, false);
//! }
//! ```
//!
//! ...and are private on the lent [`MeteredRef`] (E0624), which offers only charges, scopes
//! and the view:
//!
//! ```compile_fail,E0624
//! use selendra_state::metered::Metered;
//! use selendra_state::{ProvableNamespace, SlotKey};
//!
//! fn raw<T: Metered>(state: &mut T, key: &SlotKey) {
//!     let _ = state.metered().read(ProvableNamespace::User, key, false);
//! }
//! ```
//!
//! ```
//! use selendra_state::metered::{Metered, StateGasMeter};
//!
//! fn charge<T: Metered>(state: &mut T, gas: <T::Meter as StateGasMeter>::Gas) -> bool {
//!     state.metered().charge(gas).is_ok() && !state.metered_view().is_poisoned()
//! }
//! ```
//!
//! Its fields are private (E0451), so it cannot be built from another phase's parts either:
//!
//! ```compile_fail,E0451
//! use std::marker::PhantomData;
//!
//! use selendra_state::metered::{AccessRights, MeteredRef, StateGasMeter};
//! use selendra_state::Storage;
//!
//! fn forge<'a, St: Storage, M: StateGasMeter, R: AccessRights>() -> MeteredRef<'a, St, M, R> {
//!     MeteredRef { tx: unimplemented!(), level: None, rights: PhantomData }
//! }
//! ```
//!
//! A [`Metered`] type gets its readers and writers from the blanket impls only: a hand-written
//! unmetered one conflicts with them (E0119).
//!
//! ```compile_fail,E0119
//! use std::convert::Infallible;
//!
//! use selendra_state::metered::{
//!     Metered, MeteredRef, MeteredTx, MeteredView, StateGasMeter, TxRights,
//! };
//! use selendra_state::{SlotKey, SlotValue, StateReader, Storage, User};
//!
//! struct Free;
//! impl StateGasMeter for Free {
//!     type Gas = u64;
//!     type Error = Infallible;
//!     fn charge(&mut self, _: u64) -> Result<(), Infallible> { Ok(()) }
//! }
//!
//! struct Unmetered<St: Storage>(MeteredTx<St, Free, TxRights>);
//!
//! impl<St: Storage> Metered for Unmetered<St> {
//!     type Storage = St;
//!     type Meter = Free;
//!     type Rights = TxRights;
//!     fn metered(&mut self) -> MeteredRef<'_, St, Free, TxRights> { self.0.metered() }
//!     fn metered_view(&self) -> MeteredView<'_, Free> { self.0.metered_view() }
//! }
//!
//! impl<St: Storage> StateReader<User> for Unmetered<St> {
//!     type Error = Infallible;
//!     fn get(&mut self, _: &SlotKey) -> Result<Option<SlotValue>, Infallible> { Ok(None) }
//! }
//! ```
//!
//! The same accessor without the hand-written impl compiles, and reads through the blanket
//! impl:
//!
//! ```
//! # use std::convert::Infallible;
//! # use selendra_state::metered::{
//! #     Metered, MeteredRef, MeteredTx, MeteredView, StateGasMeter, TxRights,
//! # };
//! # use selendra_state::{BorshCodec, Prefix, StateValue, Storage};
//! # struct Free;
//! # impl StateGasMeter for Free {
//! #     type Gas = u64;
//! #     type Error = Infallible;
//! #     fn charge(&mut self, _: u64) -> Result<(), Infallible> { Ok(()) }
//! # }
//! struct Accessor<St: Storage>(MeteredTx<St, Free, TxRights>);
//!
//! impl<St: Storage> Metered for Accessor<St> {
//!     type Storage = St;
//!     type Meter = Free;
//!     type Rights = TxRights;
//!     fn metered(&mut self) -> MeteredRef<'_, St, Free, TxRights> { self.0.metered() }
//!     fn metered_view(&self) -> MeteredView<'_, Free> { self.0.metered_view() }
//! }
//!
//! fn read<St: Storage>(state: &mut Accessor<St>) -> Option<u8> {
//!     let value = StateValue::<u8>::with_codec(Prefix::new(1, 0), BorshCodec);
//!     value.get(state).ok().flatten()
//! }
//! ```
//!
//! Rights are checked at compile time ([`rights`]). No accessor reads Accessory state (P5-12:
//! upstream's `push_accessory` read an accessory vector's length in the state transition
//! function; it is not ported), E0277:
//!
//! ```compile_fail,E0277
//! use selendra_state::metered::{Metered, TxRights};
//! use selendra_state::{AccessoryStateVec, BorshCodec, Prefix};
//!
//! fn push<T: Metered<Rights = TxRights>>(state: &mut T) {
//!     let mut vec = AccessoryStateVec::<u8>::with_codec(Prefix::new(1, 3), BorshCodec);
//!     let _ = vec.push(&1, state);
//! }
//! ```
//!
//! ```compile_fail,E0277
//! use selendra_state::metered::{Metered, TxRights};
//! use selendra_state::{AccessoryStateValue, BorshCodec, Prefix};
//!
//! fn read<T: Metered<Rights = TxRights>>(state: &mut T) {
//!     let value = AccessoryStateValue::<u8>::with_codec(Prefix::new(1, 3), BorshCodec);
//!     let _ = value.get(state);
//! }
//! ```
//!
//! but writes it:
//!
//! ```
//! use selendra_state::metered::{Metered, TxRights};
//! use selendra_state::{AccessoryStateValue, BorshCodec, Prefix};
//!
//! fn write<T: Metered<Rights = TxRights>>(state: &mut T) {
//!     let mut value = AccessoryStateValue::<u8>::with_codec(Prefix::new(1, 3), BorshCodec);
//!     let _ = value.set(&1, state);
//!     let _ = value.delete(state);
//! }
//! ```
//!
//! Pre-execution reads and writes User state only (E0277 on Kernel state):
//!
//! ```compile_fail,E0277
//! use selendra_state::metered::{Metered, PreExecRights};
//! use selendra_state::{BorshCodec, KernelStateValue, Prefix};
//!
//! fn read<T: Metered<Rights = PreExecRights>>(state: &mut T) {
//!     let value = KernelStateValue::<u8>::with_codec(Prefix::new(1, 3), BorshCodec);
//!     let _ = value.get(state);
//! }
//! ```
//!
//! ```
//! use selendra_state::metered::{Metered, PreExecRights};
//! use selendra_state::{BorshCodec, Prefix, StateValue};
//!
//! fn read<T: Metered<Rights = PreExecRights>>(state: &mut T) {
//!     let mut value = StateValue::<u8>::with_codec(Prefix::new(1, 3), BorshCodec);
//!     let _ = value.get(state);
//!     let _ = value.set(&1, state);
//! }
//! ```
//!
//! Scope tokens cannot be forged (E0451):
//!
//! ```compile_fail,E0451
//! use selendra_state::metered::ScopeToken;
//!
//! fn forge() -> ScopeToken {
//!     ScopeToken { phase: unimplemented!(), level: unimplemented!(), local: unimplemented!() }
//! }
//! ```
//!
//! A token comes only from [`MeteredRef::open_scope`], is used through
//! [`MeteredRef::scoped`] and is consumed by [`MeteredRef::close_scope`], all in the metered
//! phase that issued it (a token of another phase is `ScopeMisuse`, and no safe `static` can
//! hold one: see [`ScopeToken`]):
//!
//! ```
//! use selendra_state::metered::{Metered, ScopeEnd, TxRights};
//! use selendra_state::{BorshCodec, Prefix, StateValue};
//!
//! fn nested<T: Metered<Rights = TxRights>>(state: &mut T) -> bool {
//!     let mut value = StateValue::<u8>::with_codec(Prefix::new(1, 0), BorshCodec);
//!     let token = state.metered().open_scope();
//!     let written = value.set(&1, &mut state.metered().scoped(&token)).is_ok();
//!     written && state.metered().close_scope(token, ScopeEnd::Commit).is_ok()
//! }
//! ```
//!
//! # Not ported
//! - `push_accessory` (P5-12, no upstream callers).
//! - `UnmeteredStateWrapper`/`to_unmetered` (Phase 7, with its only user, the EVM).
//! - `TempCache`/`PerBlockCache` (Phase 7, likewise).
//! - Metrics (dropped: they must never touch gas).

mod blanket;
pub mod costs;
mod error;
mod journal;
pub mod rights;
mod scope;
mod scratchpad;
mod tx;
mod view;

#[cfg(test)]
mod tests;

pub use costs::{MAX_STATE_VALUE_SIZE, StateAccessCosts, StateGas, StateGasMeter};
pub use error::{StateAccessError, StateOp};
pub use rights::{
    AccessRights, PreExecRights, ReadsKernel, ReadsUser, TxRights, WritesAccessory, WritesKernel,
    WritesUser,
};
pub use scope::{ScopeEnd, ScopeToken};
pub use scratchpad::TxScratchpad;
pub use tx::{Finalized, MeteredRef, MeteredTx, PhaseOutcome, RevertReason};
pub use view::MeteredView;

use crate::Storage;

/// The metering hook: a transaction accessor lends the metered phase it runs in, and gets
/// [`StateReader`](crate::StateReader)/[`StateWriter`](crate::StateWriter) for the namespaces
/// its `Rights` grant, and [`VersionReader`](crate::VersionReader), from blanket impls that
/// charge gas on every access (see the [module docs](self)).
///
/// Never implemented for [`StateCheckpoint`](crate::StateCheckpoint) or [`TxScratchpad`]
/// (their concrete, unmetered impls would overlap the blanket impls: E0119).
pub trait Metered {
    /// The storage of the checkpoint the phase runs on.
    type Storage: Storage;
    /// The phase's gas meter.
    type Meter: StateGasMeter;
    /// The phase's access rights.
    type Rights: AccessRights;

    /// The phase's state access at this accessor's scope.
    fn metered(&mut self) -> MeteredRef<'_, Self::Storage, Self::Meter, Self::Rights>;

    /// Read-only information on the phase: versions, meter, poison.
    fn metered_view(&self) -> MeteredView<'_, Self::Meter>;
}

/// A lent [`MeteredRef`] is itself an accessor, at the same scope and with the same rights.
impl<St: Storage, M: StateGasMeter, R: AccessRights> Metered for MeteredRef<'_, St, M, R> {
    type Storage = St;
    type Meter = M;
    type Rights = R;

    fn metered(&mut self) -> MeteredRef<'_, St, M, R> {
        MeteredRef {
            tx: &mut *self.tx,
            level: self.level,
            rights: std::marker::PhantomData,
        }
    }

    fn metered_view(&self) -> MeteredView<'_, M> {
        self.view()
    }
}

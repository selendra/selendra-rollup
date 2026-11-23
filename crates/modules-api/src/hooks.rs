//! A runtime's hooks: [`TxHooks`] around each transaction's call, [`BlockHooks`] at the
//! beginning and end of each rollup block, and [`FinalizeHook`] after a block's state changes.
//!
//! A module's hooks are provided methods of [`Module`](crate::Module), which do nothing unless
//! the module overrides them. A runtime implements these traits (with its derive) by calling
//! every module's hook, in the order of its fields, with fully qualified calls
//! (`<M as Module>::begin_rollup_block_hook(&mut self.field, …)`); the first error of a
//! transaction hook stops the rest.
//!
//! No module is a runtime: there is no impl of these traits for modules (or `&mut` modules).
//! Upstream had one of each for every `&mut M`, doing nothing, and its derive called
//! `(&mut self.field).hook(…)`, so method resolution fell back to it whenever the module's own
//! impl did not apply (an impl for one concrete spec, in a runtime generic over the spec) and
//! the hook silently did not run, or picked an inherent method of the same name (P5-31). A
//! runtime that leaves a hook out does not compile; nothing falls back (E0277), for each of the
//! three traits (one snippet each, so that each one's fallback is caught on its own):
//!
//! ```compile_fail,E0277
//! use selendra_modules_api::*;
//!
//! fn runtime<R: TxHooks>() {}
//!
//! fn module_as_runtime<M: Module>() {
//!     runtime::<&mut M>();
//! }
//! ```
//!
//! ```compile_fail,E0277
//! use selendra_modules_api::*;
//!
//! fn runtime<R: BlockHooks>() {}
//!
//! fn module_as_runtime<M: Module>() {
//!     runtime::<&mut M>();
//! }
//! ```
//!
//! ```compile_fail,E0277
//! use selendra_modules_api::*;
//!
//! fn runtime<R: FinalizeHook>() {}
//!
//! fn module_as_runtime<M: Module>() {
//!     runtime::<&mut M>();
//! }
//! ```
//!
//! A runtime over the module implements all three:
//!
//! ```
//! use selendra_modules_api::*;
//! use selendra_state::Storage;
//!
//! struct Runtime<M>(M);
//!
//! impl<M: Module> TxHooks for Runtime<M> {
//!     type Spec = M::Spec;
//!
//!     fn pre_dispatch_tx_hook<T: TxState<M::Spec>>(
//!         &mut self,
//!         tx: &AuthenticatedTransactionData<M::Spec>,
//!         state: &mut T,
//!     ) -> Result<(), ModuleError> {
//!         <M as Module>::pre_dispatch_tx_hook(&mut self.0, tx, state)?;
//!         Ok(())
//!     }
//!
//!     fn post_dispatch_tx_hook<T: TxState<M::Spec>>(
//!         &mut self,
//!         tx: &AuthenticatedTransactionData<M::Spec>,
//!         context: &Context<M::Spec>,
//!         state: &mut T,
//!     ) -> Result<(), ModuleError> {
//!         <M as Module>::post_dispatch_tx_hook(&mut self.0, tx, context, state)?;
//!         Ok(())
//!     }
//! }
//!
//! impl<M: Module> BlockHooks for Runtime<M> {
//!     type Spec = M::Spec;
//!
//!     fn begin_rollup_block_hook(
//!         &mut self,
//!         visible_hash: &<<M::Spec as Spec>::Storage as Storage>::Root,
//!         state: &mut BlockState<'_, M::Spec>,
//!     ) {
//!         <M as Module>::begin_rollup_block_hook(&mut self.0, visible_hash, state);
//!     }
//!
//!     fn end_rollup_block_hook(&mut self, state: &mut BlockState<'_, M::Spec>) {
//!         <M as Module>::end_rollup_block_hook(&mut self.0, state);
//!     }
//! }
//!
//! impl<M: Module> FinalizeHook for Runtime<M> {
//!     type Spec = M::Spec;
//!
//!     fn finalize_hook(
//!         &mut self,
//!         root_hash: &<<M::Spec as Spec>::Storage as Storage>::Root,
//!         state: &mut impl AccessoryStateReaderAndWriter,
//!     ) {
//!         <M as Module>::finalize_hook(&mut self.0, root_hash, state);
//!     }
//! }
//!
//! fn tx_runtime<R: TxHooks>() {}
//! fn block_runtime<R: BlockHooks>() {}
//! fn finalize_runtime<R: FinalizeHook>() {}
//!
//! fn module_in_runtime<M: Module>() {
//!     tx_runtime::<Runtime<M>>();
//!     block_runtime::<Runtime<M>>();
//!     finalize_runtime::<Runtime<M>>();
//! }
//! ```
//!
//! The methods have no default bodies, so a hand-written runtime cannot leave one out either.

use selendra_state::{AccessoryStateReaderAndWriter, Storage};

use crate::transaction::AuthenticatedTransactionData;
use crate::{BlockState, Context, ModuleError, Spec, TxState};

/// Runs around each transaction's call, metered as part of it: an error reverts the
/// transaction.
pub trait TxHooks {
    /// The spec.
    type Spec: Spec;

    /// Runs every module's [`Module::pre_dispatch_tx_hook`](crate::Module::pre_dispatch_tx_hook),
    /// before the call is dispatched.
    ///
    /// # Errors
    /// The first module's error, unchanged (as a [`ModuleError`]); the later modules' hooks do
    /// not run.
    fn pre_dispatch_tx_hook<T: TxState<Self::Spec>>(
        &mut self,
        tx: &AuthenticatedTransactionData<Self::Spec>,
        state: &mut T,
    ) -> Result<(), ModuleError>;

    /// Runs every module's
    /// [`Module::post_dispatch_tx_hook`](crate::Module::post_dispatch_tx_hook), after the call.
    ///
    /// # Errors
    /// As [`pre_dispatch_tx_hook`](Self::pre_dispatch_tx_hook).
    fn post_dispatch_tx_hook<T: TxState<Self::Spec>>(
        &mut self,
        tx: &AuthenticatedTransactionData<Self::Spec>,
        context: &Context<Self::Spec>,
        state: &mut T,
    ) -> Result<(), ModuleError>;
}

/// Runs at the beginning and end of each rollup block (not metered).
///
/// A rollup block is made when the blob selector decides: on a based rollup for every DA block,
/// on a soft-confirmed one each time the preferred sequencer's next batch lands.
pub trait BlockHooks {
    /// The spec.
    type Spec: Spec;

    /// Runs every module's
    /// [`Module::begin_rollup_block_hook`](crate::Module::begin_rollup_block_hook).
    fn begin_rollup_block_hook(
        &mut self,
        visible_hash: &<<Self::Spec as Spec>::Storage as Storage>::Root,
        state: &mut BlockState<'_, Self::Spec>,
    );

    /// Runs every module's
    /// [`Module::end_rollup_block_hook`](crate::Module::end_rollup_block_hook).
    fn end_rollup_block_hook(&mut self, state: &mut BlockState<'_, Self::Spec>);
}

/// Runs after a block's state changes are computed (not metered): Accessory state only. The
/// state transition function calls it natively only, never in the zk guest.
///
/// Defined in every build (it changes nothing provable), so the runtime's derive needs no
/// `cfg`.
pub trait FinalizeHook {
    /// The spec.
    type Spec: Spec;

    /// Runs every module's [`Module::finalize_hook`](crate::Module::finalize_hook).
    fn finalize_hook(
        &mut self,
        root_hash: &<<Self::Spec as Spec>::Storage as Storage>::Root,
        state: &mut impl AccessoryStateReaderAndWriter,
    );
}

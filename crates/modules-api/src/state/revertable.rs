//! [`RevertableTxState`]: a nested scope over a transaction's state.

use std::any::Any;
use std::fmt;
use std::marker::PhantomData;

use borsh::BorshSerialize;
use selendra_state::metered::{Metered, MeteredRef, MeteredView, ScopeEnd, ScopeToken};

use super::TxStateError;
use super::events::{ChargedEvents, EventContainer, EventSink, charge_event};
use crate::{Spec, TxState};

/// A nested scope over a transaction's state `I` ([`TxState::to_revertable`]): its writes and
/// events are kept only if it is [committed](Self::commit) into `I`.
///
/// Built on `selendra-state`'s nested scopes: opening it is charged `scope_open` (infallible: a
/// refused charge poisons the phase, and every access through it then fails with `Poisoned`);
/// every access through it goes into its scope, metered like any other; it shares the phase's
/// poison (reverting it never clears a failure).
///
/// **Not committed means reverted**, whatever the reason: [`revert`](Self::revert), a drop
/// (e.g. on `?`), or a leak (`ManuallyDrop`, `Box::leak`: the `mem_forget` lint does not catch
/// them). Its scope stays open until the next access through `I` (or through any enclosing
/// accessor, or the end of the phase), which reverts it first: fail-closed. Its events live in
/// it, so they go wherever it goes. (No `Drop` impl is needed for that, and none would make a
/// leak safe; upstream's version kept its writes in itself and dropped them the same way.)
///
/// It holds a scope token, which is neither `Send` nor `Sync`, so neither is it (E0277):
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
///
/// fn send<T: Send>(_: T) {}
///
/// fn nested(state: &mut WorkingSet<TestSpec>) {
///     send(state.to_revertable());
/// }
/// ```
///
/// ```
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
///
/// fn local<T>(_: T) {}
///
/// fn nested(state: &mut WorkingSet<TestSpec>) {
///     local(state.to_revertable());
/// }
/// ```
pub struct RevertableTxState<'a, S: Spec, I: TxState<S>> {
    inner: &'a mut I,
    scope: ScopeToken,
    events: ChargedEvents,
    spec: PhantomData<fn() -> S>,
}

impl<S: Spec, I: TxState<S>> fmt::Debug for RevertableTxState<'_, S, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevertableTxState")
            .field("scope", &self.scope)
            .field("events", &self.events)
            .finish_non_exhaustive()
    }
}

impl<'a, S: Spec, I: TxState<S>> RevertableTxState<'a, S, I> {
    /// Opens a nested scope over `inner` (charging `scope_open`; see the type docs).
    pub fn new(inner: &'a mut I) -> Self {
        let scope = inner.metered().open_scope();
        Self {
            inner,
            scope,
            events: ChargedEvents::new(),
            spec: PhantomData,
        }
    }

    /// Keeps the scope's writes and events in `inner`'s scope (which can still revert them)
    /// and returns `inner`.
    ///
    /// # Errors
    /// The phase is poisoned (`Poisoned`: it will be reverted anyway), or the scope was already
    /// reverted by an access through an enclosing accessor (`ScopeMisuse`, which poisons). The
    /// writes and events are dropped then.
    pub fn commit(self) -> Result<&'a mut I, TxStateError<S>> {
        let Self {
            inner,
            scope,
            events,
            spec: _,
        } = self;
        inner.metered().close_scope(scope, ScopeEnd::Commit)?;
        inner.add_charged_events(events);
        Ok(inner)
    }

    /// Drops the scope's writes and events and returns `inner`. (If the phase is poisoned the
    /// scope stays open until the phase is reverted.)
    pub fn revert(self) -> &'a mut I {
        let Self { inner, scope, .. } = self;
        // On a poisoned phase the scope stays open; the next access through `inner` or the end
        // of the phase reverts it (the whole phase is reverted then anyway).
        let _ = inner.metered().close_scope(scope, ScopeEnd::Revert);
        inner
    }

    /// The events emitted in this scope so far. Always empty without the `native` feature (the
    /// zk guest), which charges events and drops them.
    pub fn events(&self) -> &[super::TypeErasedEvent] {
        self.events.as_slice()
    }
}

/// Accesses go into the scope, with `I`'s meter and rights.
impl<S: Spec, I: TxState<S>> Metered for RevertableTxState<'_, S, I> {
    type Storage = I::Storage;
    type Meter = I::Meter;
    type Rights = I::Rights;

    fn metered(&mut self) -> MeteredRef<'_, I::Storage, I::Meter, I::Rights> {
        self.inner.metered().scoped(&self.scope)
    }

    fn metered_view(&self) -> MeteredView<'_, I::Meter> {
        self.inner.metered_view()
    }
}

impl<S: Spec, I: TxState<S>> EventContainer<S> for RevertableTxState<'_, S, I> {
    fn add_event<E>(&mut self, module: u8, key: &str, event: E) -> Result<(), TxStateError<S>>
    where
        E: BorshSerialize + Any + Send + Sync,
    {
        if let Some(event) = charge_event(self, module, key, event)? {
            self.events.push(event);
        }
        Ok(())
    }
}

impl<S: Spec, I: TxState<S>> EventSink<S> for RevertableTxState<'_, S, I> {
    fn add_charged_events(&mut self, events: ChargedEvents) {
        self.events.append(events);
    }
}

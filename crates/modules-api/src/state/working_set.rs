//! [`WorkingSet`]: the state a transaction's call runs on.

use std::any::Any;
use std::fmt;

use borsh::BorshSerialize;
use selendra_state::metered::{
    Metered, MeteredRef, MeteredTx, MeteredView, PhaseOutcome, TxRights, TxScratchpad,
};

use super::TxStateError;
use super::events::{ChargedEvents, EventContainer, EventSink, TypeErasedEvent, charge_event};
use crate::{BasicGasMeter, GasMeteringError, Spec};

/// Whether a metered phase of a transaction was committed, and if not why: `Committed`, or
/// `Reverted` because an access failed (`Poisoned`, which takes precedence: the module may
/// have ignored the failure) or because the module returned the error `E`.
///
/// The state transition function (Phase 8) consumes it: it settles the gas used either way, on
/// the scratchpad [`WorkingSet::finalize`] returns, and writes the transaction's receipt.
pub type TxOutcome<S, E> = PhaseOutcome<GasMeteringError<<S as Spec>::Gas>, E>;

/// The state a transaction's call (and its hooks) runs on: a metered phase
/// ([`MeteredTx`], with the transaction rights) over the transaction's [`TxScratchpad`], charging
/// a [`BasicGasMeter`] with the spec's gas schedule, and the events the call emits. A
/// [`TxState`](crate::TxState).
///
/// The state transition function builds it ([`new`](Self::new)), runs the call on it, and
/// [`finalize`](Self::finalize)s it with the call's result. Its writes and events are kept only
/// if no access failed **and** the call returned `Ok`: a module that ignores an out-of-gas error
/// and returns `Ok` does not keep its partial writes (upstream trusted the module's result,
/// P5-13). The scratchpad's own writes (pre-execution, the gas reservation) are not part of the
/// call's phase, so they are kept either way.
///
/// It has no `storage()` and no way to the meter but the read-only getters of
/// [`GasMeter`](crate::GasMeter) (upstream's `try_as_basic_gas_meter` handed out a `&mut` to it;
/// P5-16, E0599):
///
/// ```compile_fail,E0599
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
///
/// fn mint(state: &mut WorkingSet<TestSpec>) {
///     let _ = state.try_as_basic_gas_meter();
/// }
/// ```
///
/// ```
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
///
/// fn read(state: &mut WorkingSet<TestSpec>) -> GasUnit<2> {
///     state.remaining_gas()
/// }
/// ```
pub struct WorkingSet<S: Spec> {
    tx: MeteredTx<S::Storage, BasicGasMeter<S>, TxRights>,
    events: ChargedEvents,
}

impl<S: Spec> fmt::Debug for WorkingSet<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkingSet")
            .field("tx", &self.tx)
            .field("events", &self.events)
            .finish()
    }
}

/// What [`WorkingSet::finalize`] returns.
#[derive(Debug)]
pub struct FinalizedWorkingSet<S: Spec, E> {
    /// The transaction's scratchpad, with the call's writes iff they were committed.
    pub scratchpad: TxScratchpad<S::Storage>,
    /// The call's meter: the gas used is kept either way.
    pub meter: BasicGasMeter<S>,
    /// The call's events if they were committed, else none. Always empty without the `native`
    /// feature (the zk guest), which charges events and drops them.
    pub events: Vec<TypeErasedEvent>,
    /// Whether the call was committed.
    pub outcome: TxOutcome<S, E>,
}

impl<S: Spec> WorkingSet<S> {
    /// Starts the call of a transaction on `scratchpad`, charging `meter` with the spec's
    /// state-access costs.
    pub fn new(scratchpad: TxScratchpad<S::Storage>, meter: BasicGasMeter<S>) -> Self {
        Self {
            tx: MeteredTx::new(scratchpad, meter, S::GAS_SCHEDULE.state),
            events: ChargedEvents::new(),
        }
    }

    /// The events emitted so far. Always empty without the `native` feature (the zk guest),
    /// which charges events and drops them.
    pub fn events(&self) -> &[TypeErasedEvent] {
        self.events.as_slice()
    }

    /// Ends the call: commits its writes into the scratchpad and returns its events iff no
    /// access failed and `result` is `Ok`; otherwise reverts the writes and drops the events
    /// (see [`MeteredTx::finalize`]). Without the `native` feature the returned events are
    /// always empty (the gas they were charged is used either way).
    pub fn finalize<E>(self, result: Result<(), E>) -> FinalizedWorkingSet<S, E> {
        let finalized = self.tx.finalize(result);
        let events = match finalized.outcome {
            PhaseOutcome::Committed => self.events.into_vec(),
            PhaseOutcome::Reverted(_) => Vec::new(),
        };
        FinalizedWorkingSet {
            scratchpad: finalized.scratchpad,
            meter: finalized.meter,
            events,
            outcome: finalized.outcome,
        }
    }
}

impl<S: Spec> Metered for WorkingSet<S> {
    type Storage = S::Storage;
    type Meter = BasicGasMeter<S>;
    type Rights = TxRights;

    fn metered(&mut self) -> MeteredRef<'_, S::Storage, BasicGasMeter<S>, TxRights> {
        self.tx.metered()
    }

    fn metered_view(&self) -> MeteredView<'_, BasicGasMeter<S>> {
        self.tx.metered_view()
    }
}

impl<S: Spec> EventContainer<S> for WorkingSet<S> {
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

impl<S: Spec> EventSink<S> for WorkingSet<S> {
    fn add_charged_events(&mut self, events: ChargedEvents) {
        self.events.append(events);
    }
}

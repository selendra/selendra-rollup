//! [`GenesisStateAccessor`]: the state genesis runs on.

use std::any::Any;
use std::fmt;

use borsh::BorshSerialize;
use selendra_interface::common::SlotNumber;
use selendra_state::metered::{
    Metered, MeteredRef, MeteredTx, MeteredView, PhaseOutcome, TxRights, TxScratchpad,
};
use selendra_state::{CheckpointVersions, VersionReader};

use super::events::{ChargedEvents, EventContainer, EventSink, TypeErasedEvent, charge_event};
use super::{SpecCheckpoint, TxOutcome, TxStateError};
use crate::{BasicGasMeter, Gas, GasArray, GenesisState, PrivilegedKernelAccessor, Spec};

/// The state genesis runs on: a [`GenesisState`]. User and Kernel state read and write,
/// Accessory state write (like a transaction: upstream's genesis accessor also read Accessory
/// state; nothing provable may), and the true slot number, [`SlotNumber::GENESIS`].
///
/// Genesis is not paid for, but it is metered like a transaction, through the same blanket
/// impls: a [`BasicGasMeter`] with the most gas in every dimension at a zero price, so its gas
/// is recorded, and the per-value size bound applies (`ValueTooLarge`; upstream's genesis
/// writes were unbounded).
///
/// The state transition function builds it from the genesis checkpoint
/// ([`new`](Self::new)), runs every module's genesis on it in dependency order, and
/// [`finalize`](Self::finalize)s it.
pub struct GenesisStateAccessor<S: Spec> {
    tx: MeteredTx<S::Storage, BasicGasMeter<S>, TxRights>,
    events: ChargedEvents,
}

impl<S: Spec> fmt::Debug for GenesisStateAccessor<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenesisStateAccessor")
            .field("tx", &self.tx)
            .field("events", &self.events)
            .finish()
    }
}

/// [`GenesisStateAccessor::new`] was given a checkpoint that is not at the genesis versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("genesis runs at the genesis versions, but the checkpoint is at {versions:?}")]
pub struct NotAtGenesis {
    /// The checkpoint's versions.
    pub versions: CheckpointVersions,
}

/// What [`GenesisStateAccessor::finalize`] returns.
#[derive(Debug)]
pub struct FinalizedGenesis<S: Spec, E> {
    /// The checkpoint, with the genesis writes iff they were committed.
    pub checkpoint: SpecCheckpoint<S>,
    /// The meter (the gas genesis used).
    pub meter: BasicGasMeter<S>,
    /// The events if the writes were committed, else none. Always empty without the `native`
    /// feature (the zk guest), which charges events and drops them.
    pub events: Vec<TypeErasedEvent>,
    /// Whether the writes were committed.
    pub outcome: TxOutcome<S, E>,
}

impl<S: Spec> GenesisStateAccessor<S> {
    /// Starts genesis on `checkpoint`.
    ///
    /// # Errors
    /// If the checkpoint is not at [`CheckpointVersions::GENESIS`] (the true slot number this
    /// accessor reports would not match the versions it reads at).
    pub fn new(checkpoint: SpecCheckpoint<S>) -> Result<Self, NotAtGenesis> {
        let versions = checkpoint.versions();
        if versions != CheckpointVersions::GENESIS {
            return Err(NotAtGenesis { versions });
        }
        let meter = BasicGasMeter::new_with_gas(S::Gas::MAX, <S::Gas as Gas>::Price::ZEROED);
        Ok(Self {
            tx: MeteredTx::new(TxScratchpad::new(checkpoint), meter, S::GAS_SCHEDULE.state),
            events: ChargedEvents::new(),
        })
    }

    /// The events emitted so far. Always empty without the `native` feature (the zk guest),
    /// which charges events and drops them.
    pub fn events(&self) -> &[TypeErasedEvent] {
        self.events.as_slice()
    }

    /// Ends genesis: applies its writes to the checkpoint and returns its events iff no access
    /// failed and `result` is `Ok`; otherwise drops both. Without the `native` feature the
    /// returned events are always empty.
    pub fn finalize<E>(self, result: Result<(), E>) -> FinalizedGenesis<S, E> {
        let finalized = self.tx.finalize(result);
        let (checkpoint, events) = match finalized.outcome {
            PhaseOutcome::Committed => (finalized.scratchpad.commit(), self.events.into_vec()),
            PhaseOutcome::Reverted(_) => (finalized.scratchpad.revert(), Vec::new()),
        };
        FinalizedGenesis {
            checkpoint,
            meter: finalized.meter,
            events,
            outcome: finalized.outcome,
        }
    }
}

impl<S: Spec> Metered for GenesisStateAccessor<S> {
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

impl<S: Spec> EventContainer<S> for GenesisStateAccessor<S> {
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

impl<S: Spec> EventSink<S> for GenesisStateAccessor<S> {
    fn add_charged_events(&mut self, events: ChargedEvents) {
        self.events.append(events);
    }
}

/// At genesis the true slot number is the genesis one (and the checkpoint's versions are
/// [`CheckpointVersions::GENESIS`], checked by [`GenesisStateAccessor::new`]).
impl<S: Spec> PrivilegedKernelAccessor for GenesisStateAccessor<S> {
    fn true_slot_number(&self) -> SlotNumber {
        debug_assert_eq!(
            self.current_visible_slot_number().as_true(),
            SlotNumber::GENESIS
        );
        SlotNumber::GENESIS
    }
}

impl<S: Spec> GenesisState<S> for GenesisStateAccessor<S> {}

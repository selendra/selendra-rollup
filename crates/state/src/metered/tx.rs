//! [`MeteredTx`]: one metered phase of a transaction, and [`MeteredRef`], the access to it that
//! state accessors lend.

use std::marker::PhantomData;

use super::costs::{
    MAX_EVENT_KEY_LEN, MAX_STATE_VALUE_SIZE, StateAccessCosts, StateGas, StateGasMeter,
};
use super::error::{StateAccessError, StateOp};
use super::journal::Level;
use super::rights::AccessRights;
use super::scope::PhaseId;
use super::scratchpad::{TxScratchpad, namespace_of};
use super::view::MeteredView;
use crate::codec::{StateCodec, StateItemCodec, StateItemDecoder};
use crate::namespaces::{Namespace, ProvableNamespace};
use crate::{SlotKey, SlotValue, Storage};

/// The error of a metered access with meter `M`.
pub(crate) type Error<M> = StateAccessError<<M as StateGasMeter>::Error>;

/// The state of a metered phase that [`MeteredRef`]s borrow.
pub(crate) struct TxInner<St: Storage, M: StateGasMeter> {
    pub(crate) scratchpad: TxScratchpad<St>,
    pub(crate) meter: M,
    costs: StateAccessCosts<M::Gas>,
    /// The phase's first failure; set once, never cleared.
    pub(crate) failure: Option<Error<M>>,
    /// The base scope, opened by [`MeteredTx::new`], closed only by [`MeteredTx::finalize`].
    base: Level,
    /// The phase's identity, carried by its scope tokens (see [`PhaseId`]).
    pub(crate) id: PhaseId,
    /// The serial number of the next scope opened in the phase (the base scope's is `0`).
    next_serial: u64,
}

impl<St: Storage, M: StateGasMeter> TxInner<St, M> {
    /// Records `err` as the phase's failure (if it is the first) and returns it.
    pub(crate) fn fail(&mut self, err: Error<M>) -> Error<M> {
        if self.failure.is_none() {
            self.failure = Some(err.clone());
        }
        err
    }

    /// Charges `gas` (`None`: its computation overflowed) for `op`; any failure poisons.
    fn charge(
        &mut self,
        op: impl FnOnce() -> StateOp,
        gas: Option<M::Gas>,
    ) -> Result<(), Error<M>> {
        let Some(gas) = gas else {
            return Err(self.fail(StateAccessError::GasOverflow { op: op() }));
        };
        match self.meter.charge(gas) {
            Ok(()) => Ok(()),
            Err(source) => Err(self.fail(StateAccessError::OutOfGas { op: op(), source })),
        }
    }

    /// The first step of every access through an accessor at `level`: a poisoned phase
    /// refuses it; an accessor whose scope is no longer open poisons the phase; scopes deeper
    /// than the accessor's, left open (a leaked scope), are reverted (fail-closed).
    pub(crate) fn enter(&mut self, level: Option<Level>) -> Result<Level, Error<M>> {
        if self.failure.is_some() {
            return Err(StateAccessError::Poisoned);
        }
        match level {
            Some(level) if self.scratchpad.journal_mut().is_open(level) => {
                self.scratchpad.journal_mut().revert_above(level.depth);
                Ok(level)
            }
            _ => Err(self.fail(StateAccessError::ScopeMisuse)),
        }
    }

    /// Opens a scope inside the accessor's at `level` and returns the new scope's level:
    /// [`enter`](Self::enter)s, then charges `scope_open`, and only then pushes the scope. On
    /// any failure (which poisons the phase) nothing is opened.
    pub(crate) fn open_scope(&mut self, level: Option<Level>) -> Result<Level, Error<M>> {
        self.enter(level)?;
        let gas = self.costs.scope_open;
        self.charge(|| StateOp::OpenScope, Some(gas))?;
        let serial = self.next_serial;
        // Unique within the phase: 2^64 opens would take 2^64 calls (each charged
        // `scope_open`), so the counter never saturates in practice.
        self.next_serial = serial.saturating_add(1);
        Ok(self.scratchpad.journal_mut().open(serial))
    }
}

/// One metered phase of a transaction (pre-execution, or the call with its hooks) over a
/// [`TxScratchpad`]: a gas meter, the costs it charges, the access rights `R`, and a **base
/// scope** holding the phase's writes.
///
/// The state transition function builds it ([`new`](Self::new)) and lends it to modules through
/// an accessor that implements [`Metered`](super::Metered) (`selendra-modules-api`'s working
/// sets), then [`finalize`](Self::finalize)s it: the base scope is committed into the
/// scratchpad only if no access failed **and** the module returned `Ok`; otherwise it is
/// reverted. Nothing else can close the base scope (it has no [`ScopeToken`](super::ScopeToken)),
/// so a phase in which an access failed is never applied, whatever the module returned.
///
/// # Failures
/// The first failed access (out of gas, a gas overflow, a value too large, an event key too
/// long, a misused scope) **poisons** the phase: every later access returns
/// [`StateAccessError::Poisoned`] before touching the meter or storage (so a module that
/// ignores the error adds neither gas nor witness hints), and nested scopes share the poison
/// (reverting one does not clear it).
pub struct MeteredTx<St: Storage, M: StateGasMeter, R: AccessRights> {
    inner: TxInner<St, M>,
    rights: PhantomData<fn() -> R>,
}

impl<St: Storage, M: StateGasMeter + std::fmt::Debug, R: AccessRights> std::fmt::Debug
    for MeteredTx<St, M, R>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeteredTx")
            .field("meter", &self.inner.meter)
            .field("failure", &self.inner.failure)
            .finish_non_exhaustive()
    }
}

/// What [`MeteredTx::finalize`] returns: the scratchpad (with the phase's writes iff
/// committed), the meter (the gas used is kept either way) and the outcome.
#[derive(Debug)]
pub struct Finalized<St: Storage, M: StateGasMeter, E> {
    /// The transaction's scratchpad.
    pub scratchpad: TxScratchpad<St>,
    /// The phase's meter.
    pub meter: M,
    /// Whether the phase's writes were committed into the scratchpad.
    pub outcome: PhaseOutcome<M::Error, E>,
}

/// Whether a metered phase's writes were committed. `G` is the meter's error, `E` the module's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseOutcome<G, E> {
    /// The phase's writes are in the scratchpad.
    Committed,
    /// The phase's writes were dropped.
    Reverted(RevertReason<G, E>),
}

/// Why a metered phase was reverted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevertReason<G, E> {
    /// A state access failed (the first failure). Takes precedence over the module's result:
    /// the module may have returned `Ok` after ignoring it, or an error caused by it.
    Poisoned(StateAccessError<G>),
    /// No access failed, and the module returned this error.
    Module(E),
}

impl<St: Storage, M: StateGasMeter, R: AccessRights> MeteredTx<St, M, R> {
    /// Starts a metered phase on `scratchpad`, charging `meter` with `costs`, and opens its base
    /// scope (not charged: the state transition function opens it, not a module).
    pub fn new(
        mut scratchpad: TxScratchpad<St>,
        meter: M,
        costs: StateAccessCosts<M::Gas>,
    ) -> Self {
        debug_assert_eq!(
            scratchpad.journal().depth(),
            0,
            "a scratchpad never has open scopes outside a phase"
        );
        let base = scratchpad.journal_mut().open(0);
        Self {
            inner: TxInner {
                scratchpad,
                meter,
                costs,
                failure: None,
                base,
                id: PhaseId::new(),
                next_serial: 1,
            },
            rights: PhantomData,
        }
    }

    /// The phase's state access, at its base scope, for the accessor that owns the phase to
    /// lend ([`Metered::metered`](super::Metered::metered)).
    pub fn metered(&mut self) -> MeteredRef<'_, St, M, R> {
        let base = self.inner.base;
        MeteredRef {
            tx: &mut self.inner,
            level: Some(base),
            rights: PhantomData,
        }
    }

    /// Read-only information on the phase
    /// ([`Metered::metered_view`](super::Metered::metered_view)).
    pub fn metered_view(&self) -> MeteredView<'_, M> {
        MeteredView::new(&self.inner)
    }

    /// Ends the phase. Scopes left open are reverted; then the base scope is committed into the
    /// scratchpad iff no access failed and `result` is `Ok`, and reverted otherwise.
    pub fn finalize<E>(self, result: Result<(), E>) -> Finalized<St, M, E> {
        let TxInner {
            mut scratchpad,
            meter,
            costs: _,
            failure,
            base,
            id: _,
            next_serial: _,
        } = self.inner;
        debug_assert!(
            scratchpad.journal().is_open(base),
            "the base scope is always open"
        );
        let journal = scratchpad.journal_mut();
        journal.revert_above(base.depth);
        let outcome = match (failure, result) {
            (None, Ok(())) => {
                journal.commit_top();
                PhaseOutcome::Committed
            }
            (Some(failure), _) => {
                journal.revert_top();
                PhaseOutcome::Reverted(RevertReason::Poisoned(failure))
            }
            (None, Err(err)) => {
                journal.revert_top();
                PhaseOutcome::Reverted(RevertReason::Module(err))
            }
        };
        Finalized {
            scratchpad,
            meter,
            outcome,
        }
    }
}

/// Access to a metered phase, lent by an accessor ([`Metered::metered`](super::Metered::metered))
/// at its scope: the phase's base scope, or a nested scope ([`scoped`](Self::scoped)).
///
/// Its public operations are the charges ([`charge`](Self::charge),
/// [`charge_linear`](Self::charge_linear)), the event-key check
/// ([`check_event_key`](Self::check_event_key)), the scope operations
/// ([`open_scope`](Self::open_scope), [`close_scope`](Self::close_scope),
/// [`scoped`](Self::scoped)) and [`view`](Self::view). The raw reads and writes are
/// crate-private: only the blanket [`StateReader`](crate::StateReader)/
/// [`StateWriter`](crate::StateWriter) impls over [`Metered`](super::Metered) call them, and
/// they always charge gas. Its fields are private and it has no public constructor.
///
/// Every operation first checks the phase's poison and that the accessor's scope is still open,
/// then reverts the scopes deeper than it that were left open (a scope guard leaked with
/// `ManuallyDrop` or `Box::leak`): fail-closed, like dropping the guard.
pub struct MeteredRef<'a, St: Storage, M: StateGasMeter, R: AccessRights> {
    pub(crate) tx: &'a mut TxInner<St, M>,
    /// `None`: an accessor narrowed to a scope that is not inside its own (every access is
    /// `ScopeMisuse`).
    pub(crate) level: Option<Level>,
    pub(crate) rights: PhantomData<fn() -> R>,
}

impl<St: Storage, M: StateGasMeter, R: AccessRights> std::fmt::Debug for MeteredRef<'_, St, M, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeteredRef")
            .field("level", &self.level)
            .finish_non_exhaustive()
    }
}

impl<'a, St: Storage, M: StateGasMeter, R: AccessRights> MeteredRef<'a, St, M, R> {
    /// Charges `gas` (e.g. for computation). A refused charge poisons the phase.
    pub fn charge(&mut self, gas: M::Gas) -> Result<(), Error<M>> {
        self.tx.enter(self.level)?;
        self.tx.charge(|| StateOp::Charge, Some(gas))
    }

    /// Charges `base + per_unit·units` (e.g. a fixed cost plus a per-byte cost times a length),
    /// computed with checked arithmetic and charged as one sum. More than `u32::MAX` units, or
    /// an overflow, is [`StateAccessError::GasOverflow`]; any failure poisons the phase.
    pub fn charge_linear(
        &mut self,
        base: M::Gas,
        per_unit: M::Gas,
        units: u64,
    ) -> Result<(), Error<M>> {
        self.tx.enter(self.level)?;
        let gas = u32::try_from(units)
            .ok()
            .and_then(|units| per_unit.checked_scale(units))
            .and_then(|scaled| base.checked_add(scaled));
        self.tx.charge(|| StateOp::Charge, gas)
    }

    /// Checks an event key before the event is charged: a key of more than
    /// [`MAX_EVENT_KEY_LEN`] bytes (its UTF-8 length, `key.len()`, the measure the node's ledger
    /// uses) fails with [`StateAccessError::EventKeyTooLong`], which poisons the phase. Charges
    /// nothing either way. `selendra-modules-api`'s event containers call it for every event,
    /// so no transaction keeps an event the ledger would refuse.
    ///
    /// # Errors
    /// - [`StateAccessError::EventKeyTooLong`] (poisons the phase).
    /// - As for any access: [`StateAccessError::Poisoned`] on a poisoned phase,
    ///   [`StateAccessError::ScopeMisuse`] (poisons) if the accessor's scope is no longer open.
    pub fn check_event_key(&mut self, key: &str) -> Result<(), Error<M>> {
        self.tx.enter(self.level)?;
        let len = key.len();
        if len > MAX_EVENT_KEY_LEN {
            return Err(self.tx.fail(StateAccessError::EventKeyTooLong { len }));
        }
        Ok(())
    }

    /// Read-only information on the phase.
    pub fn view(&self) -> MeteredView<'_, M> {
        MeteredView::new(self.tx)
    }

    /// Reads `key` in `namespace`, charging per the formulas of
    /// [`costs`](super::costs) (plus decoding if `decoded`): the key part before touching
    /// storage, the value part once its size is known, before fetching it.
    pub(crate) fn read(
        &mut self,
        namespace: ProvableNamespace,
        key: &SlotKey,
        decoded: bool,
    ) -> Result<Option<SlotValue>, Error<M>> {
        self.tx.enter(self.level)?;
        let op = || StateOp::Read {
            namespace: namespace_of(namespace),
            key: key.clone(),
        };
        let key_len = u32::try_from(key.len()).ok();
        let gas = key_len.and_then(|key_len| self.tx.costs.read_key(key_len));
        self.tx.charge(op, gas)?;
        let Some(size) = self.tx.scratchpad.size(namespace, key) else {
            return Ok(None);
        };
        let gas = self.tx.costs.read_value(size, decoded);
        self.tx.charge(op, gas)?;
        Ok(self.tx.scratchpad.get(namespace, key))
    }

    /// [`read`](Self::read) with decoding charged, then decodes.
    ///
    /// # Panics
    /// If the stored bytes do not decode: see
    /// [`StateReader::get_decoded`](crate::StateReader::get_decoded).
    pub(crate) fn read_decoded<V, Codec>(
        &mut self,
        namespace: ProvableNamespace,
        key: &SlotKey,
        codec: &Codec,
    ) -> Result<Option<V>, Error<M>>
    where
        Codec: StateCodec,
        Codec::ValueCodec: StateItemCodec<V>,
    {
        Ok(self
            .read(namespace, key, true)?
            .map(|value| codec.value_codec().decode_unwrap(value.value())))
    }

    /// Writes `value` to `key` in `namespace` (`None`: a delete): fails with `ValueTooLarge`
    /// above [`MAX_STATE_VALUE_SIZE`], then charges, then journals the write.
    pub(crate) fn write(
        &mut self,
        namespace: Namespace,
        key: &SlotKey,
        value: Option<SlotValue>,
    ) -> Result<(), Error<M>> {
        self.tx.enter(self.level)?;
        let len = value.as_ref().map_or(0, SlotValue::len);
        let op = || match value {
            Some(_) => StateOp::Write {
                namespace,
                key: key.clone(),
            },
            None => StateOp::Delete {
                namespace,
                key: key.clone(),
            },
        };
        if len > MAX_STATE_VALUE_SIZE {
            return Err(self
                .tx
                .fail(StateAccessError::ValueTooLarge { op: op(), len }));
        }
        let gas = u32::try_from(key.len())
            .ok()
            .zip(u32::try_from(len).ok())
            .and_then(|(key_len, len)| match namespace {
                Namespace::User | Namespace::Kernel => self.tx.costs.write(key_len, len),
                Namespace::Accessory => self.tx.costs.accessory_write(key_len, len),
            });
        self.tx.charge(op, gas)?;
        self.tx.scratchpad.journal_mut().set(namespace, key, value);
        Ok(())
    }
}

//! Events: [`TypeErasedEvent`], and the [`EventContainer`] trait through which module code emits
//! them, charged gas.
//!
//! An event costs `event_base + event_per_byte·(key_len + borsh_len)` gas
//! ([`GasSchedule`](crate::GasSchedule)), where `key_len` is the event key's length in bytes and
//! `borsh_len` the length of the event's borsh encoding (`borsh::object_length`). It is charged
//! the same way natively and in the zk guest, before the event is kept; events are kept only
//! with the `native` feature (the guest charges and drops them: nothing in the state transition
//! reads them). So without `native`, every accessor's `events()` and the events its `finalize`
//! returns are always empty.
//! Upstream charged nothing for events (P5-14).
//!
//! An event belongs to the scope it was emitted in: the events of a reverted nested scope
//! ([`RevertableTxState`](crate::RevertableTxState)) or of a reverted phase are dropped with its
//! writes.

use std::any::Any;
use std::fmt;

use borsh::BorshSerialize;

use super::TxStateError;
use crate::{GasMeter, Spec};

/// An event emitted by a module, with its type erased: the emitting module's discriminant (its
/// `ModuleInfo::DISCRIMINANT`, which the runtime's event type maps back to the module, instead
/// of upstream's `TypeId`), its key, and the event itself.
pub struct TypeErasedEvent {
    module: u8,
    key: String,
    event: Box<dyn Any + Send + Sync>,
}

impl fmt::Debug for TypeErasedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypeErasedEvent")
            .field("module", &self.module)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl TypeErasedEvent {
    /// The event `event` with key `key`, emitted by the module with discriminant `module`. Not
    /// charged: module code emits events through [`EventContainer::add_event`], which charges
    /// them.
    pub fn new<E: Any + Send + Sync>(module: u8, key: &str, event: E) -> Self {
        Self {
            module,
            key: key.to_owned(),
            event: Box::new(event),
        }
    }

    /// The discriminant of the module that emitted it.
    pub fn module(&self) -> u8 {
        self.module
    }

    /// The event's key.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The event, if it is an `E`.
    pub fn downcast<E: Any>(self) -> Option<E> {
        self.event.downcast::<E>().ok().map(|event| *event)
    }

    /// A reference to the event, if it is an `E`.
    pub fn downcast_ref<E: Any>(&self) -> Option<&E> {
        self.event.downcast_ref::<E>()
    }
}

pub(crate) use sealed::{ChargedEvents, EventSink};

/// The crate-private half of [`EventContainer`]: how a committed nested scope hands its charged
/// events to its parent. Not nameable outside this crate, so no other crate can implement
/// [`EventContainer`] (nor receive or build charged events).
pub(crate) mod sealed {
    use std::fmt;

    use super::TypeErasedEvent;
    use crate::Spec;

    /// Events that were charged when they were emitted, moved from a committed nested scope into
    /// its parent ([`EventSink::add_charged_events`]). Only this crate's accessors build one, from
    /// events they charged, and only they receive one.
    pub struct ChargedEvents {
        events: Vec<TypeErasedEvent>,
    }

    impl fmt::Debug for ChargedEvents {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_list().entries(&self.events).finish()
        }
    }

    impl ChargedEvents {
        /// No events.
        pub(crate) const fn new() -> Self {
            Self { events: Vec::new() }
        }

        /// Adds an event that was charged.
        pub(crate) fn push(&mut self, event: TypeErasedEvent) {
            self.events.push(event);
        }

        /// Moves `other`'s events after these.
        pub(crate) fn append(&mut self, mut other: Self) {
            self.events.append(&mut other.events);
        }

        /// The events.
        pub(crate) fn as_slice(&self) -> &[TypeErasedEvent] {
            &self.events
        }

        /// The events, by value.
        pub(crate) fn into_vec(self) -> Vec<TypeErasedEvent> {
            self.events
        }
    }

    /// Accepts the events of a committed nested scope ([`EventContainer`](super::EventContainer)'s
    /// sealed supertrait).
    pub trait EventSink<S: Spec> {
        /// Adds events that were charged when emitted (a committed nested scope's), without
        /// charging them again.
        fn add_charged_events(&mut self, events: ChargedEvents);
    }
}

/// Accepts the events module code emits, charging gas for each (see the [module docs](self)).
///
/// Implemented by the transaction accessors ([`WorkingSet`](crate::WorkingSet),
/// [`RevertableTxState`](crate::RevertableTxState),
/// [`GenesisStateAccessor`](crate::GenesisStateAccessor)). Module code emits events with
/// [`add_event`](Self::add_event) (S7's `Module::emit_event` calls it with the module's
/// discriminant); events reach the state transition function only through these accessors,
/// all of which charge.
///
/// Sealed: no other crate can implement it (its supertrait is private to this crate; E0277), so
/// none can write a [`TxState`](crate::TxState) of its own. A committed nested scope hands its
/// events to the accessor it was opened on, never to module code: a forwarding accessor that
/// kept them could otherwise move a reverted scope's (or transaction's) events into another
/// transaction, unpaid there.
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
///
/// struct Forward<'a>(&'a mut WorkingSet<TestSpec>);
///
/// impl EventContainer<TestSpec> for Forward<'_> {
///     fn add_event<E>(&mut self, module: u8, key: &str, event: E) -> Result<(), TxStateError<TestSpec>>
///     where
///         E: borsh::BorshSerialize + core::any::Any + Send + Sync,
///     {
///         self.0.add_event(module, key, event)
///     }
/// }
/// ```
///
/// A wrapper can still emit events through the accessor it wraps (charged there):
///
/// ```
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
///
/// struct Forward<'a>(&'a mut WorkingSet<TestSpec>);
///
/// impl Forward<'_> {
///     fn add_event<E>(&mut self, module: u8, key: &str, event: E) -> Result<(), TxStateError<TestSpec>>
///     where
///         E: borsh::BorshSerialize + core::any::Any + Send + Sync,
///     {
///         self.0.add_event(module, key, event)
///     }
/// }
/// ```
///
/// Charged events cannot be named outside this crate either (E0603):
///
/// ```compile_fail,E0603
/// use selendra_modules_api::state::events::ChargedEvents;
///
/// fn stash(_: ChargedEvents) {}
/// ```
///
/// ```
/// use selendra_modules_api::state::events::TypeErasedEvent;
///
/// fn keep(_: TypeErasedEvent) {}
/// ```
pub trait EventContainer<S: Spec>: EventSink<S> {
    /// Charges `event_base + event_per_byte·(key.len() + borsh_len(event))`, then keeps the event
    /// with the `native` feature; without it (the zk guest) the event is charged the same and
    /// dropped.
    ///
    /// # Errors
    /// The charge was refused (`OutOfGas`), its gas overflows, or the event's borsh encoding
    /// fails (a `BorshSerialize` impl must be infallible: such an event cannot be priced, which
    /// is reported as `GasOverflow`), or the phase is poisoned. Any failure poisons the phase,
    /// and the event is dropped.
    fn add_event<E>(&mut self, module: u8, key: &str, event: E) -> Result<(), TxStateError<S>>
    where
        E: BorshSerialize + Any + Send + Sync;
}

/// Charges for `event` with key `key` (see the [module docs](self)) on `state`'s phase and
/// returns it, type-erased, if it is kept (natively).
pub(crate) fn charge_event<S, T, E>(
    state: &mut T,
    module: u8,
    key: &str,
    event: E,
) -> Result<Option<TypeErasedEvent>, TxStateError<S>>
where
    S: Spec,
    T: GasMeter<S>,
    E: BorshSerialize + Any + Send + Sync,
{
    let costs = &S::GAS_SCHEDULE;
    // An encoding that fails cannot be priced: charged as more units than any charge accepts
    // (`GasOverflow`), so it fails the same way natively and in the guest.
    let units = borsh::object_length(&event)
        .ok()
        .and_then(|len| len.checked_add(key.len()))
        .and_then(|len| u64::try_from(len).ok())
        .unwrap_or(u64::MAX);
    state
        .metered()
        .charge_linear(costs.event_base, costs.event_per_byte, units)?;
    Ok(keep(module, key, event))
}

/// The event to keep: natively, the event itself.
#[cfg(feature = "native")]
fn keep<E: Any + Send + Sync>(module: u8, key: &str, event: E) -> Option<TypeErasedEvent> {
    Some(TypeErasedEvent::new(module, key, event))
}

/// The event to keep: in the zk guest, none (it is charged and dropped).
#[cfg(not(feature = "native"))]
fn keep<E: Any + Send + Sync>(_module: u8, _key: &str, _event: E) -> Option<TypeErasedEvent> {
    None
}

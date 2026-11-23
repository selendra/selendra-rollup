//! Events: what a module's event type implements ([`ModuleEvent`]), and how a runtime maps the
//! events its modules emit to its own event type ([`RuntimeEventProcessor`]).

use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{MAX_MODULE_NAME_LEN, ModuleMessage};
use crate::{MAX_EVENT_KEY_LEN, NotInstantiable, TypeErasedEvent};

/// The longest event name [`#[derive(ModuleEvent)]`](macro@crate::ModuleEvent) accepts, in
/// bytes (223): what is left of an event key ([`MAX_EVENT_KEY_LEN`]) after the longest module
/// name ([`MAX_MODULE_NAME_LEN`]) and the `/`, so a derived key `"{NAME}/{event_name}"` always
/// fits. (A longer key fails at run time: the emitting call is reverted.)
pub const MAX_EVENT_NAME_LEN: usize = MAX_EVENT_KEY_LEN - MAX_MODULE_NAME_LEN - 1;

/// A module's event type ([`Module::Event`](crate::Module::Event)): each event's name, the
/// second half of its key (`"{module NAME}/{event_name}"`, see
/// [`EventEmitter`](crate::EventEmitter)). Derived by
/// [`#[derive(ModuleEvent)]`](macro@crate::ModuleEvent) (the variant's name, at most
/// [`MAX_EVENT_NAME_LEN`] bytes) or written by hand.
///
/// The name comes from this method, never from the event's `Debug` output (upstream parsed the
/// key out of it, P5-32).
pub trait ModuleEvent {
    /// The event's name, e.g. its variant's name: `Transfer`.
    fn event_name(&self) -> &'static str;
}

/// No events: the event type of a module that emits none.
impl ModuleEvent for NotInstantiable {
    fn event_name(&self) -> &'static str {
        match *self {}
    }
}

/// A runtime's event type, and how the events its modules emit map to it: implemented by the
/// runtime's derive.
///
/// An event maps to the module whose discriminant it carries
/// ([`TypeErasedEvent::module`], set by [`EventEmitter`](crate::EventEmitter)), so two modules
/// emitting the same event type are told apart (upstream matched on the event's `TypeId`,
/// P5-32).
pub trait RuntimeEventProcessor {
    /// The runtime's event type: an event of one of its modules, tagged with the module's
    /// discriminant in borsh and keyed by its name in JSON ([`ModuleMessage`]).
    type RuntimeEvent: ModuleMessage
        + BorshSerialize
        + BorshDeserialize
        + Serialize
        + DeserializeOwned
        + Debug
        + Clone
        + PartialEq
        + Send
        + Sync
        + Unpin;

    /// The runtime event of `event`, or `None` if no module of the runtime has its
    /// discriminant, or the event is not that module's event type.
    fn convert_to_runtime_event(event: TypeErasedEvent) -> Option<Self::RuntimeEvent>;
}

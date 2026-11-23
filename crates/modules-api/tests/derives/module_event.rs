//! `#[derive(ModuleEvent)]`: event names from variant names, whatever the `Debug` output, and
//! the event-key bound.

use std::fmt;
use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_modules_api::test_utils::TestSpec;
use selendra_modules_api::*;
use serde::{Deserialize, Serialize};

use crate::working_set;

type S = TestSpec;

#[derive(
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
    ConsensusType,
    ModuleEvent,
)]
#[allow(non_camel_case_types)]
pub enum Event {
    Named { amount: u128 },
    Unnamed(u128, u8),
    Unit,
    r#type,
}

/// Not the derived `Debug`: upstream's event key was parsed out of it.
impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an event")
    }
}

/// Every variant kind; a raw identifier without its `r#`.
#[test]
fn derived_event_names() {
    assert_eq!(Event::Named { amount: 1 }.event_name(), "Named");
    assert_eq!(Event::Unnamed(1, 2).event_name(), "Unnamed");
    assert_eq!(Event::Unit.event_name(), "Unit");
    assert_eq!(Event::r#type.event_name(), "type");
}

/// A generic event enum.
#[derive(ModuleEvent)]
#[allow(dead_code)]
pub enum GenericEvent<S: Spec> {
    Paid { to: S::Address },
    Skipped(PhantomData<S>),
}

#[test]
fn generic_event_enum() {
    let skipped = GenericEvent::<S>::Skipped(PhantomData);
    assert_eq!(skipped.event_name(), "Skipped");
    let paid = GenericEvent::<S>::Paid {
        to: selendra_primitives::MultiAddressEvm::Standard(selendra_primitives::Address::new(
            [1; 28],
        )),
    };
    assert_eq!(paid.event_name(), "Paid");
}

/// The emitting module of `E`, named `"emitter"`.
#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 250, name = "emitter")]
pub struct Emitter<S: Spec> {
    #[id]
    id: ModuleId,
    #[phantom]
    spec: PhantomData<S>,
}

impl<S: Spec> Module for Emitter<S> {
    type Config = ();
    type CallMessage = NotInstantiable;
    type Event = Event;
    type Error = anyhow::Error;

    fn call(
        &mut self,
        message: NotInstantiable,
        _context: &Context<S>,
        _state: &mut impl TxState<S>,
    ) -> anyhow::Result<()> {
        match message {}
    }
}

/// The derived name, not the `Debug` output, is the second half of the event's key.
#[test]
fn derived_event_name_ignores_debug() {
    let event = Event::Unnamed(1, 2);
    assert_eq!(format!("{event:?}"), "an event");
    let mut state = working_set::<S>(1_000_000);
    Emitter::<S>::default()
        .emit_event(&mut state, event.clone())
        .unwrap();
    let finalized = state.finalize(Ok::<(), ()>(()));
    assert!(matches!(finalized.outcome, PhaseOutcome::Committed));
    #[cfg(feature = "native")]
    {
        let [kept] = &finalized.events[..] else {
            panic!("one event")
        };
        assert_eq!(kept.key(), "emitter/Unnamed");
        assert_eq!(kept.module(), 250);
        assert_eq!(kept.downcast_ref::<Event>(), Some(&event));
    }
    #[cfg(not(feature = "native"))]
    assert!(finalized.events.is_empty());
}

/// An event whose name has the most bytes the derive accepts (`MAX_EVENT_NAME_LEN`, 223; one
/// more is a compile error, tested in `selendra-macros`).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
    ConsensusType,
    ModuleEvent,
)]
pub enum LongestEvent {
    Evvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv(
        u8,
    ),
}

/// A module whose name has the most bytes a name can have (`MAX_MODULE_NAME_LEN`, 32).
#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 251, name = "longest_module_name_32_bytes_xyz")]
pub struct LongestName<S: Spec> {
    #[id]
    id: ModuleId,
    #[phantom]
    spec: PhantomData<S>,
}

impl<S: Spec> Module for LongestName<S> {
    type Config = ();
    type CallMessage = NotInstantiable;
    type Event = LongestEvent;
    type Error = anyhow::Error;

    fn call(
        &mut self,
        message: NotInstantiable,
        _context: &Context<S>,
        _state: &mut impl TxState<S>,
    ) -> anyhow::Result<()> {
        match message {}
    }
}

/// The derive's bound is exact: the longest derived event name, emitted by the module with the
/// longest name, makes a key of exactly `MAX_EVENT_KEY_LEN` bytes, which is accepted (a key one
/// byte longer reverts the call: `custom_event_key_is_bounded`).
#[test]
fn longest_derived_event_key_fits() {
    let event = LongestEvent::Evvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv(1);
    assert_eq!(event.event_name().len(), MAX_EVENT_NAME_LEN);
    assert_eq!(LongestName::<S>::NAME.len(), MAX_MODULE_NAME_LEN);
    assert_eq!(
        MAX_MODULE_NAME_LEN + 1 + MAX_EVENT_NAME_LEN,
        MAX_EVENT_KEY_LEN
    );
    let mut state = working_set::<S>(1_000_000);
    LongestName::<S>::default()
        .emit_event(&mut state, event.clone())
        .unwrap();
    let finalized = state.finalize(Ok::<(), ()>(()));
    assert!(matches!(finalized.outcome, PhaseOutcome::Committed));
    #[cfg(feature = "native")]
    {
        let [kept] = &finalized.events[..] else {
            panic!("one event")
        };
        assert_eq!(kept.key().len(), MAX_EVENT_KEY_LEN);
        assert_eq!(
            kept.key(),
            format!("longest_module_name_32_bytes_xyz/{}", event.event_name())
        );
    }
}

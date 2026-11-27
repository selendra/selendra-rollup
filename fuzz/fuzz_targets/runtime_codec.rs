//! The runtime derives' codecs, on a test runtime: `{Runtime}Call` (`DispatchCall`) and
//! `{Runtime}Event` (`Event`).
//!
//! - borsh: a value decodes exactly when the first byte is the discriminant of a module whose
//!   message decodes from all the rest (an independent oracle: the module's message type decoded
//!   by itself); a tag that is no module's (or a module's without messages) never decodes,
//!   trailing bytes never do, and whatever decodes re-encodes to exactly the input;
//! - JSON (keyed by module name): whatever decodes is canonical; postcard (tagged by
//!   discriminant): whatever decodes round trips; every encoding of a value decodes to that
//!   value;
//! - JSON objects built from the fuzz bytes (a key from a list of names and near misses, a
//!   message): accepted exactly when the key is a module's name and the message decodes as that
//!   module's.
#![no_main]

use std::marker::PhantomData;

use libfuzzer_sys::fuzz_target;
use selendra_modules_api::test_utils::TestSpec;
use selendra_modules_api::*;
use selendra_state::StateValue;

// -------------------------------------------------------------------------------------------
// The test runtime: modules with discriminants 10, 200 and 3, listed in another order, two
// with one event type, one with no calls and no events.

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
    ConsensusType,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum AlphaCall {
    Set(u64),
    Rename { name: String },
    Data(Vec<u8>),
    Clear,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
    ConsensusType,
    ModuleEvent,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum SharedEvent {
    Changed { old: Option<u64>, new: u64 },
    Named(String),
}

/// An error without details.
#[derive(Debug)]
struct Failed;

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("failed")
    }
}

impl ErrorDetail for Failed {
    fn error_detail(&self) -> Result<ErrorContext, Box<dyn std::error::Error + Send + Sync>> {
        Ok(ErrorContext::new())
    }
}

macro_rules! module {
    ($module:ident, $discriminant:tt, $name:tt, $call:ty, $event:ty) => {
        #[derive(Clone, ModuleInfo)]
        #[module_info(discriminant = $discriminant, name = $name)]
        struct $module<S: Spec> {
            #[id]
            id: ModuleId,
            #[state(item = 0)]
            calls: StateValue<u64>,
            #[phantom]
            spec: PhantomData<S>,
        }

        impl<S: Spec> Module for $module<S> {
            type Config = ();
            type CallMessage = $call;
            type Event = $event;
            type Error = Failed;

            fn call(
                &mut self,
                _message: $call,
                _context: &Context<S>,
                state: &mut impl TxState<S>,
            ) -> Result<(), Failed> {
                let calls = self.calls.get(state).map_err(|_| Failed)?.unwrap_or(0);
                self.calls
                    .set(&calls.saturating_add(1), state)
                    .map_err(|_| Failed)
            }
        }
    };
}

module!(Alpha, 10, "alpha", AlphaCall, SharedEvent);
module!(Beta, 200, "beta", (u8, Option<u32>), SharedEvent);
module!(Gamma, 3, "gamma", NotInstantiable, NotInstantiable);

#[derive(Clone, Default, DispatchCall, Event)]
struct Fuzzed<S: Spec> {
    beta: Beta<S>,
    gamma: Gamma<S>,
    alpha: Alpha<S>,
}

type Rt = Fuzzed<TestSpec>;
type Call = FuzzedCall<TestSpec>;
type Event = FuzzedEvent<TestSpec>;

// -------------------------------------------------------------------------------------------
// Checks

/// Every encoding of `value` decodes to `value`; borsh is the module's tag, then its message.
fn round_trips<T>(value: &T, tag_and_message: (u8, Vec<u8>))
where
    T: borsh::BorshSerialize
        + borsh::BorshDeserialize
        + serde::Serialize
        + serde::de::DeserializeOwned
        + ModuleMessage
        + PartialEq
        + std::fmt::Debug,
{
    let bytes = borsh::to_vec(value).unwrap();
    let (tag, message) = tag_and_message;
    assert_eq!(bytes[0], tag);
    assert_eq!(bytes[1..], message);
    assert_eq!(value.module_discriminant(), tag);
    assert_eq!(&borsh::from_slice::<T>(&bytes).unwrap(), value);
    let json = serde_json::to_value(value).unwrap();
    let object = json.as_object().unwrap();
    assert_eq!(object.len(), 1);
    assert!(object.contains_key(value.module_name()));
    assert_eq!(&serde_json::from_value::<T>(json).unwrap(), value);
    let binary = postcard::to_allocvec(value).unwrap();
    assert_eq!(&postcard::from_bytes::<T>(&binary).unwrap(), value);
}

/// The call's tag and message bytes, independently of the derived codec.
fn call_parts(call: &Call) -> (u8, Vec<u8>) {
    match call {
        Call::Alpha(message) => (10, borsh::to_vec(message).unwrap()),
        Call::Beta(message) => (200, borsh::to_vec(message).unwrap()),
        Call::Gamma(message) => match *message {},
    }
}

fn event_parts(event: &Event) -> (u8, Vec<u8>) {
    match event {
        Event::Alpha(event) => (10, borsh::to_vec(event).unwrap()),
        Event::Beta(event) => (200, borsh::to_vec(event).unwrap()),
        Event::Gamma(event) => match *event {},
    }
}

/// The fuzz bytes as a call and as an event (borsh), against the oracle.
fn borsh_bytes(data: &[u8]) {
    let expected_call = match data.split_first() {
        Some((&10, rest)) => borsh::from_slice::<AlphaCall>(rest).ok().map(Call::Alpha),
        Some((&200, rest)) => borsh::from_slice::<(u8, Option<u32>)>(rest)
            .ok()
            .map(Call::Beta),
        _ => None,
    };
    let call = Rt::decode(data).ok();
    assert_eq!(call, expected_call);
    assert_eq!(borsh::from_slice::<Call>(data).ok(), expected_call);
    if let Some(call) = call {
        assert_eq!(
            Rt::encode(&call).unwrap(),
            data,
            "non-canonical call accepted"
        );
        round_trips(&call, call_parts(&call));
    }

    let expected_event = match data.split_first() {
        Some((&10, rest)) => borsh::from_slice::<SharedEvent>(rest)
            .ok()
            .map(Event::Alpha),
        Some((&200, rest)) => borsh::from_slice::<SharedEvent>(rest).ok().map(Event::Beta),
        _ => None,
    };
    let event = borsh::from_slice::<Event>(data).ok();
    assert_eq!(event, expected_event);
    if let Some(event) = event {
        assert_eq!(
            borsh::to_vec(&event).unwrap(),
            data,
            "non-canonical event accepted"
        );
        round_trips(&event, event_parts(&event));
    }
}

/// The fuzz bytes as postcard (tagged by the module's discriminant, a varint): whatever
/// decodes round trips. (postcard itself does not promise one encoding per value.)
fn postcard_bytes(data: &[u8]) {
    if let Ok(call) = postcard::from_bytes::<Call>(data) {
        round_trips(&call, call_parts(&call));
    }
    if let Ok(event) = postcard::from_bytes::<Event>(data) {
        round_trips(&event, event_parts(&event));
    }
}

/// JSON text: whatever decodes is canonical (it serializes back to the same JSON value).
fn json_text(s: &str) {
    if let Ok(call) = serde_json::from_str::<Call>(s) {
        let input: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(serde_json::to_value(&call).unwrap(), input);
        round_trips(&call, call_parts(&call));
    }
    if let Ok(event) = serde_json::from_str::<Event>(s) {
        let input: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(serde_json::to_value(&event).unwrap(), input);
        round_trips(&event, event_parts(&event));
    }
}

/// Keys of a built JSON object: the modules' names and near misses (field positions,
/// discriminants, case, another module's field order).
const KEYS: [&str; 9] = [
    "alpha", "beta", "gamma", "Alpha", "ALPHA", "10", "0", "delta", "alpha ",
];

/// A JSON object `{key: message}` built from the fuzz bytes: the key from `KEYS`, the message
/// the JSON of a message decoded (borsh) from the rest, or the rest as text. Accepted exactly
/// when the key names a module whose message type takes it.
fn built_json(data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let key = KEYS[usize::from(selector) % KEYS.len()];
    let messages: Vec<serde_json::Value> = [
        borsh::from_slice::<AlphaCall>(rest)
            .ok()
            .map(|m| serde_json::to_value(m).unwrap()),
        borsh::from_slice::<(u8, Option<u32>)>(rest)
            .ok()
            .map(|m| serde_json::to_value(m).unwrap()),
        borsh::from_slice::<SharedEvent>(rest)
            .ok()
            .map(|m| serde_json::to_value(m).unwrap()),
        std::str::from_utf8(rest)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok()),
    ]
    .into_iter()
    .flatten()
    .collect();
    for message in messages {
        let object = serde_json::json!({ key: message.clone() });
        let expected_call = match key {
            "alpha" => serde_json::from_value::<AlphaCall>(message.clone())
                .ok()
                .map(Call::Alpha),
            "beta" => serde_json::from_value::<(u8, Option<u32>)>(message.clone())
                .ok()
                .map(Call::Beta),
            _ => None,
        };
        assert_eq!(
            serde_json::from_value::<Call>(object.clone()).ok(),
            expected_call
        );
        let expected_event = match key {
            "alpha" => serde_json::from_value::<SharedEvent>(message.clone())
                .ok()
                .map(Event::Alpha),
            "beta" => serde_json::from_value::<SharedEvent>(message)
                .ok()
                .map(Event::Beta),
            _ => None,
        };
        assert_eq!(serde_json::from_value::<Event>(object).ok(), expected_event);
    }
}

fuzz_target!(|data: &[u8]| {
    borsh_bytes(data);
    postcard_bytes(data);
    if let Ok(s) = std::str::from_utf8(data) {
        json_text(s);
    }
    built_json(data);
});

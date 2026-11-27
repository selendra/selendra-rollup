//! The runtime derives (`DispatchCall`, `MessageCodec`, `Genesis`, `Event`, `Hooks`) on derived
//! modules: the call and event encodings (borsh tag = the module's discriminant, JSON keyed by
//! the module's name; known answers, strict decoding), dispatch with the module's error passed
//! through, the module id of a call, genesis in dependency order with a strict configuration,
//! events mapped to the module that emitted them, hooks in field order, the layout, hygiene and
//! two runtimes in one Rust module. (Upstream's `tests/integration/dispatch.rs`, rewritten.)

use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::crypto::CredentialId;
use selendra_modules_api::test_utils::{MockAddress, MockKernel, TestSpec, TestStorage};
use selendra_modules_api::*;
use selendra_state::{
    AccessoryStateValue, ArrayWitness, BorshCodec, Prefix, StateUpdate, StateValue, Storage,
    TxScratchpad,
};
use serde::{Deserialize, Serialize};

type S = TestSpec;
type Header = selendra_mock_da::MockBlockHeader;

const READER: u8 = 247;
const SECOND: u8 = 248;
const THIRD: u8 = 249;
const FIRST: u8 = 250;

// -------------------------------------------------------------------------------------------
// Modules

/// The event type of both `First` and `Second`: the runtime tells their events apart by the
/// emitting module, not by the type.
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
#[serde(rename_all = "snake_case")]
pub enum SharedEvent {
    Set { value: u8 },
    Unchanged,
}

/// `First`'s error, with an error code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize)]
#[serde(tag = "error_code", rename_all = "snake_case")]
pub enum FirstError {
    #[error("the value 0 is rejected")]
    Zero,
    #[error("{message}")]
    State { message: String },
}

impl FirstError {
    fn state(error: impl std::fmt::Display) -> Self {
        Self::State {
            message: error.to_string(),
        }
    }
}

impl ErrorDetail for FirstError {
    fn error_detail(&self) -> Result<ErrorContext, Box<dyn std::error::Error + Send + Sync>> {
        Ok(to_json_object(self)?)
    }
}

/// Sets its value (`0` is an error); its genesis sets it to the configured value.
#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 250, name = "first")]
pub struct First<S: Spec> {
    #[id]
    id: ModuleId,
    #[state(item = 0)]
    value: StateValue<u8>,
    #[phantom]
    spec: PhantomData<S>,
}

impl<S: Spec> Module for First<S> {
    type Config = u8;
    type CallMessage = u8;
    type Event = SharedEvent;
    type Error = FirstError;

    fn genesis(
        &mut self,
        _header: &<S::Da as selendra_interface::da::DaSpec>::BlockHeader,
        config: &u8,
        state: &mut impl GenesisState<S>,
    ) -> anyhow::Result<()> {
        self.value.set(config, state)?;
        Ok(())
    }

    fn call(
        &mut self,
        message: u8,
        _context: &Context<S>,
        state: &mut impl TxState<S>,
    ) -> Result<(), FirstError> {
        // The write and the event happen before the check: a failed call keeps neither.
        self.value.set(&message, state).map_err(FirstError::state)?;
        self.emit_event(state, SharedEvent::Set { value: message })
            .map_err(FirstError::state)?;
        if message == 0 {
            return Err(FirstError::Zero);
        }
        Ok(())
    }
}

/// Like `First` (the same call message and event type), without genesis configuration.
#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 248, name = "second")]
pub struct Second<S: Spec> {
    #[id]
    id: ModuleId,
    #[state(item = 0)]
    value: StateValue<u8>,
    #[phantom]
    spec: PhantomData<S>,
}

impl<S: Spec> Module for Second<S> {
    type Config = ();
    type CallMessage = u8;
    type Event = SharedEvent;
    type Error = anyhow::Error;

    fn genesis(
        &mut self,
        _header: &<S::Da as selendra_interface::da::DaSpec>::BlockHeader,
        _config: &(),
        state: &mut impl GenesisState<S>,
    ) -> anyhow::Result<()> {
        self.value.set(&2, state)?;
        Ok(())
    }

    fn call(
        &mut self,
        message: u8,
        _context: &Context<S>,
        state: &mut impl TxState<S>,
    ) -> anyhow::Result<()> {
        let event = if self.value.get(state)? == Some(message) {
            SharedEvent::Unchanged
        } else {
            SharedEvent::Set { value: message }
        };
        self.value.set(&message, state)?;
        self.emit_event(state, event)?;
        Ok(())
    }
}

/// A call message type the runtime is generic over (upstream's `ModuleThreeStorable`).
pub trait Payload: CallMessage + Default {}

impl Payload for u32 {}

/// Generic over another type than the spec: stores a `T`, set by its calls.
#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 249, name = "third")]
pub struct Third<S: Spec, T: Payload> {
    #[id]
    id: ModuleId,
    #[state(item = 0)]
    value: StateValue<T>,
    #[phantom]
    spec: PhantomData<S>,
}

impl<S: Spec, T: Payload> Module for Third<S, T> {
    type Config = ();
    type CallMessage = T;
    type Event = NotInstantiable;
    type Error = anyhow::Error;

    fn genesis(
        &mut self,
        _header: &<S::Da as selendra_interface::da::DaSpec>::BlockHeader,
        _config: &(),
        state: &mut impl GenesisState<S>,
    ) -> anyhow::Result<()> {
        self.value.set(&T::default(), state)?;
        Ok(())
    }

    fn call(
        &mut self,
        message: T,
        _context: &Context<S>,
        state: &mut impl TxState<S>,
    ) -> anyhow::Result<()> {
        self.value.set(&message, state)?;
        Ok(())
    }
}

/// Holds `First` (a dependency): its genesis records `First`'s value, so `First`'s genesis must
/// run first, though the runtime lists `reader` first.
#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 247, name = "reader")]
pub struct Reader<S: Spec> {
    #[id]
    id: ModuleId,
    #[module]
    first: First<S>,
    #[state(item = 0)]
    seen: StateValue<u8>,
}

impl<S: Spec> Module for Reader<S> {
    type Config = ();
    type CallMessage = NotInstantiable;
    type Event = NotInstantiable;
    type Error = anyhow::Error;

    fn genesis(
        &mut self,
        _header: &<S::Da as selendra_interface::da::DaSpec>::BlockHeader,
        _config: &(),
        state: &mut impl GenesisState<S>,
    ) -> anyhow::Result<()> {
        let value = self.first.value.get(state)?;
        self.seen.set(&value.unwrap_or(u8::MAX), state)?;
        Ok(())
    }

    fn call(
        &mut self,
        message: NotInstantiable,
        _context: &Context<S>,
        _state: &mut impl TxState<S>,
    ) -> anyhow::Result<()> {
        match message {}
    }
}

/// The runtime: field order (`reader`, `primary`, `second`, `third`) is neither the order of
/// the discriminants (247, 250, 248, 249) nor of the names, and the field `primary` holds the
/// module named `first`.
#[derive(Clone, Default, DispatchCall, MessageCodec, Genesis, Event, Hooks)]
pub struct Rt<S: Spec, T: Payload> {
    pub reader: Reader<S>,
    pub primary: First<S>,
    pub second: Second<S>,
    pub third: Third<S, T>,
}

type R = Rt<S, u32>;
type Call = RtCall<S, u32>;
type Event = RtEvent<S, u32>;

// -------------------------------------------------------------------------------------------
// Helpers

fn header() -> Header {
    selendra_mock_da::MockBlockHeader::from_height(0)
}

fn address(byte: u8) -> <S as Spec>::Address {
    selendra_primitives::MultiAddressEvm::Standard(selendra_primitives::Address::new([byte; 28]))
}

fn context() -> Context<S> {
    Context::new(
        address(1),
        Credential::Multisig(CredentialId::from_bytes([1; 32])),
        address(2),
        MockAddress::new([3; 32]),
        ExecutionContext::Node,
        SequencerType::Preferred,
    )
}

/// Runs `runtime`'s genesis with `config` on empty storage: its result, and the storage after
/// it (the genesis writes iff it succeeded).
fn genesis<G: Genesis<Spec = S>>(
    runtime: &mut G,
    config: &G::Config,
) -> (Result<(), ModuleError>, TestStorage) {
    let checkpoint = MockKernel::checkpoint(TestStorage::default(), ArrayWitness::default());
    let prev_root = TestStorage::default().root();
    let mut state = GenesisStateAccessor::<S>::new(checkpoint).unwrap();
    let result = runtime.genesis(&header(), config, &mut state);
    let finalized = state.finalize(result.clone());
    let (_root, mut update, accessory, _witness, storage) =
        finalized.checkpoint.materialize_update(prev_root);
    update.add_accessory_items(accessory.freeze());
    (result, storage.materialize_changes(update))
}

fn config(first: u8) -> RtGenesisConfig<S, u32> {
    RtGenesisConfig {
        reader: (),
        primary: first,
        second: (),
        third: (),
    }
}

/// A transaction's working set over `storage`.
fn working_set(storage: TestStorage) -> WorkingSet<S> {
    let checkpoint = MockKernel::checkpoint(storage, ArrayWitness::default());
    let meter = BasicGasMeter::new_with_gas(
        GasUnit::from([1_000_000; 2]),
        GasPrice::from_dimensions([Amount::new(1); 2]),
    );
    WorkingSet::new(TxScratchpad::new(checkpoint), meter)
}

// -------------------------------------------------------------------------------------------
// Calls

/// The runtime's modules, in field order, and the variant of each: the field's name in
/// `PascalCase`.
#[test]
fn runtime_modules_and_variants() {
    assert_eq!(
        R::MODULES,
        [
            ModuleDescriptor::of::<Reader<S>>(),
            ModuleDescriptor::of::<First<S>>(),
            ModuleDescriptor::of::<Second<S>>(),
            ModuleDescriptor::of::<Third<S, u32>>(),
        ]
    );
    assert_eq!(
        R::MODULES.iter().map(|m| m.key()).collect::<Vec<_>>(),
        [
            ModuleKey {
                discriminant: READER,
                name: "reader"
            },
            ModuleKey {
                discriminant: FIRST,
                name: "first"
            },
            ModuleKey {
                discriminant: SECOND,
                name: "second"
            },
            ModuleKey {
                discriminant: THIRD,
                name: "third"
            },
        ]
    );
    assert_eq!(R::validate_layout(), Ok(()));
    let call = Call::Primary(1);
    assert_eq!(
        (call.module_discriminant(), call.module_name()),
        (FIRST, "first")
    );
    let call = Call::Third(7);
    assert_eq!(
        (call.module_discriminant(), call.module_name()),
        (THIRD, "third")
    );
    assert_eq!(format!("{call:?}"), "Third(7)");
    assert_eq!(call.clone(), call);
    assert_ne!(Call::Second(1), Call::Primary(1));
}

// Regressions of upstream's runtime call bugs

/// P5-25 (regression, the call tag): a runtime call is tagged with its module's discriminant,
/// the module's state prefix byte, not the module's position in the runtime (upstream's borsh
/// derive tagged by field position: `Second(12)` was `[2, 12]`). Known answers, from the
/// discriminants and the messages' borsh (`u8`, `u32` LE; `SharedEvent`'s variant index, then
/// its fields): `python3 -I -c 'import struct; print([list(struct.pack(f, *v)) for f, v in
/// [("<BB", (248, 12)), ("<BB", (250, 5)), ("<BI", (249, 7)), ("<BBB", (248, 0, 12)), ("<BB",
/// (250, 1))]])'` prints `[[248, 12], [250, 5], [249, 7, 0, 0, 0], [248, 0, 12], [250, 1]]`.
#[test]
fn runtime_call_tag_is_module_discriminant() {
    assert_eq!(borsh::to_vec(&Call::Second(12)).unwrap(), [248, 12]);
    assert_eq!(borsh::to_vec(&Call::Primary(5)).unwrap(), [250, 5]);
    assert_eq!(borsh::to_vec(&Call::Third(7)).unwrap(), [249, 7, 0, 0, 0]);
    assert_eq!(
        <R as EncodeCall<Second<S>>>::encode_call(12).unwrap(),
        [248, 12]
    );
    assert_eq!(R::encode(&Call::Second(12)).unwrap(), [248, 12]);
    assert_eq!(R::decode(&[248, 12]).unwrap(), Call::Second(12));
    assert_eq!(R::decode(&[250, 12]).unwrap(), Call::Primary(12));
    assert_eq!(
        <R as EncodeCall<Third<S, u32>>>::to_decodable(7),
        Call::Third(7)
    );
    // The event of a module: the same tag.
    let event = Event::Second(SharedEvent::Set { value: 12 });
    assert_eq!(borsh::to_vec(&event).unwrap(), [248, 0, 12]);
    assert_eq!(
        borsh::to_vec(&Event::Primary(SharedEvent::Unchanged)).unwrap(),
        [250, 1]
    );
    assert_eq!(borsh::from_slice::<Event>(&[248, 0, 12]).unwrap(), event);
}

/// Calls decode from exactly their encoding: a tag that is no module's discriminant (`0`,
/// field positions, a gap), trailing bytes, a truncated message, and a message that does not
/// decode are errors. The same for events (`NotInstantiable` modules' tags included).
#[test]
fn runtime_call_decoding_is_strict() {
    for rejected in [
        &[][..],
        &[0, 1],
        &[1, 1],
        &[2, 1],
        &[3, 1],
        &[246, 1],
        &[251, 1],
        &[248],
        &[248, 1, 0],
        &[249, 7, 0, 0],
        &[249, 7, 0, 0, 0, 0],
        &[READER],
        &[READER, 0],
    ] {
        assert!(R::decode(rejected).is_err(), "{rejected:?}");
    }
    let error = R::decode(&[7, 1]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "no module of the runtime has the discriminant 7"
    );
    for rejected in [
        &[][..],
        &[0, 0, 1],
        &[248, 0],
        &[248, 2],
        &[248, 0, 12, 0],
        &[249],
        &[READER],
    ] {
        assert!(
            borsh::from_slice::<Event>(rejected).is_err(),
            "{rejected:?}"
        );
    }
}

/// JSON is keyed by the module's name (`first`, not the field `primary`), round trips, and is
/// strict: another key, the field's name, two keys, a missing message, the discriminant as the
/// key are errors. Binary serde formats (postcard) tag by the discriminant.
#[test]
fn runtime_call_json_roundtrip() {
    for (call, json) in [
        (Call::Primary(5), r#"{"first":5}"#),
        (Call::Second(12), r#"{"second":12}"#),
        (Call::Third(7), r#"{"third":7}"#),
    ] {
        assert_eq!(serde_json::to_string(&call).unwrap(), json);
        assert_eq!(serde_json::from_str::<Call>(json).unwrap(), call);
        let binary = postcard::to_allocvec(&call).unwrap();
        assert_eq!(binary[0], call.module_discriminant());
        assert_eq!(postcard::from_bytes::<Call>(&binary).unwrap(), call);
    }
    for rejected in [
        r#"{"primary":5}"#,
        r#"{"First":5}"#,
        r#"{"reader":null}"#,
        r#"{"first":5,"second":1}"#,
        r#"{"first":256}"#,
        r#"{"250":5}"#,
        r#"{}"#,
        r#""first""#,
        r#"[250,5]"#,
        "250",
        "null",
    ] {
        assert!(
            serde_json::from_str::<Call>(rejected).is_err(),
            "{rejected}"
        );
    }
    let error = serde_json::from_str::<Call>(r#"{"primary":5}"#).unwrap_err();
    assert!(
        error.to_string().starts_with(
            "unknown variant `primary`, expected one of `reader`, `first`, `second`, `third`"
        ),
        "{error}"
    );
    // Postcard: a tag that is no discriminant, or a field position.
    for rejected in [&[0, 5][..], &[1, 5], &[251, 1, 5]] {
        assert!(
            postcard::from_bytes::<Call>(rejected).is_err(),
            "{rejected:?}"
        );
    }
}

/// The JSON schema: one object per module, keyed by its name, holding its call message.
#[test]
fn runtime_call_json_schema() {
    let schema = serde_json::to_value(schemars::schema_for!(Call)).unwrap();
    let variants = schema["oneOf"].as_array().unwrap();
    let names: Vec<&str> = variants
        .iter()
        .map(|variant| variant["required"][0].as_str().unwrap())
        .collect();
    assert_eq!(names, ["reader", "first", "second", "third"]);
    assert_eq!(variants[1]["additionalProperties"], false);
    assert_eq!(variants[1]["properties"]["first"]["type"], "integer");
    let schema = serde_json::to_value(schemars::schema_for!(Event)).unwrap();
    assert_eq!(schema["oneOf"].as_array().unwrap().len(), 4);
}

/// The schema and the decoding agree on modules without calls (or events): their variant's
/// message schema is `false`, so the schema admits no value under their name, and none
/// decodes. (`NotInstantiable`'s schema was `{"type": "null"}`: `{"reader": null}` matched the
/// schema but never decoded.)
#[test]
fn runtime_schema_admits_no_message_of_a_module_without_messages() {
    let schema = serde_json::to_value(schemars::schema_for!(Call)).unwrap();
    assert_eq!(schema["oneOf"][0]["properties"]["reader"], false);
    assert!(serde_json::from_str::<Call>(r#"{"reader":null}"#).is_err());
    let schema = serde_json::to_value(schemars::schema_for!(Event)).unwrap();
    for (i, name) in [(0, "reader"), (3, "third")] {
        assert_eq!(schema["oneOf"][i]["properties"][name], false, "{name}");
        let json = format!(r#"{{"{name}":null}}"#);
        assert!(serde_json::from_str::<Event>(&json).is_err(), "{json}");
    }
}

/// A call runs on its module (fully qualified `Module::call`, through `TxState`), and its
/// module's id is the one of the module the call goes to.
#[test]
fn call_is_dispatched_to_its_module() {
    let mut runtime = R::default();
    let (result, storage) = genesis(&mut runtime, &config(1));
    assert_eq!(result, Ok(()));
    let mut ws = working_set(storage);
    for (call, name) in [
        (Call::Primary(5), "first"),
        (Call::Second(6), "second"),
        (Call::Third(7), "third"),
    ] {
        assert_eq!(runtime.module_id(&call), &ModuleId::from_name(name));
        assert_eq!(runtime.dispatch_call(call, &mut ws, &context()), Ok(()));
    }
    assert_eq!(runtime.module_id(&Call::Primary(1)), runtime.primary.id());
    assert_eq!(runtime.module_id(&Call::Second(1)), runtime.second.id());
    assert_eq!(runtime.module_id(&Call::Third(1)), runtime.third.id());
    assert_eq!(
        runtime.module_id(&Call::Primary(1)),
        &ModuleId::from_name("first")
    );
    assert_eq!(runtime.primary.value.get(&mut ws), Ok(Some(5)));
    assert_eq!(runtime.second.value.get(&mut ws), Ok(Some(6)));
    assert_eq!(runtime.third.value.get(&mut ws), Ok(Some(7)));
    // The nested `First` in `Reader` is the same state.
    assert_eq!(runtime.reader.first.value.get(&mut ws), Ok(Some(5)));
}

/// A module's error comes back unchanged (as a `ModuleError`, with its detail), and the call's
/// write and event are dropped.
#[test]
fn module_error_passes_through() {
    let mut runtime = R::default();
    let (_, storage) = genesis(&mut runtime, &config(1));
    let mut ws = working_set(storage);
    let error = runtime
        .dispatch_call(Call::Primary(0), &mut ws, &context())
        .unwrap_err();
    assert_eq!(error, ModuleError::from(FirstError::Zero));
    assert_eq!(error.to_string(), "the value 0 is rejected");
    assert_eq!(error.error_detail().unwrap()["error_code"], "zero");
    let finalized = ws.finalize(Err(error));
    assert!(matches!(
        finalized.outcome,
        PhaseOutcome::Reverted(RevertReason::Module(_))
    ));
    assert!(finalized.events.is_empty());
    let mut ws = WorkingSet::<S>::new(
        finalized.scratchpad,
        BasicGasMeter::new_with_gas(
            GasUnit::from([1_000_000; 2]),
            GasPrice::from_dimensions([Amount::new(1); 2]),
        ),
    );
    assert_eq!(R::default().primary.value.get(&mut ws), Ok(Some(1)));
}

// -------------------------------------------------------------------------------------------
// Events

// Regressions of upstream's runtime event bugs

/// P5-32 (regression, attribution): `First` and `Second` emit the same event type; each event
/// maps to the module that emitted it, by the discriminant it carries. Upstream matched the
/// event's `TypeId`, so every `SharedEvent` became the first such module's (`Primary`).
#[test]
fn shared_event_type_attributed_to_emitter() {
    let event = SharedEvent::Set { value: 3 };
    for (module, expected) in [
        (FIRST, Some(Event::Primary(event.clone()))),
        (SECOND, Some(Event::Second(event.clone()))),
        (THIRD, None),
        (READER, None),
        (0, None),
        (1, None),
    ] {
        let erased = TypeErasedEvent::new(module, "x", event.clone());
        assert_eq!(R::convert_to_runtime_event(erased), expected, "{module}");
    }
    // Another type under a module's discriminant maps to nothing.
    assert_eq!(
        R::convert_to_runtime_event(TypeErasedEvent::new(SECOND, "x", 3u8)),
        None
    );

    // Emitted by dispatched calls (kept natively).
    let mut runtime = R::default();
    let (_, storage) = genesis(&mut runtime, &config(1));
    let mut ws = working_set(storage);
    runtime
        .dispatch_call(Call::Second(3), &mut ws, &context())
        .unwrap();
    runtime
        .dispatch_call(Call::Primary(4), &mut ws, &context())
        .unwrap();
    let finalized = ws.finalize(Ok::<(), ModuleError>(()));
    #[cfg(feature = "native")]
    {
        let events: Vec<_> = finalized
            .events
            .into_iter()
            .map(|event| (event.key().to_owned(), R::convert_to_runtime_event(event)))
            .collect();
        assert_eq!(
            events,
            [
                (
                    "second/Set".to_owned(),
                    Some(Event::Second(SharedEvent::Set { value: 3 }))
                ),
                (
                    "first/Set".to_owned(),
                    Some(Event::Primary(SharedEvent::Set { value: 4 }))
                ),
            ]
        );
    }
    #[cfg(not(feature = "native"))]
    assert!(finalized.events.is_empty());
}

/// P5-32 (regression, JSON): runtime events are keyed by the module's name, so two modules'
/// events of one type round trip to the right module. Upstream's were `untagged`: both encoded
/// as the bare event, which decoded as the first module's.
#[test]
fn runtime_event_json_roundtrip() {
    for (event, json) in [
        (
            Event::Primary(SharedEvent::Set { value: 1 }),
            r#"{"first":{"set":{"value":1}}}"#,
        ),
        (
            Event::Second(SharedEvent::Set { value: 1 }),
            r#"{"second":{"set":{"value":1}}}"#,
        ),
        (
            Event::Second(SharedEvent::Unchanged),
            r#"{"second":"unchanged"}"#,
        ),
    ] {
        assert_eq!(serde_json::to_string(&event).unwrap(), json);
        assert_eq!(serde_json::from_str::<Event>(json).unwrap(), event);
        assert_eq!(
            borsh::from_slice::<Event>(&borsh::to_vec(&event).unwrap()).unwrap(),
            event
        );
        let binary = postcard::to_allocvec(&event).unwrap();
        assert_eq!(postcard::from_bytes::<Event>(&binary).unwrap(), event);
    }
    for rejected in [
        r#"{"set":{"value":1}}"#,
        r#"{"primary":"unchanged"}"#,
        r#"{"third":null}"#,
        r#"{"first":"unchanged","second":"unchanged"}"#,
    ] {
        assert!(
            serde_json::from_str::<Event>(rejected).is_err(),
            "{rejected}"
        );
    }
    let event = Event::Primary(SharedEvent::Unchanged);
    assert_eq!(
        (event.module_discriminant(), event.module_name()),
        (FIRST, "first")
    );
}

// -------------------------------------------------------------------------------------------
// Genesis

/// Genesis runs each module after its dependencies: `reader` (listed first) sees `first`'s
/// genesis value; every module's genesis ran.
#[test]
fn genesis_runs_in_dependency_order() {
    let mut runtime = R::default();
    let (result, storage) = genesis(&mut runtime, &config(41));
    assert_eq!(result, Ok(()));
    let mut ws = working_set(storage);
    assert_eq!(runtime.reader.seen.get(&mut ws), Ok(Some(41)));
    assert_eq!(runtime.primary.value.get(&mut ws), Ok(Some(41)));
    assert_eq!(runtime.second.value.get(&mut ws), Ok(Some(2)));
    assert_eq!(runtime.third.value.get(&mut ws), Ok(Some(0)));
}

/// The genesis configuration is an object with exactly one field per module (named like the
/// field): unknown and missing fields are errors.
#[test]
fn genesis_config_json_is_strict() {
    let json = r#"{"reader":null,"primary":7,"second":null,"third":null}"#;
    let parsed: RtGenesisConfig<S, u32> = serde_json::from_str(json).unwrap();
    assert_eq!(parsed, config(7));
    assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
    assert_eq!(parsed.clone(), parsed);
    assert_eq!(
        format!("{parsed:?}"),
        "RtGenesisConfig { reader: (), primary: 7, second: (), third: () }"
    );
    // Binary formats: the fields in order.
    let binary = postcard::to_allocvec(&parsed).unwrap();
    assert_eq!(binary, [7]);
    assert_eq!(
        postcard::from_bytes::<RtGenesisConfig<S, u32>>(&binary).unwrap(),
        parsed
    );
    assert!(postcard::from_bytes::<RtGenesisConfig<S, u32>>(&[]).is_err());
    for rejected in [
        r#"{"reader":null,"primary":7,"second":null,"third":null,"chain_state":null}"#,
        r#"{"reader":null,"first":7,"second":null,"third":null}"#,
        r#"{"reader":null,"second":null,"third":null}"#,
        r#"{"reader":null,"primary":256,"second":null,"third":null}"#,
        r#"{"reader":null,"primary":7,"primary":7,"second":null,"third":null}"#,
        r#"[null,7,null,null]"#,
        r#"{}"#,
        "null",
    ] {
        assert!(
            serde_json::from_str::<RtGenesisConfig<S, u32>>(rejected).is_err(),
            "{rejected}"
        );
    }
    for (json, message) in [
        (
            r#"{"reader":null,"primary":7,"second":null,"third":null,"extra":1}"#,
            "unknown field `extra`, expected one of `reader`, `primary`, `second`, `third`",
        ),
        (
            r#"{"reader":null,"second":null,"third":null}"#,
            "missing field `primary`",
        ),
        (
            r#"{"reader":null,"primary":7,"primary":7,"second":null,"third":null}"#,
            "duplicate field `primary`",
        ),
        (
            "[null,7,null,null]",
            "invalid type: sequence, expected the genesis configuration RtGenesisConfig: an \
             object with the fields `reader`, `primary`, `second`, `third`",
        ),
    ] {
        let error = serde_json::from_str::<RtGenesisConfig<S, u32>>(json).unwrap_err();
        assert!(error.to_string().starts_with(message), "{json}: {error}");
    }
}

/// A module whose genesis configuration is an `Option`.
#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 245, name = "optional")]
pub struct Optional<S: Spec> {
    #[id]
    id: ModuleId,
    #[state(item = 0)]
    value: StateValue<u8>,
    #[phantom]
    spec: PhantomData<S>,
}

impl<S: Spec> Module for Optional<S> {
    type Config = Option<u8>;
    type CallMessage = NotInstantiable;
    type Event = NotInstantiable;
    type Error = anyhow::Error;

    fn genesis(
        &mut self,
        _header: &<S::Da as selendra_interface::da::DaSpec>::BlockHeader,
        config: &Option<u8>,
        state: &mut impl GenesisState<S>,
    ) -> anyhow::Result<()> {
        self.value.set(&config.unwrap_or(u8::MAX), state)?;
        Ok(())
    }

    fn call(
        &mut self,
        message: NotInstantiable,
        _context: &Context<S>,
        _state: &mut impl TxState<S>,
    ) -> anyhow::Result<()> {
        match message {}
    }
}

#[derive(Default, DispatchCall, Genesis)]
pub struct OptionalRt<S: Spec> {
    pub second: Second<S>,
    pub optional: Optional<S>,
}

// Regressions of the genesis configuration's strictness

/// A missing field is an error also when the module's configuration is an `Option`: the field
/// must be there (`null` is `None`). With serde's derive, the missing field decoded as `None`,
/// and genesis ran on a configuration the operator never wrote.
#[test]
fn genesis_config_missing_option_field_is_an_error() {
    type Config = OptionalRtGenesisConfig<S>;
    let error = serde_json::from_str::<Config>(r#"{"second":null}"#).unwrap_err();
    assert!(
        error.to_string().starts_with("missing field `optional`"),
        "{error}"
    );
    for (json, optional) in [
        (r#"{"second":null,"optional":null}"#, None),
        (r#"{"second":null,"optional":3}"#, Some(3)),
    ] {
        let config = serde_json::from_str::<Config>(json).unwrap();
        assert_eq!(config.optional, optional);
        assert_eq!(serde_json::to_string(&config).unwrap(), json);
        let binary = postcard::to_allocvec(&config).unwrap();
        assert_eq!(postcard::from_bytes::<Config>(&binary).unwrap(), config);
    }
}

/// A module's genesis error is the runtime's, and genesis is reverted.
#[test]
fn genesis_error_is_returned() {
    #[derive(Clone, ModuleInfo)]
    #[module_info(discriminant = 236, name = "failing")]
    pub struct Failing<S: Spec> {
        #[id]
        id: ModuleId,
        #[phantom]
        spec: PhantomData<S>,
    }

    impl<S: Spec> Module for Failing<S> {
        type Config = ();
        type CallMessage = NotInstantiable;
        type Event = NotInstantiable;
        type Error = anyhow::Error;

        fn genesis(
            &mut self,
            _header: &<S::Da as selendra_interface::da::DaSpec>::BlockHeader,
            _config: &(),
            _state: &mut impl GenesisState<S>,
        ) -> anyhow::Result<()> {
            anyhow::bail!("bad genesis config")
        }

        fn call(
            &mut self,
            message: NotInstantiable,
            _context: &Context<S>,
            _state: &mut impl TxState<S>,
        ) -> anyhow::Result<()> {
            match message {}
        }
    }

    #[derive(Default, DispatchCall, Genesis)]
    pub struct FailingRt<S: Spec> {
        pub second: Second<S>,
        pub failing: Failing<S>,
    }

    let mut runtime = FailingRt::<S>::default();
    let config = FailingRtGenesisConfig {
        second: (),
        failing: (),
    };
    let (result, storage) = genesis(&mut runtime, &config);
    assert_eq!(result.unwrap_err().to_string(), "bad genesis config");
    // `second`'s genesis ran first; its write is reverted with the rest.
    assert_eq!(storage.root(), TestStorage::default().root());
}

/// The run-time layout check of genesis rejects a runtime whose `MODULES` break the layout
/// rules, before any module's genesis, though its fields could be sorted: a hand-written
/// `DispatchCall` (listing `second` twice) that skips the compile-time check, as a binary
/// built against other modules would (genesis also checks at run time).
#[test]
fn genesis_checks_the_layout_at_run_time() {
    #[derive(Default, Genesis)]
    pub struct Unchecked<S: Spec> {
        pub second: Second<S>,
    }

    impl<S: Spec> DispatchCall for Unchecked<S> {
        type Spec = S;
        type Decodable = two_runtimes::OneCall<S>;

        const MODULES: &'static [ModuleDescriptor] = &[
            ModuleDescriptor::of::<Second<S>>(),
            ModuleDescriptor::of::<Second<S>>(),
        ];
        const __CHECK_LAYOUT: () = ();

        fn dispatch_call<T: TxState<S>>(
            &mut self,
            call: Self::Decodable,
            state: &mut T,
            context: &Context<S>,
        ) -> Result<(), ModuleError> {
            match call {
                two_runtimes::OneCall::Second(message) => {
                    Ok(self.second.call(message, context, state)?)
                }
            }
        }

        fn module_id(&self, _call: &Self::Decodable) -> &ModuleId {
            self.second.id()
        }
    }

    let (result, storage) = genesis(
        &mut Unchecked::<S>::default(),
        &UncheckedGenesisConfig { second: () },
    );
    let error = result.unwrap_err();
    assert_eq!(
        error.to_string(),
        "modules `second` (248) and `second` (248) have the same discriminant"
    );
    assert_eq!(
        error.error_detail().unwrap()["error_code"],
        "invalid_runtime_layout"
    );
    assert_eq!(storage.root(), TestStorage::default().root());
}

/// Modules whose dependencies form a cycle (possible with hand-written `ModuleInfo`s only: a
/// derived module cannot hold itself) follow the layout rules, but their genesis cannot be
/// ordered: an error.
#[test]
fn genesis_rejects_cycles() {
    macro_rules! cyclic_module {
        ($module:ident, $discriminant:literal, $name:literal, $dependency:expr) => {
            #[derive(Clone)]
            pub struct $module<S>(ModuleId, PhantomData<S>);

            impl<S> Default for $module<S> {
                fn default() -> Self {
                    Self(ModuleId::from_name($name), PhantomData)
                }
            }

            impl<S: Spec> ModuleInfo for $module<S> {
                type Spec = S;
                const DISCRIMINANT: u8 = $discriminant;
                const NAME: &'static str = $name;
                const DEPENDENCIES: &'static [(u8, &'static str)] = &[$dependency];
                const STATE_LAYOUT: &'static [StateItem] = &[];
                fn id(&self) -> &ModuleId {
                    &self.0
                }
            }

            impl<S: Spec> Module for $module<S> {
                type Config = ();
                type CallMessage = NotInstantiable;
                type Event = NotInstantiable;
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
        };
    }
    cyclic_module!(Ping, 237, "ping", (238, "pong"));
    cyclic_module!(Pong, 238, "pong", (237, "ping"));

    #[derive(Default, DispatchCall, Genesis)]
    pub struct CyclicRt<S: Spec> {
        pub ping: Ping<S>,
        pub pong: Pong<S>,
    }

    assert_eq!(CyclicRt::<S>::validate_layout(), Ok(()));
    let (result, _) = genesis(
        &mut CyclicRt::<S>::default(),
        &CyclicRtGenesisConfig { ping: (), pong: () },
    );
    let error = result.unwrap_err();
    assert_eq!(
        error.to_string(),
        "cyclic dependency of length 2: `ping` (237) -> `pong` (238) -> `ping` (237)"
    );
    assert_eq!(
        error.error_detail().unwrap()["error_code"],
        "invalid_module_dependencies"
    );
}

// -------------------------------------------------------------------------------------------
// Hooks

const LOG: u8 = 230;

/// Which hook ran: `(hook, module)`. Module `0` is the inherent method named like a hook.
type Log = Vec<(u8, u8)>;
const BEGIN: u8 = 1;
const END: u8 = 2;
const PRE: u8 = 3;
const POST: u8 = 4;
const FINALIZE: u8 = 5;

fn log() -> StateValue<Log> {
    StateValue::with_codec(Prefix::new(LOG, 0), BorshCodec)
}

fn accessory_log() -> AccessoryStateValue<Log> {
    AccessoryStateValue::with_codec(Prefix::new(LOG, 1), BorshCodec)
}

/// A module whose every hook appends `(hook, DISCRIMINANT)` to the log; its pre-dispatch hook
/// fails for the transactions whose runtime version is its discriminant, its post-dispatch
/// hook for those whose runtime version is its discriminant plus 100.
macro_rules! hooked_module {
    ($module:ident, $discriminant:tt, $name:tt) => {
        #[derive(Clone, ModuleInfo)]
        #[module_info(discriminant = $discriminant, name = $name)]
        pub struct $module<S: Spec> {
            #[id]
            id: ModuleId,
            #[phantom]
            spec: PhantomData<S>,
        }

        impl<S: Spec> Module for $module<S> {
            type Config = ();
            type CallMessage = NotInstantiable;
            type Event = NotInstantiable;
            type Error = anyhow::Error;

            fn call(
                &mut self,
                message: NotInstantiable,
                _context: &Context<S>,
                _state: &mut impl TxState<S>,
            ) -> anyhow::Result<()> {
                match message {}
            }

            fn begin_rollup_block_hook(
                &mut self,
                _visible_hash: &<S::Storage as Storage>::Root,
                state: &mut BlockState<'_, S>,
            ) {
                let Ok(mut entries) = log().get(state);
                entries
                    .get_or_insert_default()
                    .push((BEGIN, Self::DISCRIMINANT));
                let Ok(()) = log().set(&entries.unwrap_or_default(), state);
            }

            fn end_rollup_block_hook(&mut self, state: &mut BlockState<'_, S>) {
                let Ok(mut entries) = log().get(state);
                entries
                    .get_or_insert_default()
                    .push((END, Self::DISCRIMINANT));
                let Ok(()) = log().set(&entries.unwrap_or_default(), state);
            }

            fn pre_dispatch_tx_hook<T: TxState<S>>(
                &mut self,
                tx: &AuthenticatedTransactionData<S>,
                state: &mut T,
            ) -> anyhow::Result<()> {
                if tx.0.runtime_version == u32::from(Self::DISCRIMINANT) {
                    anyhow::bail!("module {} rejects the transaction", Self::NAME);
                }
                let mut entries = log().get(state)?.unwrap_or_default();
                entries.push((PRE, Self::DISCRIMINANT));
                log().set(&entries, state)?;
                Ok(())
            }

            fn post_dispatch_tx_hook<T: TxState<S>>(
                &mut self,
                tx: &AuthenticatedTransactionData<S>,
                _context: &Context<S>,
                state: &mut T,
            ) -> anyhow::Result<()> {
                if tx.0.runtime_version == u32::from(Self::DISCRIMINANT) + 100 {
                    anyhow::bail!("module {} rejects the dispatched transaction", Self::NAME);
                }
                let mut entries = log().get(state)?.unwrap_or_default();
                entries.push((POST, Self::DISCRIMINANT));
                log().set(&entries, state)?;
                Ok(())
            }

            fn finalize_hook(
                &mut self,
                _root_hash: &<S::Storage as Storage>::Root,
                state: &mut impl AccessoryStateReaderAndWriter,
            ) {
                let Ok(mut entries) = accessory_log().get(state);
                entries
                    .get_or_insert_default()
                    .push((FINALIZE, Self::DISCRIMINANT));
                let Ok(()) = accessory_log().set(&entries.unwrap_or_default(), state);
            }
        }
    };
}

hooked_module!(Zeta, 233, "zeta");
hooked_module!(Alpha, 231, "alpha");
hooked_module!(Mid, 232, "mid");

/// Inherent methods named like `Zeta`'s hooks, logging module `0`: method-call syntax
/// (upstream's `(&mut self.field).hook(…)`) would run these instead of the module's hooks.
#[expect(dead_code, reason = "the runtime's hooks must never call these")]
impl<S: Spec> Zeta<S> {
    fn begin_rollup_block_hook(
        &mut self,
        _visible_hash: &<S::Storage as Storage>::Root,
        state: &mut BlockState<'_, S>,
    ) {
        let Ok(()) = log().set(&vec![(BEGIN, 0)], state);
    }

    fn end_rollup_block_hook(&mut self, state: &mut BlockState<'_, S>) {
        let Ok(()) = log().set(&vec![(END, 0)], state);
    }

    fn pre_dispatch_tx_hook<T: TxState<S>>(
        &mut self,
        _tx: &AuthenticatedTransactionData<S>,
        state: &mut T,
    ) -> anyhow::Result<()> {
        log().set(&vec![(PRE, 0)], state)?;
        Ok(())
    }

    fn post_dispatch_tx_hook<T: TxState<S>>(
        &mut self,
        _tx: &AuthenticatedTransactionData<S>,
        _context: &Context<S>,
        state: &mut T,
    ) -> anyhow::Result<()> {
        log().set(&vec![(POST, 0)], state)?;
        Ok(())
    }

    fn finalize_hook(
        &mut self,
        _root_hash: &<S::Storage as Storage>::Root,
        state: &mut impl AccessoryStateReaderAndWriter,
    ) {
        let Ok(()) = accessory_log().set(&vec![(FINALIZE, 0)], state);
    }
}

/// Field order `zeta`, `alpha`, `mid`: neither the order of the discriminants (233, 231, 232)
/// nor of the names.
#[derive(Default, DispatchCall, Hooks)]
pub struct HookRt<S: Spec> {
    pub zeta: Zeta<S>,
    pub alpha: Alpha<S>,
    pub mid: Mid<S>,
}

fn tx(runtime_version: u32) -> AuthenticatedTransactionData<S> {
    AuthenticatedTransactionData(TxDetails {
        max_priority_fee_bips: PriorityFeeBips::ZERO,
        max_fee: Amount::new(1_000_000),
        gas_limit: None,
        runtime_version,
    })
}

// Regressions of upstream's hook bugs

/// P5-31 (regression, runtime side): every module's hook runs, in field order, for each of the
/// five hooks; the module's `Module` hook runs, never an inherent method of the same name.
/// Upstream's derive called `(&mut self.field).hook(…)`, which method resolution sends to an
/// inherent method of that name (or to the no-op fallback impl of the hook traits).
#[test]
fn hooks_run_for_every_module_in_field_order() {
    let mut runtime = HookRt::<S>::default();
    let storage = TestStorage::default();
    let root = storage.root();
    let order = |hook: u8| -> Log { [233, 231, 232].map(|module| (hook, module)).to_vec() };

    let mut checkpoint = MockKernel::checkpoint(storage, ArrayWitness::default());
    {
        let mut block = BlockState::<S>::new(&mut checkpoint);
        runtime.begin_rollup_block_hook(&root, &mut block);
        let Ok(entries) = log().get(&mut block);
        assert_eq!(entries, Some(order(BEGIN)));
        runtime.end_rollup_block_hook(&mut block);
        let Ok(entries) = log().get(&mut block);
        assert_eq!(entries, Some([order(BEGIN), order(END)].concat()));
    }

    let meter = BasicGasMeter::new_with_gas(
        GasUnit::from([1_000_000; 2]),
        GasPrice::from_dimensions([Amount::new(1); 2]),
    );
    let mut ws = WorkingSet::<S>::new(TxScratchpad::new(checkpoint), meter);
    runtime.pre_dispatch_tx_hook(&tx(1), &mut ws).unwrap();
    runtime
        .post_dispatch_tx_hook(&tx(1), &context(), &mut ws)
        .unwrap();
    assert_eq!(
        log().get(&mut ws),
        Ok(Some(
            [order(BEGIN), order(END), order(PRE), order(POST)].concat()
        ))
    );

    let mut accessory = selendra_state::test_utils::InMemoryState::default();
    runtime.finalize_hook(&root, &mut accessory);
    let Ok(entries) = accessory_log().get(&mut accessory);
    assert_eq!(entries, Some(order(FINALIZE)));
}

/// The first failing transaction hook stops the chain: the later modules' hooks do not run, and
/// its error comes back unchanged.
#[test]
fn failing_tx_hook_stops_the_chain() {
    let mut runtime = HookRt::<S>::default();
    let mut ws = working_set(TestStorage::default());
    // `alpha` (the second module) rejects version 231: `zeta` ran, `mid` did not.
    let error = runtime.pre_dispatch_tx_hook(&tx(231), &mut ws).unwrap_err();
    assert_eq!(error.to_string(), "module alpha rejects the transaction");
    assert_eq!(log().get(&mut ws), Ok(Some(vec![(PRE, 233)])));
}

/// The same for the post-dispatch hook: `alpha` rejects version 331 after dispatch; `zeta`'s
/// post-dispatch hook ran, `mid`'s did not, and the error comes back unchanged (a lost error
/// would commit a transaction a module rejected).
#[test]
fn failing_post_dispatch_hook_stops_the_chain() {
    let mut runtime = HookRt::<S>::default();
    let mut ws = working_set(TestStorage::default());
    let error = runtime
        .post_dispatch_tx_hook(&tx(331), &context(), &mut ws)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "module alpha rejects the dispatched transaction"
    );
    assert_eq!(log().get(&mut ws), Ok(Some(vec![(POST, 233)])));
}

// -------------------------------------------------------------------------------------------
// Names and hygiene

/// A field's `PascalCase` (also of a raw identifier) names its variant; the module's name keys
/// the JSON.
#[test]
fn variant_names_are_pascal_case_fields() {
    #[derive(Default, DispatchCall, Event)]
    pub struct Names<S: Spec> {
        pub sequencer_registry_v2: Second<S>,
        pub r#type: First<S>,
    }
    let call = NamesCall::<S>::SequencerRegistryV2(1);
    assert_eq!(format!("{call:?}"), "SequencerRegistryV2(1)");
    assert_eq!(serde_json::to_string(&call).unwrap(), r#"{"second":1}"#);
    let call = NamesCall::<S>::Type(2);
    assert_eq!(borsh::to_vec(&call).unwrap(), [FIRST, 2]);
    let _ = NamesEvent::<S>::Type(SharedEvent::Unchanged);
}

// Regressions of upstream's runtime derive hygiene bugs

/// Two runtimes in one Rust module, each with every derive, built over the same modules.
mod two_runtimes {
    use super::*;

    #[derive(Default, DispatchCall, MessageCodec, Genesis, Event, Hooks)]
    pub struct One<S: Spec> {
        pub second: Second<S>,
    }

    #[derive(Default, DispatchCall, MessageCodec, Genesis, Event, Hooks)]
    pub struct Two<S: Spec> {
        pub second: Second<S>,
        pub primary: First<S>,
    }

    pub(super) fn check() {
        assert_eq!(
            borsh::to_vec(&OneCall::<S>::Second(1)).unwrap(),
            [SECOND, 1]
        );
        assert_eq!(
            borsh::to_vec(&TwoCall::<S>::Primary(1)).unwrap(),
            [FIRST, 1]
        );
        let _ = OneGenesisConfig::<S> { second: () };
        let _ = TwoGenesisConfig::<S> {
            second: (),
            primary: 1,
        };
        let _ = OneEvent::<S>::Second(SharedEvent::Unchanged);
        let _ = TwoEvent::<S>::Primary(SharedEvent::Unchanged);
        assert_eq!(One::<S>::MODULES.len(), 1);
        assert_eq!(Two::<S>::MODULES.len(), 2);
    }
}

/// P5-33 (regression, runtime side): two runtimes in one Rust module compile. Upstream's
/// derives generated fixed names (`GenesisConfig`, `mod slot_hooks`, `mod finalize_hook`, `mod
/// tx_hooks`, `pub use __generated_…::*`), so a second runtime in the module clashed with the
/// first; here every generated name is the runtime's (`{Runtime}Call`, `{Runtime}Event`,
/// `{Runtime}GenesisConfig`), and impls sit in anonymous constants.
#[test]
fn two_runtimes_in_one_module() {
    two_runtimes::check();
}

/// Every derive, in a module shadowing the crates and prelude names the generated code uses.
mod shadowed_runtime {
    #![allow(dead_code, non_camel_case_types)]

    use ::selendra_modules_api::test_utils::TestSpec;
    use ::selendra_modules_api::{
        DispatchCall, EncodeCall, Event, Genesis, Hooks, MessageCodec, ModuleMessage, Spec,
    };

    use super::{First, Payload, Second, Third};

    mod borsh {}
    mod core {}
    mod schemars {}
    mod selendra_modules_api {}
    mod serde {}
    mod std {}
    struct Default;
    struct Option;
    struct Some;
    struct None;
    struct Result;
    struct Ok;
    struct Err;
    struct Vec;
    struct String;
    struct From;
    struct bool;
    struct str;
    struct u8;
    struct u32;
    struct u64;
    struct usize;

    /// The spec is named like the generated `deserialize_reader`'s parameter, the second
    /// parameter like `serialize`'s.
    #[derive(DispatchCall, MessageCodec, Genesis, Event, Hooks)]
    pub struct Shadowed<R: Spec, W: Payload> {
        pub call: First<R>,
        pub state: Second<R>,
        pub writer: Third<R, W>,
    }

    pub(super) fn check() {
        type Rt = Shadowed<TestSpec, ::core::primitive::u32>;
        type Call = ShadowedCall<TestSpec, ::core::primitive::u32>;
        let call = <Rt as EncodeCall<First<TestSpec>>>::to_decodable(3);
        assert_eq!(call, Call::Call(3));
        assert_eq!(call.module_name(), "first");
        let bytes = Rt::encode(&Call::Writer(9)).unwrap();
        assert_eq!(bytes, [249, 9, 0, 0, 0]);
        assert_eq!(Rt::decode(&bytes).unwrap(), Call::Writer(9));
        assert_eq!(Rt::MODULES.len(), 3);
        let json = r#"{"call":4,"state":null,"writer":null}"#;
        let config: ShadowedGenesisConfig<TestSpec, ::core::primitive::u32> =
            ::serde_json::from_str(json).unwrap();
        assert_eq!(config.call, 4);
        assert_eq!(::serde_json::to_string(&config).unwrap(), json);
    }
}

/// Every derive in a module without the prelude (`#![no_implicit_prelude]`): the generated code
/// names `From` (and everything else) by its full path.
mod without_prelude {
    #![no_implicit_prelude]

    use ::selendra_modules_api::{DispatchCall, Event, Genesis, Hooks, MessageCodec, Spec};

    use super::{First, Payload, Second, Third};

    #[derive(DispatchCall, MessageCodec, Genesis, Event, Hooks)]
    pub struct NoPrelude<S: Spec, T: Payload> {
        pub primary: First<S>,
        pub second: Second<S>,
        pub third: Third<S, T>,
    }
}

/// The generated methods' generic parameters (`W`, `R`, `Ser`, `De`, `A`, `E`, `State`) do not
/// shadow types of those names that the module types use.
mod shadowed_types {
    #![expect(
        clippy::type_complexity,
        reason = "the module type names every generated parameter"
    )]

    use ::selendra_modules_api::{DispatchCall, Event, Genesis, Hooks, MessageCodec, Spec};

    use super::Third;

    pub type W = u32;
    pub type R = u32;
    pub type Ser = u32;
    pub type De = u32;
    pub type A = u32;
    pub type E = u32;
    pub type State = u32;

    #[derive(DispatchCall, MessageCodec, Genesis, Event, Hooks)]
    pub struct Named<S: Spec> {
        pub third: Third<S, (W, R, Ser, De, A, E, State)>,
    }
}

impl Payload for (u32, u32, u32, u32, u32, u32, u32) {}

/// A runtime defined by a `macro_rules!` macro, its module types written with `$crate` paths.
macro_rules! crate_runtime {
    () => {
        #[derive(Default, DispatchCall, MessageCodec, Genesis, Event, Hooks)]
        pub struct CrateRt<S: Spec> {
            pub second: $crate::runtime::Second<S>,
            pub primary: $crate::runtime::First<S>,
        }
    };
}

crate_runtime!();

/// P5-33 (regression, runtime side): the runtime derives compile in a module that shadows
/// `borsh`, `core`, `schemars`, `selendra_modules_api`, `serde`, `std`, `Default`, `Option`,
/// `Result` and `Vec`, on a runtime whose generic parameters are named like
/// the generated methods' (`R`, `W`) and whose fields are named like their locals (`call`,
/// `state`).
/// Upstream's generated code used relative `borsh::`/`serde::`/`sov_modules_api::` paths.
#[test]
fn derives_with_shadowed_borsh_serde() {
    shadowed_runtime::check();
}

// Regressions of the runtime derives' hygiene

/// Under `#![no_implicit_prelude]`, the runtime derives compile and work: the generated code
/// called `ModuleError::from` and `Vec::from`, which need the prelude's `From` in scope.
#[test]
fn derives_without_the_prelude() {
    type Rt = without_prelude::NoPrelude<S, u32>;
    type Call = without_prelude::NoPreludeCall<S, u32>;
    assert_eq!(Rt::encode(&Call::Third(7)).unwrap(), [THIRD, 7, 0, 0, 0]);
    let config: without_prelude::NoPreludeGenesisConfig<S, u32> =
        serde_json::from_str(r#"{"primary":1,"second":null,"third":null}"#).unwrap();
    let mut runtime = Rt {
        primary: First::default(),
        second: Second::default(),
        third: Third::default(),
    };
    let (result, storage) = genesis(&mut runtime, &config);
    assert_eq!(result, Ok(()));
    let mut ws = working_set(storage);
    assert_eq!(
        runtime.dispatch_call(Call::Primary(0), &mut ws, &context()),
        Err(ModuleError::from(FirstError::Zero))
    );
}

/// Types named like the generated methods' generic parameters (`W`, `R`, `Ser`, `De`, `A`,
/// `E`, `State`), used in a module type: the parameters are renamed away from them. They were
/// renamed only away from the runtime's own parameters, so `serialize<W>` shadowed the type
/// `W` in `Third<S, (W, …)>` (a type error at the derive).
#[test]
fn generated_parameters_do_not_shadow_types_of_the_fields() {
    type Rt = shadowed_types::Named<S>;
    type Call = shadowed_types::NamedCall<S>;
    let call = Call::Third((1, 2, 3, 4, 5, 6, 7));
    let bytes = Rt::encode(&call).unwrap();
    assert_eq!(bytes[0], THIRD);
    assert_eq!(Rt::decode(&bytes).unwrap(), call);
    let json = serde_json::to_string(&call).unwrap();
    assert_eq!(json, r#"{"third":[1,2,3,4,5,6,7]}"#);
    assert_eq!(serde_json::from_str::<Call>(&json).unwrap(), call);
    let config: shadowed_types::NamedGenesisConfig<S> =
        serde_json::from_str(r#"{"third":null}"#).unwrap();
    let mut runtime = Rt {
        third: Third::default(),
    };
    let (result, storage) = genesis(&mut runtime, &config);
    assert_eq!(result, Ok(()));
    let mut ws = working_set(storage);
    assert_eq!(runtime.dispatch_call(call, &mut ws, &context()), Ok(()));
    assert_eq!(runtime.pre_dispatch_tx_hook(&tx(1), &mut ws), Ok(()));
}

/// A runtime written by a `macro_rules!` macro, with `$crate::…` module types: the genesis
/// configuration's serde bounds were strings (serde's `bound` attribute), in which `$crate`
/// does not parse, so `Genesis`'s derive failed (a parse error at the runtime's name).
#[test]
fn derives_on_a_runtime_from_a_macro_with_crate_paths() {
    let json = r#"{"second":null,"primary":3}"#;
    let config: CrateRtGenesisConfig<S> = serde_json::from_str(json).unwrap();
    assert_eq!(config.primary, 3);
    assert_eq!(serde_json::to_string(&config).unwrap(), json);
    let mut runtime = CrateRt::<S>::default();
    let (result, storage) = genesis(&mut runtime, &config);
    assert_eq!(result, Ok(()));
    let mut ws = working_set(storage);
    assert_eq!(runtime.primary.value.get(&mut ws), Ok(Some(3)));
    assert_eq!(
        CrateRt::<S>::encode(&CrateRtCall::Second(1)).unwrap(),
        [SECOND, 1]
    );
}

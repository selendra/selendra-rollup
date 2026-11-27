//! The module traits end to end, on hand-written modules and a hand-written runtime (what the
//! module and runtime derives generate): module identity and layout, genesis in dependency
//! order, calls decoded and dispatched through `TxState` with the module's error passed through,
//! events emitted with each module's own discriminant and key, the hooks (no-ops unless
//! overridden; a runtime calling them in field order), and `Context`; and the same runtime
//! derived, against the hand-written one.

use std::fmt;
use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::ConsensusType;
use selendra_state::test_utils::InMemoryState;
use selendra_state::{
    AccessoryStateValue, ArrayWitness, BorshCodec, Prefix, StateUpdate, StateValue, Storage,
    TxScratchpad,
};
use serde::{Deserialize, Serialize};

use crate::test_utils::{DistinctCostSpec, MockAddress, MockKernel, TestSpec, TestStorage};
use crate::*;

type S = TestSpec;
type Header<S> = <<S as Spec>::Da as selendra_interface::da::DaSpec>::BlockHeader;

const COUNTER: u8 = 224;
const HOOKED: u8 = 225;
const PLAIN: u8 = 226;

// -------------------------------------------------------------------------------------------
// `Counter`: a module with state, calls, events, a genesis and one hook.

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
)]
#[serde(rename_all = "snake_case")]
enum CounterCall {
    Add(u64),
    Reset,
    /// Adds, emitting the event under the key `tag` (`emit_event_with_custom_key`).
    AddTagged {
        by: u64,
        tag: String,
    },
}

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
)]
enum CounterEvent {
    Added { by: u64, total: u64 },
    Reset,
}

/// Not the derived `Debug`: upstream's event key was the first identifier of this (`counter`).
impl fmt::Debug for CounterEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("counter event ")?;
        f.write_str(self.event_name())
    }
}

impl ModuleEvent for CounterEvent {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Added { .. } => "Added",
            Self::Reset => "Reset",
        }
    }
}

#[derive(Debug, Clone)]
struct Counter<S: Spec> {
    id: ModuleId,
    count: StateValue<u64>,
    pre_dispatched: StateValue<u64>,
    spec: PhantomData<fn() -> S>,
}

impl<S: Spec> Default for Counter<S> {
    fn default() -> Self {
        Self {
            id: ModuleId::from_name(Self::NAME),
            count: StateValue::with_codec(Self::STATE_LAYOUT[0].prefix(COUNTER), BorshCodec),
            pre_dispatched: StateValue::with_codec(
                Self::STATE_LAYOUT[1].prefix(COUNTER),
                BorshCodec,
            ),
            spec: PhantomData,
        }
    }
}

impl<S: Spec> ModuleInfo for Counter<S> {
    type Spec = S;
    const DISCRIMINANT: u8 = COUNTER;
    const NAME: &'static str = "counter";
    const DEPENDENCIES: &'static [(u8, &'static str)] = &[];
    const STATE_LAYOUT: &'static [StateItem] = &[
        StateItem::new(0, "count"),
        StateItem::new(1, "pre_dispatched"),
    ];

    fn id(&self) -> &ModuleId {
        &self.id
    }
}

impl<S: Spec> Module for Counter<S> {
    type Config = u64;
    type CallMessage = CounterCall;
    type Event = CounterEvent;
    type Error = anyhow::Error;

    fn genesis(
        &mut self,
        _header: &Header<S>,
        config: &u64,
        state: &mut impl GenesisState<S>,
    ) -> anyhow::Result<()> {
        self.count.set(config, state)?;
        Ok(())
    }

    fn call(
        &mut self,
        message: CounterCall,
        _context: &Context<S>,
        state: &mut impl TxState<S>,
    ) -> anyhow::Result<()> {
        match message {
            CounterCall::Add(by) => {
                let count = self.count.get(state)?.unwrap_or(0);
                // The write and the event happen before the check: a failed call must keep
                // neither.
                let total = count.wrapping_add(by);
                self.count.set(&total, state)?;
                self.emit_event(state, CounterEvent::Added { by, total })?;
                if count.checked_add(by).is_none() {
                    anyhow::bail!("count overflows");
                }
            }
            CounterCall::Reset => {
                self.count.set(&0, state)?;
                self.emit_event(state, CounterEvent::Reset)?;
            }
            CounterCall::AddTagged { by, tag } => {
                let total = self.count.get(state)?.unwrap_or(0).saturating_add(by);
                self.count.set(&total, state)?;
                self.emit_event_with_custom_key(state, &tag, CounterEvent::Added { by, total })?;
            }
        }
        Ok(())
    }

    fn pre_dispatch_tx_hook<T: TxState<S>>(
        &mut self,
        _tx: &AuthenticatedTransactionData<S>,
        state: &mut T,
    ) -> anyhow::Result<()> {
        let n = self.pre_dispatched.get(state)?.unwrap_or(0);
        self.pre_dispatched.set(&(n + 1), state)?;
        Ok(())
    }
}

// -------------------------------------------------------------------------------------------
// `Hooked`: overrides every hook, holds `Counter` (a dependency), has its own error type.

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
)]
#[serde(rename_all = "snake_case")]
enum HookedCall {
    /// Adds to the counter through the nested module.
    Forward(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize)]
#[serde(tag = "error_code", rename_all = "snake_case")]
enum HookError {
    #[error("runtime version {version} is rejected")]
    Rejected { version: u32 },
    #[error("{message}")]
    Failed { message: String },
}

impl HookError {
    fn failed(error: impl fmt::Display) -> Self {
        Self::Failed {
            message: error.to_string(),
        }
    }
}

impl ErrorDetail for HookError {
    fn error_detail(&self) -> Result<ErrorContext, Box<dyn std::error::Error + Send + Sync>> {
        Ok(to_json_object(self)?)
    }
}

#[derive(Debug, Clone)]
struct Hooked<S: Spec> {
    id: ModuleId,
    /// A `#[module]` field: the nested counter writes under the counter's own prefixes.
    counter: Counter<S>,
    begun: StateValue<u64>,
    ended: StateValue<u64>,
    last_version: StateValue<u32>,
    last_sender: StateValue<S::Address>,
    finalized: AccessoryStateValue<u64>,
    genesis_saw: StateValue<u64>,
}

impl<S: Spec> Default for Hooked<S> {
    fn default() -> Self {
        let prefix = |item: usize| Self::STATE_LAYOUT[item].prefix(HOOKED);
        Self {
            id: ModuleId::from_name(Self::NAME),
            counter: Counter::default(),
            begun: StateValue::with_codec(prefix(0), BorshCodec),
            ended: StateValue::with_codec(prefix(1), BorshCodec),
            last_version: StateValue::with_codec(prefix(2), BorshCodec),
            last_sender: StateValue::with_codec(prefix(3), BorshCodec),
            finalized: AccessoryStateValue::with_codec(prefix(4), BorshCodec),
            genesis_saw: StateValue::with_codec(prefix(5), BorshCodec),
        }
    }
}

impl<S: Spec> ModuleInfo for Hooked<S> {
    type Spec = S;
    const DISCRIMINANT: u8 = HOOKED;
    const NAME: &'static str = "hooked";
    const DEPENDENCIES: &'static [(u8, &'static str)] =
        &[(Counter::<S>::DISCRIMINANT, Counter::<S>::NAME)];
    const STATE_LAYOUT: &'static [StateItem] = &[
        StateItem::new(0, "begun"),
        StateItem::new(1, "ended"),
        StateItem::new(2, "last_version"),
        StateItem::new(3, "last_sender"),
        StateItem::new(4, "finalized"),
        StateItem::new(5, "genesis_saw"),
    ];

    fn id(&self) -> &ModuleId {
        &self.id
    }
}

impl<S: Spec> Module for Hooked<S> {
    type Config = ();
    type CallMessage = HookedCall;
    type Event = NotInstantiable;
    type Error = HookError;

    /// Reads the counter's genesis value: the counter's genesis must have run first.
    fn genesis(
        &mut self,
        _header: &Header<S>,
        _config: &(),
        state: &mut impl GenesisState<S>,
    ) -> anyhow::Result<()> {
        let count = self.counter.count.get(state)?.unwrap_or(0);
        self.genesis_saw.set(&count, state)?;
        Ok(())
    }

    fn call(
        &mut self,
        message: HookedCall,
        context: &Context<S>,
        state: &mut impl TxState<S>,
    ) -> Result<(), HookError> {
        match message {
            HookedCall::Forward(by) => self
                .counter
                .call(CounterCall::Add(by), context, state)
                .map_err(HookError::failed),
        }
    }

    fn begin_rollup_block_hook(
        &mut self,
        _visible_hash: &<S::Storage as Storage>::Root,
        state: &mut BlockState<'_, S>,
    ) {
        let Ok(n) = self.begun.get(state);
        let Ok(()) = self.begun.set(&(n.unwrap_or(0) + 1), state);
    }

    fn end_rollup_block_hook(&mut self, state: &mut BlockState<'_, S>) {
        let Ok(n) = self.ended.get(state);
        let Ok(()) = self.ended.set(&(n.unwrap_or(0) + 1), state);
    }

    /// Rejects runtime version 0.
    fn pre_dispatch_tx_hook<T: TxState<S>>(
        &mut self,
        tx: &AuthenticatedTransactionData<S>,
        state: &mut T,
    ) -> Result<(), HookError> {
        let version = tx.0.runtime_version;
        if version == 0 {
            return Err(HookError::Rejected { version });
        }
        self.last_version
            .set(&version, state)
            .map_err(HookError::failed)
    }

    fn post_dispatch_tx_hook<T: TxState<S>>(
        &mut self,
        _tx: &AuthenticatedTransactionData<S>,
        context: &Context<S>,
        state: &mut T,
    ) -> Result<(), HookError> {
        self.last_sender
            .set(context.sender(), state)
            .map_err(HookError::failed)
    }

    fn finalize_hook(
        &mut self,
        _root_hash: &<S::Storage as Storage>::Root,
        state: &mut impl AccessoryStateReaderAndWriter,
    ) {
        let Ok(n) = self.finalized.get(state);
        let Ok(()) = self.finalized.set(&(n.unwrap_or(0) + 1), state);
    }
}

// -------------------------------------------------------------------------------------------
// `Plain`: overrides nothing.

#[derive(Debug, Clone)]
struct Plain<S: Spec>(ModuleId, PhantomData<fn() -> S>);

impl<S: Spec> Default for Plain<S> {
    fn default() -> Self {
        Self(ModuleId::from_name(Self::NAME), PhantomData)
    }
}

impl<S: Spec> ModuleInfo for Plain<S> {
    type Spec = S;
    const DISCRIMINANT: u8 = PLAIN;
    const NAME: &'static str = "plain";
    const DEPENDENCIES: &'static [(u8, &'static str)] = &[];
    const STATE_LAYOUT: &'static [StateItem] = &[];

    fn id(&self) -> &ModuleId {
        &self.0
    }
}

impl<S: Spec> Module for Plain<S> {
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

// -------------------------------------------------------------------------------------------
// A runtime over `Hooked` and `Counter`, written by hand the way its derives write it: calls and
// events tagged by discriminant, keyed by name in JSON; genesis in dependency order; hooks in
// field order with fully qualified calls.

#[derive(Debug, Clone, Default)]
struct TestRuntime<S: Spec> {
    hooked: Hooked<S>,
    counter: Counter<S>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ConsensusType)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum TestRuntimeCall {
    Hooked(HookedCall),
    Counter(CounterCall),
}

impl BorshSerialize for TestRuntimeCall {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        match self {
            Self::Hooked(message) => {
                BorshSerialize::serialize(&HOOKED, writer)?;
                BorshSerialize::serialize(message, writer)
            }
            Self::Counter(message) => {
                BorshSerialize::serialize(&COUNTER, writer)?;
                BorshSerialize::serialize(message, writer)
            }
        }
    }
}

impl BorshDeserialize for TestRuntimeCall {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        match u8::deserialize_reader(reader)? {
            HOOKED => Ok(Self::Hooked(HookedCall::deserialize_reader(reader)?)),
            COUNTER => Ok(Self::Counter(CounterCall::deserialize_reader(reader)?)),
            tag => Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                format!("no module with discriminant {tag}"),
            )),
        }
    }
}

impl ModuleMessage for TestRuntimeCall {
    fn module_discriminant(&self) -> u8 {
        match self {
            Self::Hooked(_) => HOOKED,
            Self::Counter(_) => COUNTER,
        }
    }

    fn module_name(&self) -> &'static str {
        match self {
            Self::Hooked(_) => Hooked::<S>::NAME,
            Self::Counter(_) => Counter::<S>::NAME,
        }
    }
}

impl<S: Spec> DispatchCall for TestRuntime<S> {
    type Spec = S;
    type Decodable = TestRuntimeCall;

    const MODULES: &'static [ModuleDescriptor] = &[
        ModuleDescriptor::of::<Hooked<S>>(),
        ModuleDescriptor::of::<Counter<S>>(),
    ];

    fn dispatch_call<T: TxState<S>>(
        &mut self,
        call: TestRuntimeCall,
        state: &mut T,
        context: &Context<S>,
    ) -> Result<(), ModuleError> {
        match call {
            TestRuntimeCall::Hooked(message) => {
                <Hooked<S> as Module>::call(&mut self.hooked, message, context, state)
                    .map_err(ModuleError::from)
            }
            TestRuntimeCall::Counter(message) => {
                <Counter<S> as Module>::call(&mut self.counter, message, context, state)
                    .map_err(ModuleError::from)
            }
        }
    }

    fn module_id(&self, call: &TestRuntimeCall) -> &ModuleId {
        match call {
            TestRuntimeCall::Hooked(_) => self.hooked.id(),
            TestRuntimeCall::Counter(_) => self.counter.id(),
        }
    }
}

impl<S: Spec> EncodeCall<Counter<S>> for TestRuntime<S> {
    fn to_decodable(message: CounterCall) -> TestRuntimeCall {
        TestRuntimeCall::Counter(message)
    }
}

impl<S: Spec> EncodeCall<Hooked<S>> for TestRuntime<S> {
    fn to_decodable(message: HookedCall) -> TestRuntimeCall {
        TestRuntimeCall::Hooked(message)
    }
}

struct TestGenesisConfig {
    hooked: (),
    counter: u64,
}

#[derive(Debug, Clone, Copy)]
enum Field {
    Hooked,
    Counter,
}

impl<S: Spec> Genesis for TestRuntime<S> {
    type Spec = S;
    type Config = TestGenesisConfig;

    fn genesis(
        &mut self,
        header: &Header<S>,
        config: &TestGenesisConfig,
        state: &mut impl GenesisState<S>,
    ) -> Result<(), ModuleError> {
        let () = <Self as DispatchCall>::__CHECK_LAYOUT;
        Self::validate_layout()?;
        let order = sort_values_by_modules_dependencies(vec![
            (ModuleDescriptor::of::<Hooked<S>>(), Field::Hooked),
            (ModuleDescriptor::of::<Counter<S>>(), Field::Counter),
        ])
        .map_err(anyhow::Error::from)?;
        for field in order {
            match field {
                Field::Hooked => {
                    Genesis::genesis(&mut self.hooked, header, &config.hooked, state)?;
                }
                Field::Counter => {
                    Genesis::genesis(&mut self.counter, header, &config.counter, state)?;
                }
            }
        }
        Ok(())
    }
}

impl<S: Spec> TxHooks for TestRuntime<S> {
    type Spec = S;

    fn pre_dispatch_tx_hook<T: TxState<S>>(
        &mut self,
        tx: &AuthenticatedTransactionData<S>,
        state: &mut T,
    ) -> Result<(), ModuleError> {
        <Hooked<S> as Module>::pre_dispatch_tx_hook(&mut self.hooked, tx, state)?;
        <Counter<S> as Module>::pre_dispatch_tx_hook(&mut self.counter, tx, state)?;
        Ok(())
    }

    fn post_dispatch_tx_hook<T: TxState<S>>(
        &mut self,
        tx: &AuthenticatedTransactionData<S>,
        context: &Context<S>,
        state: &mut T,
    ) -> Result<(), ModuleError> {
        <Hooked<S> as Module>::post_dispatch_tx_hook(&mut self.hooked, tx, context, state)?;
        <Counter<S> as Module>::post_dispatch_tx_hook(&mut self.counter, tx, context, state)?;
        Ok(())
    }
}

impl<S: Spec> BlockHooks for TestRuntime<S> {
    type Spec = S;

    fn begin_rollup_block_hook(
        &mut self,
        visible_hash: &<S::Storage as Storage>::Root,
        state: &mut BlockState<'_, S>,
    ) {
        <Hooked<S> as Module>::begin_rollup_block_hook(&mut self.hooked, visible_hash, state);
        <Counter<S> as Module>::begin_rollup_block_hook(&mut self.counter, visible_hash, state);
    }

    fn end_rollup_block_hook(&mut self, state: &mut BlockState<'_, S>) {
        <Hooked<S> as Module>::end_rollup_block_hook(&mut self.hooked, state);
        <Counter<S> as Module>::end_rollup_block_hook(&mut self.counter, state);
    }
}

impl<S: Spec> FinalizeHook for TestRuntime<S> {
    type Spec = S;

    fn finalize_hook(
        &mut self,
        root_hash: &<S::Storage as Storage>::Root,
        state: &mut impl AccessoryStateReaderAndWriter,
    ) {
        <Hooked<S> as Module>::finalize_hook(&mut self.hooked, root_hash, state);
        <Counter<S> as Module>::finalize_hook(&mut self.counter, root_hash, state);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TestRuntimeEvent {
    Counter(CounterEvent),
}

impl BorshSerialize for TestRuntimeEvent {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        let Self::Counter(event) = self;
        BorshSerialize::serialize(&COUNTER, writer)?;
        BorshSerialize::serialize(event, writer)
    }
}

impl BorshDeserialize for TestRuntimeEvent {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        match u8::deserialize_reader(reader)? {
            COUNTER => Ok(Self::Counter(CounterEvent::deserialize_reader(reader)?)),
            tag => Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                format!("no module with discriminant {tag} emits events"),
            )),
        }
    }
}

impl ModuleMessage for TestRuntimeEvent {
    fn module_discriminant(&self) -> u8 {
        COUNTER
    }

    fn module_name(&self) -> &'static str {
        Counter::<S>::NAME
    }
}

impl<S: Spec> RuntimeEventProcessor for TestRuntime<S> {
    type RuntimeEvent = TestRuntimeEvent;

    fn convert_to_runtime_event(event: TypeErasedEvent) -> Option<TestRuntimeEvent> {
        match event.module() {
            COUNTER => event
                .downcast::<CounterEvent>()
                .map(TestRuntimeEvent::Counter),
            _ => None,
        }
    }
}

// -------------------------------------------------------------------------------------------
// Helpers

const PRICE: GasPrice<2> = GasPrice::from_dimensions([Amount::new(1); 2]);

fn header() -> Header<S> {
    selendra_mock_da::MockBlockHeader::from_height(0)
}

/// A transaction's working set over `storage`, with `budget` gas in each dimension.
fn working_set<Sp: Spec<Storage = TestStorage>>(
    storage: TestStorage,
    budget: u64,
) -> WorkingSet<Sp> {
    let scratchpad = TxScratchpad::new(MockKernel::checkpoint(storage, ArrayWitness::default()));
    let meter = BasicGasMeter::new_with_gas(
        <Sp::Gas as From<[u64; 2]>>::from([budget, budget]),
        <<Sp::Gas as Gas>::Price as From<[Amount; 2]>>::from([Amount::new(1); 2]),
    );
    WorkingSet::new(scratchpad, meter)
}

/// The storage after the test runtime's genesis with the counter at `count`.
fn genesis_storage(count: u64) -> TestStorage {
    let mut runtime = TestRuntime::<S>::default();
    let checkpoint = MockKernel::checkpoint(TestStorage::default(), ArrayWitness::default());
    let prev_root = TestStorage::default().root();
    let mut state = GenesisStateAccessor::<S>::new(checkpoint).unwrap();
    let config = TestGenesisConfig {
        hooked: (),
        counter: count,
    };
    let result = runtime.genesis(&header(), &config, &mut state);
    let finalized = state.finalize(result);
    assert_eq!(finalized.outcome, PhaseOutcome::Committed);
    let (_root, mut update, accessory, _witness, storage) =
        finalized.checkpoint.materialize_update(prev_root);
    update.add_accessory_items(accessory.freeze());
    storage.materialize_changes(update)
}

fn address(byte: u8) -> <S as Spec>::Address {
    selendra_primitives::MultiAddressEvm::Standard(selendra_primitives::Address::new([byte; 28]))
}

fn context() -> Context<S> {
    Context::new(
        address(1),
        Credential::Multisig(selendra_interface::crypto::CredentialId::from_bytes(
            [1; 32],
        )),
        address(2),
        MockAddress::new([3; 32]),
        ExecutionContext::Node,
        SequencerType::Preferred,
    )
}

fn tx(runtime_version: u32) -> AuthenticatedTransactionData<S> {
    AuthenticatedTransactionData(TxDetails {
        max_priority_fee_bips: PriorityFeeBips::ZERO,
        max_fee: Amount::new(1_000_000),
        gas_limit: None,
        runtime_version,
    })
}

fn count<T: TxState<S>>(state: &mut T) -> Option<u64> {
    Counter::<S>::default().count.get(state).unwrap()
}

// -------------------------------------------------------------------------------------------
// Identity and layout

/// The constants, the ids derived from the names, the dependencies and the item prefixes.
#[test]
fn module_info_identity_and_layout() {
    let hooked = Hooked::<S>::default();
    assert_eq!(hooked.id(), &ModuleId::from_name("hooked"));
    assert_eq!(hooked.dependencies(), [ModuleId::from_name("counter")]);
    assert_eq!(Hooked::<S>::DEPENDENCIES, &[(COUNTER, "counter")]);
    assert_eq!(Counter::<S>::default().dependencies(), []);
    assert_eq!(
        Counter::<S>::STATE_LAYOUT,
        &[
            StateItem::new(0, "count"),
            StateItem::new(1, "pre_dispatched")
        ]
    );
    assert_eq!(Counter::<S>::STATE_LAYOUT[1].item(), 1);
    assert_eq!(Counter::<S>::STATE_LAYOUT[1].name(), "pre_dispatched");
    assert_eq!(
        Counter::<S>::STATE_LAYOUT[1].prefix(COUNTER),
        Prefix::new(224, 1)
    );
    let descriptor = ModuleDescriptor::of::<Hooked<S>>();
    assert_eq!(
        descriptor.key(),
        ModuleKey {
            discriminant: HOOKED,
            name: "hooked"
        }
    );
    assert_eq!(descriptor.dependencies(), &[(COUNTER, "counter")]);
    assert_eq!(descriptor.id(), *hooked.id());
    // The nested counter shares the counter module's prefixes.
    assert_eq!(hooked.counter.count, Counter::<S>::default().count);
}

/// `Counter`'s and `Hooked`'s identity and layout, derived.
#[derive(Debug, Clone, ModuleInfo)]
#[module_info(discriminant = 224, name = "counter")]
struct DerivedCounter<S: Spec> {
    #[id]
    id: ModuleId,
    #[state(item = 0)]
    count: StateValue<u64>,
    #[state(item = 1)]
    pre_dispatched: StateValue<u64>,
    #[phantom]
    spec: PhantomData<fn() -> S>,
}

#[derive(Debug, Clone, ModuleInfo)]
#[module_info(discriminant = 225, name = "hooked")]
struct DerivedHooked<S: Spec> {
    #[id]
    id: ModuleId,
    #[module]
    counter: Counter<S>,
    #[state(item = 0)]
    begun: StateValue<u64>,
    #[state(item = 1)]
    ended: StateValue<u64>,
    #[state(item = 2)]
    last_version: StateValue<u32>,
    #[state(item = 3)]
    last_sender: StateValue<S::Address>,
    #[state(item = 4)]
    finalized: AccessoryStateValue<u64>,
    #[state(item = 5)]
    genesis_saw: StateValue<u64>,
}

/// What `#[derive(ModuleInfo)]` generates is what the hand-written test modules implement (the
/// way a module was written before the derive): the constants, the id and every prefix.
#[test]
fn derive_matches_hand_written_module_info() {
    type DC = DerivedCounter<S>;
    type HC = Counter<S>;
    assert_eq!(DC::DISCRIMINANT, HC::DISCRIMINANT);
    assert_eq!(DC::NAME, HC::NAME);
    assert_eq!(DC::DEPENDENCIES, HC::DEPENDENCIES);
    assert_eq!(DC::STATE_LAYOUT, HC::STATE_LAYOUT);
    let (derived, hand) = (DC::default(), HC::default());
    assert_eq!(derived.id(), hand.id());
    assert_eq!(derived.count, hand.count);
    assert_eq!(derived.pre_dispatched, hand.pre_dispatched);

    type DH = DerivedHooked<S>;
    type HH = Hooked<S>;
    assert_eq!(DH::DISCRIMINANT, HH::DISCRIMINANT);
    assert_eq!(DH::NAME, HH::NAME);
    assert_eq!(DH::DEPENDENCIES, HH::DEPENDENCIES);
    assert_eq!(DH::STATE_LAYOUT, HH::STATE_LAYOUT);
    let (derived, hand) = (DH::default(), HH::default());
    assert_eq!(derived.id(), hand.id());
    assert_eq!(derived.dependencies(), hand.dependencies());
    assert_eq!(derived.counter.count, hand.counter.count);
    assert_eq!(derived.begun, hand.begun);
    assert_eq!(derived.ended, hand.ended);
    assert_eq!(derived.last_version, hand.last_version);
    assert_eq!(derived.last_sender, hand.last_sender);
    assert_eq!(derived.finalized, hand.finalized);
    assert_eq!(derived.genesis_saw, hand.genesis_saw);
}

// -------------------------------------------------------------------------------------------
// Genesis

/// The runtime's genesis runs the counter before `hooked` (which depends on it and is listed
/// first): `hooked` sees the counter's genesis value.
#[test]
fn genesis_runs_in_dependency_order() {
    let storage = genesis_storage(41);
    let mut ws = working_set::<S>(storage, 1_000_000);
    assert_eq!(count(&mut ws), Some(41));
    assert_eq!(
        Hooked::<S>::default().genesis_saw.get(&mut ws),
        Ok(Some(41))
    );
}

/// A module's genesis error becomes the runtime's, and genesis is reverted.
#[test]
fn genesis_error_is_returned() {
    #[derive(Debug, Clone, Default)]
    struct Failing(Plain<S>);
    impl ModuleInfo for Failing {
        type Spec = S;
        const DISCRIMINANT: u8 = 227;
        const NAME: &'static str = "failing";
        const DEPENDENCIES: &'static [(u8, &'static str)] = &[];
        const STATE_LAYOUT: &'static [StateItem] = &[];
        fn id(&self) -> &ModuleId {
            self.0.id()
        }
    }
    impl Module for Failing {
        type Config = ();
        type CallMessage = NotInstantiable;
        type Event = NotInstantiable;
        type Error = anyhow::Error;
        fn genesis(
            &mut self,
            _: &Header<S>,
            _: &(),
            state: &mut impl GenesisState<S>,
        ) -> anyhow::Result<()> {
            Counter::<S>::default().count.set(&7, state)?;
            anyhow::bail!("bad genesis config")
        }
        fn call(
            &mut self,
            message: NotInstantiable,
            _: &Context<S>,
            _: &mut impl TxState<S>,
        ) -> anyhow::Result<()> {
            match message {}
        }
    }

    let checkpoint = MockKernel::checkpoint(TestStorage::default(), ArrayWitness::default());
    let mut state = GenesisStateAccessor::<S>::new(checkpoint).unwrap();
    let result = Genesis::genesis(&mut Failing::default(), &header(), &(), &mut state);
    let error = result.clone().unwrap_err();
    assert_eq!(error.to_string(), "bad genesis config");
    assert_eq!(
        error.error_detail().unwrap()["message"],
        "bad genesis config"
    );
    let finalized = state.finalize(result);
    assert!(matches!(finalized.outcome, PhaseOutcome::Reverted(_)));
    let (accesses, _, _) = finalized.checkpoint.freeze();
    assert!(accesses.user.ordered_writes.is_empty());
}

// -------------------------------------------------------------------------------------------
// Calls

/// A call encoded by the runtime (tag = the module's discriminant) decodes and runs through
/// `TxState`; its writes are committed.
#[test]
fn call_is_decoded_and_dispatched() {
    let bytes =
        <TestRuntime<S> as EncodeCall<Counter<S>>>::encode_call(CounterCall::Add(5)).unwrap();
    // Known answer (`python3 -I -c 'import struct …'`): the discriminant, the variant, `u64`.
    assert_eq!(bytes, [224, 0, 5, 0, 0, 0, 0, 0, 0, 0]);
    let call = TestRuntime::<S>::decode(&bytes).unwrap();
    assert_eq!(call, TestRuntimeCall::Counter(CounterCall::Add(5)));
    assert_eq!(call.module_discriminant(), COUNTER);
    assert_eq!(call.module_name(), "counter");

    let mut runtime = TestRuntime::<S>::default();
    assert_eq!(runtime.module_id(&call), &ModuleId::from_name("counter"));
    let mut ws = working_set::<S>(genesis_storage(1), 1_000_000);
    assert_eq!(runtime.dispatch_call(call, &mut ws, &context()), Ok(()));
    assert_eq!(count(&mut ws), Some(6));

    // Through the nested module: the counter's state, the counter's discriminant on the event.
    let call = <TestRuntime<S> as EncodeCall<Hooked<S>>>::to_decodable(HookedCall::Forward(7));
    assert_eq!(
        TestRuntime::<S>::encode(&call).unwrap(),
        [225, 0, 7, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(runtime.module_id(&call), &ModuleId::from_name("hooked"));
    assert_eq!(runtime.dispatch_call(call, &mut ws, &context()), Ok(()));
    assert_eq!(count(&mut ws), Some(13));

    let finalized = ws.finalize(Ok::<(), ModuleError>(()));
    assert_eq!(finalized.outcome, PhaseOutcome::Committed);
    #[cfg(feature = "native")]
    {
        let events: Vec<_> = finalized
            .events
            .into_iter()
            .map(|event| (event.module(), event.key().to_owned(), event))
            .map(|(module, key, event)| {
                (
                    module,
                    key,
                    TestRuntime::<S>::convert_to_runtime_event(event),
                )
            })
            .collect();
        assert_eq!(
            events,
            [
                (
                    COUNTER,
                    "counter/Added".to_owned(),
                    Some(TestRuntimeEvent::Counter(CounterEvent::Added {
                        by: 5,
                        total: 6
                    }))
                ),
                (
                    COUNTER,
                    "counter/Added".to_owned(),
                    Some(TestRuntimeEvent::Counter(CounterEvent::Added {
                        by: 7,
                        total: 13
                    }))
                ),
            ]
        );
    }
    #[cfg(not(feature = "native"))]
    assert!(finalized.events.is_empty());
}

/// Calls decode from exactly their encoding (`from_slice`): an unknown module tag, trailing
/// bytes and a truncated call are errors.
#[test]
fn call_decoding_is_strict() {
    assert!(TestRuntime::<S>::decode(&[224, 1]).is_ok());
    for rejected in [
        &[][..],
        &[0, 1],
        &[226, 1],
        &[224],
        &[224, 1, 0],
        &[224, 2],
        &[224, 0, 5, 0, 0, 0, 0, 0, 0],
        &[224, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0],
    ] {
        assert!(TestRuntime::<S>::decode(rejected).is_err(), "{rejected:?}");
    }
    // JSON is keyed by the module's name.
    let json = serde_json::to_string(&TestRuntimeCall::Counter(CounterCall::Add(5))).unwrap();
    assert_eq!(json, r#"{"counter":{"add":5}}"#);
}

/// A module's error comes back unchanged (as a `ModuleError`, with its detail), and the call's
/// writes and events are dropped.
#[test]
fn module_error_passes_through() {
    let mut runtime = TestRuntime::<S>::default();
    let mut ws = working_set::<S>(genesis_storage(u64::MAX), 1_000_000);
    let call = TestRuntimeCall::Counter(CounterCall::Add(1));
    let error = runtime
        .dispatch_call(call, &mut ws, &context())
        .unwrap_err();
    assert_eq!(error.to_string(), "count overflows");
    // The overflowing write and its event were made before the error.
    assert_eq!(count(&mut ws), Some(0));
    #[cfg(feature = "native")]
    {
        let [made] = ws.events() else {
            panic!("one event")
        };
        assert_eq!(
            made.downcast_ref::<CounterEvent>(),
            Some(&CounterEvent::Added { by: 1, total: 0 })
        );
    }
    let finalized = ws.finalize(Err(error));
    assert!(matches!(
        finalized.outcome,
        PhaseOutcome::Reverted(RevertReason::Module(_))
    ));
    assert!(finalized.events.is_empty());
    let mut ws = WorkingSet::<S>::new(
        finalized.scratchpad,
        BasicGasMeter::new_with_gas(GasUnit::from([1_000_000; 2]), PRICE),
    );
    assert_eq!(count(&mut ws), Some(u64::MAX));

    // A typed error keeps its detail.
    let error = ModuleError::from(HookError::Rejected { version: 0 });
    let detail = error.error_detail().unwrap();
    assert_eq!(detail["error_code"], "rejected");
    assert_eq!(detail["version"], 0);
}

// -------------------------------------------------------------------------------------------
// Events

/// A custom event key (`emit_event_with_custom_key`, in a call dispatched by the runtime) is at
/// most `MAX_EVENT_KEY_LEN` (256) bytes, the node's ledger's limit. The longest key is charged
/// like any other and kept (natively); one byte more fails the call with `EventKeyTooLong`,
/// charges nothing for the event (exactly `event_base + event_per_byte·(256 + 17)` = 274 less
/// than the accepted call, whose state accesses are the same; `Added` is 17 borsh bytes),
/// poisons the phase (a later read is `Poisoned`), and the call is reverted: no event, no write.
/// The same in both builds.
#[test]
fn custom_event_key_is_bounded() {
    let mut runtime = TestRuntime::<S>::default();
    let tagged = |tag: &str| {
        TestRuntimeCall::Counter(CounterCall::AddTagged {
            by: 2,
            tag: tag.to_owned(),
        })
    };

    let longest = "k".repeat(MAX_EVENT_KEY_LEN);
    let mut ws = working_set::<S>(genesis_storage(1), 1_000_000);
    assert_eq!(
        runtime.dispatch_call(tagged(&longest), &mut ws, &context()),
        Ok(())
    );
    let accepted = ws.gas_info().gas_used;
    assert_eq!(count(&mut ws), Some(3));
    let finalized = ws.finalize(Ok::<(), ModuleError>(()));
    assert_eq!(finalized.outcome, PhaseOutcome::Committed);
    #[cfg(feature = "native")]
    {
        let [kept] = &finalized.events[..] else {
            panic!("one event")
        };
        assert_eq!(kept.key(), longest);
        assert_eq!(kept.module(), COUNTER);
    }
    #[cfg(not(feature = "native"))]
    assert!(finalized.events.is_empty());

    let too_long = format!("{longest}k");
    let mut ws = working_set::<S>(genesis_storage(1), 1_000_000);
    let error = runtime
        .dispatch_call(tagged(&too_long), &mut ws, &context())
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "event key: 257 bytes is more than the maximum of 256"
    );
    let refused = ws.gas_info().gas_used;
    assert_eq!(accepted.checked_sub(refused), Some(GasUnit::from([274; 2])));
    assert!(ws.metered_view().is_poisoned());
    assert_eq!(
        Counter::<S>::default().count.get(&mut ws),
        Err(StateAccessError::Poisoned)
    );
    assert_eq!(ws.gas_info().gas_used, refused);
    assert!(ws.events().is_empty());
    let finalized = ws.finalize(Err(error));
    assert!(matches!(
        finalized.outcome,
        PhaseOutcome::Reverted(RevertReason::Poisoned(StateAccessError::EventKeyTooLong {
            len: 257
        }))
    ));
    assert!(finalized.events.is_empty());
    let mut ws = WorkingSet::<S>::new(
        finalized.scratchpad,
        BasicGasMeter::new_with_gas(GasUnit::from([1_000_000; 2]), PRICE),
    );
    assert_eq!(count(&mut ws), Some(1));
}

// Regressions of upstream's event bugs

/// P5-32 (regression, the key): an event's key is `"{NAME}/{event_name}"`. Upstream parsed it
/// out of the event's `Debug` output (here `counter event Added`: the key would have been
/// `counter/counter`). Pinned by gas in every build (an event is charged for its key's length:
/// `event_base + event_per_byte·(13 + 17)` on `DistinctCostSpec`, `[157 + 167·30, 163 + 173·30]`,
/// computed with `python3 -I`), and by the kept event natively.
#[test]
fn event_name_ignores_debug() {
    let event = CounterEvent::Added { by: 1, total: 2 };
    assert_eq!(format!("{event:?}"), "counter event Added");
    let mut ws = working_set::<DistinctCostSpec>(TestStorage::default(), 1_000_000);
    let before = ws.gas_info().gas_used;
    Counter::<DistinctCostSpec>::default()
        .emit_event(&mut ws, event.clone())
        .unwrap();
    let used = ws.gas_info().gas_used.checked_sub(before).unwrap();
    assert_eq!(used, GasUnit::from([5167, 5353]));
    #[cfg(feature = "native")]
    {
        let [kept] = ws.events() else {
            panic!("one event")
        };
        assert_eq!(kept.key(), "counter/Added");
        assert_eq!(kept.module(), COUNTER);
        assert_eq!(kept.downcast_ref::<CounterEvent>(), Some(&event));
    }
    #[cfg(not(feature = "native"))]
    assert!(ws.events().is_empty());

    // A custom key.
    let before = ws.gas_info().gas_used;
    Counter::<DistinctCostSpec>::default()
        .emit_event_with_custom_key(&mut ws, "k", CounterEvent::Reset)
        .unwrap();
    let used = ws.gas_info().gas_used.checked_sub(before).unwrap();
    // One key byte and one borsh byte.
    assert_eq!(used, GasUnit::from([157 + 167 * 2, 163 + 173 * 2]));
    // The custom key replaces only the key: the event still carries the emitting module's
    // discriminant (gas does not depend on it).
    #[cfg(feature = "native")]
    {
        let [_, kept] = ws.events() else {
            panic!("two events")
        };
        assert_eq!(kept.key(), "k");
        assert_eq!(kept.module(), COUNTER);
        assert_eq!(
            kept.downcast_ref::<CounterEvent>(),
            Some(&CounterEvent::Reset)
        );
    }
    #[cfg(not(feature = "native"))]
    assert!(ws.events().is_empty());
}

/// Each module emits with its own discriminant, and the runtime maps an event back by it: two
/// modules' events of one type are told apart (upstream mapped by `TypeId`, P5-32), and an
/// event of an unknown module, or of a type not the module's, maps to nothing.
#[test]
fn events_map_by_the_emitting_module() {
    let event = CounterEvent::Reset;
    assert_eq!(
        TestRuntime::<S>::convert_to_runtime_event(TypeErasedEvent::new(
            COUNTER,
            "counter/Reset",
            event.clone()
        )),
        Some(TestRuntimeEvent::Counter(event.clone()))
    );
    // `hooked` emits no events; neither does an unknown module.
    for module in [HOOKED, 0, 99] {
        assert_eq!(
            TestRuntime::<S>::convert_to_runtime_event(TypeErasedEvent::new(
                module,
                "counter/Reset",
                event.clone()
            )),
            None
        );
    }
    // The counter's discriminant with another type.
    assert_eq!(
        TestRuntime::<S>::convert_to_runtime_event(TypeErasedEvent::new(COUNTER, "x", 1u64)),
        None
    );

    let runtime_event = TestRuntimeEvent::Counter(CounterEvent::Added { by: 1, total: 2 });
    assert_eq!(runtime_event.module_discriminant(), COUNTER);
    assert_eq!(runtime_event.module_name(), "counter");
    let bytes = borsh::to_vec(&runtime_event).unwrap();
    assert_eq!(bytes[..2], [224, 0]);
    assert_eq!(
        borsh::from_slice::<TestRuntimeEvent>(&bytes).unwrap(),
        runtime_event
    );
}

// -------------------------------------------------------------------------------------------
// Hooks

/// A module that overrides no hook: every hook does nothing (no write, no gas, no event).
#[test]
fn hooks_are_no_ops_unless_overridden() {
    let mut plain = Plain::<S>::default();
    let storage = genesis_storage(1);
    let root = storage.root();

    let mut checkpoint = MockKernel::checkpoint(storage.clone(), ArrayWitness::default());
    {
        let mut block = BlockState::<S>::new(&mut checkpoint);
        plain.begin_rollup_block_hook(&root, &mut block);
        plain.end_rollup_block_hook(&mut block);
    }
    let (accesses, accessory, _) = checkpoint.freeze();
    assert!(accesses.user.ordered_writes.is_empty());
    assert!(accesses.kernel.ordered_writes.is_empty());
    assert!(accessory.freeze().is_empty());

    let mut ws = working_set::<S>(storage, 1_000_000);
    plain.pre_dispatch_tx_hook(&tx(1), &mut ws).unwrap();
    plain
        .post_dispatch_tx_hook(&tx(1), &context(), &mut ws)
        .unwrap();
    assert_eq!(ws.gas_info().gas_used, GasUnit::ZEROED);
    let finalized = ws.finalize(Ok::<(), ()>(()));
    let (accesses, accessory, _) = finalized.scratchpad.commit().freeze();
    assert!(accesses.user.ordered_writes.is_empty());
    assert!(accessory.freeze().is_empty());

    let mut accessory_state = InMemoryState::default();
    plain.finalize_hook(&root, &mut accessory_state);
    assert_eq!(accessory_state, InMemoryState::default());
}

/// A module's overridden hooks run when the runtime calls them: block hooks on the block state,
/// transaction hooks metered on the transaction's state, the finalize hook on Accessory state.
#[test]
fn overridden_hooks_run() {
    let mut runtime = TestRuntime::<S>::default();
    let storage = genesis_storage(1);
    let root = storage.root();

    let mut checkpoint = MockKernel::checkpoint(storage, ArrayWitness::default());
    {
        let mut block = BlockState::<S>::new(&mut checkpoint);
        runtime.begin_rollup_block_hook(&root, &mut block);
        runtime.begin_rollup_block_hook(&root, &mut block);
        runtime.end_rollup_block_hook(&mut block);
        let Ok(begun) = runtime.hooked.begun.get(&mut block);
        let Ok(ended) = runtime.hooked.ended.get(&mut block);
        assert_eq!((begun, ended), (Some(2), Some(1)));
    }

    let meter = BasicGasMeter::new_with_gas(GasUnit::from([1_000_000; 2]), PRICE);
    let mut ws = WorkingSet::<S>::new(TxScratchpad::new(checkpoint), meter);
    runtime.pre_dispatch_tx_hook(&tx(7), &mut ws).unwrap();
    // Metered: the hooks' accesses are charged to the transaction.
    assert_ne!(ws.gas_info().gas_used, GasUnit::ZEROED);
    runtime
        .post_dispatch_tx_hook(&tx(7), &context(), &mut ws)
        .unwrap();
    assert_eq!(runtime.hooked.last_version.get(&mut ws), Ok(Some(7)));
    assert_eq!(
        runtime.hooked.last_sender.get(&mut ws),
        Ok(Some(address(1)))
    );
    assert_eq!(runtime.counter.pre_dispatched.get(&mut ws), Ok(Some(1)));

    let mut accessory_state = InMemoryState::default();
    runtime.finalize_hook(&root, &mut accessory_state);
    runtime.finalize_hook(&root, &mut accessory_state);
    let Ok(finalized) = runtime.hooked.finalized.get(&mut accessory_state);
    assert_eq!(finalized, Some(2));
}

/// A failing transaction hook stops the runtime's chain of hooks (the later modules' hooks do
/// not run) and its error comes back unchanged.
#[test]
fn failing_tx_hook_stops_the_chain() {
    let mut runtime = TestRuntime::<S>::default();
    let mut ws = working_set::<S>(genesis_storage(1), 1_000_000);
    let error = runtime.pre_dispatch_tx_hook(&tx(0), &mut ws).unwrap_err();
    assert_eq!(error, ModuleError::from(HookError::Rejected { version: 0 }));
    assert_eq!(error.to_string(), "runtime version 0 is rejected");
    assert_eq!(runtime.counter.pre_dispatched.get(&mut ws), Ok(None));
}

// -------------------------------------------------------------------------------------------
// Context

#[test]
fn context_constructors() {
    let credential = Credential::Multisig(selendra_interface::crypto::CredentialId::from_bytes(
        [1; 32],
    ));
    let context = context();
    assert_eq!(context.sender(), &address(1));
    assert_eq!(context.sender_credential(), &credential);
    assert_eq!(context.sequencer(), &address(2));
    assert_eq!(context.sequencer_da_address(), &MockAddress::new([3; 32]));
    assert_eq!(context.gas_refund_recipient(), &address(1));
    assert_eq!(context.execution_context(), ExecutionContext::Node);
    assert!(context.sequencer_is_preferred());
    assert_eq!(context.sequencer_type(), SequencerType::Preferred);

    let mut context = Context::<S>::with_payer(
        address(1),
        credential.clone(),
        address(2),
        MockAddress::new([3; 32]),
        address(4),
        ExecutionContext::Sequencer,
        SequencerType::NonPreferred,
    );
    assert_eq!(context.gas_refund_recipient(), &address(4));
    assert!(!context.sequencer_is_preferred());
    assert_eq!(context.execution_context(), ExecutionContext::Sequencer);
    context.set_gas_refund_recipient(address(5));
    assert_eq!(context.gas_refund_recipient(), &address(5));
    assert_eq!(context.sender(), &address(1));
    assert_eq!(context.clone(), context);
}

/// `Context` is `Send` and `Sync` for every spec (upstream's held `Rc`s).
#[test]
fn context_is_send_and_sync() {
    fn send_sync<T: Send + Sync>() {}
    fn for_every_spec<Sp: Spec>() {
        send_sync::<Context<Sp>>();
    }
    for_every_spec::<S>();
    for_every_spec::<DistinctCostSpec>();
}

/// The module traits' bounds: modules' call messages and events are consensus types, and a
/// runtime is `Send + Sync` (checked at compile time).
#[test]
fn module_bounds() {
    fn consensus<T: ConsensusType>() {}
    fn module<M: Module>() {
        consensus::<M::CallMessage>();
        consensus::<M::Event>();
    }
    module::<Counter<S>>();
    module::<Hooked<S>>();
    module::<Plain<S>>();
    fn runtime<R: DispatchCall + Genesis + TxHooks + BlockHooks + FinalizeHook>() {}
    runtime::<TestRuntime<S>>();
}

// -------------------------------------------------------------------------------------------
// The derived runtime

/// The test runtime, derived.
#[derive(Debug, Clone, Default, DispatchCall, MessageCodec, Genesis, Event, Hooks)]
struct DerivedRuntime<S: Spec> {
    hooked: Hooked<S>,
    counter: Counter<S>,
}

/// What the runtime derives generate is what the hand-written runtime does (the way S7 wrote
/// it before the derives): the modules, the call encodings (borsh and JSON, both ways), the
/// event encodings and mapping, the genesis state, dispatch and the hooks' state changes.
#[test]
fn derive_matches_hand_written_runtime() {
    type D = DerivedRuntime<S>;
    type H = TestRuntime<S>;
    assert_eq!(D::MODULES, H::MODULES);
    assert_eq!(D::validate_layout(), Ok(()));

    let calls = [
        (
            DerivedRuntimeCall::Counter(CounterCall::Add(5)),
            TestRuntimeCall::Counter(CounterCall::Add(5)),
        ),
        (
            DerivedRuntimeCall::Counter(CounterCall::Reset),
            TestRuntimeCall::Counter(CounterCall::Reset),
        ),
        (
            DerivedRuntimeCall::Counter(CounterCall::AddTagged {
                by: 2,
                tag: "t".to_owned(),
            }),
            TestRuntimeCall::Counter(CounterCall::AddTagged {
                by: 2,
                tag: "t".to_owned(),
            }),
        ),
        (
            DerivedRuntimeCall::Hooked(HookedCall::Forward(7)),
            TestRuntimeCall::Hooked(HookedCall::Forward(7)),
        ),
    ];
    for (derived, hand) in &calls {
        let bytes = D::encode(derived).unwrap();
        assert_eq!(bytes, H::encode(hand).unwrap());
        assert_eq!(&H::decode(&bytes).unwrap(), hand);
        assert_eq!(&D::decode(&bytes).unwrap(), derived);
        let json = serde_json::to_string(derived).unwrap();
        assert_eq!(json, serde_json::to_string(hand).unwrap());
        assert_eq!(
            &serde_json::from_str::<TestRuntimeCall>(&json).unwrap(),
            hand
        );
        assert_eq!(
            (derived.module_discriminant(), derived.module_name()),
            (hand.module_discriminant(), hand.module_name())
        );
    }
    assert_eq!(
        <D as EncodeCall<Counter<S>>>::encode_call(CounterCall::Add(5)).unwrap(),
        <H as EncodeCall<Counter<S>>>::encode_call(CounterCall::Add(5)).unwrap()
    );

    let event = CounterEvent::Added { by: 1, total: 2 };
    let derived_event = DerivedRuntimeEvent::<S>::Counter(event.clone());
    let bytes = borsh::to_vec(&derived_event).unwrap();
    assert_eq!(
        bytes,
        borsh::to_vec(&TestRuntimeEvent::Counter(event.clone())).unwrap()
    );
    assert_eq!(
        borsh::from_slice::<TestRuntimeEvent>(&bytes).unwrap(),
        TestRuntimeEvent::Counter(event.clone())
    );
    assert_eq!(
        serde_json::to_string(&derived_event).unwrap(),
        serde_json::to_string(&TestRuntimeEvent::Counter(event.clone())).unwrap()
    );
    for module in [COUNTER, HOOKED, 0] {
        let erased = || TypeErasedEvent::new(module, "k", event.clone());
        assert_eq!(
            D::convert_to_runtime_event(erased()).map(|e| borsh::to_vec(&e).unwrap()),
            H::convert_to_runtime_event(erased()).map(|e| borsh::to_vec(&e).unwrap())
        );
    }

    // Genesis: the same state.
    let mut derived = D::default();
    let checkpoint = MockKernel::checkpoint(TestStorage::default(), ArrayWitness::default());
    let prev_root = TestStorage::default().root();
    let mut state = GenesisStateAccessor::<S>::new(checkpoint).unwrap();
    let config = DerivedRuntimeGenesisConfig {
        hooked: (),
        counter: 41,
    };
    let result = derived.genesis(&header(), &config, &mut state);
    let finalized = state.finalize(result);
    assert_eq!(finalized.outcome, PhaseOutcome::Committed);
    let (root, ..) = finalized.checkpoint.materialize_update(prev_root);
    let (hand_root, ..) = {
        let checkpoint = MockKernel::checkpoint(TestStorage::default(), ArrayWitness::default());
        let mut state = GenesisStateAccessor::<S>::new(checkpoint).unwrap();
        let config = TestGenesisConfig {
            hooked: (),
            counter: 41,
        };
        let result = TestRuntime::<S>::default().genesis(&header(), &config, &mut state);
        state
            .finalize(result)
            .checkpoint
            .materialize_update(prev_root)
    };
    assert_eq!(root, hand_root);

    // Dispatch and the transaction hooks: the same writes, the same gas.
    let run = |dispatch: &mut dyn FnMut(&mut WorkingSet<S>)| {
        let mut ws = working_set::<S>(genesis_storage(1), 1_000_000);
        dispatch(&mut ws);
        let gas = ws.gas_info().gas_used;
        let finalized = ws.finalize(Ok::<(), ModuleError>(()));
        let (accesses, _, _) = finalized.scratchpad.commit().freeze();
        (gas, accesses.user.ordered_writes)
    };
    let mut derived = D::default();
    let mut hand = H::default();
    let derived_run = run(&mut |ws| {
        derived.pre_dispatch_tx_hook(&tx(3), ws).unwrap();
        for (call, _) in calls.clone() {
            derived.dispatch_call(call, ws, &context()).unwrap();
        }
        derived
            .post_dispatch_tx_hook(&tx(3), &context(), ws)
            .unwrap();
    });
    let hand_run = run(&mut |ws| {
        hand.pre_dispatch_tx_hook(&tx(3), ws).unwrap();
        for (_, call) in calls.clone() {
            hand.dispatch_call(call, ws, &context()).unwrap();
        }
        hand.post_dispatch_tx_hook(&tx(3), &context(), ws).unwrap();
    });
    assert_eq!(derived_run, hand_run);
    assert_eq!(
        derived.pre_dispatch_tx_hook(&tx(0), &mut working_set::<S>(genesis_storage(1), 1_000_000)),
        hand.pre_dispatch_tx_hook(&tx(0), &mut working_set::<S>(genesis_storage(1), 1_000_000))
    );
}

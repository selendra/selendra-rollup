//! `#[derive(ModuleInfo)]`: identity, state layout and prefixes, dependencies, custom codecs,
//! foreign attributes, hygiene, and a derived module running as a `Module`.

use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_modules_api::test_utils::TestSpec;
use selendra_modules_api::*;
use selendra_state::{
    AccessoryStateMap, BorshCodec, KernelStateValue, Prefix, StateCodec, StateMap, StateValue,
    StateVec,
};
use serde::{Deserialize, Serialize};

use crate::working_set;

type S = TestSpec;

const LEDGER: u8 = 240;
const INNER: u8 = 241;
const CODECS: u8 = 243;

/// Fields out of item-id order, in every namespace and container kind.
#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 240, name = "ledger")]
pub struct Ledger<S: Spec> {
    #[id]
    id: ModuleId,
    #[state(item = 3)]
    balances: StateMap<S::Address, u128>,
    #[state(item = 0)]
    total: StateValue<u128>,
    #[state(item = 4)]
    config: KernelStateValue<u64>,
    #[state(item = 1)]
    history: StateVec<u64>,
    #[state(item = 2)]
    index: AccessoryStateMap<u64, u64>,
}

#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 241, name = "inner")]
pub struct Inner<S: Spec> {
    #[id]
    id: ModuleId,
    #[state(item = 0)]
    value: StateValue<u64>,
    #[phantom]
    spec: PhantomData<S>,
}

/// Holds three modules: its dependencies, in field order. That order is neither the order of
/// their names (field, type or `NAME`) nor of their discriminants, either way round, so the
/// known answers tell field order from any sort.
#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 242, name = "outer")]
pub struct Outer<S: Spec> {
    #[module]
    ledger: Ledger<S>,
    #[state(item = 0)]
    own: StateValue<u64>,
    #[module]
    codecs: Codecs<S>,
    #[id]
    id: ModuleId,
    #[module]
    inner: Inner<S>,
}

/// The constants, in item-id order, and every container's prefix `(DISCRIMINANT, item)`: one
/// numbering for the module (upstream took the prefix's module byte from `constants.toml` and
/// numbered items by position).
#[test]
fn state_layout_known_answer() {
    type L = Ledger<S>;
    assert_eq!(L::DISCRIMINANT, LEDGER);
    assert_eq!(L::NAME, "ledger");
    assert_eq!(
        L::STATE_LAYOUT,
        [
            StateItem::new(0, "total"),
            StateItem::new(1, "history"),
            StateItem::new(2, "index"),
            StateItem::new(3, "balances"),
            StateItem::new(4, "config"),
        ]
    );
    assert_eq!(L::DEPENDENCIES, []);
    let ledger = L::default();
    assert_eq!(ledger.total.prefix(), &Prefix::new(240, 0));
    assert_eq!(ledger.history.prefix(), &Prefix::new(240, 1));
    assert_eq!(ledger.index.prefix(), &Prefix::new(240, 2));
    assert_eq!(ledger.balances.prefix(), &Prefix::new(240, 3));
    assert_eq!(ledger.config.prefix(), &Prefix::new(240, 4));
    for item in L::STATE_LAYOUT {
        assert_eq!(item.prefix(L::DISCRIMINANT), Prefix::new(240, item.item()));
    }
    assert_eq!(ledger.dependencies(), []);
}

/// A module's dependencies are its `#[module]` fields, in field order (not sorted by name or
/// discriminant: see `Outer`); each nested module keeps its own discriminant, so it writes under
/// its own prefixes, the same as the top-level instance of that module.
#[test]
fn dependencies_known_answer() {
    type O = Outer<S>;
    assert_eq!(
        O::DEPENDENCIES,
        [(LEDGER, "ledger"), (CODECS, "codecs"), (INNER, "inner")]
    );
    assert_eq!(O::STATE_LAYOUT, [StateItem::new(0, "own")]);
    let outer = O::default();
    assert_eq!(
        outer.dependencies(),
        [
            ModuleId::from_name("ledger"),
            ModuleId::from_name("codecs"),
            ModuleId::from_name("inner"),
        ]
    );
    assert_eq!(outer.own.prefix(), &Prefix::new(242, 0));
    assert_eq!(outer.inner.value.prefix(), &Prefix::new(INNER, 0));
    assert_eq!(outer.inner.value, Inner::<S>::default().value);
    assert_eq!(outer.ledger.total, Ledger::<S>::default().total);
    assert_eq!(outer.ledger.id(), &ModuleId::from_name("ledger"));
    assert_eq!(outer.codecs.custom.prefix(), &Prefix::new(CODECS, 0));
    assert_eq!(outer.codecs.custom.codec(), &CustomCodec::new());

    let descriptor = ModuleDescriptor::of::<O>();
    assert_eq!(descriptor.dependencies(), O::DEPENDENCIES);
    // The genesis order: the dependencies first, in the order `Outer` lists them (the input
    // order alone would give `inner`, `codecs`, `ledger`).
    let order = sort_values_by_modules_dependencies(vec![
        (ModuleDescriptor::of::<O>(), "outer"),
        (ModuleDescriptor::of::<Inner<S>>(), "inner"),
        (ModuleDescriptor::of::<Codecs<S>>(), "codecs"),
        (ModuleDescriptor::of::<Ledger<S>>(), "ledger"),
    ])
    .unwrap();
    assert_eq!(order, ["ledger", "codecs", "inner", "outer"]);
}

/// The state really lives under the prefixes: writes through each item read back, and the
/// items do not see each other's values.
#[test]
fn derived_items_store_under_their_prefixes() {
    let mut state = working_set::<S>(1_000_000);
    let mut ledger = Ledger::<S>::default();
    let mut outer = Outer::<S>::default();
    ledger.total.set(&7, &mut state).unwrap();
    ledger.history.push(&8, &mut state).unwrap();
    ledger.config.set(&9, &mut state).unwrap();
    outer.inner.value.set(&10, &mut state).unwrap();
    outer.own.set(&11, &mut state).unwrap();
    assert_eq!(ledger.total.get(&mut state).unwrap(), Some(7));
    assert_eq!(ledger.history.get(0, &mut state).unwrap(), Some(8));
    assert_eq!(ledger.config.get(&mut state).unwrap(), Some(9));
    // The nested ledger is the ledger: the same item.
    assert_eq!(outer.ledger.total.get(&mut state).unwrap(), Some(7));
    assert_eq!(
        Inner::<S>::default().value.get(&mut state).unwrap(),
        Some(10)
    );
    assert_eq!(outer.own.get(&mut state).unwrap(), Some(11));
}

// -------------------------------------------------------------------------------------------
// A custom codec (upstream `custom_state_codec_builder.rs`)

/// A codec with a value only its builder sets: encodes with borsh.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct CustomCodec {
    built_by: &'static str,
    inner: BorshCodec,
}

impl CustomCodec {
    fn new() -> Self {
        Self {
            built_by: "CustomCodec::new",
            inner: BorshCodec,
        }
    }
}

impl StateCodec for CustomCodec {
    type KeyCodec = BorshCodec;
    type ValueCodec = BorshCodec;

    fn key_codec(&self) -> &BorshCodec {
        &self.inner
    }

    fn value_codec(&self) -> &BorshCodec {
        &self.inner
    }
}

#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 243, name = "codecs")]
struct Codecs<S: Spec> {
    #[id]
    id: ModuleId,
    #[state(item = 0, codec = CustomCodec::new)]
    custom: StateValue<u32, CustomCodec>,
    #[state(item = 1)]
    default: StateValue<u32, CustomCodec>,
    #[phantom]
    spec: PhantomData<S>,
}

/// `codec = path` builds the item's codec with `path()`; without it, with `Default`.
#[test]
fn custom_codec_builder_is_used() {
    let mut module = Codecs::<S>::default();
    assert_eq!(module.custom.codec(), &CustomCodec::new());
    assert_eq!(module.default.codec(), &CustomCodec::default());
    let mut state = working_set::<S>(1_000_000);
    module.custom.set(&42, &mut state).unwrap();
    assert_eq!(module.custom.get(&mut state).unwrap(), Some(42));
    assert_eq!(module.custom.prefix(), &Prefix::new(243, 0));
}

// -------------------------------------------------------------------------------------------
// Foreign attributes (upstream `unrecognized_state_attributes_are_ignored.rs`)

#[derive(Clone, Debug, ModuleInfo)]
#[module_info(discriminant = 244, name = "attributed")]
/// Doc comments, lint attributes and other derives' attributes stay as they are.
struct Attributed<S: Spec> {
    /// The id.
    #[id]
    id: ModuleId,
    // A comment.
    #[allow(dead_code)]
    #[state(item = 0)]
    #[cfg_attr(not(test), allow(unused))]
    value: StateMap<u32, S::Address>,
    #[cfg(any())]
    #[state(item = 1)]
    removed: StateValue<u64>,
    /// After a `#[cfg]`'d-out field: its id stays unused, nothing moves.
    #[state(item = 2)]
    after: StateValue<u64>,
}

#[test]
fn foreign_field_attributes_are_accepted() {
    assert_eq!(
        Attributed::<S>::STATE_LAYOUT,
        [StateItem::new(0, "value"), StateItem::new(2, "after")]
    );
    assert_eq!(
        Attributed::<S>::default().after.prefix(),
        &Prefix::new(244, 2)
    );
}

// -------------------------------------------------------------------------------------------
// A derived module is a module

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
pub enum LedgerCall {
    Mint(u128),
}

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
pub enum LedgerEvent {
    Minted { amount: u128, total: u128 },
}

impl<S: Spec> Module for Ledger<S> {
    type Config = u128;
    type CallMessage = LedgerCall;
    type Event = LedgerEvent;
    type Error = anyhow::Error;

    fn genesis(
        &mut self,
        _header: &<<S as Spec>::Da as selendra_interface::da::DaSpec>::BlockHeader,
        config: &u128,
        state: &mut impl GenesisState<S>,
    ) -> anyhow::Result<()> {
        self.total.set(config, state)?;
        Ok(())
    }

    fn call(
        &mut self,
        message: LedgerCall,
        _context: &Context<S>,
        state: &mut impl TxState<S>,
    ) -> anyhow::Result<()> {
        let LedgerCall::Mint(amount) = message;
        let total = self
            .total
            .get(state)?
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or_else(|| anyhow::anyhow!("total overflows"))?;
        self.total.set(&total, state)?;
        self.emit_event(state, LedgerEvent::Minted { amount, total })?;
        Ok(())
    }
}

/// A derived module runs as a module: its call writes under its prefixes and emits under its
/// discriminant and name.
#[test]
fn derived_module_runs() {
    let mut ledger = Ledger::<S>::default();
    let mut state = working_set::<S>(1_000_000);
    let context = context();
    ledger
        .call(LedgerCall::Mint(5), &context, &mut state)
        .unwrap();
    ledger
        .call(LedgerCall::Mint(6), &context, &mut state)
        .unwrap();
    assert_eq!(ledger.total.get(&mut state).unwrap(), Some(11));
    let finalized = state.finalize(Ok::<(), ()>(()));
    assert!(matches!(finalized.outcome, PhaseOutcome::Committed));
    #[cfg(feature = "native")]
    {
        let [first, second] = &finalized.events[..] else {
            panic!("two events")
        };
        assert_eq!(first.module(), LEDGER);
        assert_eq!(first.key(), "ledger/Minted");
        assert_eq!(
            second.downcast_ref::<LedgerEvent>(),
            Some(&LedgerEvent::Minted {
                amount: 6,
                total: 11
            })
        );
    }
    #[cfg(not(feature = "native"))]
    assert!(finalized.events.is_empty());
}

fn context() -> Context<S> {
    let address = |byte| {
        selendra_primitives::MultiAddressEvm::Standard(selendra_primitives::Address::new(
            [byte; 28],
        ))
    };
    Context::new(
        address(1),
        Credential::Multisig(selendra_interface::crypto::CredentialId::from_bytes(
            [1; 32],
        )),
        address(2),
        selendra_modules_api::test_utils::MockAddress::new([3; 32]),
        ExecutionContext::Node,
        SequencerType::Preferred,
    )
}

// -------------------------------------------------------------------------------------------
// Hygiene: what the derive generates means the same wherever it is expanded.

/// Local items named like the crates the generated code uses, fields named like the derive's
/// own words, an odd spec name, and two modules in one Rust module (upstream
/// `hygienic_module_info.rs`).
mod shadowed {
    #![allow(dead_code, non_camel_case_types)]

    use ::selendra_modules_api::test_utils::TestSpec;
    use ::selendra_modules_api::{ModuleId, ModuleInfo, Spec, StateItem};
    use selendra_state::{Prefix, StateMap, StateValue};

    mod borsh {}
    mod core {}
    mod selendra_modules_api {}
    mod serde {}
    mod std {}
    struct Default;
    struct PhantomData;

    #[derive(Clone, ModuleInfo)]
    #[module_info(discriminant = 245, name = "module_one")]
    pub struct Module1<SpecWithWeirdNameForTesting: Spec> {
        #[id]
        pub id: ModuleId,
        #[state(item = 0)]
        pub prefix: StateMap<SpecWithWeirdNameForTesting::Address, u32>,
        #[state(item = 1)]
        pub discriminant: StateValue<u8>,
        #[state(item = 2)]
        pub state: StateValue<u8>,
        #[phantom]
        pub spec: ::core::marker::PhantomData<SpecWithWeirdNameForTesting>,
    }

    #[derive(Clone, ModuleInfo)]
    #[module_info(discriminant = 246, name = "module_two")]
    pub struct Module2<SpecWithWeirdNameForTesting: Spec> {
        #[id]
        pub id: ModuleId,
        #[state(item = 0)]
        pub prefix: StateMap<SpecWithWeirdNameForTesting::Address, u32>,
        #[module]
        pub module: Module1<SpecWithWeirdNameForTesting>,
    }

    pub(super) fn check() {
        type M1 = Module1<TestSpec>;
        type M2 = Module2<TestSpec>;
        assert_eq!(
            M1::STATE_LAYOUT,
            [
                StateItem::new(0, "prefix"),
                StateItem::new(1, "discriminant"),
                StateItem::new(2, "state"),
            ]
        );
        let two = <M2 as ::core::default::Default>::default();
        assert_eq!(two.prefix.prefix(), &Prefix::new(246, 0));
        assert_eq!(two.module.prefix.prefix(), &Prefix::new(245, 0));
        assert_eq!(two.module.state.prefix(), &Prefix::new(245, 2));
        assert_eq!(M2::DEPENDENCIES, [(245, "module_one")]);
        assert_eq!(two.id(), &ModuleId::from_name("module_two"));
    }
}

// -------------------------------------------------------------------------------------------
// Regressions of upstream's module macro bugs

/// P5-27: upstream's id was the untagged hash of `module_path!()` and the struct name, so moving
/// or renaming a module (a refactor) changed its id and every account derived from it; the id is
/// `SHA-256("SELENDRA/module-id/v1" ‖ NAME)`. Known answers computed independently (Python's
/// `hashlib.sha256`, BIP-350 bech32m).
#[test]
fn module_id_known_answer() {
    let ledger = Ledger::<S>::default();
    assert_eq!(
        ledger.id().as_bytes(),
        &[
            0xa2, 0xf8, 0x7d, 0x88, 0x05, 0x5d, 0xfe, 0x66, 0x39, 0x09, 0x57, 0xeb, 0x6a, 0x92,
            0xa0, 0x69, 0x04, 0xbd, 0xd9, 0xe0, 0xcd, 0xbc, 0x44, 0x76, 0xf9, 0x82, 0x19, 0x55,
            0xd7, 0x82, 0x7b, 0x37
        ]
    );
    assert_eq!(
        ledger.id().to_string(),
        "module_15tu8mzq9thlxvwgf2l4k4y4qdyztmk0qek7ygahesgv4t4uz0vms9q4a3h"
    );
}

mod first_path {
    use std::marker::PhantomData;

    use selendra_modules_api::{ModuleId, ModuleInfo, Spec};

    #[derive(Clone, ModuleInfo)]
    #[module_info(discriminant = 247, name = "same")]
    pub struct Same<S: Spec> {
        #[id]
        pub id: ModuleId,
        #[phantom]
        pub spec: PhantomData<S>,
    }
}

mod second_path {
    pub mod nested {
        use std::marker::PhantomData;

        use selendra_modules_api::{ModuleId, ModuleInfo, Spec};

        /// The same module, moved and renamed.
        #[derive(Clone, ModuleInfo)]
        #[module_info(discriminant = 247, name = "same")]
        pub struct Renamed<S: Spec> {
            #[id]
            pub id: ModuleId,
            #[phantom]
            pub spec: PhantomData<S>,
        }
    }
}

/// P5-27: the same name in two Rust modules, on two structs, gives the same id.
#[test]
fn module_id_independent_of_rust_path() {
    let first = first_path::Same::<S>::default();
    let second = second_path::nested::Renamed::<S>::default();
    assert_eq!(first.id(), second.id());
    assert_eq!(first.id(), &ModuleId::from_name("same"));
    assert_eq!(
        first.id().as_bytes(),
        &[
            0x29, 0x77, 0x75, 0x90, 0x9b, 0xf7, 0xb4, 0xb5, 0xc7, 0xca, 0x01, 0xd1, 0x5c, 0xbc,
            0x98, 0x05, 0xc5, 0x34, 0x59, 0xc6, 0x68, 0x79, 0x73, 0x05, 0x6f, 0x79, 0xd7, 0x1f,
            0x29, 0x15, 0x77, 0x0c
        ]
    );
}

#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 248, name = "full_byte")]
struct FullByte<S: Spec> {
    #[id]
    id: ModuleId,
    #[state(item = 255)]
    last: StateValue<u64>,
    #[state(item = 128)]
    upper: StateValue<u64>,
    #[state(item = 127)]
    lower: StateValue<u64>,
    #[state(item = 0)]
    first: StateValue<u64>,
    #[phantom]
    spec: PhantomData<S>,
}

/// P5-28: upstream numbered state items by position and refused more than 128 of them (another
/// check said 255): ids are explicit and cover the whole byte, and items on both sides of 128
/// do not collide.
#[test]
fn item_ids_cover_full_u8() {
    assert_eq!(
        FullByte::<S>::STATE_LAYOUT,
        [
            StateItem::new(0, "first"),
            StateItem::new(127, "lower"),
            StateItem::new(128, "upper"),
            StateItem::new(255, "last"),
        ]
    );
    let mut module = FullByte::<S>::default();
    assert_eq!(module.last.prefix(), &Prefix::new(248, 255));
    let mut state = working_set::<S>(1_000_000);
    for (value, item) in [
        (1, &mut module.first),
        (2, &mut module.lower),
        (3, &mut module.upper),
        (4, &mut module.last),
    ] {
        item.set(&value, &mut state).unwrap();
    }
    for (value, item) in [
        (1, &module.first),
        (2, &module.lower),
        (3, &module.upper),
        (4, &module.last),
    ] {
        assert_eq!(item.get(&mut state).unwrap(), Some(value));
    }
}

#[derive(Clone, ModuleInfo)]
#[module_info(discriminant = 249, name = "raw")]
struct Raw<S: Spec> {
    #[id]
    r#id: ModuleId,
    #[state(item = 0)]
    r#type: StateValue<u64>,
    #[state(item = 1)]
    r#match: StateValue<u64>,
    #[phantom]
    r#spec: PhantomData<S>,
}

/// P5-29: upstream built identifiers from field names (`Ident::new`), which panics on a raw
/// identifier; the derive builds none, and names items without the `r#`.
#[test]
fn raw_identifier_field_is_supported() {
    assert_eq!(
        Raw::<S>::STATE_LAYOUT,
        [StateItem::new(0, "type"), StateItem::new(1, "match")]
    );
    let module = Raw::<S>::default();
    assert_eq!(module.r#type.prefix(), &Prefix::new(249, 0));
    assert_eq!(module.r#match.prefix(), &Prefix::new(249, 1));
    assert_eq!(module.id(), &ModuleId::from_name("raw"));
}

/// P5-33 (module side): upstream's module derive named `sov_modules_api::…` without a leading
/// `::`, so a local item of that name broke it; the derive's paths start with `::` (the
/// `shadowed` module above compiles, and its modules work).
#[test]
fn derives_with_shadowed_borsh_serde() {
    shadowed::check();
}

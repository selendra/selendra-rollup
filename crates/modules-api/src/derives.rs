//! The module system's derives (`selendra-macros`), re-exported with their documentation: for
//! modules ([`ModuleInfo`], [`ModuleEvent`]), for runtimes ([`DispatchCall`], [`MessageCodec`],
//! [`Genesis`], [`Event`], [`Hooks`]) and for consensus types ([`ConsensusType`]). The code they
//! generate names only `::selendra_modules_api` (its hidden `__private` module) and `::core`.

/// Derives [`ModuleInfo`](trait@crate::ModuleInfo) and `Default` for a module struct: its
/// discriminant and name, its dependencies, its state layout, and a constructor that gives
/// every state item its prefix.
///
/// ```
/// use std::marker::PhantomData;
///
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_state::{Prefix, StateMap, StateValue};
///
/// #[derive(Clone, ModuleInfo)]
/// #[module_info(discriminant = 240, name = "ledger")]
/// pub struct Ledger<S: Spec> {
///     #[id]
///     id: ModuleId,
///     /// Item ids are explicit: fields can be reordered.
///     #[state(item = 1)]
///     balances: StateMap<S::Address, u128>,
///     #[state(item = 0)]
///     total: StateValue<u128>,
///     #[phantom]
///     spec: PhantomData<S>,
/// }
///
/// type L = Ledger<TestSpec>;
/// assert_eq!(L::DISCRIMINANT, 240);
/// assert_eq!(L::NAME, "ledger");
/// assert_eq!(L::STATE_LAYOUT, [StateItem::new(0, "total"), StateItem::new(1, "balances")]);
/// let ledger = L::default();
/// assert_eq!(ledger.id(), &ModuleId::from_name("ledger"));
/// assert_eq!(ledger.total.prefix(), &Prefix::new(240, 0));
/// assert_eq!(ledger.balances.prefix(), &Prefix::new(240, 1));
/// ```
///
/// # Attributes
/// - On the struct, once: `#[module_info(discriminant = N, name = "…")]`.
///   - `discriminant`: an integer literal in 1..=255 (`0` is reserved), the
///     [`DISCRIMINANT`](crate::ModuleInfo::DISCRIMINANT): the first byte of the prefix of every
///     state item, and the tag of the module's calls and events. Ranges:
///     `docs/serialization.md`, "Module discriminants".
///   - `name`: `^[a-z][a-z0-9_]{0,31}$`, the [`NAME`](crate::ModuleInfo::NAME), which the
///     module's [`ModuleId`](crate::ModuleId) is derived from.
/// - On each field, exactly one of:
///   - `#[id]`, on exactly one field, a [`ModuleId`](crate::ModuleId):
///     `ModuleId::from_name(NAME)`, returned by [`id`](crate::ModuleInfo::id). It depends on
///     the name only: moving or renaming the struct does not change it.
///   - `#[state(item = N)]`, N an integer literal in 0..=255, unique within the module: a state
///     container (`StateValue`, `StateMap`, `StateVec`, in any namespace) under the prefix
///     `(DISCRIMINANT, N)`, built with `with_codec(prefix, Default::default())`;
///     `#[state(item = N, codec = path)]` builds the codec with `path()` instead. Listed in
///     [`STATE_LAYOUT`](crate::ModuleInfo::STATE_LAYOUT) by item id. A field removed (or
///     `#[cfg]`'d out) leaves its id unused instead of moving every later item.
///   - `#[module]`: a module this one holds and calls, with the same spec, built with its
///     `Default`. Its `(DISCRIMINANT, NAME)` is listed in
///     [`DEPENDENCIES`](crate::ModuleInfo::DEPENDENCIES), in field order;
///     [`dependencies`](crate::ModuleInfo::dependencies) is computed from them.
///   - `#[phantom]`: a `PhantomData`.
///
///   Other attributes (doc comments, `#[allow]`, other derives' attributes) are left alone.
/// - The first generic parameter is the module's spec ([`Spec`](crate::ModuleInfo::Spec)).
///
/// Anything else is a compile error at the offending input: an enum, a union or a tuple struct;
/// a struct without a type as its first generic parameter; a missing, repeated or malformed
/// `#[module_info]`, discriminant 0, an invalid name; a key other than these inside the
/// attributes; a field with none or several of the field attributes; no or two `#[id]` fields;
/// an item id outside 0..=255 or used twice; a `#[state]` field whose type is not a path.
///
/// The derive implements `Default` too: build the module with it (a struct literal could give
/// it another id), and do not implement `Default` yourself (E0119).
///
/// A `#[module]` field runs with the module's spec (E0271 otherwise):
///
/// ```compile_fail,E0271
/// use std::marker::PhantomData;
///
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
///
/// #[derive(Clone, ModuleInfo)]
/// #[module_info(discriminant = 241, name = "inner")]
/// pub struct Inner<S: Spec> {
///     #[id]
///     id: ModuleId,
///     #[phantom]
///     spec: PhantomData<S>,
/// }
///
/// #[derive(Clone, ModuleInfo)]
/// #[module_info(discriminant = 242, name = "outer")]
/// pub struct Outer<S: Spec> {
///     #[id]
///     id: ModuleId,
///     #[module]
///     inner: Inner<TestSpec>,
///     #[phantom]
///     spec: PhantomData<S>,
/// }
/// ```
///
/// ```
/// use std::marker::PhantomData;
///
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
///
/// #[derive(Clone, ModuleInfo)]
/// #[module_info(discriminant = 241, name = "inner")]
/// pub struct Inner<S: Spec> {
///     #[id]
///     id: ModuleId,
///     #[phantom]
///     spec: PhantomData<S>,
/// }
///
/// #[derive(Clone, ModuleInfo)]
/// #[module_info(discriminant = 242, name = "outer")]
/// pub struct Outer<S: Spec> {
///     #[id]
///     id: ModuleId,
///     #[module]
///     inner: Inner<S>,
/// }
///
/// assert_eq!(Outer::<TestSpec>::DEPENDENCIES, [(241, "inner")]);
/// ```
///
/// Upstream read the discriminant from `constants.toml` under a key made from the struct's
/// name (P5-26), numbered state items by position with two different limits (P5-28), hashed
/// the id from the Rust path and the struct name (P5-27), and panicked on raw identifiers
/// (P5-29) and on an attribute it accepted but did not handle (P5-30).
pub use selendra_macros::ModuleInfo;

/// Derives [`ModuleEvent`](trait@crate::ModuleEvent) for a module's event enum: each event's
/// name is its variant's name (without `r#`), whatever its `Debug` output.
///
/// ```
/// use selendra_modules_api::*;
///
/// #[derive(Debug, ModuleEvent)]
/// enum BankEvent {
///     Transfer { amount: u128 },
///     Burned(u128),
///     Paused,
/// }
///
/// assert_eq!(BankEvent::Transfer { amount: 1 }.event_name(), "Transfer");
/// assert_eq!(BankEvent::Burned(1).event_name(), "Burned");
/// assert_eq!(BankEvent::Paused.event_name(), "Paused");
/// ```
///
/// An event is emitted with the key `"{module NAME}/{event name}"`
/// ([`EventEmitter`](crate::EventEmitter)), of at most
/// [`MAX_EVENT_KEY_LEN`](crate::MAX_EVENT_KEY_LEN) (256) bytes, or the call is reverted. Module
/// names are at most [`MAX_MODULE_NAME_LEN`](crate::MAX_MODULE_NAME_LEN) (32) bytes, so a
/// variant name of more than [`MAX_EVENT_NAME_LEN`](crate::MAX_EVENT_NAME_LEN) (223) bytes is
/// a compile error: a derived key always fits. Structs and unions are compile errors too.
pub use selendra_macros::ModuleEvent;

/// Derives [`ConsensusType`](trait@crate::ConsensusType) for a struct or enum whose fields are
/// all consensus types: no `usize`, `isize`, `f32`, `f64`, `HashMap` or `HashSet` at any
/// depth (`docs/serialization.md`, "Consensus types").
///
/// By default the impl is bounded by the field types, not by the generic parameters: a generic
/// type is a consensus type for the parameters that make its fields consensus types, and a
/// `PhantomData<S>` field bounds nothing. A field whose type has no generic parameter is
/// checked where the type is defined; one that has is checked where the type is used with
/// concrete parameters (as a state value, a call message, an event, …). The check sees through
/// type aliases and nested types. `#[consensus_type(bound(…))]` gives the bounds instead (for
/// generic types that hold each other; below).
///
/// ```
/// use std::collections::BTreeMap;
/// use std::marker::PhantomData;
///
/// use selendra_modules_api::*;
///
/// type Balance = u128;
///
/// #[derive(ConsensusType)]
/// struct Account {
///     balance: Balance,
///     tags: BTreeMap<u8, String>,
/// }
///
/// #[derive(ConsensusType)]
/// enum Entry<T> {
///     Account(Account),
///     Value { value: T, next: Option<Box<Entry<T>>> },
///     Empty(PhantomData<f64>),
/// }
///
/// fn stored<T: ConsensusType>() {}
/// stored::<Account>();
/// stored::<Entry<u64>>();
/// ```
///
/// Each of these fails with E0277: a `usize` field, a field of an alias to `f64`, a nested type
/// holding a `HashMap`, a generic type used with `usize`, an enum with an `f64` field in a later
/// variant, and a generic enum whose parameter is only in a later variant, used with `usize`:
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
///
/// #[derive(ConsensusType)]
/// struct Stored {
///     len: usize,
/// }
/// ```
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
///
/// type Ratio = f64;
///
/// #[derive(ConsensusType)]
/// struct Price {
///     ratio: Ratio,
/// }
/// ```
///
/// ```compile_fail,E0277
/// use std::collections::HashMap;
///
/// use selendra_modules_api::*;
///
/// #[derive(ConsensusType)]
/// struct Inner<M> {
///     map: M,
/// }
///
/// #[derive(ConsensusType)]
/// struct Outer {
///     inner: Inner<HashMap<u8, u8>>,
/// }
/// ```
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
///
/// #[derive(ConsensusType)]
/// struct Wrapper<T> {
///     value: T,
/// }
///
/// fn stored<T: ConsensusType>() {}
/// stored::<Wrapper<usize>>();
/// ```
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
///
/// #[derive(ConsensusType)]
/// enum Call {
///     Pay(u64),
///     Rate { ratio: f64 },
/// }
/// ```
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
///
/// #[derive(ConsensusType)]
/// enum Slot<T> {
///     Empty,
///     Value(T),
/// }
///
/// fn stored<T: ConsensusType>() {}
/// stored::<Slot<usize>>();
/// ```
///
/// With `u64`, `u64`, a `BTreeMap`, `u64`, `u64` and `u64`, they compile:
///
/// ```
/// use std::collections::BTreeMap;
///
/// use selendra_modules_api::*;
///
/// #[derive(ConsensusType)]
/// struct Stored {
///     len: u64,
/// }
///
/// type Ratio = u64;
///
/// #[derive(ConsensusType)]
/// struct Price {
///     ratio: Ratio,
/// }
///
/// #[derive(ConsensusType)]
/// struct Inner<M> {
///     map: M,
/// }
///
/// #[derive(ConsensusType)]
/// struct Outer {
///     inner: Inner<BTreeMap<u8, u8>>,
/// }
///
/// #[derive(ConsensusType)]
/// struct Wrapper<T> {
///     value: T,
/// }
///
/// #[derive(ConsensusType)]
/// enum Call {
///     Pay(u64),
///     Rate { ratio: u64 },
/// }
///
/// #[derive(ConsensusType)]
/// enum Slot<T> {
///     Empty,
///     Value(T),
/// }
///
/// fn stored<T: ConsensusType>() {}
/// stored::<Stored>();
/// stored::<Price>();
/// stored::<Outer>();
/// stored::<Wrapper<u64>>();
/// stored::<Call>();
/// stored::<Slot<u64>>();
/// ```
///
/// Unions are a compile error.
///
/// # Generic types that hold each other: `#[consensus_type(bound(…))]`
///
/// The inferred bounds cannot describe two generic types holding each other (`A<T>` holding a
/// `B<T>` holding an `A<T>`): `A`'s impl requires `B`'s field type to be a consensus type and
/// `B`'s requires `A`'s, so the trait solver loops where they are used (E0275):
///
/// ```compile_fail,E0275
/// use selendra_modules_api::*;
///
/// #[derive(ConsensusType)]
/// struct Forest<T> {
///     groves: Vec<Grove<T>>,
///     value: T,
/// }
///
/// #[derive(ConsensusType)]
/// struct Grove<T> {
///     forest: Option<Box<Forest<T>>>,
/// }
///
/// fn stored<T: ConsensusType>() {}
/// stored::<Forest<u64>>();
/// ```
///
/// The container attribute `#[consensus_type(bound(PRED, …))]` replaces the inferred bounds by
/// the given `where` predicates (unquoted; `bound()` gives none): the impl's `where` clause is
/// the type's own plus exactly those. Every field type, generic or not, is then checked where
/// the type is defined, under exactly those bounds. So the attribute can make the impl apply
/// to more or fewer types than the inferred bounds (`bound()` on a type with a `PhantomData<T>`
/// and an `Option<Box<Self>>` field drops the `T: ConsensusType` the recursive field would
/// infer), but never to a type whose fields are not consensus types. On one of the two types
/// (or both), `bound(T: ConsensusType)` breaks the cycle:
///
/// ```
/// use selendra_modules_api::*;
///
/// #[derive(ConsensusType)]
/// #[consensus_type(bound(T: ConsensusType))]
/// struct Forest<T> {
///     groves: Vec<Grove<T>>,
///     value: T,
/// }
///
/// #[derive(ConsensusType)]
/// struct Grove<T> {
///     forest: Option<Box<Forest<T>>>,
/// }
///
/// fn stored<T: ConsensusType>() {}
/// stored::<Forest<u64>>();
/// stored::<Grove<u64>>();
/// ```
///
/// Predicates may name projections (`bound(S::Address: ConsensusType)`) and any other bound.
/// The attribute goes on the type, once, with one `bound`; on a type without type parameters it
/// is an error (no bound is inferred there: every field is checked where the type is defined).
///
/// Each of these fails with E0277: a field the bounds do not make a consensus type (`bound()`
/// with a `T` field fails where the type is defined), and the attributed pair used with
/// `usize`:
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
///
/// #[derive(ConsensusType)]
/// #[consensus_type(bound())]
/// struct Wrapper<T>(T);
/// ```
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
///
/// #[derive(ConsensusType)]
/// #[consensus_type(bound(T: ConsensusType))]
/// struct Forest<T> {
///     groves: Vec<Grove<T>>,
///     value: T,
/// }
///
/// #[derive(ConsensusType)]
/// struct Grove<T> {
///     forest: Option<Box<Forest<T>>>,
/// }
///
/// fn stored<T: ConsensusType>() {}
/// stored::<Forest<usize>>();
/// ```
///
/// With `bound(T: ConsensusType)` and with `u64`, they compile:
///
/// ```
/// use selendra_modules_api::*;
///
/// #[derive(ConsensusType)]
/// #[consensus_type(bound(T: ConsensusType))]
/// struct Wrapper<T>(T);
///
/// #[derive(ConsensusType)]
/// #[consensus_type(bound(T: ConsensusType))]
/// struct Forest<T> {
///     groves: Vec<Grove<T>>,
///     value: T,
/// }
///
/// #[derive(ConsensusType)]
/// struct Grove<T> {
///     forest: Option<Box<Forest<T>>>,
/// }
///
/// fn stored<T: ConsensusType>() {}
/// stored::<Wrapper<u64>>();
/// stored::<Forest<u64>>();
/// ```
///
/// The derive does not check that `BorshSerialize` never fails, nor that every encoding
/// decodes (`docs/serialization.md`): those stay review rules.
pub use selendra_macros::ConsensusType;

/// Derives [`DispatchCall`](trait@crate::DispatchCall) for a runtime, and generates its call
/// type `{Runtime}Call`.
///
/// A runtime is a struct with named fields, generic over its spec first (other generic
/// parameters are allowed), each field a module running with that spec. The runtime derives
/// (this one, [`MessageCodec`](macro@crate::MessageCodec), [`Genesis`](macro@crate::Genesis),
/// [`Event`](macro@crate::Event), [`Hooks`](macro@crate::Hooks)) take no attributes; the other
/// four need this one's impl (its layout check, below).
///
/// Below, `Bank` (discriminant 240, name `bank`) and `Accounts` (241, `accounts`, holding a
/// `Bank`) are modules taking `u8` calls (hidden):
///
/// ```
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// # module!(Accounts, 241, "accounts", Bank);
/// #[derive(Clone, Default, DispatchCall, MessageCodec, Genesis, Event, Hooks)]
/// pub struct Runtime<S: Spec> {
///     pub accounts: Accounts<S>,
///     pub bank: Bank<S>,
/// }
///
/// type Rt = Runtime<TestSpec>;
/// type Call = RuntimeCall<TestSpec>;
///
/// // borsh: the module's discriminant, then its call message (not the field's position).
/// assert_eq!(Rt::encode(&Call::Bank(7)).unwrap(), [240, 7]);
/// assert_eq!(<Rt as EncodeCall<Bank<TestSpec>>>::encode_call(7).unwrap(), [240, 7]);
/// assert_eq!(Rt::decode(&[241, 7]).unwrap(), Call::Accounts(7));
/// assert!(Rt::decode(&[0, 7]).is_err()); // no module has the tag
/// assert!(Rt::decode(&[240, 7, 0]).is_err()); // trailing bytes
///
/// // JSON: keyed by the module's name.
/// assert_eq!(serde_json::to_string(&Call::Bank(7)).unwrap(), r#"{"bank":7}"#);
/// assert_eq!(Call::Bank(7).module_name(), "bank");
///
/// let runtime = Rt::default();
/// assert_eq!(runtime.module_id(&Call::Bank(7)), runtime.bank.id());
/// assert_eq!(Rt::MODULES, [ModuleDescriptor::of::<Accounts<TestSpec>>(), ModuleDescriptor::of::<Bank<TestSpec>>()]);
/// assert_eq!(Rt::validate_layout(), Ok(()));
/// ```
///
/// # Generated
/// - At the call site, with the runtime's visibility and generic parameters, `{Runtime}Call`
///   (`RuntimeCall` above): an enum with one variant per module, named after the field in
///   `PascalCase` (`sequencer_registry` → `SequencerRegistry`, without `r#`), holding the
///   module's `CallMessage`. Its encodings (`docs/serialization.md`, "Runtimes"):
///   - borsh: the module's [`DISCRIMINANT`](crate::ModuleInfo::DISCRIMINANT), then the
///     message, so adding, removing or reordering modules changes no call's encoding (upstream
///     tagged by field position, P5-25); a tag that is no module's is an error;
///   - serde: externally tagged by the module's [`NAME`](crate::ModuleInfo::NAME)
///     (`{"bank": 7}`; another key, two keys or none are errors); in binary serde formats the
///     variant index is the discriminant;
///   - a JSON schema, `ConsensusType` (derived), [`ModuleMessage`](crate::ModuleMessage)
///     (upstream's strum enums), `Debug`, `Clone`, `PartialEq`, `Eq`.
/// - `DispatchCall`: [`MODULES`](crate::DispatchCall::MODULES) (each module's
///   [`ModuleDescriptor`](crate::ModuleDescriptor), in field order), `dispatch_call` (the
///   module's [`Module::call`](crate::Module::call), called fully qualified, its error returned
///   unchanged as a [`ModuleError`](crate::ModuleError)) and `module_id`. Upstream's
///   `module_info` is not generated (`ModuleInfo` is not object safe).
///
/// The impls are in an anonymous constant; every path they use is
/// `::selendra_modules_api::__private::…` or `::core::…` (trait methods called fully
/// qualified, primitive types as `::core::primitive::…`), so local items named like a crate
/// (`mod borsh {}`), a prelude item or a primitive type (`struct u8;`) do not change them, the
/// derives work under `#![no_implicit_prelude]`, and two runtimes can share a Rust module
/// (upstream generated fixed names: P5-33). The generated methods' generic parameters are
/// named unlike anything the runtime's generics, where clause and module types name.
///
/// # Errors
/// At compile time, spanned at the input: an enum, a union, a tuple or unit struct, no generic
/// parameter or a lifetime or const one first, no field, two fields with the same variant name
/// (`foo_bar` and `foo__bar`), a field whose `PascalCase` is not an identifier (`self_`). A
/// field that is not a module, or runs with another spec (E0271), fails to compile.
///
/// # The layout check
/// The runtime's modules follow the layout rules ([`check_layout`](crate::check_layout)): no
/// discriminant `0`, no two modules with one discriminant or one name, and every module's
/// [`DEPENDENCIES`](crate::ModuleInfo::DEPENDENCIES) (the modules it holds) modules of the
/// runtime with exactly that discriminant and name (upstream checked only that the runtime's own
/// modules had distinct discriminants, and only at genesis: P5-25). Only the pairs are compared,
/// not the types: a held module of another type that declares a runtime module's discriminant
/// and name is not detected (see [`check_layout`](crate::check_layout)). The derived codecs
/// (borsh and serde, both ways), the JSON schema, `module_discriminant`/`module_name`, dispatch,
/// `EncodeCall`, genesis and its configuration's codecs, event mapping and hooks evaluate
/// [`DispatchCall`](trait@crate::DispatchCall)'s layout check, a constant: instantiating the
/// runtime with modules that break the rules is a compile error (E0080) naming the rule. It is
/// evaluated in builds that generate code (`cargo build`, `cargo test`, doctests), not by
/// `cargo check` or clippy, which do not evaluate the constants of generic code; a concrete
/// runtime adds `const _: () = Runtime::<…>::__CHECK_LAYOUT;`, which they evaluate. Genesis
/// checks the rules again at run time, and so does
/// [`validate_layout`](crate::DispatchCall::validate_layout) (the node at startup).
///
/// Each of these fails with E0080: two modules with one discriminant, two with one name (also
/// when the program only encodes a call to JSON, or asks a call for its module's name), a
/// module holding a module the runtime does not have, and a hand-written module with the
/// discriminant `0` (the module derive rejects it):
///
/// ```compile_fail,E0080
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// # module!(Vault, 240, "vault");
/// // `Bank` and `Vault` both have the discriminant 240 (hidden).
/// #[derive(DispatchCall)]
/// pub struct Runtime<S: Spec> {
///     pub bank: Bank<S>,
///     pub vault: Vault<S>,
/// }
///
/// fn main() {
///     let _ = Runtime::<TestSpec>::decode(&[240, 7]);
/// }
/// ```
///
/// ```compile_fail,E0080
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// # module!(OtherBank, 241, "bank");
/// // `Bank` (240) and `OtherBank` (241) are both named `bank` (hidden).
/// #[derive(DispatchCall)]
/// pub struct Runtime<S: Spec> {
///     pub bank: Bank<S>,
///     pub other_bank: OtherBank<S>,
/// }
///
/// fn main() {
///     let _ = Runtime::<TestSpec>::decode(&[240, 7]);
/// }
/// ```
///
/// Encoding a call to JSON is enough (the same runtime, hidden):
///
/// ```compile_fail,E0080
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// # module!(OtherBank, 241, "bank");
/// # #[derive(DispatchCall)]
/// # pub struct Runtime<S: Spec> {
/// #     pub bank: Bank<S>,
/// #     pub other_bank: OtherBank<S>,
/// # }
/// fn main() {
///     let _ = serde_json::to_string(&RuntimeCall::<TestSpec>::OtherBank(7));
/// }
/// ```
///
/// So is asking a call for its module's name:
///
/// ```compile_fail,E0080
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// # module!(OtherBank, 241, "bank");
/// # #[derive(DispatchCall)]
/// # pub struct Runtime<S: Spec> {
/// #     pub bank: Bank<S>,
/// #     pub other_bank: OtherBank<S>,
/// # }
/// fn main() {
///     let _ = RuntimeCall::<TestSpec>::OtherBank(7).module_name();
/// }
/// ```
///
/// ```compile_fail,E0080
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// # module!(Accounts, 241, "accounts", Bank);
/// // `Accounts` holds a `Bank` (hidden), which the runtime does not have.
/// #[derive(DispatchCall)]
/// pub struct Runtime<S: Spec> {
///     pub accounts: Accounts<S>,
/// }
///
/// fn main() {
///     let _ = Runtime::<TestSpec>::decode(&[241, 7]);
/// }
/// ```
///
/// ```compile_fail,E0080
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// #[derive(Clone)]
/// pub struct Zero<S>(ModuleId, PhantomData<S>);
///
/// impl<S: Spec> ModuleInfo for Zero<S> {
///     type Spec = S;
///     const DISCRIMINANT: u8 = 0;
///     const NAME: &'static str = "zero";
///     const DEPENDENCIES: &'static [(u8, &'static str)] = &[];
///     const STATE_LAYOUT: &'static [StateItem] = &[];
///     fn id(&self) -> &ModuleId {
///         &self.0
///     }
/// }
/// # impl<S: Spec> Module for Zero<S> {
/// #     type Config = ();
/// #     type CallMessage = u8;
/// #     type Event = NotInstantiable;
/// #     type Error = anyhow::Error;
/// #     fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #         Ok(())
/// #     }
/// # }
///
/// #[derive(DispatchCall)]
/// pub struct Runtime<S: Spec> {
///     pub bank: Bank<S>,
///     pub zero: Zero<S>,
/// }
///
/// fn main() {
///     let _ = Runtime::<TestSpec>::decode(&[240, 7]);
/// }
/// ```
///
/// With distinct discriminants and names, the held module in the runtime, and a discriminant
/// other than `0`, it compiles:
///
/// ```
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// # module!(Vault, 242, "vault");
/// # module!(Accounts, 241, "accounts", Bank);
/// #[derive(Clone)]
/// pub struct One<S>(ModuleId, PhantomData<S>);
///
/// impl<S: Spec> ModuleInfo for One<S> {
///     type Spec = S;
///     const DISCRIMINANT: u8 = 1;
///     const NAME: &'static str = "one";
///     const DEPENDENCIES: &'static [(u8, &'static str)] = &[];
///     const STATE_LAYOUT: &'static [StateItem] = &[];
///     fn id(&self) -> &ModuleId {
///         &self.0
///     }
/// }
/// # impl<S: Spec> Module for One<S> {
/// #     type Config = ();
/// #     type CallMessage = u8;
/// #     type Event = NotInstantiable;
/// #     type Error = anyhow::Error;
/// #     fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #         Ok(())
/// #     }
/// # }
///
/// #[derive(DispatchCall)]
/// pub struct Runtime<S: Spec> {
///     pub bank: Bank<S>,
///     pub vault: Vault<S>,
///     pub accounts: Accounts<S>,
///     pub one: One<S>,
/// }
///
/// fn main() {
///     let _ = Runtime::<TestSpec>::decode(&[240, 7]);
///     let _ = serde_json::to_string(&RuntimeCall::<TestSpec>::Vault(7));
///     let _ = RuntimeCall::<TestSpec>::Vault(7).module_name();
/// }
/// ```
pub use selendra_macros::DispatchCall;

/// Derives [`EncodeCall<M>`](crate::EncodeCall) for a runtime, for each of its modules `M`:
/// a module's call message as the runtime's call (`{Runtime}Call`, generated by
/// [`DispatchCall`](macro@crate::DispatchCall)'s derive, which this one needs).
///
/// ```
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// #[derive(DispatchCall, MessageCodec)]
/// pub struct Runtime<S: Spec> {
///     pub bank: Bank<S>,
/// }
///
/// type Rt = Runtime<TestSpec>;
/// assert_eq!(<Rt as EncodeCall<Bank<TestSpec>>>::to_decodable(7), RuntimeCall::Bank(7));
/// assert_eq!(<Rt as EncodeCall<Bank<TestSpec>>>::encode_call(7).unwrap(), [240, 7]);
/// ```
///
/// Two fields of one module type conflict (E0119); they would break the layout rules anyway.
pub use selendra_macros::MessageCodec;

/// Derives [`Genesis`](trait@crate::Genesis) for a runtime, and generates its genesis
/// configuration type `{Runtime}GenesisConfig`.
///
/// `{Runtime}GenesisConfig` (at the call site, with the runtime's visibility and generic
/// parameters) has one field per module, named like the runtime's field, holding the module's
/// [`Config`](crate::Module::Config). Its JSON is an object with exactly these fields, each
/// once: an unknown, duplicate or missing field is an error, also a missing field whose
/// configuration is an `Option` (write `null` for `None`; serde's derive would read a missing
/// `Option` as `None`), and so is an array. In binary serde formats, the fields in order. Its
/// serde impls are written out by the derive (not serde's derive, which names primitive types
/// unqualified and takes bounds as strings, so `$crate::…` module types failed to parse);
/// serde, `Debug`, `Clone` and `PartialEq` are implemented where the modules' configurations
/// implement them.
///
/// The runtime's genesis checks the layout rules (at compile time like every runtime derive,
/// see [`DispatchCall`](macro@crate::DispatchCall), whose derive this one needs; and again at
/// run time), then runs each module's genesis, every module after the modules it depends on
/// ([`sort_values_by_modules_dependencies`](crate::sort_values_by_modules_dependencies): a
/// cycle is an error), otherwise in field order. The first error is returned (and the caller
/// reverts the genesis state). No module is special (upstream required a `chain_state` field).
///
/// ```
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// # module!(Accounts, 241, "accounts", Bank);
/// // `Accounts` holds a `Bank`: the bank's genesis runs first.
/// #[derive(DispatchCall, Genesis)]
/// pub struct Runtime<S: Spec> {
///     pub accounts: Accounts<S>,
///     pub bank: Bank<S>,
/// }
///
/// let config: RuntimeGenesisConfig<TestSpec> =
///     serde_json::from_str(r#"{"accounts": 1, "bank": 2}"#).unwrap();
/// assert_eq!(config, RuntimeGenesisConfig { accounts: 1, bank: 2 });
/// // A missing field, an unknown one, are errors.
/// assert!(serde_json::from_str::<RuntimeGenesisConfig<TestSpec>>(r#"{"accounts": 1}"#).is_err());
/// assert!(
///     serde_json::from_str::<RuntimeGenesisConfig<TestSpec>>(r#"{"accounts": 1, "bank": 2, "chain_state": 3}"#)
///         .is_err()
/// );
/// ```
pub use selendra_macros::Genesis;

/// Derives [`RuntimeEventProcessor`](crate::RuntimeEventProcessor) for a runtime, and
/// generates its event type `{Runtime}Event`.
///
/// `{Runtime}Event` (at the call site, with the runtime's visibility and generic parameters)
/// has one variant per module, named like `{Runtime}Call`'s, holding the module's
/// [`Event`](crate::Module::Event), with the same encodings (borsh: the module's discriminant,
/// then the event; serde: keyed by the module's name, where upstream's was `untagged`, P5-32),
/// a JSON schema, `ConsensusType`, [`ModuleMessage`](crate::ModuleMessage), `Debug`, `Clone`
/// and `PartialEq`.
///
/// An emitted event ([`TypeErasedEvent`](crate::TypeErasedEvent)) maps to the variant of the
/// module whose discriminant it carries, if its type is that module's event type: two modules
/// emitting one event type are told apart (upstream matched the `TypeId`, so the first such
/// module got them all, P5-32). This derive needs [`DispatchCall`](macro@crate::DispatchCall)'s.
///
/// ```
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// #[derive(DispatchCall, Event)]
/// pub struct Runtime<S: Spec> {
///     pub bank: Bank<S>,
/// }
///
/// // `Bank` emits no events (`NotInstantiable`): a `u8` under its discriminant maps to nothing.
/// let event = TypeErasedEvent::new(240, "bank/Minted", 7u8);
/// assert_eq!(Runtime::<TestSpec>::convert_to_runtime_event(event), None);
/// ```
pub use selendra_macros::Event;

/// Derives [`TxHooks`](crate::TxHooks), [`BlockHooks`](crate::BlockHooks) and
/// [`FinalizeHook`](crate::FinalizeHook) for a runtime: each hook calls every module's hook
/// (the [`Module`](crate::Module) provided methods), in field order, fully qualified
/// (`<M as Module>::begin_rollup_block_hook(&mut self.field, …)`). So the module's own hook
/// always runs: never an inherent method of the same name, nor a fallback (upstream's
/// `(&mut self.field).hook(…)` could pick either, P5-31). A transaction hook's first error is
/// returned unchanged (as a [`ModuleError`](crate::ModuleError)), and the later modules' hooks
/// do not run. This derive needs [`DispatchCall`](macro@crate::DispatchCall)'s.
///
/// ```
/// # use std::marker::PhantomData;
/// # use selendra_modules_api::*;
/// # use selendra_modules_api::test_utils::TestSpec;
/// # macro_rules! module {
/// #     ($module:ident, $discriminant:tt, $name:tt $(, $dependency:ident)?) => {
/// #         #[derive(Clone, ModuleInfo)]
/// #         #[module_info(discriminant = $discriminant, name = $name)]
/// #         pub struct $module<S: Spec> {
/// #             #[id]
/// #             pub id: ModuleId,
/// #             $(#[module] pub dependency: $dependency<S>,)?
/// #             #[phantom]
/// #             spec: ::core::marker::PhantomData<S>,
/// #         }
/// #         impl<S: Spec> Module for $module<S> {
/// #             type Config = u8;
/// #             type CallMessage = u8;
/// #             type Event = NotInstantiable;
/// #             type Error = anyhow::Error;
/// #             fn call(&mut self, _: u8, _: &Context<S>, _: &mut impl TxState<S>) -> anyhow::Result<()> {
/// #                 Ok(())
/// #             }
/// #         }
/// #     };
/// # }
/// # module!(Bank, 240, "bank");
/// #[derive(DispatchCall, Hooks)]
/// pub struct Runtime<S: Spec> {
///     pub bank: Bank<S>,
/// }
///
/// fn runtime<R: TxHooks + BlockHooks + FinalizeHook>() {}
/// runtime::<Runtime<TestSpec>>();
/// ```
pub use selendra_macros::Hooks;

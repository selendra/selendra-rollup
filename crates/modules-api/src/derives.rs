//! The module system's derives (`selendra-macros`), re-exported with their documentation. The
//! code they generate names only `::selendra_modules_api` (its hidden `__private` module) and
//! `::core`.

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
/// The impl is bounded by the field types, not by the generic parameters: a generic type is a
/// consensus type for the parameters that make its fields consensus types, and a
/// `PhantomData<S>` field bounds nothing. A field whose type has no generic parameter is
/// checked where the type is defined; one that has is checked where the type is used with
/// concrete parameters (as a state value, a call message, an event, …). The check sees through
/// type aliases and nested types.
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
/// Unions are a compile error. Two generic types holding each other (`A<T>` holding a `B<T>`
/// holding an `A<T>`) make the trait solver loop where they are used (E0275).
///
/// The derive does not check that `BorshSerialize` never fails, nor that every encoding
/// decodes (`docs/serialization.md`): those stay review rules.
pub use selendra_macros::ConsensusType;

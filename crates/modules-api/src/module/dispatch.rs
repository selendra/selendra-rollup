//! How a runtime routes calls to its modules: [`DispatchCall`], [`EncodeCall`] and
//! [`ModuleMessage`].

use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::ConsensusType;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{Context, Module, Spec};
use crate::{LayoutError, ModuleDescriptor, ModuleError, ModuleId, TxState, check_layout};

/// A runtime-level message, a runtime's call or event: one module's message, tagged with that
/// module. Implemented by the runtime's call and event types (derived; upstream used strum's
/// discriminant enums and variant names instead).
pub trait ModuleMessage {
    /// The [`DISCRIMINANT`](crate::ModuleInfo::DISCRIMINANT) of the module the message belongs
    /// to: its tag in the borsh encoding.
    fn module_discriminant(&self) -> u8;

    /// The [`NAME`](crate::ModuleInfo::NAME) of that module: its key in JSON.
    fn module_name(&self) -> &'static str;
}

/// A runtime: decodes calls and dispatches each to its module. Implemented by the runtime's
/// derive.
///
/// The runtime's call type ([`Decodable`](Self::Decodable)) is tagged with the module's
/// [`DISCRIMINANT`](crate::ModuleInfo::DISCRIMINANT) in borsh (not the module's position in
/// the runtime, so adding, removing or reordering modules changes no call's encoding) and keyed
/// by the module's [`NAME`](crate::ModuleInfo::NAME) in JSON. It is signed, so it is a
/// consensus type.
///
/// # Layout
/// The runtime's modules ([`MODULES`](Self::MODULES)) must follow the layout rules
/// ([`check_layout`]: no discriminant `0`, no two modules with one discriminant or one name,
/// every dependency a module of the runtime with its discriminant and name). The derive checks
/// them at compile time wherever the runtime is used: its call and event codecs, its dispatch,
/// genesis and hooks evaluate the hidden constant `__CHECK_LAYOUT`, which fails to compile
/// (E0080, with the rule broken) when the runtime is instantiated with modules that break them.
/// That happens in every build that generates code (`cargo build`, `cargo test`, doctests),
/// not under `cargo check` or clippy, which do not evaluate constants of generic code; a
/// concrete runtime also adds `const _: () = Runtime::<…>::__CHECK_LAYOUT;`, which they do
/// evaluate (Phase 8). Genesis checks them again at run time, and so does the node at startup
/// ([`validate_layout`](Self::validate_layout)): an upgrade does not rerun genesis.
pub trait DispatchCall: Send + Sync {
    /// The spec.
    type Spec: Spec;

    /// The runtime's modules ([`ModuleDescriptor::of`] each), in the order of its fields.
    const MODULES: &'static [ModuleDescriptor];

    /// The compile-time layout check: evaluating it fails to compile (E0080) if
    /// [`MODULES`](Self::MODULES) break the layout rules.
    #[doc(hidden)]
    const __CHECK_LAYOUT: () = crate::layout::assert_layout(Self::MODULES);

    /// The runtime's call type: a call of one of its modules.
    type Decodable: ModuleMessage
        + ConsensusType
        + BorshSerialize
        + BorshDeserialize
        + Serialize
        + DeserializeOwned
        + Debug
        + Clone
        + PartialEq
        + Eq
        + Send
        + Sync;

    /// The borsh encoding of `call`.
    ///
    /// # Errors
    /// If a call message's `BorshSerialize` fails (which consensus types must never do).
    fn encode(call: &Self::Decodable) -> Result<Vec<u8>, borsh::io::Error> {
        borsh::to_vec(call)
    }

    /// Decodes a call from exactly `bytes` (`borsh::from_slice`: trailing bytes are an error,
    /// so a call has one encoding). Unmetered: the authenticator decodes transactions, calls
    /// included, with metered decoding.
    ///
    /// # Errors
    /// If `bytes` is not exactly the encoding of a call (an unknown module tag included).
    fn decode(bytes: &[u8]) -> Result<Self::Decodable, borsh::io::Error> {
        borsh::from_slice(bytes)
    }

    /// Runs `call` on its module ([`Module::call`]), with `state` (generic: any
    /// [`TxState`]) and `context`.
    ///
    /// # Errors
    /// The module's error, unchanged (as a [`ModuleError`]). The call's writes and events are
    /// then dropped (also if a state access failed and the module returned `Ok`).
    fn dispatch_call<T: TxState<Self::Spec>>(
        &mut self,
        call: Self::Decodable,
        state: &mut T,
        context: &Context<Self::Spec>,
    ) -> Result<(), ModuleError>;

    /// The id of the module `call` goes to.
    fn module_id(&self, call: &Self::Decodable) -> &ModuleId;

    /// Checks the runtime's layout ([`check_layout`] of [`MODULES`](Self::MODULES)) at run
    /// time: genesis does, and the node at startup (an upgrade does not rerun genesis).
    ///
    /// # Errors
    /// The first layout rule the runtime's modules break.
    fn validate_layout() -> Result<(), LayoutError> {
        check_layout(Self::MODULES)
    }
}

/// Wraps a module's call message in the runtime's call type: implemented by the runtime's derive
/// for each of its modules.
pub trait EncodeCall<M: Module>: DispatchCall {
    /// `message` as a call of the runtime.
    fn to_decodable(message: M::CallMessage) -> Self::Decodable;

    /// The borsh encoding of `message` as a call of the runtime.
    ///
    /// # Errors
    /// As [`DispatchCall::encode`].
    fn encode_call(message: M::CallMessage) -> Result<Vec<u8>, borsh::io::Error> {
        Self::encode(&Self::to_decodable(message))
    }
}

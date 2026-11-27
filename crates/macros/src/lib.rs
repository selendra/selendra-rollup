//! The Selendra module system's derives: [`ModuleInfo`](macro@ModuleInfo) and
//! [`ModuleEvent`](macro@ModuleEvent) for modules; [`DispatchCall`](macro@DispatchCall),
//! [`MessageCodec`](macro@MessageCodec), [`Genesis`](macro@Genesis), [`Event`](macro@Event) and
//! [`Hooks`](macro@Hooks) for runtimes; [`ConsensusType`](macro@ConsensusType) for the types of
//! consensus data.
//!
//! Use them through `selendra-modules-api`, which re-exports them and documents their
//! attributes, the rules they check and examples. The code they generate names only
//! `::selendra_modules_api` (its hidden `__private` module) and `::core`, so a crate using them
//! needs no other dependency, and local items named like a crate (`mod borsh {}`) do not change
//! what it means.
//!
//! An invalid input is a compile error (a `syn::Error` spanned at the offending tokens); a
//! derive never panics, and builds no identifier from a string taken from the input (the only
//! identifiers it makes are fixed helper names, with mixed-site hygiene). The output depends
//! only on the input: no hash collections (`clippy.toml`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod attrs;
mod common;
mod consensus_type;
mod dispatch_call;
mod event;
mod genesis;
mod hooks;
mod message_codec;
mod module_event;
mod module_info;
mod runtime;

#[cfg(test)]
mod tests;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

/// Derives `ModuleInfo` and `Default` for a module struct, from
/// `#[module_info(discriminant = N, name = "…")]` and one attribute per field (`#[id]`,
/// `#[state(item = N)]`, `#[module]`, `#[phantom]`). See `selendra_modules_api::ModuleInfo`.
#[proc_macro_derive(ModuleInfo, attributes(module_info, id, state, module, phantom))]
pub fn derive_module_info(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(module_info::derive(&input))
}

/// Derives `ModuleEvent` for a module's event enum: each event's name is its variant's name.
/// See `selendra_modules_api::ModuleEvent`.
#[proc_macro_derive(ModuleEvent)]
pub fn derive_module_event(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(module_event::derive(&input))
}

/// Derives `ConsensusType` for a struct or enum whose fields are all consensus types, with
/// bounds inferred from the field types, or given by `#[consensus_type(bound(…))]` (for
/// generic types that contain each other). See `selendra_modules_api::ConsensusType`.
#[proc_macro_derive(ConsensusType, attributes(consensus_type))]
pub fn derive_consensus_type(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(consensus_type::derive(&input))
}

/// Derives `DispatchCall` for a runtime (a struct with one module per field, generic over its
/// spec first), and generates its call type `{Runtime}Call`. See
/// `selendra_modules_api::DispatchCall`.
#[proc_macro_derive(DispatchCall)]
pub fn derive_dispatch_call(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(dispatch_call::derive(&input))
}

/// Derives `EncodeCall<M>` for a runtime, for each of its modules `M`. See
/// `selendra_modules_api::MessageCodec`.
#[proc_macro_derive(MessageCodec)]
pub fn derive_message_codec(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(message_codec::derive(&input))
}

/// Derives `Genesis` for a runtime, and generates its configuration type
/// `{Runtime}GenesisConfig`. See `selendra_modules_api::Genesis`.
#[proc_macro_derive(Genesis)]
pub fn derive_genesis(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(genesis::derive(&input))
}

/// Derives `RuntimeEventProcessor` for a runtime, and generates its event type
/// `{Runtime}Event`. See `selendra_modules_api::Event`.
#[proc_macro_derive(Event)]
pub fn derive_event(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(event::derive(&input))
}

/// Derives `TxHooks`, `BlockHooks` and `FinalizeHook` for a runtime: every module's hooks, in
/// field order. See `selendra_modules_api::Hooks`.
#[proc_macro_derive(Hooks)]
pub fn derive_hooks(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(hooks::derive(&input))
}

/// The derive's output, or its error as a `compile_error!`.
fn expand(result: syn::Result<proc_macro2::TokenStream>) -> TokenStream {
    result.unwrap_or_else(syn::Error::into_compile_error).into()
}

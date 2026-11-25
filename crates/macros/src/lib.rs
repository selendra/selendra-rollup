//! The Selendra module system's derives: [`ModuleInfo`](macro@ModuleInfo) and
//! [`ModuleEvent`](macro@ModuleEvent) for modules, [`ConsensusType`](macro@ConsensusType) for
//! the types of consensus data.
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
mod module_event;
mod module_info;

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

/// The derive's output, or its error as a `compile_error!`.
fn expand(result: syn::Result<proc_macro2::TokenStream>) -> TokenStream {
    result.unwrap_or_else(syn::Error::into_compile_error).into()
}

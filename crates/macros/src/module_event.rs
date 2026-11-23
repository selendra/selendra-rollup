//! `#[derive(ModuleEvent)]`: a module event enum's `event_name`, the variant's name (without
//! `r#`), never its `Debug` output (P5-32).
//!
//! Each event is emitted with the key `"{module NAME}/{event name}"`, which must fit in
//! `MAX_EVENT_KEY_LEN` (256) bytes, or the emitting call is reverted. Module names are at most
//! [`MAX_MODULE_NAME_LEN`] (32) bytes, so the derive rejects an event name of more than
//! [`MAX_EVENT_NAME_LEN`] (223) bytes: a derived key always fits, with any module, and the
//! runtime failure becomes a compile error. The bound is computed here (a proc-macro crate
//! cannot read `selendra-state`'s constant), so the generated code also asserts it equals
//! `selendra-modules-api`'s `MAX_EVENT_NAME_LEN`, which is computed from the real constant.

use proc_macro2::{Literal, TokenStream};
use quote::quote;
use syn::{Data, DeriveInput, Fields};

use crate::attrs::MAX_MODULE_NAME_LEN;
use crate::common;

/// The longest event key (`selendra_state::metered::MAX_EVENT_KEY_LEN`).
const MAX_EVENT_KEY_LEN: usize = 256;

/// The longest event name: what is left of a key after the longest module name and the `/`.
pub(crate) const MAX_EVENT_NAME_LEN: usize = MAX_EVENT_KEY_LEN - MAX_MODULE_NAME_LEN - 1;

const ENUMS_ONLY: &str = "`ModuleEvent` can only be derived for an enum (each variant is an event)";

/// The tokens implementing `ModuleEvent` for `input`.
pub(crate) fn derive(input: &DeriveInput) -> syn::Result<TokenStream> {
    let variants = match &input.data {
        Data::Enum(data) => &data.variants,
        Data::Struct(data) => return Err(syn::Error::new_spanned(data.struct_token, ENUMS_ONLY)),
        Data::Union(data) => return Err(syn::Error::new_spanned(data.union_token, ENUMS_ONLY)),
    };

    let mut arms = Vec::with_capacity(variants.len());
    for variant in variants {
        let ident = &variant.ident;
        let name = common::name(ident);
        if name.len() > MAX_EVENT_NAME_LEN {
            return Err(syn::Error::new(
                ident.span(),
                format!(
                    "the event name `{name}` is {} bytes, more than {MAX_EVENT_NAME_LEN}: its key \
                     `\"{{module name}}/{name}\"` could exceed MAX_EVENT_KEY_LEN \
                     ({MAX_EVENT_KEY_LEN} bytes; module names are at most {MAX_MODULE_NAME_LEN})",
                    name.len()
                ),
            ));
        }
        let pattern = match &variant.fields {
            Fields::Named(_) => quote!(Self::#ident { .. }),
            Fields::Unnamed(_) => quote!(Self::#ident(..)),
            Fields::Unit => quote!(Self::#ident),
        };
        arms.push(quote!(#pattern => #name,));
    }

    let private = common::private();
    let max = Literal::usize_unsuffixed(MAX_EVENT_NAME_LEN);
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    Ok(common::in_anonymous_const(quote! {
        #[automatically_derived]
        impl #impl_generics #private::ModuleEvent for #ident #ty_generics #where_clause {
            fn event_name(&self) -> &'static str {
                match *self {
                    #(#arms)*
                }
            }
        }

        // The names were checked against the bound `selendra-modules-api` computes from the
        // event key limit.
        const _: () = ::core::assert!(
            #max == #private::MAX_EVENT_NAME_LEN,
            "selendra-macros checks event names against another bound than \
             selendra_modules_api::MAX_EVENT_NAME_LEN: update it",
        );
    }))
}

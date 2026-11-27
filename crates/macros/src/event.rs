//! `#[derive(Event)]` on a runtime: its event type `{Runtime}Event` and
//! `RuntimeEventProcessor`.
//!
//! Generated, at the call site (with the runtime's visibility and generics): the enum
//! `{Runtime}Event`, one variant per module holding its `Event`, deriving `ConsensusType`.
//! Inside an anonymous constant: its codecs (borsh: the module's `DISCRIMINANT`, then the
//! event; serde: keyed by the module's `NAME`; upstream's JSON was `untagged`, so two modules'
//! events of one type could not be told apart, P5-32), its JSON schema, `ModuleMessage`,
//! `Debug`, `Clone`, `PartialEq`; and `RuntimeEventProcessor` for the runtime, which maps an
//! emitted event to the variant of the module whose discriminant it carries (upstream matched
//! the event's `TypeId`: the first module with that event type got every such event, P5-32).

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

use crate::common;
use crate::runtime::{MessageEnum, Runtime, local};

/// The tokens of `#[derive(Event)]` on `input`.
pub(crate) fn derive(input: &DeriveInput) -> syn::Result<TokenStream> {
    let runtime = Runtime::parse(input, "Event")?;
    let event = MessageEnum {
        runtime: &runtime,
        ident: runtime.derived_ident("Event")?,
        message: format_ident!("Event"),
        doc: format!(
            "An event of one of the modules of `{}` (derived by `Event`): borsh-encoded as the \
             module's discriminant, then its event; in JSON, keyed by the module's name.",
            common::name(runtime.ident())
        ),
        holds: "events",
        eq: false,
    };

    let private = common::private();
    let self_ty = runtime.self_ty();
    let event_ident = &event.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let layout_check = runtime.layout_check();
    let (erased, module) = (local("event"), local("module"));
    let arms = runtime.modules.iter().map(|module_def| {
        let (variant, ty) = (&module_def.variant, module_def.ty);
        quote! {
            if #module == <#ty as #private::ModuleInfo>::DISCRIMINANT {
                return #private::TypeErasedEvent::downcast::<<#ty as #private::Module>::Event>(
                    #erased,
                )
                .map(#event_ident::#variant);
            }
        }
    });

    let definition = event.definition();
    let impls = event.impls();
    Ok(quote! {
        #definition

        const _: () = {
            #impls

            #[automatically_derived]
            impl #impl_generics #private::RuntimeEventProcessor for #self_ty #where_clause {
                type RuntimeEvent = #event_ident #ty_generics;

                fn convert_to_runtime_event(
                    #erased: #private::TypeErasedEvent,
                ) -> ::core::option::Option<Self::RuntimeEvent> {
                    #layout_check
                    let #module = #private::TypeErasedEvent::module(&#erased);
                    #(#arms)*
                    ::core::option::Option::None
                }
            }
        };
    })
}

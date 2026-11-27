//! `#[derive(DispatchCall)]` on a runtime: its call type `{Runtime}Call` and `DispatchCall`.
//!
//! Generated, at the call site (with the runtime's visibility and generics): the enum
//! `{Runtime}Call`, one variant per module holding its `CallMessage`, deriving `ConsensusType`.
//! Inside an anonymous constant: its codecs (borsh: the module's `DISCRIMINANT`, then the
//! message; serde: keyed by the module's `NAME`), its JSON schema, `ModuleMessage`, `Debug`,
//! `Clone`, `PartialEq`, `Eq`; and `DispatchCall` for the runtime: `MODULES` (each module's
//! `ModuleDescriptor`, in field order, which the layout check runs on), `dispatch_call` (the
//! module's `call`, fully qualified, its error passed through) and `module_id`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

use crate::common;
use crate::runtime::{MessageEnum, Runtime, local};

/// The tokens of `#[derive(DispatchCall)]` on `input`.
pub(crate) fn derive(input: &DeriveInput) -> syn::Result<TokenStream> {
    let runtime = Runtime::parse(input, "DispatchCall")?;
    let call = MessageEnum {
        runtime: &runtime,
        ident: runtime.derived_ident("Call")?,
        message: format_ident!("CallMessage"),
        doc: format!(
            "A call of one of the modules of `{}` (derived by `DispatchCall`): borsh-encoded as \
             the module's discriminant, then its call message; in JSON, keyed by the module's \
             name.",
            common::name(runtime.ident())
        ),
        holds: "calls",
        eq: true,
    };

    let private = common::private();
    let spec = runtime.spec;
    let self_ty = runtime.self_ty();
    let call_ident = &call.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let layout_check = runtime.layout_check();
    let same_spec = runtime.same_spec_checks();
    let state_param = runtime.fresh_param("State");
    let (call_arg, state, context, message) = (
        local("call"),
        local("state"),
        local("context"),
        local("message"),
    );
    let descriptors = runtime.modules.iter().map(|module| {
        let ty = module.ty;
        quote!(#private::ModuleDescriptor::of::<#ty>())
    });
    let dispatch_arms = runtime.modules.iter().map(|module| {
        let (variant, field, ty) = (&module.variant, module.field, module.ty);
        quote! {
            #call_ident::#variant(#message) => {
                <#ty as #private::Module>::call(&mut self.#field, #message, #context, #state)
                    .map_err(<#private::ModuleError as ::core::convert::From<_>>::from)
            }
        }
    });
    let id_arms = runtime.modules.iter().map(|module| {
        let (variant, field, ty) = (&module.variant, module.field, module.ty);
        quote! {
            #call_ident::#variant(_) => <#ty as #private::ModuleInfo>::id(&self.#field),
        }
    });

    let definition = call.definition();
    let impls = call.impls();
    Ok(quote! {
        #definition

        const _: () = {
            #impls

            #[automatically_derived]
            impl #impl_generics #private::DispatchCall for #self_ty #where_clause {
                type Spec = #spec;
                type Decodable = #call_ident #ty_generics;

                const MODULES: &'static [#private::ModuleDescriptor] = &[#(#descriptors),*];

                fn dispatch_call<#state_param: #private::TxState<#spec>>(
                    &mut self,
                    #call_arg: Self::Decodable,
                    #state: &mut #state_param,
                    #context: &#private::Context<#spec>,
                ) -> ::core::result::Result<(), #private::ModuleError> {
                    #layout_check
                    #same_spec
                    match #call_arg {
                        #(#dispatch_arms)*
                    }
                }

                fn module_id(&self, #call_arg: &Self::Decodable) -> &#private::ModuleId {
                    #layout_check
                    match #call_arg {
                        #(#id_arms)*
                    }
                }
            }
        };
    })
}

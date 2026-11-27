//! `#[derive(MessageCodec)]` on a runtime: `EncodeCall<M>` for each of its modules `M` (a
//! module's call message wrapped in the runtime's `{Runtime}Call`, which `DispatchCall`'s
//! derive generates).

use proc_macro2::TokenStream;
use quote::quote;
use syn::DeriveInput;

use crate::common;
use crate::runtime::{Runtime, local};

/// The tokens of `#[derive(MessageCodec)]` on `input`.
pub(crate) fn derive(input: &DeriveInput) -> syn::Result<TokenStream> {
    let runtime = Runtime::parse(input, "MessageCodec")?;
    let call_ident = runtime.derived_ident("Call")?;
    let private = common::private();
    let self_ty = runtime.self_ty();
    let (impl_generics, _, where_clause) = input.generics.split_for_impl();
    let layout_check = runtime.layout_check();
    let message = local("message");
    let impls = runtime.modules.iter().map(|module| {
        let (variant, ty) = (&module.variant, module.ty);
        quote! {
            #[automatically_derived]
            impl #impl_generics #private::EncodeCall<#ty> for #self_ty #where_clause {
                fn to_decodable(
                    #message: <#ty as #private::Module>::CallMessage,
                ) -> <Self as #private::DispatchCall>::Decodable {
                    #layout_check
                    #call_ident::#variant(#message)
                }
            }
        }
    });
    Ok(common::in_anonymous_const(quote!(#(#impls)*)))
}

//! `#[derive(Hooks)]` on a runtime: `TxHooks`, `BlockHooks` and `FinalizeHook`, each calling
//! every module's hook in field order, fully qualified (`<M as Module>::hook(&mut self.field,
//! …)`): a module's own hook always runs, never an inherent method of the same name or a
//! fallback impl (upstream's `(&mut self.field).hook(…)` picked either, P5-31). The first
//! error of a transaction hook is returned, and the later modules' hooks do not run.

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::DeriveInput;

use crate::common;
use crate::runtime::{Runtime, local};

/// The tokens of `#[derive(Hooks)]` on `input`.
pub(crate) fn derive(input: &DeriveInput) -> syn::Result<TokenStream> {
    let runtime = Runtime::parse(input, "Hooks")?;
    let private = common::private();
    let spec = runtime.spec;
    let self_ty = runtime.self_ty();
    let (impl_generics, _, where_clause) = input.generics.split_for_impl();
    let layout_check = runtime.layout_check();
    let state_param = runtime.fresh_param("State");
    let (tx, context, state, visible_hash, root_hash) = (
        local("tx"),
        local("context"),
        local("state"),
        local("visible_hash"),
        local("root_hash"),
    );
    let root = quote!(<<#spec as #private::Spec>::Storage as #private::Storage>::Root);

    // Each module's `hook`, with `args`, in field order (`?` after each if `fallible`).
    let calls = |hook: &str, args: &[&Ident], fallible: bool| {
        let hook = Ident::new(hook, proc_macro2::Span::call_site());
        let calls = runtime.modules.iter().map(|module| {
            let (ty, field) = (module.ty, module.field);
            let question = fallible.then(|| quote!(?));
            quote! {
                <#ty as #private::Module>::#hook(&mut self.#field, #(#args),*)#question;
            }
        });
        quote!(#(#calls)*)
    };
    let pre_dispatch = calls("pre_dispatch_tx_hook", &[&tx, &state], true);
    let post_dispatch = calls("post_dispatch_tx_hook", &[&tx, &context, &state], true);
    let begin = calls("begin_rollup_block_hook", &[&visible_hash, &state], false);
    let end = calls("end_rollup_block_hook", &[&state], false);
    let finalize = calls("finalize_hook", &[&root_hash, &state], false);

    Ok(common::in_anonymous_const(quote! {
        #[automatically_derived]
        impl #impl_generics #private::TxHooks for #self_ty #where_clause {
            type Spec = #spec;

            fn pre_dispatch_tx_hook<#state_param: #private::TxState<#spec>>(
                &mut self,
                #tx: &#private::AuthenticatedTransactionData<#spec>,
                #state: &mut #state_param,
            ) -> ::core::result::Result<(), #private::ModuleError> {
                #layout_check
                #pre_dispatch
                ::core::result::Result::Ok(())
            }

            fn post_dispatch_tx_hook<#state_param: #private::TxState<#spec>>(
                &mut self,
                #tx: &#private::AuthenticatedTransactionData<#spec>,
                #context: &#private::Context<#spec>,
                #state: &mut #state_param,
            ) -> ::core::result::Result<(), #private::ModuleError> {
                #layout_check
                #post_dispatch
                ::core::result::Result::Ok(())
            }
        }

        #[automatically_derived]
        impl #impl_generics #private::BlockHooks for #self_ty #where_clause {
            type Spec = #spec;

            fn begin_rollup_block_hook(
                &mut self,
                #visible_hash: &#root,
                #state: &mut #private::BlockState<'_, #spec>,
            ) {
                #layout_check
                #begin
            }

            fn end_rollup_block_hook(&mut self, #state: &mut #private::BlockState<'_, #spec>) {
                #layout_check
                #end
            }
        }

        #[automatically_derived]
        impl #impl_generics #private::FinalizeHook for #self_ty #where_clause {
            type Spec = #spec;

            fn finalize_hook(
                &mut self,
                #root_hash: &#root,
                #state: &mut impl #private::AccessoryStateReaderAndWriter,
            ) {
                #layout_check
                #finalize
            }
        }
    }))
}

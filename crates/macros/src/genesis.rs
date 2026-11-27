//! `#[derive(Genesis)]` on a runtime: its genesis configuration `{Runtime}GenesisConfig` and
//! `Genesis`.
//!
//! Generated, at the call site (with the runtime's visibility and generics): the struct
//! `{Runtime}GenesisConfig`, one field per module (same name, the module's `Config`). Inside an
//! anonymous constant: its serde impls, written out (not serde's derive, whose code names
//! primitive types unqualified and takes its bounds as strings), strict: exactly one field per
//! module, unknown, duplicate and missing fields rejected (a missing `Option` included),
//! through `__private::deserialize_genesis_config`; its `Debug`, `Clone` and `PartialEq`; each
//! implemented where the configs implement the trait. And `Genesis` for the runtime: the layout
//! check (at compile time and again at run time), then each module's genesis, every module after
//! its dependencies (`sort_values_by_modules_dependencies`), the first error returned. No module
//! is special (upstream required a `chain_state` field: Phase 8).

use proc_macro2::{Literal, TokenStream};
use quote::{ToTokens, quote};
use syn::DeriveInput;

use crate::common;
use crate::runtime::{Runtime, local};

/// The tokens of `#[derive(Genesis)]` on `input`.
pub(crate) fn derive(input: &DeriveInput) -> syn::Result<TokenStream> {
    let runtime = Runtime::parse(input, "Genesis")?;
    let config_ident = runtime.derived_ident("GenesisConfig")?;
    let private = common::private();
    let spec = runtime.spec;
    let self_ty = runtime.self_ty();
    let vis = &input.vis;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let layout_check = runtime.layout_check();
    let same_spec = runtime.same_spec_checks();
    let (header, config, state, order, index, f, other) = (
        local("genesis_rollup_header"),
        local("config"),
        local("state"),
        local("order"),
        local("index"),
        local("f"),
        local("other"),
    );

    let fields: Vec<_> = runtime.modules.iter().map(|module| module.field).collect();
    let configs: Vec<TokenStream> = runtime
        .modules
        .iter()
        .map(|module| {
            let ty = module.ty;
            quote!(<#ty as #private::Module>::Config)
        })
        .collect();
    let field_docs = runtime.modules.iter().map(|module| {
        format!(
            "The genesis configuration of the runtime's `{}` module.",
            common::name(module.field)
        )
    });
    let doc = format!(
        "The genesis configuration of `{}` (derived by `Genesis`): each module's, by field \
         name. In JSON, an object with exactly these fields, none missing.",
        common::name(runtime.ident())
    );
    let config_name = config_ident.to_string();
    let descriptors = runtime.modules.iter().enumerate().map(|(i, module)| {
        let (ty, i) = (module.ty, Literal::usize_suffixed(i));
        quote!((#private::ModuleDescriptor::of::<#ty>(), #i))
    });
    let genesis_arms = runtime.modules.iter().enumerate().map(|(i, module)| {
        let (ty, field, i) = (module.ty, module.field, Literal::usize_suffixed(i));
        quote! {
            #i => <#ty as #private::Genesis>::genesis(
                &mut self.#field,
                #header,
                &#config.#field,
                #state,
            )?,
        }
    });

    let serde = quote!(#private::serde);
    let bounded = |trait_: TokenStream| {
        let mut generics = generics.clone();
        let predicates = &mut generics.make_where_clause().predicates;
        for config in &configs {
            predicates.push(syn::parse_quote!(#config: #trait_));
        }
        generics
    };
    let debug_generics = bounded(quote!(::core::fmt::Debug));
    let clone_generics = bounded(quote!(::core::clone::Clone));
    let eq_generics = bounded(quote!(::core::cmp::PartialEq));
    let ser_generics = bounded(quote!(#serde::Serialize));
    // `impl<'de, …>`, the configs `Deserialize<'de>`.
    let mut de_generics = bounded(quote!(#serde::Deserialize<'de>));
    de_generics.params.insert(0, syn::parse_quote!('de));
    let (debug_impl, _, debug_where) = debug_generics.split_for_impl();
    let (clone_impl, _, clone_where) = clone_generics.split_for_impl();
    let (eq_impl, _, eq_where) = eq_generics.split_for_impl();
    let (ser_impl, _, ser_where) = ser_generics.split_for_impl();
    let (de_impl, _, de_where) = de_generics.split_for_impl();
    let field_names: Vec<String> = fields.iter().map(|field| common::name(field)).collect();
    let config_ty = quote!(#config_ident #ty_generics);
    let where_tokens = where_clause.map(ToTokens::to_token_stream);
    let count = Literal::usize_unsuffixed(fields.len());
    let indices: Vec<Literal> = (0..fields.len()).map(Literal::usize_unsuffixed).collect();
    let nones = fields.iter().map(|_| quote!(::core::option::Option::None));
    let (serializer, deserializer, fields_state, slots, map, seq) = (
        local("serializer"),
        local("deserializer"),
        local("fields"),
        local("slots"),
        local("map"),
        local("seq"),
    );
    let ser = runtime.fresh_param("Ser");
    let de = runtime.fresh_param("De");
    let access = runtime.fresh_param("A");
    let error = runtime.fresh_param("E");

    Ok(quote! {
        #[doc = #doc]
        #vis struct #config_ident #generics #where_tokens {
            #(
                #[doc = #field_docs]
                #vis #fields: #configs,
            )*
        }

        const _: () = {
            #[automatically_derived]
            impl #debug_impl ::core::fmt::Debug for #config_ty #debug_where {
                fn fmt(&self, #f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    ::core::fmt::Formatter::debug_struct(#f, #config_name)
                        #(.field(#field_names, &self.#fields))*
                        .finish()
                }
            }

            #[automatically_derived]
            impl #clone_impl ::core::clone::Clone for #config_ty #clone_where {
                fn clone(&self) -> Self {
                    Self {
                        #(#fields: ::core::clone::Clone::clone(&self.#fields),)*
                    }
                }
            }

            #[automatically_derived]
            impl #eq_impl ::core::cmp::PartialEq for #config_ty #eq_where {
                fn eq(&self, #other: &Self) -> ::core::primitive::bool {
                    true #(&& self.#fields == #other.#fields)*
                }
            }

            #[automatically_derived]
            impl #ser_impl #serde::Serialize for #config_ty #ser_where {
                fn serialize<#ser: #serde::Serializer>(
                    &self,
                    #serializer: #ser,
                ) -> ::core::result::Result<<#ser as #serde::Serializer>::Ok, <#ser as #serde::Serializer>::Error> {
                    #layout_check
                    let mut #fields_state =
                        #serde::Serializer::serialize_struct(#serializer, #config_name, #count)?;
                    #(#serde::ser::SerializeStruct::serialize_field(
                        &mut #fields_state,
                        #field_names,
                        &self.#fields,
                    )?;)*
                    #serde::ser::SerializeStruct::end(#fields_state)
                }
            }

            #[automatically_derived]
            impl #de_impl #serde::Deserialize<'de> for #config_ty #de_where {
                fn deserialize<#de: #serde::Deserializer<'de>>(
                    #deserializer: #de,
                ) -> ::core::result::Result<Self, <#de as #serde::Deserializer<'de>>::Error> {
                    #layout_check
                    #private::deserialize_genesis_config(#deserializer)
                }
            }

            #[automatically_derived]
            impl #de_impl #private::GenesisConfigFields<'de> for #config_ty #de_where {
                const TYPE_NAME: &'static ::core::primitive::str = #config_name;
                const FIELDS: &'static [&'static ::core::primitive::str] = &[#(#field_names),*];
                type Slots = (#(::core::option::Option<#configs>,)*);

                fn empty_slots() -> Self::Slots {
                    (#(#nones,)*)
                }

                fn next_value<#access: #serde::de::MapAccess<'de>>(
                    #slots: &mut Self::Slots,
                    #index: ::core::primitive::usize,
                    #map: &mut #access,
                ) -> ::core::result::Result<(), <#access as #serde::de::MapAccess<'de>>::Error> {
                    #(if #index == #indices {
                        return #private::fill_slot(&mut #slots.#indices, #field_names, #map);
                    })*
                    ::core::result::Result::Err(#private::no_field_at(#index))
                }

                fn next_element<#access: #serde::de::SeqAccess<'de>>(
                    #slots: &mut Self::Slots,
                    #index: ::core::primitive::usize,
                    #seq: &mut #access,
                ) -> ::core::result::Result<::core::primitive::bool, <#access as #serde::de::SeqAccess<'de>>::Error> {
                    #(if #index == #indices {
                        return #private::fill_element(&mut #slots.#indices, #seq);
                    })*
                    ::core::result::Result::Err(#private::no_field_at(#index))
                }

                fn from_slots<#error: #serde::de::Error>(
                    #slots: Self::Slots,
                ) -> ::core::result::Result<Self, #error> {
                    ::core::result::Result::Ok(Self {
                        #(#fields: #private::take_slot(#slots.#indices, #field_names)?,)*
                    })
                }
            }

            #[automatically_derived]
            impl #impl_generics #private::Genesis for #self_ty #where_clause {
                type Spec = #spec;
                type Config = #config_ty;

                fn genesis(
                    &mut self,
                    #header: &<<#spec as #private::Spec>::Da as #private::DaSpec>::BlockHeader,
                    #config: &Self::Config,
                    #state: &mut impl #private::GenesisState<#spec>,
                ) -> ::core::result::Result<(), #private::ModuleError> {
                    #layout_check
                    #same_spec
                    <Self as #private::DispatchCall>::validate_layout()
                        .map_err(<#private::ModuleError as ::core::convert::From<_>>::from)?;
                    let #order = #private::sort_values_by_modules_dependencies(
                        <#private::Vec<_> as ::core::convert::From<[_; #count]>>::from([
                            #(#descriptors),*
                        ]),
                    )
                    .map_err(<#private::ModuleError as ::core::convert::From<_>>::from)?;
                    for #index in #order {
                        match #index {
                            #(#genesis_arms)*
                            // `order` holds exactly the indices above.
                            _ => {}
                        }
                    }
                    ::core::result::Result::Ok(())
                }
            }
        };
    })
}

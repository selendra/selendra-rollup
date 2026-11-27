//! `#[derive(ModuleInfo)]`: a module's identity and state layout (`ModuleInfo`), and its
//! `Default` constructor, which gives every state item its prefix.
//!
//! Generated (inside an anonymous constant), for
//! `#[module_info(discriminant = D, name = "n")]`:
//! - `ModuleInfo`: `type Spec` = the first generic parameter; `DISCRIMINANT = D`;
//!   `NAME = "n"`; `DEPENDENCIES`, the `(DISCRIMINANT, NAME)` of each `#[module]` field in field
//!   order; `STATE_LAYOUT`, one `StateItem::new(item, "field")` per `#[state]` field in item-id
//!   order; `id()`, the `#[id]` field. `dependencies()` is the trait's provided method
//!   (computed from `DEPENDENCIES`), not generated.
//! - `Default`: the `#[id]` field is `ModuleId::from_name(NAME)` (the stable-name id, P5-27);
//!   each `#[state(item = N)]` field is `<Type>::with_codec(Prefix::new(D, N), codec())`; each
//!   `#[module]` field is its `Default` (after a check that it runs with the same spec); each
//!   `#[phantom]` field is `PhantomData`.
//!
//! Checked here (errors spanned at the input): a struct with named fields, generic over its
//! spec first; one `#[module_info]` with a discriminant in 1..=255 and a valid name; one
//! `#[id]` field; one attribute per field; item ids in 0..=255, unique within the module.

use std::collections::BTreeMap;

use proc_macro2::{Ident, Literal, TokenStream};
use quote::quote;
use syn::{Data, DataStruct, DeriveInput, Field, Fields, Type};

use crate::attrs::{self, FieldKind};
use crate::common;

/// The tokens implementing `ModuleInfo` and `Default` for `input`.
pub(crate) fn derive(input: &DeriveInput) -> syn::Result<TokenStream> {
    let fields = named_fields(input)?;
    let spec = common::spec_param(&input.generics, &input.ident, "module")?;
    let attrs::ModuleAttrs { discriminant, name } = attrs::module_attrs(input)?;

    let private = common::private();
    let disc = Literal::u8_unsuffixed(discriminant);
    let mut id_field: Option<&Ident> = None;
    // Item id → field: unique ids, and the layout in item-id order.
    let mut items: BTreeMap<u8, &Ident> = BTreeMap::new();
    let mut inits = Vec::with_capacity(fields.len());
    let mut dependencies = Vec::new();
    let mut checks = Vec::new();

    for field in fields {
        let Some(ident) = &field.ident else {
            return Err(syn::Error::new_spanned(field, NAMED_FIELDS_ONLY));
        };
        let ty = &field.ty;
        match attrs::field_kind(field, ident)? {
            FieldKind::Id => {
                if let Some(first) = id_field {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!(
                            "only one field can be `#[id]` (`{}` already is)",
                            common::name(first)
                        ),
                    ));
                }
                id_field = Some(ident);
                inits.push(quote! {
                    #ident: #private::ModuleId::from_name(<Self as #private::ModuleInfo>::NAME)
                });
            }
            FieldKind::State {
                item,
                item_lit,
                codec,
            } => {
                if !is_path_type(ty) {
                    return Err(syn::Error::new_spanned(
                        ty,
                        "a `#[state]` field must be a state container type (e.g. `StateValue<V>`, \
                         `StateMap<K, V>`, `StateVec<V>`)",
                    ));
                }
                if let Some(other) = items.get(&item) {
                    return Err(syn::Error::new(
                        item_lit.span(),
                        format!(
                            "item id {item} is already used by field `{}`",
                            common::name(other)
                        ),
                    ));
                }
                items.insert(item, ident);
                let item = Literal::u8_unsuffixed(item);
                let codec = match codec {
                    Some(path) => quote!(#path),
                    None => quote!(::core::default::Default::default),
                };
                inits.push(quote! {
                    #ident: <#ty>::with_codec(#private::Prefix::new(#disc, #item), #codec())
                });
            }
            FieldKind::Module => {
                dependencies.push(quote! {
                    (
                        <#ty as #private::ModuleInfo>::DISCRIMINANT,
                        <#ty as #private::ModuleInfo>::NAME,
                    )
                });
                checks.push(quote! { #private::same_spec::<#ty, #spec>(); });
                inits.push(quote! { #ident: <#ty as ::core::default::Default>::default() });
            }
            FieldKind::Phantom => inits.push(quote! { #ident: ::core::marker::PhantomData }),
        }
    }

    let Some(id_field) = id_field else {
        return Err(syn::Error::new(
            input.ident.span(),
            "a module needs an `#[id]` field (its `ModuleId`)",
        ));
    };
    let layout = items.iter().map(|(&item, ident)| {
        let item = Literal::u8_unsuffixed(item);
        let name = common::name(ident);
        quote!(#private::StateItem::new(#item, #name))
    });

    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    Ok(common::in_anonymous_const(quote! {
        #[automatically_derived]
        impl #impl_generics #private::ModuleInfo for #ident #ty_generics #where_clause {
            type Spec = #spec;
            const DISCRIMINANT: u8 = #disc;
            const NAME: &'static str = #name;
            const DEPENDENCIES: &'static [(u8, &'static str)] = &[#(#dependencies),*];
            const STATE_LAYOUT: &'static [#private::StateItem] = &[#(#layout),*];

            fn id(&self) -> &#private::ModuleId {
                &self.#id_field
            }
        }

        #[automatically_derived]
        impl #impl_generics ::core::default::Default for #ident #ty_generics #where_clause {
            fn default() -> Self {
                #(#checks)*
                Self {
                    #(#inits),*
                }
            }
        }
    }))
}

const NAMED_FIELDS_ONLY: &str = "`ModuleInfo` can only be derived for a struct with named fields";

/// The fields of a struct with named fields (none for a unit struct).
fn named_fields(input: &DeriveInput) -> syn::Result<Vec<&Field>> {
    match &input.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => Ok(fields.named.iter().collect()),
        Data::Struct(DataStruct {
            fields: Fields::Unit,
            ..
        }) => Ok(Vec::new()),
        Data::Struct(DataStruct {
            fields: Fields::Unnamed(fields),
            ..
        }) => Err(syn::Error::new_spanned(fields, NAMED_FIELDS_ONLY)),
        Data::Enum(data) => Err(syn::Error::new_spanned(data.enum_token, NAMED_FIELDS_ONLY)),
        Data::Union(data) => Err(syn::Error::new_spanned(data.union_token, NAMED_FIELDS_ONLY)),
    }
}

/// Whether `ty` is a path type (`StateMap<K, V>`, an alias, …), seen through parentheses and
/// the invisible groups of `macro_rules!` expansions.
fn is_path_type(ty: &Type) -> bool {
    match ty {
        Type::Path(_) => true,
        Type::Group(group) => is_path_type(&group.elem),
        Type::Paren(paren) => is_path_type(&paren.elem),
        _ => false,
    }
}

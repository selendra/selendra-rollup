//! `#[derive(ConsensusType)]` (D20 of the Phase 5 plan): a struct or enum is a consensus type
//! if every field's type is one.
//!
//! By default the impl is bounded by the field types themselves ("perfect derive"), not by the
//! type's generic parameters: `struct Wrapper<T>(T)` is a consensus type when `T` is, and a
//! field `PhantomData<S>` puts no bound on `S`. Each field type is checked in one of two places:
//! - a type that mentions a generic parameter (and not the type itself): a bound in the impl's
//!   `where` clause, checked where the type is used with concrete parameters;
//! - any other type (no generic parameter, or the type itself, like `Option<Box<Self>>`): a
//!   check in a function next to the impl, which fails at the definition (E0277). In a `where`
//!   clause, a bound on the type itself would make the trait solver loop (E0275), and so would
//!   a bound on a non-generic type that contains this one. The generic parameters a recursive
//!   field mentions are bounded instead (`Vec<(Self, T)>` bounds `T`).
//!
//! What the inferred bounds cannot handle: two generic types that contain each other (`A<T>`
//! holding a `B<T>` that holds an `A<T>`): `A`'s impl is bounded by `B<T>`'s field type and
//! `B`'s by `A<T>`'s, so the trait solver loops (E0275) where they are used. For those, the
//! container attribute `#[consensus_type(bound(PRED, …))]` replaces the inferred bounds: the
//! impl's `where` clause is the type's own plus exactly those predicates (unquoted where
//! predicates; `bound()` adds none), and every field type, generic or not, is checked in the
//! function next to the impl under exactly the impl's generics and `where` clause. So the
//! attribute decides how widely the impl applies (more or fewer types than the inferred bounds:
//! `bound()` drops the bound a recursive field puts on the parameters it mentions), but never
//! to a type whose fields are not consensus types: `#[consensus_type(bound())] struct W<T>(T);`
//! fails at the definition (E0277: `T` is not proven a consensus type).
//! `bound(T: ConsensusType)` on either type of the pair breaks the cycle. On a type without type parameters, `bound` is an error: no bound is
//! inferred there (every field is checked at the definition), so there is nothing to replace.

use std::collections::BTreeSet;

use proc_macro2::{Ident, Span, TokenStream};
use quote::{ToTokens, quote, quote_spanned};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, GenericParam, Generics, Type, WherePredicate};

use crate::{attrs, common};

/// The tokens implementing `ConsensusType` for `input`.
pub(crate) fn derive(input: &DeriveInput) -> syn::Result<TokenStream> {
    let field_types: Vec<&Type> = match &input.data {
        Data::Struct(data) => data.fields.iter().map(|field| &field.ty).collect(),
        Data::Enum(data) => data
            .variants
            .iter()
            .flat_map(|variant| variant.fields.iter().map(|field| &field.ty))
            .collect(),
        Data::Union(data) => {
            return Err(syn::Error::new_spanned(
                data.union_token,
                "`ConsensusType` cannot be derived for a union",
            ));
        }
    };
    let explicit_bound = attrs::consensus_type_bound(input)?;

    let private = common::private();
    let ident = &input.ident;
    let param_idents: Vec<&Ident> = input
        .generics
        .params
        .iter()
        .filter_map(|param| match param {
            GenericParam::Type(param) => Some(&param.ident),
            GenericParam::Lifetime(_) | GenericParam::Const(_) => None,
        })
        .collect();
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let self_ty = quote!(#ident #ty_generics);
    let check = Ident::new("consensus_type", Span::mixed_site());

    let explicit = explicit_bound.is_some();
    let (generics, checked) = match explicit_bound {
        Some(explicit) => {
            if param_idents.is_empty() {
                return Err(syn::Error::new_spanned(
                    explicit.attr,
                    format!(
                        "`bound` is for types with type parameters: `{}` has none, so no bound \
                         is inferred (every field is checked where the type is defined)",
                        common::name(ident)
                    ),
                ));
            }
            // The type's own bounds plus exactly the given ones; every field type checked.
            let mut generics = input.generics.clone();
            if !explicit.predicates.is_empty() {
                generics
                    .make_where_clause()
                    .predicates
                    .extend(explicit.predicates);
            }
            let checked = field_types
                .iter()
                .map(|ty| {
                    let span = ty.span();
                    let ty = common::replace_self(ty.to_token_stream(), &self_ty);
                    quote_spanned!(span=> #check::<#ty>();)
                })
                .collect();
            (generics, checked)
        }
        None => inferred_bounds(input, &field_types, &param_idents, &self_ty, &check),
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let mut fields_check = None;
    if !checked.is_empty() {
        let name = Ident::new("check_fields", Span::mixed_site());
        let mut check_generics = bounds_in_where_clause(&generics);
        if let (true, Some(where_clause)) = (explicit, &mut check_generics.where_clause) {
            // A function has no `Self`: the given predicates may use it for the type.
            let replaced =
                common::replace_self(where_clause.predicates.to_token_stream(), &self_ty);
            where_clause.predicates = Punctuated::parse_terminated.parse2(replaced)?;
        }
        let (fn_generics, _, fn_where_clause) = check_generics.split_for_impl();
        fields_check = Some(quote! {
            // The field types that are not bounds of the impl, under exactly its bounds.
            fn #name #fn_generics () #fn_where_clause {
                fn #check<T: #private::ConsensusType + ?::core::marker::Sized>() {}
                #(#checked)*
            }
        });
    }
    Ok(common::in_anonymous_const(quote! {
        #[automatically_derived]
        impl #impl_generics #private::ConsensusType for #ident #ty_generics #where_clause {}

        #fields_check
    }))
}

/// The inferred ("perfect derive") bounds: the impl's generics, with a bound for each field
/// type that mentions a generic parameter and not the type itself, and the checks of the other
/// field types (recursive ones with their generic parameters bounded).
fn inferred_bounds(
    input: &DeriveInput,
    field_types: &[&Type],
    param_idents: &[&Ident],
    self_ty: &TokenStream,
    check: &Ident,
) -> (Generics, Vec<TokenStream>) {
    let private = common::private();
    let params: Vec<String> = param_idents
        .iter()
        .map(|ident| common::name(ident))
        .collect();
    let itself = [common::name(&input.ident), "Self".to_owned()];
    let mut generics = input.generics.clone();
    let mut bounded = BTreeSet::new();
    let mut bound = |generics: &mut Generics, ty: TokenStream| {
        if bounded.insert(ty.to_string()) {
            generics
                .make_where_clause()
                .predicates
                .push(syn::parse_quote!(#ty: #private::ConsensusType));
        }
    };
    let mut checked = Vec::new();
    for ty in field_types {
        let span = ty.span();
        let tokens = ty.to_token_stream();
        if !common::mentions(tokens.clone(), &itself) {
            if common::mentions(tokens.clone(), &params) {
                bound(&mut generics, tokens);
            } else {
                checked.push(quote_spanned!(span=> #check::<#ty>();));
            }
            continue;
        }
        // A recursive field (`Vec<(Self, T)>`): checked in the function, with each generic
        // parameter it mentions bounded (it may be the only field holding a `T`).
        for (param, name) in param_idents.iter().zip(&params) {
            if common::mentions(tokens.clone(), std::slice::from_ref(name)) {
                bound(&mut generics, quote!(#param));
            }
        }
        let ty = common::replace_self(tokens, self_ty);
        checked.push(quote_spanned!(span=> #check::<#ty>();));
    }
    (generics, checked)
}

/// `generics` with every bound of a parameter moved into the `where` clause (`<T: Clone>` →
/// `<T> where T: Clone`), for the generated function: a function with a parameter bounded in
/// both places trips clippy's `multiple_bound_locations` in the crate using the derive.
fn bounds_in_where_clause(generics: &Generics) -> Generics {
    let mut generics = generics.clone();
    let mut moved: Vec<WherePredicate> = Vec::new();
    for param in &mut generics.params {
        match param {
            GenericParam::Type(param) if !param.bounds.is_empty() => {
                let (ident, bounds) = (&param.ident, &param.bounds);
                moved.push(syn::parse_quote!(#ident: #bounds));
                param.bounds.clear();
                param.colon_token = None;
            }
            GenericParam::Lifetime(param) if !param.bounds.is_empty() => {
                let (lifetime, bounds) = (&param.lifetime, &param.bounds);
                moved.push(syn::parse_quote!(#lifetime: #bounds));
                param.bounds.clear();
                param.colon_token = None;
            }
            GenericParam::Type(_) | GenericParam::Lifetime(_) | GenericParam::Const(_) => {}
        }
    }
    if !moved.is_empty() {
        let predicates = &mut generics.make_where_clause().predicates;
        let rest = std::mem::take(predicates);
        predicates.extend(moved);
        predicates.extend(rest);
    }
    generics
}

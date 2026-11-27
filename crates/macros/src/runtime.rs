//! What the runtime derives (`DispatchCall`, `MessageCodec`, `Genesis`, `Event`, `Hooks`)
//! share: the runtime struct (its spec and its modules, one per field), the names they
//! generate, and the runtime's message enums (`{Runtime}Call`, `{Runtime}Event`).
//!
//! A runtime is a struct with named fields, generic over its spec first, every field a module
//! of that spec. Each module is the variant of the message enums named after its field in
//! `PascalCase` (`sequencer_registry` → `SequencerRegistry`); the encodings use the module's
//! own `DISCRIMINANT` (borsh tag) and `NAME` (JSON key), never the field's position or name.
//!
//! Every function the derives generate that encodes, decodes or describes a message, or uses
//! the runtime's modules (the codecs, the JSON schema, `ModuleMessage`, dispatch, `EncodeCall`,
//! genesis and its configuration's codecs, the event mapping, the hooks) evaluates the
//! runtime's layout check (`<Runtime as DispatchCall>::__CHECK_LAYOUT`), so the other derives
//! need `DispatchCall`'s. (`Debug`, `Clone`, `PartialEq` and `Default` do not.)

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::{ToTokens, quote};
use syn::{Data, DataStruct, DeriveInput, Fields, GenericParam, LitStr, Type};

use crate::common;

/// A runtime: the input struct, its spec, its modules.
pub(crate) struct Runtime<'a> {
    pub(crate) input: &'a DeriveInput,
    /// The first generic parameter.
    pub(crate) spec: &'a Ident,
    /// One per field, in field order.
    pub(crate) modules: Vec<RuntimeModule<'a>>,
}

/// A module of a runtime: a field of the runtime struct.
pub(crate) struct RuntimeModule<'a> {
    /// The field.
    pub(crate) field: &'a Ident,
    /// The module type.
    pub(crate) ty: &'a Type,
    /// The field's name in `PascalCase`: the module's variant in the message enums.
    pub(crate) variant: Ident,
}

impl<'a> Runtime<'a> {
    /// Parses `input` for the derive named `derive`.
    pub(crate) fn parse(input: &'a DeriveInput, derive: &str) -> syn::Result<Self> {
        let named_only = format!(
            "`{derive}` can only be derived for a runtime: a struct with named fields, one per \
             module"
        );
        let fields = match &input.data {
            Data::Struct(DataStruct {
                fields: Fields::Named(fields),
                ..
            }) => &fields.named,
            Data::Struct(DataStruct {
                fields: Fields::Unnamed(fields),
                ..
            }) => return Err(syn::Error::new_spanned(fields, named_only)),
            Data::Struct(DataStruct {
                fields: Fields::Unit,
                struct_token,
                ..
            }) => return Err(syn::Error::new_spanned(struct_token, named_only)),
            Data::Enum(data) => return Err(syn::Error::new_spanned(data.enum_token, named_only)),
            Data::Union(data) => return Err(syn::Error::new_spanned(data.union_token, named_only)),
        };
        let spec = common::spec_param(&input.generics, &input.ident, "runtime")?;
        if fields.is_empty() {
            return Err(syn::Error::new(
                input.ident.span(),
                "a runtime needs at least one module (one per field)",
            ));
        }

        // Variant → field: two fields must not make the same variant.
        let mut variants: BTreeMap<String, &Ident> = BTreeMap::new();
        let mut modules = Vec::with_capacity(fields.len());
        for field in fields {
            let Some(ident) = &field.ident else {
                return Err(syn::Error::new_spanned(field, named_only));
            };
            let variant = pascal_case(ident)?;
            if let Some(other) = variants.insert(variant.to_string(), ident) {
                return Err(syn::Error::new(
                    ident.span(),
                    format!(
                        "fields `{}` and `{}` both name the variant `{variant}` of the runtime's \
                         call and event types: rename one",
                        common::name(other),
                        common::name(ident),
                    ),
                ));
            }
            modules.push(RuntimeModule {
                field: ident,
                ty: &field.ty,
                variant,
            });
        }
        Ok(Self {
            input,
            spec,
            modules,
        })
    }

    /// The runtime's name.
    pub(crate) fn ident(&self) -> &Ident {
        &self.input.ident
    }

    /// The name of a type generated for the runtime: `{Runtime}{suffix}` (`RuntimeCall`), at the
    /// runtime's name's span.
    pub(crate) fn derived_ident(&self, suffix: &str) -> syn::Result<Ident> {
        let name = format!("{}{suffix}", common::name(self.ident()));
        let mut ident = syn::parse_str::<Ident>(&name).map_err(|_| {
            syn::Error::new(
                self.ident().span(),
                format!("`{name}` is not a valid identifier"),
            )
        })?;
        ident.set_span(self.ident().span());
        Ok(ident)
    }

    /// A type parameter name (`base`, or `base` with a number) that names nothing the runtime
    /// mentions: none of its generic parameters, no identifier in its module types or its
    /// where clause. For the generic parameters of generated methods, whose bodies and
    /// signatures name the runtime's parameters and its module types: a parameter named like a
    /// type they use (`type W = u32;` in `Bank<S, W>`) would shadow it there.
    pub(crate) fn fresh_param(&self, base: &str) -> Ident {
        let generics = &self.input.generics;
        let mut taken: BTreeSet<String> = generics
            .params
            .iter()
            .map(|param| match param {
                GenericParam::Type(param) => common::name(&param.ident),
                GenericParam::Const(param) => common::name(&param.ident),
                GenericParam::Lifetime(param) => param.lifetime.ident.to_string(),
            })
            .collect();
        for module in &self.modules {
            common::collect_names(module.ty.to_token_stream(), &mut taken);
        }
        if let Some(where_clause) = &generics.where_clause {
            common::collect_names(where_clause.to_token_stream(), &mut taken);
        }
        let mut name = base.to_owned();
        let mut n = 0u32;
        while taken.contains(&name) {
            n += 1;
            name = format!("{base}{n}");
        }
        Ident::new(&name, Span::mixed_site())
    }

    /// `#generics` without defaults or bounds: `Runtime<S, T>` (the runtime's type).
    pub(crate) fn self_ty(&self) -> TokenStream {
        let ident = self.ident();
        let (_, ty_generics, _) = self.input.generics.split_for_impl();
        quote!(#ident #ty_generics)
    }

    /// The statement evaluating the runtime's layout check.
    pub(crate) fn layout_check(&self) -> TokenStream {
        let private = common::private();
        let self_ty = self.self_ty();
        quote! {
            let () = <#self_ty as #private::DispatchCall>::__CHECK_LAYOUT;
        }
    }

    /// The statements checking that each module runs with the runtime's spec (E0271).
    pub(crate) fn same_spec_checks(&self) -> TokenStream {
        let private = common::private();
        let spec = self.spec;
        let checks = self.modules.iter().map(|module| {
            let ty = module.ty;
            quote!(#private::same_spec::<#ty, #spec>();)
        });
        quote!(#(#checks)*)
    }
}

/// `field` in `PascalCase` (without `r#`): each `_`-separated part capitalized, the `_`s
/// dropped. An error if that is not an identifier (e.g. `_`, or `self_` → `Self`).
fn pascal_case(field: &Ident) -> syn::Result<Ident> {
    let name = common::name(field);
    let mut pascal = String::with_capacity(name.len());
    for part in name.split('_') {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            pascal.extend(first.to_uppercase());
            pascal.push_str(chars.as_str());
        }
    }
    let mut variant = syn::parse_str::<Ident>(&pascal).map_err(|_| {
        syn::Error::new(
            field.span(),
            format!(
                "the field `{name}` names the variant `{pascal}` of the runtime's call and event \
                 types, which is not a valid identifier: rename the field"
            ),
        )
    })?;
    variant.set_span(field.span());
    Ok(variant)
}

/// One of the runtime's message enums: `{Runtime}Call` (each module's `CallMessage`) or
/// `{Runtime}Event` (each module's `Event`).
pub(crate) struct MessageEnum<'r, 'a> {
    pub(crate) runtime: &'r Runtime<'a>,
    /// The enum's name.
    pub(crate) ident: Ident,
    /// The associated type of `Module` each variant holds.
    pub(crate) message: Ident,
    /// The enum's doc comment.
    pub(crate) doc: String,
    /// What a variant holds, for its doc comment (`calls` → "The calls of the `bank` module").
    pub(crate) holds: &'static str,
    /// Whether to implement `Eq` (`Module::Event` is only `PartialEq`).
    pub(crate) eq: bool,
}

impl MessageEnum<'_, '_> {
    /// The enum, at the call site, deriving `ConsensusType` (each variant's message is one, by
    /// the `Module` bounds).
    pub(crate) fn definition(&self) -> TokenStream {
        let private = common::private();
        let input = self.runtime.input;
        let vis = &input.vis;
        let generics = &input.generics;
        let where_clause = &generics.where_clause;
        let ident = &self.ident;
        let doc = &self.doc;
        let message = &self.message;
        let variants = self.runtime.modules.iter().map(|module| {
            let (variant, ty) = (&module.variant, module.ty);
            let doc = format!(
                "The {} of the runtime's `{}` module.",
                self.holds,
                common::name(module.field)
            );
            quote! {
                #[doc = #doc]
                #variant(<#ty as #private::Module>::#message),
            }
        });
        quote! {
            #[doc = #doc]
            #[derive(#private::ConsensusType)]
            #vis enum #ident #generics #where_clause {
                #(#variants)*
            }
        }
    }

    /// The enum's impls: borsh (tag = discriminant), serde (keyed by name), the JSON schema,
    /// `MessageEnum`, `ModuleMessage`, `Debug`, `Clone`, `PartialEq` (and `Eq`).
    pub(crate) fn impls(&self) -> TokenStream {
        let private = common::private();
        let borsh = quote!(#private::borsh);
        let serde = quote!(#private::serde);
        let schemars = quote!(#private::schemars);
        let generics = &self.runtime.input.generics;
        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
        let ident = &self.ident;
        let message = &self.message;
        let type_name = LitStr::new(&ident.to_string(), ident.span());
        let layout_check = self.runtime.layout_check();
        let modules = &self.runtime.modules;
        let variants: Vec<&Ident> = modules.iter().map(|module| &module.variant).collect();
        let tys: Vec<&Type> = modules.iter().map(|module| module.ty).collect();
        let count = Literal::usize_unsuffixed(modules.len());
        let disc = quote!(#private::ModuleInfo>::DISCRIMINANT);
        let name = quote!(#private::ModuleInfo>::NAME);

        let (writer, reader, tag) = (local("writer"), local("reader"), local("tag"));
        let (serializer, deserializer) = (local("serializer"), local("deserializer"));
        let (discriminant, variant) = (local("discriminant"), local("variant"));
        let (generator, f, other) = (local("generator"), local("f"), local("other"));
        let (msg, msg2) = (local("message"), local("other_message"));
        let w = self.runtime.fresh_param("W");
        let r = self.runtime.fresh_param("R");
        let ser = self.runtime.fresh_param("Ser");
        let de = self.runtime.fresh_param("De");
        let access = self.runtime.fresh_param("A");

        // `impl<'de, …> Deserialize<'de>`
        let mut de_generics = generics.clone();
        de_generics.params.insert(0, syn::parse_quote!('de));
        let (de_impl_generics, _, _) = de_generics.split_for_impl();

        let partial_eq_fallback = (modules.len() > 1).then(|| quote!(_ => false,));
        let eq = self.eq.then(|| {
            quote! {
                #[automatically_derived]
                impl #impl_generics ::core::cmp::Eq for #ident #ty_generics #where_clause {}
            }
        });

        quote! {
            #[automatically_derived]
            impl #impl_generics #borsh::BorshSerialize for #ident #ty_generics #where_clause {
                fn serialize<#w: #borsh::io::Write>(
                    &self,
                    #writer: &mut #w,
                ) -> #borsh::io::Result<()> {
                    #layout_check
                    match self {
                        #(Self::#variants(#msg) => {
                            #borsh::BorshSerialize::serialize(&<#tys as #disc, #writer)?;
                            #borsh::BorshSerialize::serialize(#msg, #writer)
                        })*
                    }
                }
            }

            #[automatically_derived]
            impl #impl_generics #borsh::BorshDeserialize for #ident #ty_generics #where_clause {
                fn deserialize_reader<#r: #borsh::io::Read>(
                    #reader: &mut #r,
                ) -> #borsh::io::Result<Self> {
                    #layout_check
                    let #tag = <::core::primitive::u8 as #borsh::BorshDeserialize>::deserialize_reader(
                        #reader,
                    )?;
                    #(if #tag == <#tys as #disc {
                        return ::core::result::Result::Ok(Self::#variants(
                            #borsh::BorshDeserialize::deserialize_reader(#reader)?,
                        ));
                    })*
                    ::core::result::Result::Err(#private::unknown_module_tag(#tag))
                }
            }

            #[automatically_derived]
            impl #impl_generics #serde::Serialize for #ident #ty_generics #where_clause {
                fn serialize<#ser: #serde::Serializer>(
                    &self,
                    #serializer: #ser,
                ) -> ::core::result::Result<<#ser as #serde::Serializer>::Ok, <#ser as #serde::Serializer>::Error> {
                    #layout_check
                    match self {
                        #(Self::#variants(#msg) => #serde::Serializer::serialize_newtype_variant(
                            #serializer,
                            #type_name,
                            <::core::primitive::u32 as ::core::convert::From<::core::primitive::u8>>::from(
                                <#tys as #disc,
                            ),
                            <#tys as #name,
                            #msg,
                        ),)*
                    }
                }
            }

            #[automatically_derived]
            impl #de_impl_generics #serde::Deserialize<'de> for #ident #ty_generics #where_clause {
                fn deserialize<#de: #serde::Deserializer<'de>>(
                    #deserializer: #de,
                ) -> ::core::result::Result<Self, <#de as #serde::Deserializer<'de>>::Error> {
                    #private::deserialize_message(#deserializer)
                }
            }

            #[automatically_derived]
            impl #impl_generics #private::MessageEnum for #ident #ty_generics #where_clause {
                const TYPE_NAME: &'static ::core::primitive::str = #type_name;
                const MODULES: &'static [(::core::primitive::u8, &'static ::core::primitive::str)] =
                    &[#((<#tys as #disc, <#tys as #name)),*];
                const NAMES: &'static [&'static ::core::primitive::str] = &[#(<#tys as #name),*];

                fn deserialize_variant<'de, #access: #serde::de::VariantAccess<'de>>(
                    #discriminant: ::core::primitive::u8,
                    #variant: #access,
                ) -> ::core::result::Result<Self, <#access as #serde::de::VariantAccess<'de>>::Error> {
                    #layout_check
                    #(if #discriminant == <#tys as #disc {
                        return #serde::de::VariantAccess::newtype_variant::<
                            <#tys as #private::Module>::#message,
                        >(#variant)
                        .map(Self::#variants);
                    })*
                    ::core::result::Result::Err(#private::no_module_with(#discriminant))
                }

                fn variant_schemas(
                    #generator: &mut #schemars::SchemaGenerator,
                ) -> #private::Vec<(&'static ::core::primitive::str, #schemars::Schema)> {
                    <#private::Vec<_> as ::core::convert::From<[_; #count]>>::from([#((
                        <#tys as #name,
                        #schemars::SchemaGenerator::subschema_for::<
                            <#tys as #private::Module>::#message,
                        >(#generator),
                    )),*])
                }
            }

            #[automatically_derived]
            impl #impl_generics #schemars::JsonSchema for #ident #ty_generics #where_clause {
                fn inline_schema() -> ::core::primitive::bool {
                    true
                }

                fn schema_name() -> #private::Cow<'static, ::core::primitive::str> {
                    #private::Cow::Borrowed(#type_name)
                }

                fn json_schema(#generator: &mut #schemars::SchemaGenerator) -> #schemars::Schema {
                    #layout_check
                    #private::messages_schema::<Self>(#generator)
                }
            }

            #[automatically_derived]
            impl #impl_generics #private::ModuleMessage for #ident #ty_generics #where_clause {
                fn module_discriminant(&self) -> ::core::primitive::u8 {
                    #layout_check
                    match self {
                        #(Self::#variants(_) => <#tys as #disc,)*
                    }
                }

                fn module_name(&self) -> &'static ::core::primitive::str {
                    #layout_check
                    match self {
                        #(Self::#variants(_) => <#tys as #name,)*
                    }
                }
            }

            #[automatically_derived]
            impl #impl_generics ::core::fmt::Debug for #ident #ty_generics #where_clause {
                fn fmt(&self, #f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    match self {
                        #(Self::#variants(#msg) => ::core::fmt::Formatter::debug_tuple(
                            #f,
                            ::core::stringify!(#variants),
                        )
                        .field(#msg)
                        .finish(),)*
                    }
                }
            }

            #[automatically_derived]
            impl #impl_generics ::core::clone::Clone for #ident #ty_generics #where_clause {
                fn clone(&self) -> Self {
                    match self {
                        #(Self::#variants(#msg) => Self::#variants(::core::clone::Clone::clone(#msg)),)*
                    }
                }
            }

            #[automatically_derived]
            impl #impl_generics ::core::cmp::PartialEq for #ident #ty_generics #where_clause {
                fn eq(&self, #other: &Self) -> ::core::primitive::bool {
                    match (self, #other) {
                        #((Self::#variants(#msg), Self::#variants(#msg2)) => #msg == #msg2,)*
                        #partial_eq_fallback
                    }
                }
            }

            #eq
        }
    }
}

/// A generated local variable (or parameter) named `name` (a fixed name), with mixed-site
/// hygiene: the input cannot name it, nor shadow it.
pub(crate) fn local(name: &str) -> Ident {
    Ident::new(name, Span::mixed_site())
}

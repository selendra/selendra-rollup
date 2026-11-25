//! The derives' attributes: for `#[derive(ModuleInfo)]`,
//! `#[module_info(discriminant = N, name = "…")]` on the struct and one of `#[id]`,
//! `#[state(item = N)]`, `#[module]`, `#[phantom]` on each field; for
//! `#[derive(ConsensusType)]`, an optional `#[consensus_type(bound(…))]` on the type.
//!
//! Unknown keys inside these attributes are errors (upstream had keys it accepted and then
//! hit `unreachable!` on, P5-30); other attributes on a field (doc comments, `#[allow]`,
//! another derive's) are left alone.

use syn::parse::ParseStream;
use syn::punctuated::Punctuated;
use syn::{
    Attribute, Data, DeriveInput, Field, Ident, LitInt, LitStr, Meta, Path, Token, WherePredicate,
    parenthesized, token,
};

use crate::common;

/// The longest module name: names are `^[a-z][a-z0-9_]{0,31}$`.
pub(crate) const MAX_MODULE_NAME_LEN: usize = 32;

const DISCRIMINANT_RANGE: &str = "the discriminant must be an integer literal in 1..=255";
const ITEM_RANGE: &str = "the item id must be an integer literal in 0..=255";
const STATE_NEEDS_ITEM: &str = "`#[state]` needs an item id: `#[state(item = N)]`, N in 0..=255";
const MODULE_INFO_FORM: &str = "expected `#[module_info(discriminant = N, name = \"…\")]`";

/// The values of a module's `#[module_info(…)]`.
pub(crate) struct ModuleAttrs {
    /// `discriminant = N`: never `0`.
    pub(crate) discriminant: u8,
    /// `name = "…"`: a valid module name.
    pub(crate) name: LitStr,
}

/// What a field of a module is, from its attribute.
pub(crate) enum FieldKind {
    /// `#[id]`: the module's `ModuleId`.
    Id,
    /// `#[state(item = N, codec = path)]`: a state container under the prefix
    /// `(discriminant, item)`, built with the codec `path()` (default `Default::default()`).
    State {
        /// The item id.
        item: u8,
        /// The literal it was written as (for errors).
        item_lit: LitInt,
        /// The codec builder, if not the default.
        codec: Option<Path>,
    },
    /// `#[module]`: a module this one depends on (built with `Default`).
    Module,
    /// `#[phantom]`: a `PhantomData`.
    Phantom,
}

/// The field attributes of the derive.
const FIELD_ATTRS: [&str; 4] = ["id", "state", "module", "phantom"];

/// Parses the struct's one `#[module_info(discriminant = N, name = "…")]`.
pub(crate) fn module_attrs(input: &DeriveInput) -> syn::Result<ModuleAttrs> {
    let mut found: Option<&Attribute> = None;
    for attr in &input.attrs {
        if attr.path().is_ident("module_info") {
            if found.is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate `#[module_info]` attribute",
                ));
            }
            found = Some(attr);
        }
    }
    let Some(attr) = found else {
        return Err(syn::Error::new(
            input.ident.span(),
            "missing `#[module_info(discriminant = N, name = \"…\")]`",
        ));
    };
    let Meta::List(_) = &attr.meta else {
        return Err(syn::Error::new_spanned(attr, MODULE_INFO_FORM));
    };

    let mut discriminant = None;
    let mut name = None;
    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("discriminant") {
            if discriminant.is_some() {
                return Err(meta.error("duplicate `discriminant` in `#[module_info]`"));
            }
            let lit = int_literal(meta.value()?, DISCRIMINANT_RANGE)?;
            let value =
                u8_value(&lit).ok_or_else(|| syn::Error::new(lit.span(), DISCRIMINANT_RANGE))?;
            if value == 0 {
                return Err(syn::Error::new(
                    lit.span(),
                    "discriminant 0 is reserved: use 1..=255",
                ));
            }
            discriminant = Some(value);
            Ok(())
        } else if meta.path.is_ident("name") {
            if name.is_some() {
                return Err(meta.error("duplicate `name` in `#[module_info]`"));
            }
            let lit: LitStr = meta
                .value()?
                .parse()
                .map_err(|error| syn::Error::new(error.span(), "the name must be a string literal"))?;
            if !is_valid_module_name(&lit.value()) {
                return Err(syn::Error::new(
                    lit.span(),
                    format!(
                        "invalid module name {:?}: expected `^[a-z][a-z0-9_]{{0,31}}$` (a lowercase \
                         letter, then at most 31 lowercase letters, digits or `_`)",
                        lit.value()
                    ),
                ));
            }
            name = Some(lit);
            Ok(())
        } else {
            Err(meta.error(format!(
                "unknown key `{}` in `#[module_info]`: expected `discriminant` or `name`",
                path_name(&meta.path)
            )))
        }
    })?;

    let discriminant = discriminant.ok_or_else(|| {
        syn::Error::new_spanned(attr, "`#[module_info]` is missing `discriminant = N`")
    })?;
    let name = name.ok_or_else(|| {
        syn::Error::new_spanned(attr, "`#[module_info]` is missing `name = \"…\"`")
    })?;
    Ok(ModuleAttrs { discriminant, name })
}

const CONSENSUS_TYPE_FORM: &str = "expected `#[consensus_type(bound(…))]`, with unquoted where \
     predicates inside `bound(…)` (e.g. `bound(T: ConsensusType)`), or none";
const BOUND_FORM: &str = "expected `bound(…)`, with unquoted where predicates inside (e.g. \
     `bound(T: ConsensusType)`), or none";

/// A type's `#[consensus_type(bound(…))]`.
pub(crate) struct ConsensusTypeBound<'a> {
    /// The attribute (for errors).
    pub(crate) attr: &'a Attribute,
    /// The where predicates inside `bound(…)` (possibly none).
    pub(crate) predicates: Punctuated<WherePredicate, Token![,]>,
}

/// Parses the type's optional `#[consensus_type(bound(…))]` (`None` without it). The attribute
/// goes on the type only: one on a field or a variant is an error (it would otherwise be
/// ignored).
pub(crate) fn consensus_type_bound(
    input: &DeriveInput,
) -> syn::Result<Option<ConsensusTypeBound<'_>>> {
    let inner_attrs: Vec<&Attribute> = match &input.data {
        Data::Struct(data) => data.fields.iter().flat_map(|field| &field.attrs).collect(),
        Data::Enum(data) => data
            .variants
            .iter()
            .flat_map(|variant| {
                variant
                    .attrs
                    .iter()
                    .chain(variant.fields.iter().flat_map(|field| &field.attrs))
            })
            .collect(),
        // Rejected by the derive before its attributes are read.
        Data::Union(_) => Vec::new(),
    };
    if let Some(attr) = inner_attrs
        .into_iter()
        .find(|attr| attr.path().is_ident("consensus_type"))
    {
        return Err(syn::Error::new_spanned(
            attr,
            "`#[consensus_type]` goes on the type, not on a field or a variant",
        ));
    }

    let mut found: Option<&Attribute> = None;
    for attr in &input.attrs {
        if attr.path().is_ident("consensus_type") {
            if found.is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate `#[consensus_type]` attribute",
                ));
            }
            found = Some(attr);
        }
    }
    let Some(attr) = found else {
        return Ok(None);
    };
    let Meta::List(_) = &attr.meta else {
        return Err(syn::Error::new_spanned(attr, CONSENSUS_TYPE_FORM));
    };

    let mut bound = None;
    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("bound") {
            if bound.is_some() {
                return Err(meta.error("duplicate `bound` in `#[consensus_type]`"));
            }
            if !meta.input.peek(token::Paren) {
                return Err(meta.error(BOUND_FORM));
            }
            let content;
            parenthesized!(content in meta.input);
            bound = Some(Punctuated::<WherePredicate, Token![,]>::parse_terminated(
                &content,
            )?);
            Ok(())
        } else {
            Err(meta.error(format!(
                "unknown key `{}` in `#[consensus_type]`: expected `bound`",
                path_name(&meta.path)
            )))
        }
    })?;
    let predicates = bound.ok_or_else(|| syn::Error::new_spanned(attr, CONSENSUS_TYPE_FORM))?;
    Ok(Some(ConsensusTypeBound { attr, predicates }))
}

/// Parses the attribute that says what `field` (named `ident`) is.
pub(crate) fn field_kind(field: &Field, ident: &Ident) -> syn::Result<FieldKind> {
    let mut ours = field
        .attrs
        .iter()
        .filter(|attr| FIELD_ATTRS.iter().any(|name| attr.path().is_ident(name)));
    let Some(attr) = ours.next() else {
        return Err(syn::Error::new(
            ident.span(),
            format!(
                "field `{}` needs one of `#[id]`, `#[state(item = N)]`, `#[module]` or `#[phantom]`",
                common::name(ident)
            ),
        ));
    };
    if let Some(second) = ours.next() {
        return Err(syn::Error::new_spanned(
            second,
            format!(
                "field `{}` has more than one of `#[id]`, `#[state]`, `#[module]` and `#[phantom]`",
                common::name(ident)
            ),
        ));
    }

    if attr.path().is_ident("state") {
        return state_attr(attr);
    }
    let Meta::Path(path) = &attr.meta else {
        return Err(syn::Error::new_spanned(
            attr,
            format!("`#[{}]` takes no arguments", path_name(attr.path())),
        ));
    };
    if path.is_ident("id") {
        Ok(FieldKind::Id)
    } else if path.is_ident("module") {
        Ok(FieldKind::Module)
    } else {
        Ok(FieldKind::Phantom)
    }
}

/// Parses `#[state(item = N, codec = path)]`.
fn state_attr(attr: &Attribute) -> syn::Result<FieldKind> {
    let Meta::List(_) = &attr.meta else {
        return Err(syn::Error::new_spanned(attr, STATE_NEEDS_ITEM));
    };
    let mut item = None;
    let mut codec = None;
    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("item") {
            if item.is_some() {
                return Err(meta.error("duplicate `item` in `#[state]`"));
            }
            let lit = int_literal(meta.value()?, ITEM_RANGE)?;
            let value = u8_value(&lit).ok_or_else(|| syn::Error::new(lit.span(), ITEM_RANGE))?;
            item = Some((value, lit));
            Ok(())
        } else if meta.path.is_ident("codec") {
            if codec.is_some() {
                return Err(meta.error("duplicate `codec` in `#[state]`"));
            }
            codec = Some(meta.value()?.parse::<Path>()?);
            Ok(())
        } else {
            Err(meta.error(format!(
                "unknown key `{}` in `#[state]`: expected `item` or `codec`",
                path_name(&meta.path)
            )))
        }
    })?;
    let (item, item_lit) = item.ok_or_else(|| syn::Error::new_spanned(attr, STATE_NEEDS_ITEM))?;
    Ok(FieldKind::State {
        item,
        item_lit,
        codec,
    })
}

/// An integer literal alone (up to the next `,`), or the error `message` spanned at what is
/// there instead (another token, or what follows the literal, e.g. the `+` of `1 + 2`).
fn int_literal(input: ParseStream<'_>, message: &str) -> syn::Result<LitInt> {
    let lit = input
        .parse::<LitInt>()
        .map_err(|error| syn::Error::new(error.span(), message))?;
    if !input.is_empty() && !input.peek(Token![,]) {
        return Err(syn::Error::new(input.span(), message));
    }
    Ok(lit)
}

/// The value of an integer literal that fits a `u8` and has no suffix or `u8`.
fn u8_value(lit: &LitInt) -> Option<u8> {
    if !matches!(lit.suffix(), "" | "u8") {
        return None;
    }
    lit.base10_parse::<u8>().ok()
}

/// Whether `name` is a module name: `^[a-z][a-z0-9_]{0,31}$`.
pub(crate) fn is_valid_module_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= MAX_MODULE_NAME_LEN
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// A path as written, segments joined by `::` (for error messages).
fn path_name(path: &Path) -> String {
    path.segments
        .iter()
        .map(|segment| common::name(&segment.ident))
        .collect::<Vec<_>>()
        .join("::")
}

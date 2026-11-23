//! What the derives share: the path every generated item goes through, the anonymous constant
//! the items are generated in, and token helpers.

use proc_macro2::{Group, Ident, TokenStream, TokenTree};
use quote::quote;
use syn::ext::IdentExt;

/// The module every path the derives generate goes through: `::selendra_modules_api::__private`
/// (with a leading `::`, so a local item named `selendra_modules_api` cannot shadow it).
pub(crate) fn private() -> TokenStream {
    quote!(::selendra_modules_api::__private)
}

/// `items` inside an anonymous constant (`const _: () = { … };`): helper items defined there
/// cannot clash with anything at the call site, and nothing outside can name them.
pub(crate) fn in_anonymous_const(items: TokenStream) -> TokenStream {
    quote! {
        const _: () = {
            #items
        };
    }
}

/// An identifier's name without the `r#` of a raw identifier (`r#type` → `type`): the name the
/// derives store (state item names, event names) and compare identifiers by.
pub(crate) fn name(ident: &Ident) -> String {
    ident.unraw().to_string()
}

/// Whether `tokens` contain, at any depth, an identifier named like one of `names`
/// (compared by [`name`]).
pub(crate) fn mentions(tokens: TokenStream, names: &[String]) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(ident) => names.contains(&name(&ident)),
        TokenTree::Group(group) => mentions(group.stream(), names),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

/// `tokens` with every `Self` replaced by `with`, at any depth (for a type written inside a
/// type definition, used outside of it).
pub(crate) fn replace_self(tokens: TokenStream, with: &TokenStream) -> TokenStream {
    let mut out = TokenStream::new();
    for token in tokens {
        match token {
            TokenTree::Ident(ident) if ident == "Self" => out.extend(with.clone()),
            TokenTree::Group(group) => {
                let mut replaced =
                    Group::new(group.delimiter(), replace_self(group.stream(), with));
                replaced.set_span(group.span());
                out.extend([TokenTree::Group(replaced)]);
            }
            other => out.extend([other]),
        }
    }
    out
}

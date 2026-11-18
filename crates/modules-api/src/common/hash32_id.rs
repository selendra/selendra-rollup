//! [`hash32_id!`](crate::hash32_id): 32-byte identifiers shown as bech32m strings (module ids;
//! Phase 6's token ids and derived holders).

use selendra_primitives::bech32::{self, Bech32ParseError};

/// The longest prefix [`hash32_id!`](crate::hash32_id) accepts. With 32 bytes (52 data symbols,
/// a separator and a 6-symbol checksum), the string stays within bech32m's 90 characters.
pub const MAX_HASH32_ID_PREFIX_LEN: usize = 20;

/// A byte slice that is not 32 bytes long.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("an id is 32 bytes long, got {found}")]
pub struct InvalidIdLength {
    /// The length of the slice.
    pub found: usize,
}

/// Whether `prefix` is a valid [`hash32_id!`](crate::hash32_id) prefix: 1 to
/// [`MAX_HASH32_ID_PREFIX_LEN`] characters out of `a-z`, `0-9` and `_` (so it needs no escaping
/// in the JSON schema's pattern). Checked at compile time by the macro.
#[doc(hidden)]
pub const fn __is_valid_prefix(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_HASH32_ID_PREFIX_LEN {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return false;
        }
        i += 1;
    }
    true
}

/// The bech32m string of an id.
#[doc(hidden)]
pub fn __encode(prefix: &'static str, bytes: &[u8; 32]) -> String {
    bech32::encode(prefix, bytes)
}

/// Parses an id's bech32m string. Only the string [`__encode`] prints is accepted: lowercase,
/// the right prefix, the canonical encoding of 32 bytes (no extra padding symbol, zero padding
/// bits).
///
/// P5-22: upstream decoded the data symbols with `byte_iter` after checking only the symbol
/// count, which ignores the 4 padding bits of a 32-byte payload: 16 strings decoded to each id.
#[doc(hidden)]
pub fn __parse(prefix: &'static str, s: &str) -> Result<[u8; 32], Bech32ParseError> {
    // bech32 allows an all-uppercase string; an id has one spelling.
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(Bech32ParseError::NonCanonical);
    }
    // Rejects a wrong prefix, a wrong length and a non-canonical encoding.
    bech32::decode::<32>(prefix, s)
}

/// The JSON schema of an id with this prefix.
#[doc(hidden)]
pub fn __json_schema(prefix: &'static str) -> schemars::Schema {
    // 32 bytes: 52 data symbols and a 6-symbol checksum after the separator `1`.
    schemars::json_schema!({
        "type": "string",
        "pattern": format!("^{prefix}1[02-9ac-hj-np-z]{{58}}$"),
        "description": format!("32 bytes as bech32m with the `{prefix}` prefix"),
    })
}

/// Defines a 32-byte identifier type shown as a bech32m string with a fixed prefix.
///
/// ```
/// selendra_modules_api::hash32_id! {
///     /// The id of a widget.
///     pub struct WidgetId, prefix = "widget_"
/// }
///
/// let id = WidgetId::new([7; 32]);
/// let text = id.to_string();
/// assert!(text.starts_with("widget_1"));
/// assert_eq!(text.parse::<WidgetId>().unwrap(), id);
/// ```
///
/// The type is `[u8; 32]` with a private field ([`new`](crate::ModuleId::new),
/// [`as_bytes`](crate::ModuleId::as_bytes), `From<[u8; 32]>`, `TryFrom<&[u8]>`), and:
/// - borsh: the 32 bytes; a consensus type;
/// - [`Display`](std::fmt::Display), [`FromStr`](std::str::FromStr) and JSON (and every
///   human-readable serde format): bech32m, `<prefix>1…`. Parsing accepts only that string:
///   lowercase, the canonical encoding (no extra padding symbol, zero padding bits);
/// - binary serde formats: the 32 bytes;
/// - a JSON schema named after the type, with the string's pattern.
///
/// The prefix is 1 to 20 characters out of `a-z`, `0-9` and `_` (checked at compile time):
///
/// ```compile_fail,E0080
/// selendra_modules_api::hash32_id! {
///     /// Not a valid prefix.
///     pub struct WidgetId, prefix = "Widget"
/// }
/// ```
#[macro_export]
macro_rules! hash32_id {
    ($(#[$meta:meta])* $vis:vis struct $id:ident, prefix = $prefix:literal $(,)?) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis struct $id([u8; 32]);

        const _: () = assert!(
            $crate::common::__is_valid_prefix($prefix),
            "a hash32_id! prefix is 1 to 20 characters out of a-z, 0-9 and _"
        );

        impl $id {
            /// The bech32m prefix of the text form.
            pub const PREFIX: &'static str = $prefix;

            /// The id with these bytes.
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// The id's bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// The bech32m string (the same as `to_string()`).
            pub fn to_bech32(self) -> ::std::string::String {
                $crate::common::__encode($prefix, &self.0)
            }
        }

        impl ::core::convert::From<[u8; 32]> for $id {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl ::core::convert::From<$id> for [u8; 32] {
            fn from(id: $id) -> Self {
                id.0
            }
        }

        impl ::core::convert::AsRef<[u8]> for $id {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl ::core::convert::TryFrom<&[u8]> for $id {
            type Error = $crate::common::InvalidIdLength;

            fn try_from(bytes: &[u8]) -> ::core::result::Result<Self, Self::Error> {
                <[u8; 32]>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| $crate::common::InvalidIdLength { found: bytes.len() })
            }
        }

        impl ::core::fmt::Display for $id {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(&self.to_bech32())
            }
        }

        impl ::core::fmt::Debug for $id {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(f, "{}({})", ::core::stringify!($id), self)
            }
        }

        impl ::core::str::FromStr for $id {
            type Err = $crate::__private::bech32::Bech32ParseError;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                $crate::common::__parse($prefix, s).map(Self)
            }
        }

        impl $crate::__private::borsh::BorshSerialize for $id {
            fn serialize<W: $crate::__private::borsh::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::__private::borsh::io::Result<()> {
                writer.write_all(&self.0)
            }
        }

        impl $crate::__private::borsh::BorshDeserialize for $id {
            fn deserialize_reader<R: $crate::__private::borsh::io::Read>(
                reader: &mut R,
            ) -> $crate::__private::borsh::io::Result<Self> {
                <[u8; 32] as $crate::__private::borsh::BorshDeserialize>::deserialize_reader(reader)
                    .map(Self)
            }
        }

        impl $crate::__private::ConsensusType for $id {}

        impl $crate::__private::serde::Serialize for $id {
            fn serialize<S: $crate::__private::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    serializer.collect_str(self)
                } else {
                    <[u8; 32] as $crate::__private::serde::Serialize>::serialize(&self.0, serializer)
                }
            }
        }

        impl<'de> $crate::__private::serde::Deserialize<'de> for $id {
            fn deserialize<D: $crate::__private::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                if deserializer.is_human_readable() {
                    let s = <::std::string::String as $crate::__private::serde::Deserialize>::deserialize(
                        deserializer,
                    )?;
                    s.parse()
                        .map_err(<D::Error as $crate::__private::serde::de::Error>::custom)
                } else {
                    <[u8; 32] as $crate::__private::serde::Deserialize>::deserialize(deserializer)
                        .map(Self)
                }
            }
        }

        impl $crate::__private::schemars::JsonSchema for $id {
            fn schema_name() -> ::std::borrow::Cow<'static, str> {
                ::std::borrow::Cow::Borrowed(::core::stringify!($id))
            }

            fn json_schema(
                _generator: &mut $crate::__private::schemars::SchemaGenerator,
            ) -> $crate::__private::schemars::Schema {
                $crate::common::__json_schema($prefix)
            }
        }

        $crate::__hash32_id_arbitrary!($id);
    };
}

/// `arbitrary::Arbitrary` and proptest's `Arbitrary` for a [`hash32_id!`](crate::hash32_id)
/// type, with this crate's `arbitrary` feature (a `#[cfg]` in the macro's output would test
/// the calling crate's features instead).
#[cfg(feature = "arbitrary")]
#[doc(hidden)]
#[macro_export]
macro_rules! __hash32_id_arbitrary {
    ($id:ident) => {
        impl<'a> $crate::__private::arbitrary::Arbitrary<'a> for $id {
            fn arbitrary(
                u: &mut $crate::__private::arbitrary::Unstructured<'a>,
            ) -> $crate::__private::arbitrary::Result<Self> {
                <[u8; 32] as $crate::__private::arbitrary::Arbitrary<'a>>::arbitrary(u).map(Self)
            }
        }

        impl $crate::__private::proptest::arbitrary::Arbitrary for $id {
            type Parameters = ();
            type Strategy = $crate::__private::proptest::strategy::Map<
                $crate::__private::proptest::array::UniformArrayStrategy<
                    $crate::__private::proptest::num::u8::Any,
                    [u8; 32],
                >,
                fn([u8; 32]) -> Self,
            >;

            fn arbitrary_with((): ()) -> Self::Strategy {
                $crate::__private::proptest::strategy::Strategy::prop_map(
                    $crate::__private::proptest::array::uniform32(
                        $crate::__private::proptest::num::u8::ANY,
                    ),
                    Self::new as fn([u8; 32]) -> Self,
                )
            }
        }
    };
}

/// Without this crate's `arbitrary` feature: nothing.
#[cfg(not(feature = "arbitrary"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __hash32_id_arbitrary {
    ($id:ident) => {};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ModuleId;

    crate::hash32_id! {
        /// A second id type (Phase 6's token ids use the macro too).
        pub struct TestTokenId, prefix = "token_"
    }

    /// Known answers computed independently (Python's BIP-350 reference code):
    /// `bech32m("module_", [0x00, 0x01, …, 0x1f])` and `bech32m("token_", [0xff; 32])`.
    const MODULE_ID_0_TO_31: &str =
        "module_1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s62mfmt";
    const TOKEN_ID_ALL_FF: &str =
        "token_1llllllllllllllllllllllllllllllllllllllllllllllllllls3h988v";

    fn counting() -> [u8; 32] {
        std::array::from_fn(|i| u8::try_from(i).unwrap())
    }

    #[test]
    fn hash32_id_text_known_answers() {
        let module = ModuleId::new(counting());
        assert_eq!(module.to_string(), MODULE_ID_0_TO_31);
        assert_eq!(module.to_bech32(), MODULE_ID_0_TO_31);
        assert_eq!(MODULE_ID_0_TO_31.parse::<ModuleId>().unwrap(), module);
        assert_eq!(
            format!("{module:?}"),
            format!("ModuleId({MODULE_ID_0_TO_31})")
        );

        let token = TestTokenId::new([0xff; 32]);
        assert_eq!(token.to_string(), TOKEN_ID_ALL_FF);
        assert_eq!(TOKEN_ID_ALL_FF.parse::<TestTokenId>().unwrap(), token);
    }

    #[test]
    fn hash32_id_rejects_other_strings() {
        let canonical = MODULE_ID_0_TO_31;
        // A well-formed string (prefix, separator, 52 data and 6 checksum symbols, all from the
        // charset) whose last checksum symbol is changed (`t` → `q`): only the checksum check
        // rejects it.
        let mut wrong_checksum = canonical.to_string();
        assert_eq!(wrong_checksum.pop(), Some('t'));
        wrong_checksum.push('q');
        let (_, data) = wrong_checksum.rsplit_once('1').unwrap();
        assert_eq!(data.len(), 52 + 6);
        let err = wrong_checksum.parse::<ModuleId>().unwrap_err();
        assert!(
            matches!(err, Bech32ParseError::Bech32(_))
                && format!("{err:?}").contains("Checksum(InvalidResidue"),
            "{err:?}"
        );
        for rejected in [
            canonical.to_ascii_uppercase(),
            canonical.replacen("module_", "token_", 1),
            format!(" {canonical}"),
            String::new(),
            // The id of `[0; 31]`: 31 bytes.
            "module_1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwkhp".to_string(),
        ] {
            assert!(
                rejected.parse::<ModuleId>().is_err(),
                "{rejected:?} accepted"
            );
        }
        // A token id is not a module id, nor the other way round.
        assert!(TOKEN_ID_ALL_FF.parse::<ModuleId>().is_err());
        assert!(MODULE_ID_0_TO_31.parse::<TestTokenId>().is_err());
    }

    #[test]
    fn hash32_id_encodings() {
        let id = ModuleId::new(counting());
        assert_eq!(borsh::to_vec(&id).unwrap(), counting());
        assert_eq!(borsh::from_slice::<ModuleId>(&counting()).unwrap(), id);
        assert!(borsh::from_slice::<ModuleId>(&counting()[..31]).is_err());
        let mut long = counting().to_vec();
        long.push(0);
        assert!(borsh::from_slice::<ModuleId>(&long).is_err());

        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{MODULE_ID_0_TO_31}\""));
        assert_eq!(serde_json::from_str::<ModuleId>(&json).unwrap(), id);
        assert!(serde_json::from_str::<ModuleId>("[0,1]").is_err());

        let binary = postcard::to_allocvec(&id).unwrap();
        assert_eq!(binary, postcard::to_allocvec(&counting()).unwrap());
        assert_eq!(postcard::from_bytes::<ModuleId>(&binary).unwrap(), id);

        assert_eq!(ModuleId::try_from(&counting()[..]).unwrap(), id);
        assert_eq!(
            ModuleId::try_from(&counting()[..31]),
            Err(InvalidIdLength { found: 31 })
        );
        assert_eq!(<[u8; 32]>::from(id), counting());
        assert_eq!(id.as_ref(), &counting()[..]);
    }

    #[test]
    fn hash32_id_schemas_name_the_type() {
        let schema = schemars::schema_for!(TestTokenId);
        let json = serde_json::to_value(&schema).unwrap();
        assert_eq!(json["title"], "TestTokenId");
        assert_eq!(json["pattern"], "^token_1[02-9ac-hj-np-z]{58}$");
        // The printed strings fit the pattern: the prefix, `1`, then 58 symbols.
        assert_eq!(TOKEN_ID_ALL_FF.len(), "token_1".len() + 58);
        assert_eq!(MODULE_ID_0_TO_31.len(), "module_1".len() + 58);
    }

    #[test]
    fn prefixes_are_checked() {
        assert!(__is_valid_prefix("module_"));
        assert!(__is_valid_prefix("a"));
        assert!(__is_valid_prefix("abcdefghij0123456789"));
        assert!(!__is_valid_prefix(""));
        assert!(!__is_valid_prefix("abcdefghij0123456789x"));
        assert!(!__is_valid_prefix("Module"));
        assert!(!__is_valid_prefix("mod-ule"));
        assert!(!__is_valid_prefix("mod.ule"));
    }

    // Regressions of upstream's bech32 id bugs

    /// P5-22 (regression): bech32 ids accepted non-zero padding bits (upstream decoded with
    /// `byte_iter`, which drops them), so 16 strings decoded to the same id. Checked on the
    /// generic macro with two id types. The strings were computed independently (Python's
    /// BIP-350 reference code) from the canonical data symbols of the ids above: 32 bytes are
    /// 52 symbols, the last one holding 1 data bit and 4 padding bits.
    #[test]
    fn hash32_id_rejects_noncanonical_padding() {
        // `[0, 1, …, 31]`, last symbol `s` (`0b10000`) → `3` (`0b10001`), checksum recomputed.
        let module_padded = "module_1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc038u0uxe";
        // `[0xff; 32]`, last symbol `s` (`0b10000`) → `l` (`0b11111`), checksum recomputed.
        let token_padded = "token_1llllllllllllllllllllllllllllllllllllllllllllllllllllw6kmc5";
        for (s, err) in [
            (module_padded, module_padded.parse::<ModuleId>().err()),
            (token_padded, token_padded.parse::<TestTokenId>().err()),
        ] {
            assert!(
                matches!(err, Some(Bech32ParseError::NonCanonical)),
                "{s} accepted: {err:?}"
            );
        }
    }
}

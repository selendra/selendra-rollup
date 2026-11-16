//! [`SizedSafeString`]: a short string of printable ASCII.

use std::borrow::Cow;
use std::fmt::Display;
use std::io::Read;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use thiserror::Error;

use crate::common::ConsensusType;

/// Why a string is not a valid [`SizedSafeString`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SafeStringError {
    /// More bytes than the maximum.
    #[error("String was too long: {length}, maximum: {max}")]
    StringTooLong {
        /// The string's length in bytes.
        length: usize,
        /// The maximum.
        max: usize,
    },
    /// A character outside printable ASCII.
    #[error(
        "String contained invalid character: {character}. Only printable ASCII characters are allowed."
    )]
    InvalidCharacter {
        /// The first invalid character.
        character: char,
    },
}

/// A string of at most `MAX_LEN` bytes of printable ASCII (`0x20..=0x7e`: no control
/// characters, no Unicode), safe to show in a transaction without confusing the user.
///
/// Use it instead of `String` in call messages and stored values (e.g. a token name or a
/// memo). Every decoder checks the charset, and rejects a string over the cap before
/// allocating for it: borsh checks the length prefix, serde checks the string the format hands
/// over before copying it (a format's own buffer, e.g. serde_json's for an escaped string, is
/// bounded by the input).
///
/// Encodings: borsh and serde like `String` (borsh: `u32` LE length, then the bytes; JSON: a
/// string). JSON schema: a string with `maxLength` `MAX_LEN` and the pattern
/// `^[\x20-\x7e]*$`.
#[derive(Default, Hash, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(into = "String")]
pub struct SizedSafeString<const MAX_LEN: usize>(String);

/// The default maximum length of a [`SafeString`].
pub const DEFAULT_MAX_STRING_LENGTH: usize = 128;

/// A [`SizedSafeString`] of at most [`DEFAULT_MAX_STRING_LENGTH`] bytes.
pub type SafeString = SizedSafeString<DEFAULT_MAX_STRING_LENGTH>;

impl<const MAX_LEN: usize> SizedSafeString<MAX_LEN> {
    /// The maximum length in bytes.
    pub const MAX_LEN: usize = MAX_LEN;

    /// Returns the string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The maximum length of this type, in bytes.
    pub const fn max_len(&self) -> usize {
        MAX_LEN
    }

    /// Returns an empty string. Does not allocate.
    pub const fn new() -> Self {
        Self(String::new())
    }

    /// Returns the length of the string in bytes (= characters).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Appends `c` if it is printable ASCII and the string is not full.
    pub fn try_push(&mut self, c: char) -> Result<(), SafeStringError> {
        if self.len() >= MAX_LEN {
            return Err(SafeStringError::StringTooLong {
                length: self.len().saturating_add(1),
                max: MAX_LEN,
            });
        }
        if !Self::is_valid_char(c) {
            return Err(SafeStringError::InvalidCharacter { character: c });
        }
        self.0.push(c);
        Ok(())
    }

    /// Returns true if `c` may appear in a [`SizedSafeString`]: printable ASCII.
    pub const fn is_valid_char(c: char) -> bool {
        c.is_ascii() && !c.is_ascii_control()
    }

    fn check(value: &str) -> Result<(), SafeStringError> {
        if value.len() > MAX_LEN {
            return Err(SafeStringError::StringTooLong {
                length: value.len(),
                max: MAX_LEN,
            });
        }
        match value.chars().find(|c| !Self::is_valid_char(*c)) {
            Some(character) => Err(SafeStringError::InvalidCharacter { character }),
            None => Ok(()),
        }
    }
}

impl<const MAX_LEN: usize> ConsensusType for SizedSafeString<MAX_LEN> {}

impl<const MAX_LEN: usize> BorshSerialize for SizedSafeString<MAX_LEN> {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.serialize(writer)
    }
}

impl<const MAX_LEN: usize> BorshDeserialize for SizedSafeString<MAX_LEN> {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let invalid = |msg: String| std::io::Error::new(std::io::ErrorKind::InvalidData, msg);
        let len = u32::deserialize_reader(reader)?;
        if usize::try_from(len).map_or(true, |len| len > MAX_LEN) {
            return Err(invalid(format!(
                "SizedSafeString length {len} exceeds the maximum of {MAX_LEN}"
            )));
        }
        // Within the cap: decode like `String`, with the length prefix put back in front.
        let prefix = len.to_le_bytes();
        let string = String::deserialize_reader(&mut prefix.as_slice().chain(reader))?;
        Self::check(&string).map_err(|e| invalid(e.to_string()))?;
        Ok(Self(string))
    }
}

impl<'de, const MAX_LEN: usize> serde::Deserialize<'de> for SizedSafeString<MAX_LEN> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SafeStringVisitor<const MAX_LEN: usize>;

        impl<const MAX_LEN: usize> serde::de::Visitor<'_> for SafeStringVisitor<MAX_LEN> {
            type Value = SizedSafeString<MAX_LEN>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    formatter,
                    "a string of at most {MAX_LEN} printable ASCII characters"
                )
            }

            // Checked before it is copied: a string over the cap is rejected without
            // allocating for it.
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                SizedSafeString::try_from(v).map_err(E::custom)
            }

            // Already allocated by the format: checked, then kept rather than copied.
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                SizedSafeString::try_from(v).map_err(E::custom)
            }

            // Like `String`: UTF-8 bytes are accepted as a string.
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                let string = std::str::from_utf8(v)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Bytes(v), &self))?;
                self.visit_str(string)
            }
        }

        deserializer.deserialize_str(SafeStringVisitor::<MAX_LEN>)
    }
}

impl<const MAX_LEN: usize> schemars::JsonSchema for SizedSafeString<MAX_LEN> {
    fn schema_name() -> Cow<'static, str> {
        format!("SafeStringMax{MAX_LEN}").into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "maxLength": MAX_LEN,
            "pattern": r"^[\x20-\x7e]*$",
            "description": format!("Printable ASCII (no control characters), at most {MAX_LEN} characters."),
        })
    }
}

/// Generates at most `MAX_LEN` printable ASCII characters.
#[cfg(feature = "arbitrary")]
impl<'a, const MAX_LEN: usize> arbitrary::Arbitrary<'a> for SizedSafeString<MAX_LEN> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.arbitrary_len::<u8>()?.min(MAX_LEN);
        (0..len)
            .map(|_| u.int_in_range(0x20u8..=0x7e).map(char::from))
            .collect::<arbitrary::Result<String>>()
            .map(Self)
    }
}

/// Generates at most `min(MAX_LEN, PROPTEST_MAX_LEN)` printable ASCII characters.
#[cfg(feature = "arbitrary")]
impl<const MAX_LEN: usize> proptest::arbitrary::Arbitrary for SizedSafeString<MAX_LEN> {
    type Parameters = ();
    type Strategy = proptest::strategy::Map<
        proptest::collection::VecStrategy<std::ops::RangeInclusive<u8>>,
        fn(Vec<u8>) -> Self,
    >;

    fn arbitrary_with((): ()) -> Self::Strategy {
        use proptest::strategy::Strategy;
        proptest::collection::vec(
            0x20u8..=0x7e,
            0..=MAX_LEN.min(super::safe_vec::PROPTEST_MAX_LEN),
        )
        .prop_map(
            (|bytes: Vec<u8>| Self(bytes.into_iter().map(char::from).collect()))
                as fn(Vec<u8>) -> Self,
        )
    }
}

impl<const MAX_LEN: usize> TryFrom<String> for SizedSafeString<MAX_LEN> {
    type Error = SafeStringError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::check(&value)?;
        Ok(Self(value))
    }
}

impl<'a, const MAX_LEN: usize> TryFrom<&'a str> for SizedSafeString<MAX_LEN> {
    type Error = SafeStringError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::check(value)?;
        Ok(Self(value.to_owned()))
    }
}

impl<const MAX_LEN: usize> FromStr for SizedSafeString<MAX_LEN> {
    type Err = SafeStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl<const MAX_LEN: usize> From<SizedSafeString<MAX_LEN>> for String {
    fn from(value: SizedSafeString<MAX_LEN>) -> Self {
        value.0
    }
}

impl<const MAX_LEN: usize> AsRef<[u8]> for SizedSafeString<MAX_LEN> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const MAX_LEN: usize> AsRef<str> for SizedSafeString<MAX_LEN> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<const MAX_LEN: usize> std::fmt::Debug for SizedSafeString<MAX_LEN> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl<const MAX_LEN: usize> Display for SizedSafeString<MAX_LEN> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{SafeString, SafeStringError, SizedSafeString};

    #[test]
    fn test_sizedsafestring_maxlen() {
        let string_good: String = ['a'; 31].iter().collect();
        let string_bad: String = ['a'; 32].iter().collect();

        let conversion_good = <SizedSafeString<31>>::try_from(string_good);
        assert!(conversion_good.is_ok());

        let conversion_bad = <SizedSafeString<31>>::try_from(string_bad);
        assert_eq!(
            conversion_bad,
            Err(SafeStringError::StringTooLong {
                length: 32,
                max: 31
            })
        );
    }

    #[test]
    fn test_safestring_default_len() {
        let string_good: String = ['a'; 128].iter().collect();
        let string_bad: String = ['a'; 129].iter().collect();

        let conversion_good = SafeString::try_from(string_good);
        assert!(conversion_good.is_ok());

        let conversion_bad = SafeString::try_from(string_bad);
        assert_eq!(
            conversion_bad,
            Err(SafeStringError::StringTooLong {
                length: 129,
                max: 128
            })
        );
    }

    #[test]
    fn test_safestring_rejects_nonascii() {
        let string = "hello •";
        let conversion = SafeString::try_from(string);
        assert_eq!(
            conversion,
            Err(SafeStringError::InvalidCharacter { character: '•' })
        );
    }

    #[test]
    fn test_safestring_rejects_control_chars() {
        for (string, character) in [("hello \n world", '\n'), ("del\x7f", '\x7f'), ("\0", '\0')] {
            assert_eq!(
                SafeString::try_from(string),
                Err(SafeStringError::InvalidCharacter { character })
            );
        }
        assert!(SafeString::try_from(" ~").is_ok());
    }

    #[test]
    fn test_try_push() {
        let mut s = SizedSafeString::<2>::new();
        s.try_push('a').unwrap();
        assert_eq!(
            s.try_push('\n'),
            Err(SafeStringError::InvalidCharacter { character: '\n' })
        );
        s.try_push('~').unwrap();
        assert_eq!(
            s.try_push('b'),
            Err(SafeStringError::StringTooLong { length: 3, max: 2 })
        );
        assert_eq!(s.as_str(), "a~");
    }

    #[test]
    fn json_deserializing_safestring_accepts_valid() {
        let de: SafeString = serde_json::from_str("\"Good string\"").unwrap();
        let expected: SafeString = "Good string".try_into().unwrap();
        assert_eq!(de, expected);
        assert_eq!(serde_json::to_string(&de).unwrap(), "\"Good string\"");
    }

    #[test]
    fn json_deserializing_safestring_rejects_invalid() {
        let de: Result<SafeString, _> = serde_json::from_str("\"Bad•string\"");
        assert_eq!(
            de.unwrap_err().to_string(),
            // The check runs inside the visitor, so serde_json adds the position.
            "String contained invalid character: •. Only printable ASCII characters are allowed. at line 1 column 14"
        );
    }

    #[test]
    fn test_safe_string_borsh_invalid_char() {
        use borsh::{BorshDeserialize, to_vec};
        // the SafeString does not accept ascii control chars and is limited to 128 chars
        let input = String::from_utf8(vec![b'\n'; 1]).unwrap();
        assert_eq!(None, SafeString::try_from(input.clone()).ok());
        let encoded = to_vec(&input).unwrap();
        let output = SafeString::try_from_slice(&encoded);
        assert!(output.is_err());
        // Invalid UTF-8, too.
        assert!(SafeString::try_from_slice(&[1, 0, 0, 0, 0xff]).is_err());
    }

    #[test]
    fn test_safe_string_borsh_too_long() {
        use borsh::{BorshDeserialize, to_vec};
        // the SafeString does not accept ascii control chars and is limited to 128 chars
        let large_input = String::from_utf8(vec![b'a'; 300]).unwrap();
        assert_eq!(None, SafeString::try_from(large_input.clone()).ok());
        let encoded = to_vec(&large_input).unwrap();
        let output = SafeString::try_from_slice(&encoded);
        assert!(output.is_err());
        // A huge claimed length is rejected before anything is allocated for it.
        assert!(SafeString::try_from_slice(&[0xff; 4]).is_err());
        // Exactly the maximum is accepted, and encodes like `String`.
        let max = "a".repeat(128);
        let encoded = to_vec(&max).unwrap();
        let decoded = SafeString::try_from_slice(&encoded).unwrap();
        assert_eq!(to_vec(&decoded).unwrap(), encoded);
    }

    #[test]
    fn test_safe_string_serde_invalid_char() {
        let de: Result<SafeString, _> = serde_json::from_str("\"\\n\"");
        assert_eq!(
            de.unwrap_err().to_string(),
            "String contained invalid character: \n. Only printable ASCII characters are allowed. at line 1 column 4"
        );
    }

    #[test]
    fn test_safe_string_serde_too_long() {
        let large_input = String::from_utf8(vec![b'a'; 300]).unwrap();
        let de: Result<SafeString, _> = serde_json::from_str(&format!("\"{large_input}\""));
        assert_eq!(
            de.unwrap_err().to_string(),
            "String was too long: 300, maximum: 128 at line 1 column 302"
        );
    }

    // Regressions of upstream's `SizedSafeString` bugs

    /// P5-05: the derived JSON schema was a plain string (no `maxLength`, no charset) named
    /// `SizedSafeString` for every length, so clients could not see the limits.
    #[test]
    fn safe_string_schema_has_bounds() {
        #[derive(schemars::JsonSchema)]
        #[allow(dead_code)]
        struct Both {
            a: SizedSafeString<16>,
            b: SafeString,
        }
        let schema = serde_json::to_value(schemars::schema_for!(Both)).unwrap();
        let short = &schema["$defs"]["SafeStringMax16"];
        assert_eq!(short["type"], "string");
        assert_eq!(short["maxLength"], 16);
        assert_eq!(short["pattern"], r"^[\x20-\x7e]*$");
        assert_eq!(schema["$defs"]["SafeStringMax128"]["maxLength"], 128);
    }

    #[test_strategy::proptest]
    fn roundtrips(s: SizedSafeString<10>) {
        prop_assert!(s.len() <= 10);
        prop_assert!(s.as_str().bytes().all(|b| (0x20..=0x7e).contains(&b)));
        let bytes = borsh::to_vec(&s).unwrap();
        prop_assert_eq!(&bytes, &borsh::to_vec(s.as_str()).unwrap());
        prop_assert_eq!(
            &borsh::from_slice::<SizedSafeString<10>>(&bytes).unwrap(),
            &s
        );
        let json = serde_json::to_string(&s).unwrap();
        prop_assert_eq!(
            &serde_json::from_str::<SizedSafeString<10>>(&json).unwrap(),
            &s
        );
        prop_assert_eq!(&s.to_string().parse::<SizedSafeString<10>>().unwrap(), &s);
    }
}

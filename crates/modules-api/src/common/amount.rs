//! [`Amount`]: a token amount in base units.

use std::fmt;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The number of decimal digits of `u128::MAX` (39), upstream's bound on token decimals.
///
/// A token with this many decimals cannot hold one whole token (`10^39 > u128::MAX`); the
/// bank module (Phase 6) decides the bound it enforces.
pub const MAX_U128_DECIMAL_PLACES: u8 = 39;

/// A token amount, in the token's base units.
///
/// - borsh: the `u128`, 16 bytes little-endian.
/// - JSON (and every human-readable serde format), [`Display`](fmt::Display) and
///   [`FromStr`]: the decimal string, canonical only: digits only (no `+`, `-`, spaces or
///   separators), no leading zeros (`"0"` itself excepted), at most `u128::MAX`. A JSON number
///   is rejected (JavaScript loses precision above 2^53). Upstream parsed with
///   `u128::from_str`, which also accepts `"+1"` and `"01"`, so one amount had many spellings.
/// - Binary serde formats: the `u128`.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BorshSerialize, BorshDeserialize,
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
pub struct Amount(pub u128);

selendra_interface::impl_consensus_type!(Amount);

impl Amount {
    /// The largest amount.
    pub const MAX: Amount = Amount(u128::MAX);
    /// The smallest amount (zero).
    pub const MIN: Amount = Amount(u128::MIN);
    /// Zero.
    pub const ZERO: Amount = Amount(0);
    /// Upstream's bound on token decimals ([`MAX_U128_DECIMAL_PLACES`]).
    pub const MAX_DECIMALS: u8 = MAX_U128_DECIMAL_PLACES;

    /// An amount of `amount` base units.
    pub const fn new(amount: u128) -> Self {
        Self(amount)
    }

    /// The amount in base units.
    pub const fn get(self) -> u128 {
        self.0
    }

    /// `self + other`, or `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, other: Amount) -> Option<Amount> {
        match self.0.checked_add(other.0) {
            Some(sum) => Some(Amount(sum)),
            None => None,
        }
    }

    /// `self - other`, or `None` if `other` is larger.
    #[must_use]
    pub const fn checked_sub(self, other: Amount) -> Option<Amount> {
        match self.0.checked_sub(other.0) {
            Some(difference) => Some(Amount(difference)),
            None => None,
        }
    }

    /// `self · other`, or `None` on overflow.
    #[must_use]
    pub const fn checked_mul(self, other: Amount) -> Option<Amount> {
        match self.0.checked_mul(other.0) {
            Some(product) => Some(Amount(product)),
            None => None,
        }
    }

    /// `self / other` rounded down, or `None` if `other` is zero.
    #[must_use]
    pub const fn checked_div(self, other: Amount) -> Option<Amount> {
        match self.0.checked_div(other.0) {
            Some(quotient) => Some(Amount(quotient)),
            None => None,
        }
    }

    /// `self + other`, at most [`Amount::MAX`].
    #[must_use]
    pub const fn saturating_add(self, other: Amount) -> Amount {
        Amount(self.0.saturating_add(other.0))
    }

    /// `self - other`, at least zero.
    #[must_use]
    pub const fn saturating_sub(self, other: Amount) -> Amount {
        Amount(self.0.saturating_sub(other.0))
    }

    /// `self · other`, at most [`Amount::MAX`].
    #[must_use]
    pub const fn saturating_mul(self, other: Amount) -> Amount {
        Amount(self.0.saturating_mul(other.0))
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Why a string is not an [`Amount`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseAmountError {
    /// The string is empty.
    #[error("empty amount")]
    Empty,
    /// A character other than an ASCII digit (e.g. `+`, `-`, a space, a separator).
    #[error("an amount is decimal digits only")]
    InvalidDigit,
    /// More than one digit, starting with `0`.
    #[error("an amount has no leading zeros")]
    LeadingZero,
    /// Larger than `u128::MAX`.
    #[error("amount larger than u128::MAX")]
    Overflow,
}

impl FromStr for Amount {
    type Err = ParseAmountError;

    /// Parses the canonical decimal form only (see [`Amount`]).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        let Some(&first) = bytes.first() else {
            return Err(ParseAmountError::Empty);
        };
        if !bytes.iter().all(u8::is_ascii_digit) {
            return Err(ParseAmountError::InvalidDigit);
        }
        if first == b'0' && bytes.len() > 1 {
            return Err(ParseAmountError::LeadingZero);
        }
        // Only digits are left, so the one remaining error is an overflow.
        s.parse::<u128>()
            .map(Amount)
            .map_err(|_| ParseAmountError::Overflow)
    }
}

impl PartialEq<u128> for Amount {
    fn eq(&self, other: &u128) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u128> for Amount {
    fn partial_cmp(&self, other: &u128) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl From<u128> for Amount {
    fn from(amount: u128) -> Self {
        Self(amount)
    }
}

impl From<u64> for Amount {
    fn from(amount: u64) -> Self {
        Self(u128::from(amount))
    }
}

impl From<Amount> for u128 {
    fn from(amount: Amount) -> Self {
        amount.0
    }
}

impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            serializer.serialize_u128(self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(AmountStrVisitor)
        } else {
            <u128 as Deserialize>::deserialize(deserializer).map(Amount)
        }
    }
}

/// Reads the canonical decimal string without copying it.
struct AmountStrVisitor;

impl serde::de::Visitor<'_> for AmountStrVisitor {
    type Value = Amount;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a decimal string without sign or leading zeros")
    }

    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Amount, E> {
        s.parse().map_err(E::custom)
    }
}

impl schemars::JsonSchema for Amount {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Amount".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^(0|[1-9][0-9]*)$",
            "maxLength": 39,
            "description": "A token amount in base units: a decimal string (no sign, no leading zeros), at most 2^128 - 1",
        })
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;

    #[test]
    fn parse_errors_say_why() {
        assert_eq!("".parse::<Amount>(), Err(ParseAmountError::Empty));
        assert_eq!("+1".parse::<Amount>(), Err(ParseAmountError::InvalidDigit));
        assert_eq!("01".parse::<Amount>(), Err(ParseAmountError::LeadingZero));
        assert_eq!(
            "340282366920938463463374607431768211456".parse::<Amount>(),
            Err(ParseAmountError::Overflow)
        );
    }

    #[test]
    fn amount_encodings_are_pinned() {
        let amount = Amount::new(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
        assert_eq!(
            borsh::to_vec(&amount).unwrap(),
            [
                0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
                0x02, 0x01
            ]
        );
        assert_eq!(
            postcard::to_allocvec(&Amount::new(300)).unwrap(),
            postcard::to_allocvec(&300u128).unwrap()
        );
        assert_eq!(Amount::new(42).to_string(), "42");
        assert_eq!(format!("{:?}", Amount::new(42)), "42");
    }

    #[test]
    fn checked_arithmetic() {
        assert_eq!(Amount::MAX.checked_add(Amount::new(1)), None);
        assert_eq!(Amount::ZERO.checked_sub(Amount::new(1)), None);
        assert_eq!(Amount::MAX.checked_mul(Amount::new(2)), None);
        assert_eq!(Amount::new(1).checked_div(Amount::ZERO), None);
        assert_eq!(
            Amount::new(7).checked_div(Amount::new(2)),
            Some(Amount::new(3))
        );
        assert_eq!(Amount::MAX.saturating_add(Amount::new(1)), Amount::MAX);
        assert_eq!(Amount::ZERO.saturating_sub(Amount::new(1)), Amount::ZERO);
        assert_eq!(Amount::MAX.saturating_mul(Amount::new(2)), Amount::MAX);
        assert_eq!(
            usize::from(MAX_U128_DECIMAL_PLACES),
            u128::MAX.to_string().len()
        );
    }

    #[proptest]
    fn amount_round_trips(value: u128) {
        let amount = Amount::new(value);
        let json = serde_json::to_string(&amount).unwrap();
        assert_eq!(json, format!("\"{value}\""));
        assert_eq!(serde_json::from_str::<Amount>(&json).unwrap(), amount);
        assert_eq!(
            borsh::from_slice::<Amount>(&borsh::to_vec(&amount).unwrap()).unwrap(),
            amount
        );
        assert_eq!(
            postcard::from_bytes::<Amount>(&postcard::to_allocvec(&amount).unwrap()).unwrap(),
            amount
        );
        assert_eq!(amount.to_string().parse::<Amount>().unwrap(), amount);
    }

    // Regressions of upstream's `Amount` bugs

    /// P5-23 (regression): JSON accepted `"+1"` and `"01"` (upstream parsed with
    /// `u128::from_str`), so one amount had several encodings.
    #[test]
    fn amount_json_is_canonical() {
        for accepted in ["0", "1", "10", "340282366920938463463374607431768211455"] {
            let json = format!("\"{accepted}\"");
            let amount: Amount = serde_json::from_str(&json).unwrap();
            assert_eq!(serde_json::to_string(&amount).unwrap(), json);
            assert_eq!(accepted.parse::<Amount>().unwrap(), amount);
        }
        for rejected in [
            "+1",
            "01",
            "00",
            "-0",
            "-1",
            "",
            " 1",
            "1 ",
            "1_000",
            "1e3",
            "0x10",
            "١",
            "340282366920938463463374607431768211456",
        ] {
            let json = serde_json::to_string(rejected).unwrap();
            assert!(
                serde_json::from_str::<Amount>(&json).is_err(),
                "{rejected:?} accepted"
            );
            assert!(rejected.parse::<Amount>().is_err(), "{rejected:?} parsed");
        }
        // A JSON number is not an amount.
        assert!(serde_json::from_str::<Amount>("1").is_err());
    }
}

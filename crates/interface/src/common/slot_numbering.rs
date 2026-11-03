use std::ops::{Deref, DerefMut};
use std::str::FromStr;

/// A string that is not the canonical decimal form of a slot number or height.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected a decimal number without sign or leading zeros, got {0:?}")]
pub struct NonCanonicalNumber(String);

/// Parses the form `Display` prints: ASCII digits, no sign, no leading zeros.
/// (`u64::from_str` also accepts `+5` and `005`, which would give one number several strings.)
fn parse_canonical_u64(s: &str) -> Result<u64, NonCanonicalNumber> {
    let canonical =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    match canonical.then(|| s.parse()) {
        Some(Ok(n)) => Ok(n),
        _ => Err(NonCanonicalNumber(s.to_owned())),
    }
}

/// Uniquely identifies a slot **within the canonical DA fork**.
///
/// Slots across reorgs can have the same [`SlotNumber`].
#[derive(
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    derive_more::Add,
    derive_more::Sub,
    derive_more::Display,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshDeserialize,
    borsh::BorshSerialize,
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
pub struct SlotNumber(u64);

impl FromStr for SlotNumber {
    type Err = NonCanonicalNumber;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_canonical_u64(s).map(Self)
    }
}

impl std::fmt::Debug for SlotNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get())
    }
}

impl SlotNumber {
    /// The very first [`SlotNumber`] of the rollup.
    pub const GENESIS: Self = Self(0);

    /// The [`SlotNumber`] after genesis.
    pub const ONE: Self = Self(1);

    /// The largest possible [`SlotNumber`].
    pub const MAX: Self = Self(u64::MAX);

    /// Wraps a raw [`u64`] that is already a slot number.
    ///
    /// The caller asserts the value really is a slot number — e.g. decoded from storage or a
    /// ledger key, or derived from a DA height. There is no validation. To obtain a
    /// [`SlotNumber`] from a [`RollupHeight`] or [`VisibleSlotNumber`] (which only coincide
    /// with the slot number for a based rollup), go through the kernel's `KernelWithSlotMapping`
    /// instead — there is no correct stateless conversion.
    pub const fn new(height: u64) -> Self {
        Self(height)
    }

    /// Increments by one and also returns the new [`SlotNumber`].
    pub fn incr(&mut self) -> Self {
        *self = self.next();
        *self
    }

    /// Decrements by one and also returns the new [`SlotNumber`].
    pub fn decr(&mut self) -> Self {
        *self = self.prev();
        *self
    }

    /// The current [`SlotNumber`] plus one.
    ///
    /// # Panics
    ///
    /// Panics in case of overflow.
    pub fn next(&self) -> Self {
        Self(self.0.checked_add(1).unwrap())
    }

    /// The current [`SlotNumber`] minus one.
    ///
    /// # Panics
    ///
    /// Panics if the result underflows.
    pub fn prev(&self) -> Self {
        Self(self.0.checked_sub(1).unwrap())
    }

    /// The current [`SlotNumber`] as a [`u64`].
    pub fn get(&self) -> u64 {
        self.0
    }

    /// Calculates the difference between two [`SlotNumber`]s as a [`u64`].
    ///
    /// # Panics
    ///
    /// Panics if the result underflows.
    pub fn delta(&self, rhs: Self) -> u64 {
        self.0.checked_sub(rhs.0).unwrap()
    }

    /// Calculates the difference between two [`SlotNumber`]s as a [`u64`].
    ///
    /// # Return
    ///
    /// Returns `self - rhs`, or `0` if `rhs` is greater than `self` (see
    /// [`u64::saturating_sub`]). Use [`SlotNumber::checked_delta`] to tell the two apart.
    pub fn saturating_delta(&self, rhs: Self) -> u64 {
        self.0.saturating_sub(rhs.0)
    }

    /// Calculates `self - rhs`, or `None` if `rhs` is greater than `self`.
    pub fn checked_delta(&self, rhs: Self) -> Option<u64> {
        self.0.checked_sub(rhs.0)
    }

    /// See [`u64::saturating_add`].
    pub fn saturating_add(&self, rhs: u64) -> Self {
        Self(self.0.saturating_add(rhs))
    }

    /// See [`u64::saturating_sub`].
    pub fn saturating_sub(&self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }

    /// See [`u64::checked_add`].
    pub fn checked_add(&self, rhs: u64) -> Option<Self> {
        self.0.checked_add(rhs).map(Self)
    }
    /// See [`u64::checked_sub`].
    pub fn checked_sub(&self, rhs: u64) -> Option<Self> {
        self.0.checked_sub(rhs).map(Self)
    }

    /// Iterates over all [`SlotNumber`]s in the range `[self, end]`.
    pub fn range_inclusive(&self, end: Self) -> impl Iterator<Item = Self> {
        (self.get()..=end.get()).map(Self::new)
    }

    /// Iterates over all [`SlotNumber`]s in the range `[self, end)`.
    pub fn range_exclusive(&self, end: Self) -> impl Iterator<Item = Self> {
        (self.get()..end.get()).map(Self::new)
    }
}

/// Easy initialization of [`SlotNumber`].
pub trait IntoSlotNumber {
    /// Creates a new [`SlotNumber`].
    fn to_slot_number(self) -> SlotNumber;
}

macro_rules! impl_into_slot_number {
    ($t:ty) => {
        impl IntoSlotNumber for $t {
            fn to_slot_number(self) -> SlotNumber {
                SlotNumber::new(u64::from(self))
            }
        }
    };
}

impl_into_slot_number!(u8);
impl_into_slot_number!(u32);
impl_into_slot_number!(u64);

impl IntoSlotNumber for usize {
    fn to_slot_number(self) -> SlotNumber {
        // Lossless: `usize` is at most 64 bits on every supported target.
        SlotNumber::new(self as u64)
    }
}

/// For integer literals, which default to `i32` (`5.to_slot_number()`).
impl IntoSlotNumber for i32 {
    /// # Panics
    ///
    /// Panics if `self` is negative (a cast would turn it into a huge slot number).
    fn to_slot_number(self) -> SlotNumber {
        SlotNumber::new(u64::try_from(self).expect("slot number must not be negative"))
    }
}

/// A [`SlotNumber`] at which a user-space state transition happened.
///
/// A [`VisibleSlotNumber`] can safely be type cast into a [`SlotNumber`] to
/// obtain a valid [`SlotNumber`], but the reverse is not true.
#[derive(
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    derive_more::Add, // TODO(@nesofu): remove this, as it's not safe.
    derive_more::Display,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshDeserialize,
    borsh::BorshSerialize,
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
pub struct VisibleSlotNumber(SlotNumber);

impl FromStr for VisibleSlotNumber {
    type Err = NonCanonicalNumber;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SlotNumber::from_str(s).map(Self)
    }
}

impl std::fmt::Debug for VisibleSlotNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get())
    }
}

impl Deref for VisibleSlotNumber {
    type Target = SlotNumber;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for VisibleSlotNumber {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl VisibleSlotNumber {
    /// At genesis, [`VisibleSlotNumber`] is equal to [`SlotNumber`].
    pub const GENESIS: Self = Self(SlotNumber::GENESIS);

    /// The [`VisibleSlotNumber`] after genesis.
    pub const ONE: Self = Self(SlotNumber::ONE);

    /// The largest possible [`VisibleSlotNumber`].
    pub const MAX: Self = Self(SlotNumber::MAX);

    /// Wraps a [`u64`] into a [`VisibleSlotNumber`].
    /// This method should be used with caution,
    /// since passing a [`VisibleSlotNumber`] that is not a valid height can lead to unexpected results.
    pub fn new_dangerous(height: u64) -> Self {
        Self(SlotNumber::new(height))
    }

    /// Increments by a certain `amount` and also returns the new
    /// [`VisibleSlotNumber`].
    ///
    /// # Panics
    ///
    /// Panics in case of overflow.
    pub fn advance(&mut self, amount: u64) -> Self {
        self.0 = self.0.checked_add(amount).unwrap();
        *self
    }

    /// Casts this value into a [`SlotNumber`].
    ///
    /// <div class="warning">
    /// Type casting between [`SlotNumber`] and [`VisibleSlotNumber`] is not
    /// encouraged as it can easily lead to bugs. TODO(@neysofu): carefully
    /// review all type casts and possibly remove this method.
    /// </div>
    pub fn as_true(&self) -> SlotNumber {
        self.0
    }
}

#[test]
fn test_visible_slot_number() {
    let mut number = VisibleSlotNumber::GENESIS;
    let output = number.advance(5);
    assert_eq!(number.get(), 5);
    assert_eq!(output.get(), 5);
}

/// A rollup "block number". Rollup heights increase in order (1, 2, 3, ...),
/// regardless of what happens on the underlying DA layer.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    derive_more::Display,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshDeserialize,
    borsh::BorshSerialize,
    schemars::JsonSchema,
)]
pub struct RollupHeight(u64);

impl FromStr for RollupHeight {
    type Err = NonCanonicalNumber;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_canonical_u64(s).map(Self)
    }
}

impl std::fmt::Debug for RollupHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get())
    }
}

impl RollupHeight {
    /// The genesis rollup height.
    pub const GENESIS: Self = Self(0);

    /// The height of the first rollup block after genesis.
    pub const ONE: Self = Self(1);

    /// The largest possible [`RollupHeight`].
    pub const MAX: Self = Self(u64::MAX);

    /// Create a new rollup height from a u64.
    pub fn new(height: u64) -> Self {
        Self(height)
    }

    /// Returns the inner value of a rollup height.
    pub fn get(&self) -> u64 {
        self.0
    }

    /// Increment a rollup height by one.
    pub fn incr(&mut self) {
        self.0 += 1;
    }

    /// See [`u64::checked_sub`]
    #[must_use]
    pub fn checked_sub(self, rhs: u64) -> Option<Self> {
        self.0.checked_sub(rhs).map(Self)
    }

    /// See [`u64::checked_add`]
    #[must_use]
    pub fn checked_add(self, rhs: u64) -> Option<Self> {
        self.0.checked_add(rhs).map(Self)
    }

    /// See [`u64::saturating_sub`]
    #[must_use]
    pub fn saturating_sub(self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }

    /// See [`u64::saturating_add`]
    #[must_use]
    pub fn saturating_add(self, rhs: u64) -> Self {
        Self(self.0.saturating_add(rhs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_canonical_decimal_string_is_accepted() {
        for (s, n) in [("0", 0), ("5", 5), ("18446744073709551615", u64::MAX)] {
            assert_eq!(SlotNumber::from_str(s).unwrap().get(), n);
            assert_eq!(VisibleSlotNumber::from_str(s).unwrap().get(), n);
            assert_eq!(RollupHeight::from_str(s).unwrap().get(), n);
            assert_eq!(SlotNumber::new(n).to_string(), s);
            assert_eq!(RollupHeight::new(n).to_string(), s);
        }
        for bad in [
            "",
            "+5",
            "-5",
            "05",
            "00",
            " 5",
            "5 ",
            "0x5",
            "18446744073709551616",
        ] {
            assert!(SlotNumber::from_str(bad).is_err(), "{bad:?}");
            assert!(VisibleSlotNumber::from_str(bad).is_err(), "{bad:?}");
            assert!(RollupHeight::from_str(bad).is_err(), "{bad:?}");
        }
    }
}

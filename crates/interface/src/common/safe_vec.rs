//! [`SafeVec`]: a `Vec` with a maximum length fixed at compile time.
//!
//! The fallible API is inspired by the [arrayvec](https://docs.rs/arrayvec/latest/arrayvec/struct.ArrayVec.html) crate.

use std::borrow::Cow;
use std::fmt;
use std::io::Read;
use std::ops::{Bound, Index, IndexMut, RangeBounds};
use std::slice::SliceIndex;
use std::vec::Drain;

use borsh::{BorshDeserialize, BorshSerialize};
use schemars::{JsonSchema, SchemaGenerator};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::common::ConsensusType;

/// A `Vec` that never holds more than `MAX_SIZE` elements.
///
/// Use it for every variable-length field of a call message or other decoded input: the cap
/// is checked by every decoder (borsh, serde) before it allocates for more elements, so a
/// decoded value can never be larger than `MAX_SIZE`.
///
/// Every operation that can grow the vector is fallible (`try_*`) and leaves the vector
/// unchanged when it fails. Nothing panics because the vector is full, and an invalid range is
/// an `Err`. The only panics are the ones a `Vec` or a slice has for an out-of-bounds index
/// ([`Index`], [`Self::remove`], [`Self::drain`]).
///
/// Encodings are those of `Vec<T>` (borsh: `u32` LE length, then the elements; serde: a
/// sequence), with the length capped. Collections of zero-sized types are rejected by both
/// decoders, as borsh does for `Vec`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SafeVec<T, const MAX_SIZE: usize> {
    contents: Vec<T>,
}

/// Generates at most `MAX_SIZE` elements.
#[cfg(feature = "arbitrary")]
impl<'a, T: arbitrary::Arbitrary<'a>, const MAX_SIZE: usize> arbitrary::Arbitrary<'a>
    for SafeVec<T, MAX_SIZE>
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.arbitrary_len::<T>()?.min(MAX_SIZE);
        let contents = (0..len)
            .map(|_| T::arbitrary(u))
            .collect::<arbitrary::Result<Vec<T>>>()?;
        Ok(Self { contents })
    }
}

/// The most elements the proptest strategy generates, whatever `MAX_SIZE` is (to keep test
/// cases small); vectors of capacity at most this are generated up to and including full.
#[cfg(feature = "arbitrary")]
pub const PROPTEST_MAX_LEN: usize = 64;

/// Generates at most `min(MAX_SIZE, PROPTEST_MAX_LEN)` elements.
#[cfg(feature = "arbitrary")]
impl<T: proptest::arbitrary::Arbitrary + 'static, const MAX_SIZE: usize>
    proptest::arbitrary::Arbitrary for SafeVec<T, MAX_SIZE>
{
    type Parameters = T::Parameters;
    type Strategy =
        proptest::strategy::Map<proptest::collection::VecStrategy<T::Strategy>, fn(Vec<T>) -> Self>;

    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        use proptest::strategy::Strategy;
        proptest::collection::vec(
            proptest::arbitrary::any_with::<T>(args),
            0..=MAX_SIZE.min(PROPTEST_MAX_LEN),
        )
        .prop_map((|contents| Self { contents }) as fn(Vec<T>) -> Self)
    }
}

impl<T: JsonSchema, const MAX_SIZE: usize> JsonSchema for SafeVec<T, MAX_SIZE> {
    fn schema_name() -> Cow<'static, str> {
        format!("SafeVec_{}_of_{}", MAX_SIZE, T::schema_name()).into()
    }

    fn schema_id() -> Cow<'static, str> {
        format!("SafeVec<{}, {}>", MAX_SIZE, T::schema_id()).into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "array",
            "items": generator.subschema_for::<T>(),
            "minItems": 0,
            "maxItems": MAX_SIZE,
        })
    }
}

impl<T: ConsensusType, const MAX_SIZE: usize> ConsensusType for SafeVec<T, MAX_SIZE> {}

impl<T, const MAX_SIZE: usize> Default for SafeVec<T, MAX_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

/// The error returned when a [`SafeVec`] is out of capacity. When applicable, it contains
/// the item that could not be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Error, Hash)]
#[error("Not enough capacity")]
pub struct CapacityError<T = ()>(pub T);

impl<T> CapacityError<T> {
    /// Creates a new `CapacityError`.
    pub fn new(item: T) -> Self {
        CapacityError(item)
    }

    /// Replaces the contents of the capacity error with a new value.
    pub fn with<U>(self, new_contents: U) -> CapacityError<U> {
        CapacityError(new_contents)
    }
}

/// The error of [`SafeVec::try_extend_from_within`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ExtendFromWithinError {
    /// The range is reversed, or ends past the vector's length.
    #[error("invalid range for a vector of length {len}")]
    InvalidRange {
        /// The vector's length.
        len: usize,
    },
    /// The copied elements would not fit.
    #[error(transparent)]
    Capacity(#[from] CapacityError),
}

impl<T, const MAX_SIZE: usize> From<SafeVec<T, MAX_SIZE>> for Vec<T> {
    fn from(vec: SafeVec<T, MAX_SIZE>) -> Vec<T> {
        vec.contents
    }
}

impl<T: Clone, const MAX_SIZE: usize> TryFrom<&[T]> for SafeVec<T, MAX_SIZE> {
    type Error = CapacityError;

    fn try_from(value: &[T]) -> std::result::Result<Self, Self::Error> {
        if value.len() > MAX_SIZE {
            return Err(CapacityError(()));
        }
        Ok(Self {
            contents: value.to_vec(),
        })
    }
}

impl<T, const MAX_SIZE: usize> TryFrom<Vec<T>> for SafeVec<T, MAX_SIZE> {
    type Error = CapacityError;

    fn try_from(value: Vec<T>) -> std::result::Result<Self, Self::Error> {
        if value.len() > MAX_SIZE {
            return Err(CapacityError(()));
        }
        Ok(Self { contents: value })
    }
}

impl<T, const MAX_SIZE: usize> std::ops::Deref for SafeVec<T, MAX_SIZE> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        &self.contents
    }
}

impl<T, const MAX_SIZE: usize> std::ops::DerefMut for SafeVec<T, MAX_SIZE> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.contents
    }
}

impl<T, const MAX_SIZE: usize> IntoIterator for SafeVec<T, MAX_SIZE> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.contents.into_iter()
    }
}

impl<'a, T, const MAX_SIZE: usize> IntoIterator for &'a SafeVec<T, MAX_SIZE> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.contents.iter()
    }
}

impl<'a, T, const MAX_SIZE: usize> IntoIterator for &'a mut SafeVec<T, MAX_SIZE> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.contents.iter_mut()
    }
}

impl<T, I: SliceIndex<[T]>, const MAX_SIZE: usize> Index<I> for SafeVec<T, MAX_SIZE> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        self.contents.index(index)
    }
}

impl<T, I: SliceIndex<[T]>, const MAX_SIZE: usize> IndexMut<I> for SafeVec<T, MAX_SIZE> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        self.contents.index_mut(index)
    }
}

impl<T, const MAX_SIZE: usize> AsRef<[T]> for SafeVec<T, MAX_SIZE> {
    fn as_ref(&self) -> &[T] {
        &self.contents
    }
}

/// A type alias for `Result<T, CapacityError>`.
pub type Result<T = (), E = CapacityError> = std::result::Result<T, E>;

impl<T, const MAX_SIZE: usize> SafeVec<T, MAX_SIZE> {
    /// The maximum number of elements.
    pub const MAX_SIZE: usize = MAX_SIZE;

    /// Constructs a new, empty `SafeVec<T, MAX_SIZE>`.
    ///
    /// The vector will not allocate until elements are pushed onto it.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            contents: Vec::new(),
        }
    }

    /// A convenience function to return the max size of a `SafeVec`.
    pub const fn max_size(&self) -> usize {
        MAX_SIZE
    }

    /// Clears the vector, removing all values.
    ///
    /// Note that this method has no effect on the allocated capacity of the vector.
    #[inline]
    pub fn clear(&mut self) {
        self.contents.clear();
    }

    /// Moves all the elements of `other` into `self`, leaving `other` empty. On failure
    /// neither vector changes.
    #[inline]
    pub fn try_append(&mut self, other: &mut Vec<T>) -> Result {
        self.try_reserve(other.len())?;
        self.contents.append(other);
        Ok(())
    }

    /// Tries to reserve capacity for at least `items_to_add` more elements. The collection may
    /// reserve more space to speculatively avoid frequent reallocations, but never more than
    /// `MAX_SIZE` elements in total. Does nothing if capacity is already sufficient.
    ///
    /// # Errors
    ///
    /// If the new length would exceed `MAX_SIZE`, or the allocator reports a failure.
    pub fn try_reserve(&mut self, items_to_add: usize) -> Result {
        let new_len = self.len().saturating_add(items_to_add);
        if new_len > MAX_SIZE {
            return Err(CapacityError(()));
        }
        if new_len <= self.capacity() {
            return Ok(());
        }
        // Double the capacity if that covers the request, capped at `MAX_SIZE`; otherwise
        // reserve exactly the requested length. `new_len <= MAX_SIZE`, so the target covers it.
        let target = new_len.max(MAX_SIZE.min(self.capacity().saturating_mul(2)));
        self.contents
            .try_reserve_exact(target.saturating_sub(self.len()))
            .map_err(|_| CapacityError(()))
    }

    /// Constructs a new, empty `SafeVec` with at least the specified capacity.
    ///
    /// # Errors
    ///
    /// If `capacity` exceeds `MAX_SIZE`, or the allocator reports a failure.
    #[inline]
    pub fn try_with_capacity(capacity: usize) -> Result<Self> {
        let mut output = Self::new();
        output.try_reserve(capacity)?;
        Ok(output)
    }

    /// Tries to reserve the minimum capacity for at least `additional` more elements. Unlike
    /// [`Self::try_reserve`], this does not deliberately over-allocate.
    ///
    /// # Errors
    ///
    /// If the new length would exceed `MAX_SIZE`, or the allocator reports a failure.
    pub fn try_reserve_exact(&mut self, additional: usize) -> Result {
        if self.len().saturating_add(additional) > MAX_SIZE {
            return Err(CapacityError(()));
        }
        self.contents
            .try_reserve_exact(additional)
            .map_err(|_| CapacityError(()))
    }

    /// Returns the total number of elements the vector can hold without reallocating.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.contents.capacity()
    }

    /// Returns the number of additional elements the vector can hold without reallocating.
    #[inline]
    pub fn remaining_capacity(&self) -> usize {
        self.capacity().saturating_sub(self.len())
    }

    /// Removes all but the first of consecutive elements in the vector satisfying a given
    /// equality relation. See [`Vec::dedup_by`].
    pub fn dedup_by<F>(&mut self, same_bucket: F)
    where
        F: FnMut(&mut T, &mut T) -> bool,
    {
        self.contents.dedup_by(same_bucket);
    }

    /// Removes all but the first of consecutive elements in the vector that resolve to the same
    /// key. See [`Vec::dedup_by_key`].
    #[inline]
    pub fn dedup_by_key<F, K>(&mut self, key: F)
    where
        F: FnMut(&mut T) -> K,
        K: PartialEq,
    {
        self.contents.dedup_by_key(key);
    }

    /// Removes the specified range from the vector in bulk, returning all removed elements as
    /// an iterator. See [`Vec::drain`].
    ///
    /// # Panics
    ///
    /// Panics if the starting point is greater than the end point or if the end point is
    /// greater than the length of the vector.
    pub fn drain<R>(&mut self, range: R) -> Drain<'_, T>
    where
        R: RangeBounds<usize>,
    {
        self.contents.drain(range)
    }

    /// Tries to insert an element at position `index`, shifting all elements after it to the
    /// right. Returns the element on failure: the vector is full, or `index > len`.
    pub fn try_insert(&mut self, index: usize, element: T) -> Result<(), CapacityError<T>> {
        if index > self.len() || self.try_reserve(1).is_err() {
            return Err(CapacityError(element));
        }
        self.contents.insert(index, element);
        Ok(())
    }

    /// Appends an element to the back of the vector. Returns the element if the vector is full.
    #[inline]
    pub fn try_push(&mut self, value: T) -> Result<(), CapacityError<T>> {
        if let Err(e) = self.try_reserve(1) {
            return Err(e.with(value));
        }
        self.contents.push(value);
        Ok(())
    }

    /// Removes the last element and returns it, or `None` if the vector is empty.
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        self.contents.pop()
    }

    /// Retains only the elements specified by the predicate. See [`Vec::retain`].
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.contents.retain(f);
    }

    /// Removes the element at the given index and returns it.
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds.
    #[inline]
    pub fn remove(&mut self, index: usize) -> T {
        self.contents.remove(index)
    }

    /// Shortens the vector, keeping the first `len` elements and dropping the rest. Has no
    /// effect if `len` is at least the current length.
    pub fn truncate(&mut self, len: usize) {
        self.contents.truncate(len);
    }

    /// Extends the vector with the contents of an iterator. On failure (more items than fit)
    /// the vector is left as it was.
    pub fn try_extend<I: IntoIterator<Item = T>>(&mut self, iter: I) -> Result {
        let iter = iter.into_iter();
        let original_len = self.len();
        self.try_reserve(iter.size_hint().0)?;
        for item in iter {
            if self.try_push(item).is_err() {
                self.contents.truncate(original_len);
                return Err(CapacityError(()));
            }
        }
        Ok(())
    }
}

impl<T: PartialEq, const MAX_SIZE: usize> SafeVec<T, MAX_SIZE> {
    /// Removes consecutive repeated elements. See [`Vec::dedup`].
    pub fn dedup(&mut self) {
        self.contents.dedup();
    }
}

impl<T: Clone, const N: usize> SafeVec<T, N> {
    /// Clones and appends all elements in a slice. On failure the vector is unchanged.
    pub fn try_extend_from_slice(&mut self, other: &[T]) -> Result {
        self.try_reserve(other.len())?;
        self.contents.extend_from_slice(other);
        Ok(())
    }

    /// Copies the elements of the range `src` to the end of the vector. On failure the vector
    /// is unchanged.
    ///
    /// # Errors
    ///
    /// [`ExtendFromWithinError::InvalidRange`] if the range is reversed or ends past the
    /// vector's length, [`ExtendFromWithinError::Capacity`] if the elements do not fit.
    pub fn try_extend_from_within<R>(&mut self, src: R) -> Result<(), ExtendFromWithinError>
    where
        R: RangeBounds<usize>,
    {
        let len = self.len();
        let invalid = ExtendFromWithinError::InvalidRange { len };
        let start = match src.start_bound() {
            Bound::Included(&start) => start,
            Bound::Excluded(&start) => start.checked_add(1).ok_or(invalid)?,
            Bound::Unbounded => 0,
        };
        let end = match src.end_bound() {
            Bound::Included(&end) => end.checked_add(1).ok_or(invalid)?,
            Bound::Excluded(&end) => end,
            Bound::Unbounded => len,
        };
        if start > end || end > len {
            return Err(invalid);
        }
        self.try_reserve(end - start)?;
        self.contents.extend_from_within(start..end);
        Ok(())
    }
}

impl<T: BorshSerialize, const N: usize> BorshSerialize for SafeVec<T, N> {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.contents.serialize(writer)
    }
}

impl<T: BorshDeserialize, const MAX_SIZE: usize> BorshDeserialize for SafeVec<T, MAX_SIZE> {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let len = u32::deserialize_reader(reader)?;
        if usize::try_from(len).map_or(true, |len| len > MAX_SIZE) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SafeVec length {len} exceeds the maximum of {MAX_SIZE}"),
            ));
        }
        // The length is within the cap: decode exactly like `Vec<T>` (which rejects zero-sized
        // types and allocates cautiously), with the length prefix put back in front.
        let prefix = len.to_le_bytes();
        let contents = Vec::<T>::deserialize_reader(&mut prefix.as_slice().chain(reader))?;
        Ok(Self { contents })
    }
}

impl<T: Serialize, const N: usize> Serialize for SafeVec<T, N> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.contents.serialize(serializer)
    }
}

/// How many elements to allocate for up front from an untrusted size hint: at most 32 KiB.
pub(crate) fn cautious_size_hint<T>(size_hint: usize) -> usize {
    const MAX_PREALLOC_BYTES: usize = 32 * 1024;
    match std::mem::size_of::<T>() {
        0 => 0,
        size => size_hint.min(MAX_PREALLOC_BYTES / size),
    }
}

const ERROR_ZST_FORBIDDEN: &str = "Collections of zero-sized types are not allowed by borsh due to denial-of-service concerns on deserialization.";

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for SafeVec<T, N> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VecVisitor<T, const N: usize>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for VecVisitor<T, N> {
            type Value = SafeVec<T, N>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a sequence of at most {N} items")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                use serde::de::Error;

                // Like borsh (and so every encoding of a `SafeVec` has the same rules).
                if std::mem::size_of::<T>() == 0 {
                    return Err(A::Error::custom(ERROR_ZST_FORBIDDEN));
                }
                // The size hint only sizes the first allocation: a format may under-report it,
                // so the elements are read until the sequence ends, checking the cap each time.
                let hint = seq.size_hint().unwrap_or(0);
                if hint > N {
                    return Err(A::Error::invalid_length(hint, &self));
                }
                let mut output = SafeVec::<T, N>::new();
                output
                    .try_reserve(cautious_size_hint::<T>(hint))
                    .map_err(|_| A::Error::custom("out of memory"))?;
                while let Some(value) = seq.next_element()? {
                    if output.try_push(value).is_err() {
                        return Err(A::Error::invalid_length(N.saturating_add(1), &self));
                    }
                }
                Ok(output)
            }
        }

        deserializer.deserialize_seq(VecVisitor::<T, N>(std::marker::PhantomData))
    }
}

#[cfg(test)]
mod tests;

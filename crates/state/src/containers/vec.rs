//! A growable array of values.

use std::iter::FusedIterator;
use std::marker::PhantomData;

use thiserror::Error;

#[cfg(feature = "native")]
use crate::SlotValue;
use crate::codec::{BorshCodec, EncodeLike, StateCodec, StateItemCodec};
use crate::namespaces::{Accessory, CompileTimeNamespace, Kernel, User};
use crate::{Prefix, SlotKey, StateReader, StateReaderAndWriter, StateWriter};

/// A growable array of values.
///
/// Key layout (both under the vector's own prefix, so no other item is touched):
/// - the length (`u64`, encoded with the value codec) at `[module, item]`;
/// - element `i` at `[module, item] ‖ i.to_le_bytes()` (8 bytes, the borsh encoding of `i: u64`,
///   independent of the codec).
///
/// The length key is 2 bytes and every element key 10, so they can never collide.
///
/// # Invariants
/// - Every element in `0..len` is stored, **even after an operation failed**: writes are
///   ordered so that the length shrinks before elements are deleted and grows after they are
///   written. Reads never see an element at or past `len` (they are all bounds-checked).
/// - If no operation failed, *exactly* the elements `0..len` are stored: [`pop`](Self::pop),
///   [`remove`](Self::remove), [`clear`](Self::clear) and [`set_all`](Self::set_all) delete
///   what they drop.
///
/// An operation whose accessor returns `Err` (e.g. out of gas) may have applied some of its
/// writes: it can leave elements past `len` behind (unreadable, and overwritten by a later
/// `push`/`set_all`) and leave `0..len` partly updated (e.g. `remove` mid-shift). Operations are
/// not atomic: on `Err` the caller must discard all of the accessor's writes (the Phase 5
/// transaction accessor reverts the transaction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacedStateVec<N, V, Codec = BorshCodec>
where
    N: CompileTimeNamespace,
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
{
    _phantom: PhantomData<(N, V)>,
    codec: Codec,
    prefix: Prefix,
}

/// An error type for vector getters.
#[derive(Debug, Error)]
pub enum StateVecError<N> {
    /// Operation failed because the index was out of bounds.
    #[error("Index out of bounds for index: {0} with namespace {ns}", ns = std::any::type_name::<N>())]
    IndexOutOfBounds(u64),
    /// Value not found.
    #[error("Value not found for prefix: {0} and index: {1} with namespace {ns}", ns = std::any::type_name::<N>())]
    MissingValue(Prefix, u64, PhantomData<N>),
}

type StateVecResult<N, V> = Result<V, StateVecError<N>>;

/// A vector of state values stored in the user namespace.
pub type StateVec<V, Codec = BorshCodec> = NamespacedStateVec<User, V, Codec>;
/// A vector of state values stored in the accessory namespace.
pub type AccessoryStateVec<V, Codec = BorshCodec> = NamespacedStateVec<Accessory, V, Codec>;
/// A vector of state values stored in the kernel namespace.
pub type KernelStateVec<V, Codec = BorshCodec> = NamespacedStateVec<Kernel, V, Codec>;

impl<N, V, Codec> NamespacedStateVec<N, V, Codec>
where
    N: CompileTimeNamespace,
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
{
    /// Creates a new [`StateVec`] with the given prefix and codec.
    pub fn with_codec(prefix: Prefix, codec: Codec) -> Self {
        Self {
            _phantom: PhantomData,
            codec,
            prefix,
        }
    }

    /// Returns the prefix used when this vector was created.
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    /// Returns the codec used when this vector was created.
    pub fn codec(&self) -> &Codec {
        &self.codec
    }

    /// The key holding the length: the bare prefix.
    fn len_key(&self) -> SlotKey {
        SlotKey::singleton(&self.prefix)
    }

    /// The key holding element `index`: the prefix followed by `index` as 8 little-endian bytes.
    fn elem_key(&self, index: u64) -> SlotKey {
        SlotKey::from_parts(&self.prefix, &index.to_le_bytes())
    }

    fn set_len<Writer: StateWriter<N>>(
        &self,
        length: u64,
        state: &mut Writer,
    ) -> Result<(), Writer::Error> {
        let value = super::encode_value::<u64, u64, _>(&length, self.codec.value_codec());
        state.set(&self.len_key(), value)
    }

    fn set_elem<Vq, Writer>(
        &self,
        index: u64,
        value: &Vq,
        state: &mut Writer,
    ) -> Result<(), Writer::Error>
    where
        Vq: ?Sized,
        Codec::ValueCodec: EncodeLike<Vq, V>,
        Writer: StateWriter<N>,
    {
        let value = super::encode_value::<V, Vq, _>(value, self.codec.value_codec());
        state.set(&self.elem_key(index), value)
    }

    /// Sets a value in the vector.
    /// If the index is out of bounds, returns an error.
    /// To push a value to the end of the vector, use [`NamespacedStateVec::push`].
    pub fn set<Vq, ReaderAndWriter>(
        &mut self,
        index: u64,
        value: &Vq,
        state: &mut ReaderAndWriter,
    ) -> Result<Result<(), StateVecError<N>>, <ReaderAndWriter as StateWriter<N>>::Error>
    where
        Vq: ?Sized,
        Codec::ValueCodec: EncodeLike<Vq, V>,
        ReaderAndWriter: StateReaderAndWriter<N>,
    {
        let len = self.len(state)?;

        Ok(if index < len {
            self.set_elem(index, value, state)?;
            Ok(())
        } else {
            Err(StateVecError::IndexOutOfBounds(index))
        })
    }

    /// Reads element `index` without checking it against the length: callers check
    /// `index < len` first (an element past `len` may be left over from a failed operation).
    fn get_in_bounds<Reader: StateReader<N>>(
        &self,
        index: u64,
        state: &mut Reader,
    ) -> Result<Option<V>, Reader::Error> {
        state.get_decoded(&self.elem_key(index), &self.codec)
    }

    /// Returns the value for the given index, or `None` if it is out of bounds.
    ///
    /// Reads the length and then the element (upstream skipped the length read, which returned
    /// elements left past `len` by a failed operation).
    pub fn get<Reader: StateReader<N>>(
        &self,
        index: u64,
        state: &mut Reader,
    ) -> Result<Option<V>, Reader::Error> {
        if index < self.len(state)? {
            self.get_in_bounds(index, state)
        } else {
            Ok(None)
        }
    }

    /// Returns the value for the given index.
    /// If the index is out of bounds, returns an error.
    /// If the value is absent (which the vector's invariant rules out), returns an error.
    pub fn get_or_err<Reader: StateReader<N>>(
        &self,
        index: u64,
        state: &mut Reader,
    ) -> Result<StateVecResult<N, V>, Reader::Error> {
        let len = self.len(state)?;

        Ok(if index < len {
            self.get_in_bounds(index, state)?
                .ok_or(StateVecError::MissingValue(self.prefix, index, PhantomData))
        } else {
            Err(StateVecError::IndexOutOfBounds(index))
        })
    }

    /// Returns the length of the vector.
    pub fn len<Reader: StateReader<N>>(&self, state: &mut Reader) -> Result<u64, Reader::Error> {
        let len: Option<u64> = state.get_decoded(&self.len_key(), &self.codec)?;
        Ok(len.unwrap_or_default())
    }

    /// Pushes a value to the end of the vector. Writes the element, then the length.
    ///
    /// # Panics
    /// If the vector already has `u64::MAX` elements, which would take `2^64` pushes.
    pub fn push<Vq, ReaderAndWriter>(
        &mut self,
        value: &Vq,
        state: &mut ReaderAndWriter,
    ) -> Result<(), <ReaderAndWriter as StateWriter<N>>::Error>
    where
        Vq: ?Sized,
        Codec::ValueCodec: EncodeLike<Vq, V>,
        ReaderAndWriter: StateReaderAndWriter<N>,
    {
        let len = self.len(state)?;
        let new_len = len
            .checked_add(1)
            .expect("a state vec cannot reach u64::MAX elements: that takes 2^64 pushes");

        self.set_elem(len, value, state)?;
        self.set_len(new_len, state)
    }

    /// Pops a value from the end of the vector and returns it. Shrinks the length, then deletes
    /// the element.
    pub fn pop<ReaderAndWriter: StateReaderAndWriter<N>>(
        &mut self,
        state: &mut ReaderAndWriter,
    ) -> Result<Option<V>, <ReaderAndWriter as StateWriter<N>>::Error> {
        let len = self.len(state)?;
        let Some(last_i) = len.checked_sub(1) else {
            return Ok(None);
        };

        let Some(elem) = self.get_in_bounds(last_i, state)? else {
            // Missing element (ruled out by the invariant): leave state as it is.
            return Ok(None);
        };

        self.set_len(last_i, state)?;
        state.delete(&self.elem_key(last_i))?;
        Ok(Some(elem))
    }

    /// Removes the value at the specified index and returns it, shifting all elements after it
    /// to the left (like [`Vec::remove`]). Returns `None` if the index is out of bounds.
    ///
    /// This is `O(len - index)` reads and writes: prefer [`pop`](Self::pop) to remove the last
    /// element. Shifted elements are moved as raw bytes (no decoding or re-encoding). Shrinks
    /// the length first, then shifts, then deletes the old last element.
    pub fn remove<ReaderAndWriter: StateReaderAndWriter<N>>(
        &mut self,
        index: u64,
        state: &mut ReaderAndWriter,
    ) -> Result<Option<V>, <ReaderAndWriter as StateWriter<N>>::Error> {
        let len = self.len(state)?;
        if index >= len {
            return Ok(None);
        }
        let Some(elem) = self.get_in_bounds(index, state)? else {
            return Ok(None);
        };

        // `index < len`, so `len >= 1`.
        let last = len.saturating_sub(1);
        self.set_len(last, state)?;
        // Each write lands in `0..last`, which stays fully stored if a write fails.
        for i in index..last {
            // `i < last <= u64::MAX - 1`, so this cannot saturate.
            let next = StateReader::<N>::get(state, &self.elem_key(i.saturating_add(1)))?;
            match next {
                Some(next) => state.set(&self.elem_key(i), next)?,
                None => state.delete(&self.elem_key(i))?,
            }
        }
        state.delete(&self.elem_key(last))?;

        Ok(Some(elem))
    }

    /// Removes all values from this vector. This is `O(len)` deletes: the length first, then
    /// the elements.
    pub fn clear<ReaderAndWriter: StateReaderAndWriter<N>>(
        &mut self,
        state: &mut ReaderAndWriter,
    ) -> Result<(), <ReaderAndWriter as StateWriter<N>>::Error> {
        let len = self.len(state)?;

        state.delete(&self.len_key())?;
        for i in 0..len {
            state.delete(&self.elem_key(i))?;
        }
        Ok(())
    }

    /// Replaces the contents of the vector with `values`.
    ///
    /// If `values` is shorter than the vector, the remaining elements are removed from storage.
    ///
    /// Shrinking: writes the new length, deletes the tail, then overwrites the elements.
    /// Growing (or same length): writes the elements, then the new length.
    pub fn set_all<Vq, ReaderAndWriter>(
        &mut self,
        values: Vec<Vq>,
        state: &mut ReaderAndWriter,
    ) -> Result<(), <ReaderAndWriter as StateWriter<N>>::Error>
    where
        Codec::ValueCodec: EncodeLike<Vq, V>,
        ReaderAndWriter: StateReaderAndWriter<N>,
    {
        let old_len = self.len(state)?;
        // A `Vec` has at most `usize::MAX` (<= u64::MAX) elements, so this never fails; the
        // fallback only avoids a panic path and an `as` cast.
        let new_len = u64::try_from(values.len()).unwrap_or(u64::MAX);
        let shrinking = new_len < old_len;

        if shrinking {
            self.set_len(new_len, state)?;
            for i in new_len..old_len {
                state.delete(&self.elem_key(i))?;
            }
        }

        // `zip` with `0..` counts in `u64` (no cast), and stops after `values.len()` items.
        for (i, value) in (0..u64::MAX).zip(&values) {
            self.set_elem(i, value, state)?;
        }

        if shrinking {
            Ok(())
        } else {
            self.set_len(new_len, state)
        }
    }

    /// Returns the last value in the vector, or [`None`] if empty.
    pub fn last<Reader: StateReader<N>>(
        &self,
        state: &mut Reader,
    ) -> Result<Option<V>, Reader::Error> {
        let len = self.len(state)?;
        let Some(i) = len.checked_sub(1) else {
            return Ok(None);
        };

        self.get_in_bounds(i, state)
    }

    /// Returns an iterator over all the values in the vector. It reads one element per step.
    pub fn iter<'a, 'ws, Reader>(
        &'a self,
        state: &'ws mut Reader,
    ) -> Result<StateVecIter<'a, 'ws, N, V, Codec, Reader>, Reader::Error>
    where
        Reader: StateReader<N>,
    {
        let len = self.len(state)?;
        Ok(StateVecIter {
            state_vec: self,
            state,
            next_i: 0,
            end: len,
        })
    }

    /// Collects all items returned by [`NamespacedStateVec::iter`] into a collection. Only
    /// available with infallible state accessors.
    pub fn collect_infallible<B, Reader>(&self, state: &mut Reader) -> B
    where
        B: FromIterator<V>,
        Reader: StateReader<N, Error = std::convert::Infallible>,
    {
        let Ok(iter) = self.iter(state);
        iter.map(|item| {
            let Ok(value) = item;
            value
        })
        .collect()
    }
}

/// An [`Iterator`] over a state vector, from both ends.
///
/// See [`NamespacedStateVec::iter`]. The iterator ends after yielding an error (e.g. out of
/// gas), or if an element is missing (which the vector's invariant rules out).
pub struct StateVecIter<'a, 'ws, N, V, Codec, Reader>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
    N: CompileTimeNamespace,
    Reader: StateReader<N>,
{
    state_vec: &'a NamespacedStateVec<N, V, Codec>,
    state: &'ws mut Reader,
    /// Next index from the front.
    next_i: u64,
    /// One past the next index from the back. Invariant: `next_i <= end`.
    end: u64,
}

impl<N, V, Codec, Reader> StateVecIter<'_, '_, N, V, Codec, Reader>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
    N: CompileTimeNamespace,
    Reader: StateReader<N>,
{
    /// Reads element `index`; on an error or a missing element, ends the iterator.
    fn read(&mut self, index: u64) -> Option<Result<V, Reader::Error>> {
        // `index < end <= len` (read when the iterator was created).
        let item = self.state_vec.get_in_bounds(index, self.state).transpose();
        if !matches!(item, Some(Ok(_))) {
            self.end = self.next_i;
        }
        item
    }
}

impl<N, V, Codec, Reader> Iterator for StateVecIter<'_, '_, N, V, Codec, Reader>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
    N: CompileTimeNamespace,
    Reader: StateReader<N>,
{
    type Item = Result<V, Reader::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_i >= self.end {
            return None;
        }
        let index = self.next_i;
        // `index < end`, so this cannot saturate.
        self.next_i = index.saturating_add(1);
        self.read(index)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // Lower bound 0: a missing element ends the iteration early. The upper bound is unknown
        // if the remaining count doesn't fit in `usize` (on the 32-bit zk guest).
        let remaining = self.end.saturating_sub(self.next_i);
        (0, usize::try_from(remaining).ok())
    }
}

impl<N, V, Codec, Reader> DoubleEndedIterator for StateVecIter<'_, '_, N, V, Codec, Reader>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
    N: CompileTimeNamespace,
    Reader: StateReader<N>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.next_i >= self.end {
            return None;
        }
        // `end > next_i >= 0`, so this cannot saturate.
        self.end = self.end.saturating_sub(1);
        self.read(self.end)
    }
}

impl<N, V, Codec, Reader> FusedIterator for StateVecIter<'_, '_, N, V, Codec, Reader>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
    N: CompileTimeNamespace,
    Reader: StateReader<N>,
{
}

/// Raw APIs (native only): the stored element bytes, without the value codec. The length is
/// still read and written with the codec, and the layout and write ordering are those of the
/// typed operations (see [`NamespacedStateVec`]).
#[cfg(feature = "native")]
impl<N, V, Codec> NamespacedStateVec<N, V, Codec>
where
    N: CompileTimeNamespace,
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
{
    /// Returns the raw bytes of element `index`, or `None` if it is out of bounds.
    pub fn get_raw<Reader: StateReader<N>>(
        &self,
        index: u64,
        state: &mut Reader,
    ) -> Result<Option<Vec<u8>>, Reader::Error> {
        if index < self.len(state)? {
            self.get_raw_in_bounds(index, state)
        } else {
            Ok(None)
        }
    }

    /// Reads element `index` without checking the length (callers check `index < len`).
    fn get_raw_in_bounds<Reader: StateReader<N>>(
        &self,
        index: u64,
        state: &mut Reader,
    ) -> Result<Option<Vec<u8>>, Reader::Error> {
        Ok(state
            .get(&self.elem_key(index))?
            .map(|v| v.value().to_vec()))
    }

    /// Sets the raw bytes of element `index`. If the index is out of bounds, returns an error.
    ///
    /// The bytes are stored as they are: if they do not decode as a `V`, every later typed read
    /// of the element panics (see [`StateReader::get_decoded`]). Only for node tooling.
    pub fn set_raw<ReaderAndWriter>(
        &mut self,
        index: u64,
        value: &[u8],
        state: &mut ReaderAndWriter,
    ) -> Result<Result<(), StateVecError<N>>, <ReaderAndWriter as StateWriter<N>>::Error>
    where
        ReaderAndWriter: StateReaderAndWriter<N>,
    {
        let len = self.len(state)?;
        Ok(if index < len {
            state.set(&self.elem_key(index), SlotValue::from(value.to_vec()))?;
            Ok(())
        } else {
            Err(StateVecError::IndexOutOfBounds(index))
        })
    }

    /// Pushes raw bytes to the end of the vector. Writes the element, then the length (like
    /// [`push`](Self::push); same caveat as [`set_raw`](Self::set_raw)).
    ///
    /// # Panics
    /// If the vector already has `u64::MAX` elements, which would take `2^64` pushes.
    pub fn push_raw<ReaderAndWriter>(
        &mut self,
        value: &[u8],
        state: &mut ReaderAndWriter,
    ) -> Result<(), <ReaderAndWriter as StateWriter<N>>::Error>
    where
        ReaderAndWriter: StateReaderAndWriter<N>,
    {
        let len = self.len(state)?;
        let new_len = len
            .checked_add(1)
            .expect("a state vec cannot reach u64::MAX elements: that takes 2^64 pushes");
        state.set(&self.elem_key(len), SlotValue::from(value.to_vec()))?;
        self.set_len(new_len, state)
    }

    /// Pops the last element and returns its raw bytes. Shrinks the length, then deletes the
    /// element (like [`pop`](Self::pop); upstream deleted first, so a failed length write left a
    /// hole at `len - 1`).
    pub fn pop_raw<ReaderAndWriter>(
        &mut self,
        state: &mut ReaderAndWriter,
    ) -> Result<Option<Vec<u8>>, <ReaderAndWriter as StateWriter<N>>::Error>
    where
        ReaderAndWriter: StateReaderAndWriter<N>,
    {
        let len = self.len(state)?;
        let Some(last_i) = len.checked_sub(1) else {
            return Ok(None);
        };
        let Some(elem) = self.get_raw_in_bounds(last_i, state)? else {
            // Missing element (ruled out by the invariant): leave state as it is.
            return Ok(None);
        };
        self.set_len(last_i, state)?;
        state.delete(&self.elem_key(last_i))?;
        Ok(Some(elem))
    }

    /// Returns an iterator over the raw bytes of all elements, reading through `state` (so it
    /// sees uncommitted writes and, in a checkpoint, records reads like any other access). It
    /// reads the length once, then one element per step.
    pub fn iter_raw<'a, 'ws, Reader>(
        &'a self,
        state: &'ws mut Reader,
    ) -> Result<StateVecRawIter<'a, 'ws, N, V, Codec, Reader>, Reader::Error>
    where
        Reader: StateReader<N>,
    {
        let end = self.len(state)?;
        Ok(StateVecRawIter {
            state_vec: self,
            state,
            next_i: 0,
            end,
        })
    }
}

/// An [`Iterator`] over the raw bytes of a state vector's elements, from both ends (native
/// only). See [`NamespacedStateVec::iter_raw`]; behaves like [`StateVecIter`] (ends after an
/// error or a missing element, fused, no `ExactSizeIterator`).
#[cfg(feature = "native")]
pub struct StateVecRawIter<'a, 'ws, N, V, Codec, Reader>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
    N: CompileTimeNamespace,
    Reader: StateReader<N>,
{
    state_vec: &'a NamespacedStateVec<N, V, Codec>,
    state: &'ws mut Reader,
    /// Next index from the front.
    next_i: u64,
    /// One past the next index from the back. Invariant: `next_i <= end`.
    end: u64,
}

#[cfg(feature = "native")]
impl<N, V, Codec, Reader> StateVecRawIter<'_, '_, N, V, Codec, Reader>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
    N: CompileTimeNamespace,
    Reader: StateReader<N>,
{
    /// Reads element `index`; on an error or a missing element, ends the iterator.
    fn read(&mut self, index: u64) -> Option<Result<Vec<u8>, Reader::Error>> {
        // `index < end <= len` (read when the iterator was created).
        let item = self
            .state_vec
            .get_raw_in_bounds(index, self.state)
            .transpose();
        if !matches!(item, Some(Ok(_))) {
            self.end = self.next_i;
        }
        item
    }
}

#[cfg(feature = "native")]
impl<N, V, Codec, Reader> Iterator for StateVecRawIter<'_, '_, N, V, Codec, Reader>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
    N: CompileTimeNamespace,
    Reader: StateReader<N>,
{
    type Item = Result<Vec<u8>, Reader::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_i >= self.end {
            return None;
        }
        let index = self.next_i;
        // `index < end`, so this cannot saturate.
        self.next_i = index.saturating_add(1);
        self.read(index)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.end.saturating_sub(self.next_i);
        (0, usize::try_from(remaining).ok())
    }
}

#[cfg(feature = "native")]
impl<N, V, Codec, Reader> DoubleEndedIterator for StateVecRawIter<'_, '_, N, V, Codec, Reader>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
    N: CompileTimeNamespace,
    Reader: StateReader<N>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.next_i >= self.end {
            return None;
        }
        // `end > next_i >= 0`, so this cannot saturate.
        self.end = self.end.saturating_sub(1);
        self.read(self.end)
    }
}

#[cfg(feature = "native")]
impl<N, V, Codec, Reader> FusedIterator for StateVecRawIter<'_, '_, N, V, Codec, Reader>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V> + StateItemCodec<u64>,
    N: CompileTimeNamespace,
    Reader: StateReader<N>,
{
}

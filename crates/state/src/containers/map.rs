//! A container that maps keys to values.

use std::marker::PhantomData;
use std::str::FromStr;

use thiserror::Error;

use super::{Borrowed, BorrowedMut};
use crate::codec::{BorshCodec, EncodeLike, StateCodec, StateItemCodec};
use crate::namespaces::{Accessory, CompileTimeNamespace, Kernel, User};
use crate::{Prefix, SlotKey, SlotValue, StateReader, StateReaderAndWriter, StateWriter};

/// A container that maps keys to values. The value for `key` is stored under
/// `[module, item] ‖ key_codec(key)`.
///
/// # Type parameters
/// [`NamespacedStateMap`] is generic over:
/// - a namespace `N`;
/// - a key type `K` (`FromStr + Display`, for the REST API in Phase 13);
/// - a value type `V`;
/// - a [`StateCodec`] `Codec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacedStateMap<N, K, V, Codec = BorshCodec>
where
    N: CompileTimeNamespace,
    Codec: StateCodec,
    Codec::KeyCodec: StateItemCodec<K>,
    Codec::ValueCodec: StateItemCodec<V>,
    K: FromStr + std::fmt::Display,
{
    _phantom: PhantomData<(N, K, V)>,
    codec: Codec,
    prefix: Prefix,
}

/// Error type for the getters of state maps.
#[derive(Debug, Error)]
pub enum StateMapError<N> {
    /// Value not found.
    #[error("Value not found for prefix: {0} and storage key: {1} in namespace {ns}", ns = std::any::type_name::<N>())]
    MissingValue(Prefix, SlotKey, PhantomData<N>),
}

type ValueOrError<V, N> = Result<V, StateMapError<N>>;

/// A container that maps keys to values in user space.
pub type StateMap<K, V, Codec = BorshCodec> = NamespacedStateMap<User, K, V, Codec>;

/// A container that maps keys to values stored as "accessory" state, outside merklized state.
pub type AccessoryStateMap<K, V, Codec = BorshCodec> = NamespacedStateMap<Accessory, K, V, Codec>;

/// A container that maps keys to values which are only accessible in the kernel.
pub type KernelStateMap<K, V, Codec = BorshCodec> = NamespacedStateMap<Kernel, K, V, Codec>;

impl<N, K, V, Codec> NamespacedStateMap<N, K, V, Codec>
where
    N: CompileTimeNamespace,
    Codec: StateCodec,
    Codec::KeyCodec: StateItemCodec<K>,
    Codec::ValueCodec: StateItemCodec<V>,
    K: FromStr + std::fmt::Display,
{
    /// Creates a new [`StateMap`] with the given prefix and codec.
    pub fn with_codec(prefix: Prefix, codec: Codec) -> Self {
        Self {
            _phantom: PhantomData,
            codec,
            prefix,
        }
    }

    /// Returns the prefix used when this map was created.
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    /// Returns the codec used when this map was created.
    pub fn codec(&self) -> &Codec {
        &self.codec
    }

    /// Returns the [`SlotKey`] under which the value for `key` is stored.
    pub fn slot_key<Kq>(&self, key: &Kq) -> SlotKey
    where
        Kq: ?Sized,
        Codec::KeyCodec: EncodeLike<Kq, K>,
    {
        SlotKey::new::<K, Kq, _>(self.prefix(), key, self.codec().key_codec())
    }

    /// Encodes the provided value into a slot value.
    pub(crate) fn slot_value<Vq>(&self, value: &Vq) -> SlotValue
    where
        Vq: ?Sized,
        Codec::ValueCodec: EncodeLike<Vq, V>,
    {
        super::encode_value::<V, Vq, _>(value, self.codec().value_codec())
    }

    /// Inserts a key-value pair into the map.
    ///
    /// The key and value may be anything the codec can encode like `K` and `V`
    /// (see [`EncodeLike`]).
    pub fn set<Kq, Vq, Writer>(
        &mut self,
        key: &Kq,
        value: &Vq,
        state: &mut Writer,
    ) -> Result<(), Writer::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Codec::ValueCodec: EncodeLike<Vq, V>,
        Kq: ?Sized,
        Vq: ?Sized,
        Writer: StateWriter<N>,
    {
        state.set(&self.slot_key(key), self.slot_value(value))
    }

    /// Calls [`NamespacedStateMap::set`] iff the key is not already present in the map.
    pub fn set_if_absent<Kq, Vq, Writer>(
        &mut self,
        key: &Kq,
        value: &Vq,
        state: &mut Writer,
    ) -> Result<(), <Writer as StateWriter<N>>::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Codec::ValueCodec: EncodeLike<Vq, V>,
        Kq: ?Sized,
        Vq: ?Sized,
        Writer: StateReaderAndWriter<N>,
    {
        let slot_key = self.slot_key(key);
        // Presence only: no need to decode the existing value.
        if StateReader::<N>::get(state, &slot_key)?.is_none() {
            state.set(&slot_key, self.slot_value(value))?;
        }
        Ok(())
    }

    /// Returns the value corresponding to the key, or [`None`] if the map doesn't contain the
    /// key.
    ///
    /// The key may be anything the codec can encode like the map's key type. For example a
    /// `StateMap<HexString, u64>` can be queried with a `&[u8]`, because a `HexString` is
    /// borsh-encoded exactly like a byte vector:
    ///
    /// ```
    /// use selendra_interface::common::HexString;
    /// use selendra_state::{StateMap, StateReader, User};
    ///
    /// fn foo<R: StateReader<User>>(
    ///     map: &StateMap<HexString, u64>,
    ///     key: [u8; 32],
    ///     state: &mut R,
    /// ) -> Result<Option<u64>, R::Error> {
    ///     map.get(key.as_slice(), state)
    /// }
    /// ```
    pub fn get<Kq, Reader>(&self, key: &Kq, state: &mut Reader) -> Result<Option<V>, Reader::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Kq: ?Sized,
        Reader: StateReader<N>,
    {
        state.get_decoded(&self.slot_key(key), self.codec())
    }

    /// Returns a borrowed value from the map, preventing mutable access to the map until this
    /// reference is dropped.
    pub fn borrow<Kq, Reader>(
        &self,
        key: &Kq,
        state: &mut Reader,
    ) -> Result<Borrowed<'_, Option<V>, Self>, Reader::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Kq: ?Sized,
        Reader: StateReader<N>,
    {
        let val = state.get_decoded(&self.slot_key(key), self.codec())?;
        Ok(Borrowed::new(val, self))
    }

    /// Returns a mutably borrowed value from the map, preventing access to the map until this
    /// reference is dropped. Call [`BorrowedMut::save`] to write changes back.
    pub fn borrow_mut<Kq, Reader>(
        &mut self,
        key: &Kq,
        state: &mut Reader,
    ) -> Result<BorrowedMut<'_, Option<V>, Self>, Reader::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Kq: ?Sized,
        Reader: StateReader<N>,
    {
        let key = self.slot_key(key);
        let val = state.get_decoded(&key, self.codec())?;
        Ok(BorrowedMut::new(key, val, self))
    }

    /// Returns the value corresponding to the key or [`StateMapError`] if key is absent from
    /// the map.
    pub fn get_or_err<Kq, Reader>(
        &self,
        key: &Kq,
        state: &mut Reader,
    ) -> Result<ValueOrError<V, N>, Reader::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Kq: ?Sized,
        Reader: StateReader<N>,
    {
        let slot_key = self.slot_key(key);
        Ok(match state.get_decoded(&slot_key, self.codec())? {
            Some(value) => Ok(value),
            None => Err(StateMapError::MissingValue(
                self.prefix,
                slot_key,
                PhantomData,
            )),
        })
    }

    /// Removes a key from the map, returning the corresponding value (or [`None`] if the key is
    /// absent).
    pub fn remove<Kq, ReaderAndWriter>(
        &mut self,
        key: &Kq,
        state: &mut ReaderAndWriter,
    ) -> Result<Option<V>, <ReaderAndWriter as StateWriter<N>>::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Kq: ?Sized,
        ReaderAndWriter: StateReaderAndWriter<N>,
    {
        state.remove_decoded(&self.slot_key(key), self.codec())
    }

    /// Removes a key from the map, returning the corresponding value (or [`StateMapError`] if
    /// the key is absent).
    ///
    /// Use [`NamespacedStateMap::remove`] if you want an [`Option`] instead of a [`Result`].
    pub fn remove_or_err<Kq, ReaderAndWriter>(
        &mut self,
        key: &Kq,
        state: &mut ReaderAndWriter,
    ) -> Result<ValueOrError<V, N>, <ReaderAndWriter as StateWriter<N>>::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Kq: ?Sized,
        ReaderAndWriter: StateReaderAndWriter<N>,
    {
        let slot_key = self.slot_key(key);
        Ok(match state.remove_decoded(&slot_key, self.codec())? {
            Some(value) => Ok(value),
            None => Err(StateMapError::MissingValue(
                self.prefix,
                slot_key,
                PhantomData,
            )),
        })
    }

    /// Deletes a key-value pair from the map.
    ///
    /// This is equivalent to [`NamespacedStateMap::remove`], but doesn't deserialize and return
    /// the value before deletion.
    pub fn delete<Kq, Writer>(&mut self, key: &Kq, state: &mut Writer) -> Result<(), Writer::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Kq: ?Sized,
        Writer: StateWriter<N>,
    {
        state.delete(&self.slot_key(key))
    }
}

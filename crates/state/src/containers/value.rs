//! A container for a single value.

use std::marker::PhantomData;

use thiserror::Error;

use super::{Borrowed, BorrowedMut};
use crate::codec::{BorshCodec, EncodeLike, StateCodec, StateItemCodec, StateItemDecoder};
use crate::namespaces::{Accessory, CompileTimeNamespace, Kernel, User};
use crate::{Prefix, SlotKey, SlotValue, StateReader, StateReaderAndWriter, StateWriter};

/// Container for a single value, stored under the key `[module, item]` (its prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacedStateValue<N, V, Codec = BorshCodec>
where
    N: CompileTimeNamespace,
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V>,
{
    _phantom: PhantomData<(V, N)>,
    codec: Codec,
    prefix: Prefix,
}

/// Error type for getters from state values method.
#[derive(Debug, Error)]
pub enum StateValueError<N: CompileTimeNamespace> {
    /// The value was not found for the combination of (namespace, prefix) provided.
    #[error("Value not found for prefix: {0} in namespace: {ns}", ns = std::any::type_name::<N>())]
    MissingValue(Prefix, PhantomData<N>),
}

type ValueOrError<V, N> = Result<V, StateValueError<N>>;

/// A container for a single user-space value.
pub type StateValue<V, Codec = BorshCodec> = NamespacedStateValue<User, V, Codec>;
/// A container for a single value which is only accessible in the kernel.
pub type KernelStateValue<V, Codec = BorshCodec> = NamespacedStateValue<Kernel, V, Codec>;
/// A container for a single value stored as "accessory" state, outside merklized state.
pub type AccessoryStateValue<V, Codec = BorshCodec> = NamespacedStateValue<Accessory, V, Codec>;

impl<N, V, Codec> NamespacedStateValue<N, V, Codec>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V>,
    N: CompileTimeNamespace,
{
    /// Creates a new [`StateValue`] with the given prefix and codec.
    pub fn with_codec(prefix: Prefix, codec: Codec) -> Self {
        Self {
            _phantom: PhantomData,
            codec,
            prefix,
        }
    }

    /// Decodes the provided value.
    ///
    /// # Panics
    /// If the bytes do not decode: see [`StateReader::get_decoded`].
    pub fn decode_unwrap(&self, value: &SlotValue) -> V {
        self.codec().value_codec().decode_unwrap(value.value())
    }

    /// Returns the prefix used when this value was created.
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    /// Returns the codec used for this value.
    pub fn codec(&self) -> &Codec {
        &self.codec
    }

    /// Returns the [`SlotKey`] for this value.
    pub fn slot_key(&self) -> SlotKey {
        SlotKey::singleton(self.prefix())
    }

    /// Encodes the provided value into a slot value.
    pub(crate) fn slot_value<Vq>(&self, value: &Vq) -> SlotValue
    where
        Vq: ?Sized,
        Codec::ValueCodec: EncodeLike<Vq, V>,
    {
        super::encode_value::<V, Vq, _>(value, self.codec().value_codec())
    }

    /// Sets the value.
    ///
    /// The value may be anything the codec can encode like `V` (see [`EncodeLike`]).
    pub fn set<Vq, Writer>(&mut self, value: &Vq, state: &mut Writer) -> Result<(), Writer::Error>
    where
        Vq: ?Sized,
        Codec::ValueCodec: EncodeLike<Vq, V>,
        Writer: StateWriter<N>,
    {
        state.set(&self.slot_key(), self.slot_value(value))
    }

    /// Gets the value from state or returns `None` if the value is absent.
    pub fn get<Reader: StateReader<N>>(
        &self,
        state: &mut Reader,
    ) -> Result<Option<V>, Reader::Error> {
        state.get_decoded(&self.slot_key(), self.codec())
    }

    /// Returns a borrowed value, preventing mutable access to the container until this
    /// reference is dropped.
    pub fn borrow<Reader>(
        &self,
        state: &mut Reader,
    ) -> Result<Borrowed<'_, Option<V>, Self>, Reader::Error>
    where
        Reader: StateReader<N>,
    {
        Ok(Borrowed::new(
            state.get_decoded(&self.slot_key(), self.codec())?,
            self,
        ))
    }

    /// Returns a mutably borrowed value, preventing access to the container until this
    /// reference is dropped. Call [`BorrowedMut::save`] to write changes back.
    pub fn borrow_mut<Reader>(
        &mut self,
        state: &mut Reader,
    ) -> Result<BorrowedMut<'_, Option<V>, Self>, Reader::Error>
    where
        Reader: StateReader<N>,
    {
        let key = self.slot_key();
        let val = state.get_decoded(&key, self.codec())?;
        Ok(BorrowedMut::new(key, val, self))
    }

    /// Gets the value from state or an error if the value is absent.
    pub fn get_or_err<Reader: StateReader<N>>(
        &self,
        state: &mut Reader,
    ) -> Result<ValueOrError<V, N>, Reader::Error> {
        Ok(self
            .get(state)?
            .ok_or(StateValueError::MissingValue(self.prefix, PhantomData)))
    }

    /// Removes the value from state, returning the value (or `None` if the key is absent).
    pub fn remove<ReaderAndWriter: StateReaderAndWriter<N>>(
        &mut self,
        state: &mut ReaderAndWriter,
    ) -> Result<Option<V>, <ReaderAndWriter as StateWriter<N>>::Error> {
        state.remove_decoded(&self.slot_key(), self.codec())
    }

    /// Removes the value from state, returning the value (or an error if the key is absent).
    pub fn remove_or_err<ReaderAndWriter: StateReaderAndWriter<N>>(
        &mut self,
        state: &mut ReaderAndWriter,
    ) -> Result<ValueOrError<V, N>, <ReaderAndWriter as StateWriter<N>>::Error> {
        Ok(self
            .remove(state)?
            .ok_or(StateValueError::MissingValue(self.prefix, PhantomData)))
    }

    /// Deletes the value from state.
    pub fn delete<Writer: StateWriter<N>>(
        &mut self,
        state: &mut Writer,
    ) -> Result<(), Writer::Error> {
        state.delete(&self.slot_key())
    }
}

//! A container that maps keys to values.

use std::marker::PhantomData;
use std::str::FromStr;

use thiserror::Error;

use super::{Borrowed, BorrowedMut};
use crate::codec::{BorshCodec, EncodeLike, StateCodec, StateItemCodec, StateItemDecoder};
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

/// An entry of [`NamespacedStateMap::iter_raw`]: the decoded key and the raw value bytes, or why
/// the stored key is not one of this map's keys.
#[cfg(feature = "native")]
pub type RawMapEntry<K> = anyhow::Result<(K, Vec<u8>)>;

/// Raw APIs (native only): the stored value bytes, without the value codec.
#[cfg(feature = "native")]
impl<N, K, V, Codec> NamespacedStateMap<N, K, V, Codec>
where
    N: CompileTimeNamespace,
    Codec: StateCodec,
    Codec::KeyCodec: StateItemCodec<K>,
    Codec::ValueCodec: StateItemCodec<V>,
    K: FromStr + std::fmt::Display,
{
    /// Returns the raw value bytes for the key, or `None` if the map doesn't contain the key.
    pub fn get_raw<Kq, Reader>(
        &self,
        key: &Kq,
        state: &mut Reader,
    ) -> Result<Option<Vec<u8>>, Reader::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Kq: ?Sized,
        Reader: StateReader<N>,
    {
        Ok(state.get(&self.slot_key(key))?.map(|v| v.value().to_vec()))
    }

    /// Inserts a key and already-encoded value bytes into the map.
    ///
    /// The bytes are stored as they are: if they do not decode as a `V`, every later typed read
    /// of the key panics (see [`StateReader::get_decoded`]). Only for node tooling such as
    /// migrations.
    pub fn set_raw<Kq, Writer>(
        &mut self,
        key: &Kq,
        value: &[u8],
        state: &mut Writer,
    ) -> Result<(), Writer::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Kq: ?Sized,
        Writer: StateWriter<N>,
    {
        state.set(&self.slot_key(key), SlotValue::from(value.to_vec()))
    }

    /// Removes a key from the map, returning the raw value bytes (or `None` if the key is
    /// absent).
    pub fn remove_raw<Kq, ReaderAndWriter>(
        &mut self,
        key: &Kq,
        state: &mut ReaderAndWriter,
    ) -> Result<Option<Vec<u8>>, <ReaderAndWriter as StateWriter<N>>::Error>
    where
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Kq: ?Sized,
        ReaderAndWriter: StateReaderAndWriter<N>,
    {
        let key = self.slot_key(key);
        let value = StateReader::<N>::get(state, &key)?;
        state.delete(&key)?;
        Ok(value.map(|v| v.value().to_vec()))
    }

    /// Reads the raw values of caller-provided keys, in the given order (`None` for absent
    /// keys). Works with any accessor, including uncommitted writes; for storages without
    /// prefix iteration.
    #[allow(clippy::type_complexity)]
    pub fn iter_raw_from_keys<I, Kq, Reader>(
        &self,
        keys: I,
        state: &mut Reader,
    ) -> Result<Vec<(Kq, Option<Vec<u8>>)>, Reader::Error>
    where
        I: IntoIterator<Item = Kq>,
        Codec::KeyCodec: EncodeLike<Kq, K>,
        Reader: StateReader<N>,
    {
        keys.into_iter()
            .map(|key| {
                let value = self.get_raw(&key, state)?;
                Ok((key, value))
            })
            .collect()
    }

    /// Decodes the key of a stored entry, checking that it is one of this map's keys: it has
    /// this map's prefix and is the canonical encoding of the decoded key.
    fn decode_stored_key(&self, key: &SlotKey) -> anyhow::Result<K> {
        anyhow::ensure!(
            key.prefix() == self.prefix,
            "storage returned key {key} outside the map prefix {}",
            self.prefix
        );
        let decoded: K = self
            .codec()
            .key_codec()
            .try_decode(key.without_prefix())
            .map_err(|e| anyhow::anyhow!("Failed to decode map key {key}: {e:?}"))?;
        anyhow::ensure!(
            self.slot_key(&decoded) == *key,
            "map key {key} is not the canonical encoding of its decoded key"
        );
        Ok(decoded)
    }

    fn decode_raw_iter<'a>(
        &'a self,
        iter: Option<impl Iterator<Item = (SlotKey, SlotValue)> + 'a>,
    ) -> Option<impl Iterator<Item = RawMapEntry<K>> + 'a> {
        iter.map(move |iter| {
            iter.map(move |(key, value)| {
                Ok((self.decode_stored_key(&key)?, value.value().to_vec()))
            })
        })
    }
}

/// Prefix iteration over committed storage (native only).
macro_rules! impl_iter_raw {
    ($namespace:ty, $iter_fn:ident, $name:literal) => {
        #[cfg(feature = "native")]
        impl<K, V, Codec> NamespacedStateMap<$namespace, K, V, Codec>
        where
            Codec: StateCodec,
            Codec::KeyCodec: StateItemCodec<K>,
            Codec::ValueCodec: StateItemCodec<V>,
            K: FromStr + std::fmt::Display,
        {
            #[doc = concat!("Iterates over the raw values of this map in the committed ", $name, " state, in")]
            /// ascending order of the encoded keys.
            ///
            /// Reads `storage` directly: writes in an uncommitted
            /// [`StateCheckpoint`](crate::StateCheckpoint) are not seen, and nothing is added to
            /// a witness (node tooling, e.g. migrations).
            ///
            /// Returns `Ok(None)` if the storage does not support prefix iteration. An entry
            /// whose stored key is not the canonical encoding of a `K` under this map's prefix
            /// is returned as an `Err` item (and iteration continues).
            pub fn iter_raw<'a, S: crate::NativeStorage>(
                &'a self,
                storage: &'a S,
            ) -> anyhow::Result<Option<impl Iterator<Item = RawMapEntry<K>> + 'a>> {
                let prefix = SlotKey::singleton(self.prefix());
                let iter = storage.$iter_fn(prefix, None)?;
                Ok(self.decode_raw_iter(iter))
            }
        }
    };
}

impl_iter_raw!(User, maybe_iter_user_values_with_prefix, "user");
impl_iter_raw!(Kernel, maybe_iter_kernel_values_with_prefix, "kernel");

/// Storage proofs.
impl<N, K, V, Codec> NamespacedStateMap<N, K, V, Codec>
where
    N: crate::ProvableCompileTimeNamespace,
    Codec: StateCodec,
    Codec::KeyCodec: StateItemCodec<K>,
    Codec::ValueCodec: StateItemCodec<V>,
    K: FromStr + std::fmt::Display,
{
    /// Gets the value for `key` with a proof of its presence or absence against the latest
    /// committed state root (native only). See
    /// [`ProvenStateAccessor`](crate::ProvenStateAccessor).
    #[cfg(feature = "native")]
    pub fn get_with_proof<Kq, W>(
        &self,
        key: &Kq,
        state: &mut W,
    ) -> Option<crate::StorageProof<W::Proof>>
    where
        Kq: ?Sized,
        Codec::KeyCodec: EncodeLike<Kq, K>,
        W: crate::ProvenStateAccessor<N>,
    {
        state.get_global_latest_with_proof(self.slot_key(key))
    }

    /// Verifies a proof of an entry of this map against `state_root`, returning the key and
    /// the value (`None`: proven absent).
    ///
    /// Checks that the proof is for this map's namespace and prefix, and that the proven key
    /// is the canonical encoding of the returned key, so the result means exactly "`map[key]`
    /// is `value`". Needs no `native`: light clients and the guest can verify.
    ///
    /// Upstream decoded the key without checking the prefix, so a proof of another map's (or
    /// any other container's) entry was accepted as an entry of this map.
    ///
    /// # Errors
    /// If the proof is for another namespace or container, does not open against
    /// `state_root`, or the proven key or value does not decode (canonically, for the key).
    pub fn verify_proof<St: crate::Storage>(
        &self,
        state_root: St::Root,
        proof: crate::StorageProof<St::Proof>,
    ) -> anyhow::Result<(K, Option<V>)> {
        anyhow::ensure!(
            proof.namespace == N::PROVABLE_NAMESPACE,
            "The provided proof comes from a different namespace. Expected {:?} but found {:?}",
            N::PROVABLE_NAMESPACE,
            proof.namespace
        );

        let (complete_key, value) = St::open_proof(state_root, proof)?;
        anyhow::ensure!(
            complete_key.prefix() == self.prefix,
            "The provided proof is for another container. Expected prefix {} but found {}",
            self.prefix,
            complete_key.prefix()
        );
        let key: K = self
            .codec()
            .key_codec()
            .try_decode(complete_key.without_prefix())
            .map_err(|e| anyhow::anyhow!("Failed to decode key from proof: {e:?}"))?;
        anyhow::ensure!(
            self.slot_key(&key) == complete_key,
            "The proven key {complete_key} is not the canonical encoding of its decoded key"
        );

        let value = value
            .map(|v| {
                self.codec()
                    .value_codec()
                    .try_decode(v.value())
                    .map_err(|e| anyhow::anyhow!("Failed to decode value from proof: {e:?}"))
            })
            .transpose()?;
        Ok((key, value))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, N, K, V, Codec> NamespacedStateMap<N, K, V, Codec>
where
    K: arbitrary::Arbitrary<'a> + FromStr + std::fmt::Display,
    V: arbitrary::Arbitrary<'a>,
    Codec: StateCodec,
    Codec::KeyCodec: StateItemCodec<K>,
    Codec::ValueCodec: StateItemCodec<V>,
    N: CompileTimeNamespace,
{
    /// Returns a map with an arbitrary prefix, filled with arbitrary entries written to
    /// `state`. See the [`arbitrary`] crate.
    ///
    /// Never panics for key and value types the codec can always encode (see
    /// [`BorshCodec`]: no floats). Upstream required a `StateCheckpoint`; any infallible writer
    /// of the namespace works (also a write-only accessory writer).
    pub fn arbitrary_state_map<W>(
        u: &mut arbitrary::Unstructured<'a>,
        state: &mut W,
    ) -> arbitrary::Result<Self>
    where
        W: StateWriter<N, Error = std::convert::Infallible>,
    {
        let prefix = Prefix::new(u.arbitrary()?, u.arbitrary()?);
        let len = u.arbitrary_len::<(K, V)>()?;
        let mut map = Self::with_codec(prefix, Codec::default());
        for _ in 0..len {
            let key = K::arbitrary(u)?;
            let value = V::arbitrary(u)?;
            let Ok(()) = map.set(&key, &value, state);
        }
        Ok(map)
    }
}

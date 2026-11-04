//! Traits through which containers read and write state, one implementation per namespace.
//!
//! An accessor implements [`StateReader<N>`] / [`StateWriter<N>`] for each namespace `N` it may
//! touch, so access rights are checked at compile time: e.g. the transaction accessor (Phase 5)
//! will write but not read [`Accessory`] state. Container methods that only write
//! (`set`, `delete` on values and maps) need only a [`StateWriter`]:
//!
//! ```
//! use std::convert::Infallible;
//!
//! use selendra_state::{
//!     Accessory, AccessoryStateMap, AccessoryStateValue, BorshCodec, Prefix, SlotKey, SlotValue,
//!     StateWriter,
//! };
//!
//! struct WriteOnly;
//! impl StateWriter<Accessory> for WriteOnly {
//!     type Error = Infallible;
//!     fn set(&mut self, _: &SlotKey, _: SlotValue) -> Result<(), Infallible> { Ok(()) }
//!     fn delete(&mut self, _: &SlotKey) -> Result<(), Infallible> { Ok(()) }
//! }
//!
//! let mut value = AccessoryStateValue::<u8>::with_codec(Prefix::new(1, 1), BorshCodec);
//! let mut map = AccessoryStateMap::<u8, u8>::with_codec(Prefix::new(1, 2), BorshCodec);
//! let Ok(()) = value.set(&1, &mut WriteOnly);
//! let Ok(()) = value.delete(&mut WriteOnly);
//! let Ok(()) = map.set(&1, &2, &mut WriteOnly);
//! let Ok(()) = map.delete(&1, &mut WriteOnly);
//! ```
//!
//! Anything that reads does not compile with a write-only accessor:
//!
//! ```compile_fail,E0277
//! # use std::convert::Infallible;
//! # use selendra_state::{Accessory, AccessoryStateValue, BorshCodec, Prefix, SlotKey, SlotValue, StateWriter};
//! # struct WriteOnly;
//! # impl StateWriter<Accessory> for WriteOnly {
//! #     type Error = Infallible;
//! #     fn set(&mut self, _: &SlotKey, _: SlotValue) -> Result<(), Infallible> { Ok(()) }
//! #     fn delete(&mut self, _: &SlotKey) -> Result<(), Infallible> { Ok(()) }
//! # }
//! let value = AccessoryStateValue::<u8>::with_codec(Prefix::new(1, 1), BorshCodec);
//! let _ = value.get(&mut WriteOnly);
//! ```
//!
//! ```compile_fail,E0277
//! # use std::convert::Infallible;
//! # use selendra_state::{Accessory, AccessoryStateValue, BorshCodec, Prefix, SlotKey, SlotValue, StateWriter};
//! # struct WriteOnly;
//! # impl StateWriter<Accessory> for WriteOnly {
//! #     type Error = Infallible;
//! #     fn set(&mut self, _: &SlotKey, _: SlotValue) -> Result<(), Infallible> { Ok(()) }
//! #     fn delete(&mut self, _: &SlotKey) -> Result<(), Infallible> { Ok(()) }
//! # }
//! let mut value = AccessoryStateValue::<u8>::with_codec(Prefix::new(1, 1), BorshCodec);
//! let _ = value.remove(&mut WriteOnly);
//! ```
//!
//! ```compile_fail,E0277
//! # use std::convert::Infallible;
//! # use selendra_state::{Accessory, AccessoryStateMap, BorshCodec, Prefix, SlotKey, SlotValue, StateWriter};
//! # struct WriteOnly;
//! # impl StateWriter<Accessory> for WriteOnly {
//! #     type Error = Infallible;
//! #     fn set(&mut self, _: &SlotKey, _: SlotValue) -> Result<(), Infallible> { Ok(()) }
//! #     fn delete(&mut self, _: &SlotKey) -> Result<(), Infallible> { Ok(()) }
//! # }
//! let mut map = AccessoryStateMap::<u8, u8>::with_codec(Prefix::new(1, 2), BorshCodec);
//! let _ = map.set_if_absent(&1, &2, &mut WriteOnly);
//! ```
//!
//! ```compile_fail,E0277
//! # use std::convert::Infallible;
//! # use selendra_state::{Accessory, AccessoryStateVec, BorshCodec, Prefix, SlotKey, SlotValue, StateWriter};
//! # struct WriteOnly;
//! # impl StateWriter<Accessory> for WriteOnly {
//! #     type Error = Infallible;
//! #     fn set(&mut self, _: &SlotKey, _: SlotValue) -> Result<(), Infallible> { Ok(()) }
//! #     fn delete(&mut self, _: &SlotKey) -> Result<(), Infallible> { Ok(()) }
//! # }
//! let mut vec = AccessoryStateVec::<u8>::with_codec(Prefix::new(1, 3), BorshCodec);
//! let _ = vec.push(&1, &mut WriteOnly);
//! ```
//!
//! A reader for one namespace can't read another:
//!
//! ```
//! # use std::convert::Infallible;
//! # use selendra_state::{BorshCodec, Prefix, SlotKey, SlotValue, StateReader, StateValue, User};
//! struct UserReader;
//! impl StateReader<User> for UserReader {
//!     type Error = Infallible;
//!     fn get(&mut self, _: &SlotKey) -> Result<Option<SlotValue>, Infallible> { Ok(None) }
//! }
//! let value = StateValue::<u8>::with_codec(Prefix::new(1, 1), BorshCodec);
//! let Ok(None) = value.get(&mut UserReader) else { unreachable!() };
//! ```
//!
//! ```compile_fail,E0277
//! # use std::convert::Infallible;
//! # use selendra_state::{BorshCodec, KernelStateValue, Prefix, SlotKey, SlotValue, StateReader, User};
//! struct UserReader;
//! impl StateReader<User> for UserReader {
//!     type Error = Infallible;
//!     fn get(&mut self, _: &SlotKey) -> Result<Option<SlotValue>, Infallible> { Ok(None) }
//! }
//! let value = KernelStateValue::<u8>::with_codec(Prefix::new(1, 1), BorshCodec);
//! let _ = value.get(&mut UserReader);
//! ```
//!
//! # Errors and atomicity
//! Container operations make several accessor calls and are **not atomic**: one that returns
//! `Err` (e.g. out of gas) may have applied some of its writes. The caller must then discard all
//! of the accessor's writes (the Phase 5 transaction accessor reverts the transaction) and must
//! not catch the error and carry on with them kept. `StateVec` orders its writes so that even
//! then every element in `0..len` stays present and reads stay in bounds, but its contents are
//! unspecified.

use std::convert::Infallible;

use crate::codec::{StateCodec, StateItemCodec, StateItemDecoder};
use crate::namespaces::{Accessory, CompileTimeNamespace};
use crate::slot::{SlotKey, SlotValue};

/// A storage reader which can access a particular namespace.
pub trait StateReader<N: CompileTimeNamespace> {
    /// The error type returned when a state read operation fails (e.g. out of gas).
    type Error: std::error::Error + Send + Sync + 'static;

    /// Gets a value from the storage.
    ///
    /// ## Error
    /// Implementations may fail, e.g. if the gas meter can't pay for the read.
    fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error>;

    /// Gets a value from the storage and decodes it with the codec's value codec.
    ///
    /// The default implementation calls [`StateReader::get`] and decodes; gas-metered accessors
    /// (Phase 5) override it to also charge for decoding.
    ///
    /// # Panics
    /// If the stored bytes do not decode ([`StateItemDecoder::decode_unwrap`]). This is not input
    /// validation. Every key is written only by the container that owns its prefix, with that
    /// container's codec, so a decode failure means one of:
    /// - **the value type breaks the round-trip precondition** of [`StateItemCodec`]: its decoder
    ///   rejects some value its encoder accepts (e.g. an over-size `RawTx`). This is a bug in the
    ///   module's choice of stored type, and it can be triggered by whoever chooses the stored
    ///   value, so stored types must make it impossible;
    /// - two containers share a prefix (a bug), or the native database is corrupt;
    /// - **in the zk guest, an invalid witness**: guest storage answers reads with the prover's
    ///   hints, which are checked against the state root only later. A failure there means the
    ///   prover supplied bad bytes, and panicking (no proof) is the intended result. This panic
    ///   must never become a recoverable error: control flow would then depend on unverified
    ///   bytes.
    fn get_decoded<V, Codec>(
        &mut self,
        storage_key: &SlotKey,
        codec: &Codec,
    ) -> Result<Option<V>, Self::Error>
    where
        Codec: StateCodec,
        Codec::ValueCodec: StateItemCodec<V>,
    {
        Ok(self
            .get(storage_key)?
            .map(|value| codec.value_codec().decode_unwrap(value.value())))
    }
}

/// Provides write access to a particular namespace.
pub trait StateWriter<N: CompileTimeNamespace> {
    /// The error type returned when a state write operation fails (e.g. out of gas).
    type Error: std::error::Error + Send + Sync + 'static;

    /// Sets a value in the storage.
    ///
    /// ## Error
    /// Implementations may fail, e.g. if the gas meter can't pay for the write.
    fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Self::Error>;

    /// Deletes a value from the storage.
    ///
    /// ## Error
    /// Implementations may fail, e.g. if the gas meter can't pay for the delete.
    fn delete(&mut self, key: &SlotKey) -> Result<(), Self::Error>;
}

/// A [`StateReader`] and [`StateWriter`] for the same namespace with the same error type.
pub trait StateReaderAndWriter<N: CompileTimeNamespace>:
    StateReader<N> + StateWriter<N, Error = <Self as StateReader<N>>::Error>
{
    /// Removes a value from storage and returns it decoded.
    ///
    /// # Panics
    /// If the stored bytes do not decode: see [`StateReader::get_decoded`].
    fn remove_decoded<V, Codec>(
        &mut self,
        key: &SlotKey,
        codec: &Codec,
    ) -> Result<Option<V>, <Self as StateWriter<N>>::Error>
    where
        Codec: StateCodec,
        Codec::ValueCodec: StateItemCodec<V>,
    {
        let value = self.get_decoded(key, codec)?;
        <Self as StateWriter<N>>::delete(self, key)?;
        Ok(value)
    }
}

impl<T, N> StateReaderAndWriter<N> for T
where
    T: StateReader<N> + StateWriter<N, Error = <Self as StateReader<N>>::Error>,
    N: CompileTimeNamespace,
{
}

/// A [`StateReader`] and [`StateWriter`] to a given namespace that never fails.
///
/// ```
/// use std::convert::Infallible;
///
/// use selendra_state::{InfallibleStateReaderAndWriter, StateValue, User};
///
/// fn delete_state_string<A: InfallibleStateReaderAndWriter<User>>(
///     value: &mut StateValue<String>,
///     state: &mut A,
/// ) {
///     let Ok(original) = value.get(state);
///     if let Some(original) = original {
///         println!("original: {original}");
///     }
///     let Ok(()) = value.delete(state);
/// }
/// ```
pub trait InfallibleStateReaderAndWriter<N: CompileTimeNamespace>:
    StateReader<N, Error = Infallible> + StateWriter<N, Error = Infallible>
{
}

impl<T, N> InfallibleStateReaderAndWriter<N> for T
where
    T: StateReader<N, Error = Infallible> + StateWriter<N, Error = Infallible>,
    N: CompileTimeNamespace,
{
}

/// An [`InfallibleStateReaderAndWriter`] for the [`Accessory`] namespace.
pub trait AccessoryStateReaderAndWriter: InfallibleStateReaderAndWriter<Accessory> {}

impl<T: InfallibleStateReaderAndWriter<Accessory>> AccessoryStateReaderAndWriter for T {}

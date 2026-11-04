//! Typed state containers: [`StateValue`], [`StateMap`], [`StateVec`] and their kernel and
//! accessory variants.
//!
//! A container is a [`Prefix`](crate::Prefix) plus a codec. It holds no data: every operation
//! takes the accessor (`state`) to read or write through. Key layout (see
//! `docs/serialization.md`, "State keys"):
//!
//! | Container | Key | Value |
//! |---|---|---|
//! | value | `[module, item]` | `encode(value)` |
//! | map | `[module, item] ‖ key_codec(key)` | `encode(value)` |
//! | vec length | `[module, item]` | `encode(len: u64)` |
//! | vec element `i` | `[module, item] ‖ i as u64 LE (8 bytes)` | `encode(element)` |

pub(crate) mod map;
pub(crate) mod value;
pub(crate) mod vec;

use std::fmt::Display;
use std::str::FromStr;

#[cfg(feature = "native")]
pub use map::RawMapEntry;
pub use map::{AccessoryStateMap, KernelStateMap, NamespacedStateMap, StateMap, StateMapError};
pub use value::{
    AccessoryStateValue, KernelStateValue, NamespacedStateValue, StateValue, StateValueError,
};
#[cfg(feature = "native")]
pub use vec::StateVecRawIter;
pub use vec::{
    AccessoryStateVec, KernelStateVec, NamespacedStateVec, StateVec, StateVecError, StateVecIter,
};

use crate::{
    CompileTimeNamespace, EncodeLike, SlotKey, SlotValue, StateCodec, StateItemCodec,
    StateItemDecoder, StateWriter,
};

/// Encodes a value to store, as if it were a `V`.
///
/// Debug builds check the round-trip precondition of [`StateItemCodec`]: the bytes must decode
/// back as a `V`, or every later read of this key would panic. This catches a value type whose
/// decoder is stricter than its encoder at the write, in tests, instead of at some later read.
pub(crate) fn encode_value<V, Vq, VC>(value: &Vq, codec: &VC) -> SlotValue
where
    Vq: ?Sized,
    VC: EncodeLike<Vq, V> + StateItemDecoder<V>,
{
    let encoded = SlotValue::new::<V, Vq, VC>(value, codec);
    debug_assert!(
        codec.try_decode(encoded.value()).is_ok(),
        "a {} value does not decode from its own encoding, so it can't be stored \
         (see the round-trip precondition on `StateItemCodec`)",
        core::any::type_name::<V>()
    );
    encoded
}

/// A borrowed state value which points to the state variable that it came from.
///
/// This extends the borrow checker to state variables as if the value were a reference into the
/// container, rather than a decoded copy of the bytes in state. The borrow is purely imaginary:
/// the data is cloned.
pub struct Borrowed<'a, T, U> {
    value: T,
    _reference: &'a U,
}

impl<T: std::fmt::Debug, U> std::fmt::Debug for Borrowed<'_, T, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.value)
    }
}

impl<T: std::fmt::Display, U> std::fmt::Display for Borrowed<'_, T, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<T, U> std::ops::Deref for Borrowed<'_, T, U> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<'a, T, U> Borrowed<'a, T, U> {
    /// Builds a borrowed state value.
    pub(crate) fn new(value: T, _reference: &'a U) -> Self {
        Self { value, _reference }
    }
}

impl<'a, T, U> Borrowed<'a, Option<T>, U> {
    /// Unwraps the `Option`.
    ///
    /// # Panics
    /// If the value is `None`.
    pub fn unwrap(self) -> Borrowed<'a, T, U> {
        Borrowed::new(self.value.unwrap(), self._reference)
    }

    /// Unwraps the `Option`.
    ///
    /// # Panics
    /// With the provided message if the value is `None`.
    pub fn expect(self, msg: &str) -> Borrowed<'a, T, U> {
        Borrowed::new(self.value.expect(msg), self._reference)
    }

    /// Unwraps the `Option`, returning the provided default value if the value is `None`.
    pub fn unwrap_or(self, default: T) -> Borrowed<'a, T, U> {
        Borrowed::new(self.value.unwrap_or(default), self._reference)
    }

    /// Unwraps the `Option`, returning an error if the value is `None`.
    pub fn ok_or_else<E>(self, err: impl FnOnce() -> E) -> Result<Borrowed<'a, T, U>, E> {
        Ok(Borrowed::new(self.value.ok_or_else(err)?, self._reference))
    }

    /// Unwraps the `Option`, returning an error if the value is `None`.
    pub fn ok_or<E>(self, err: E) -> Result<Borrowed<'a, T, U>, E> {
        Ok(Borrowed::new(self.value.ok_or(err)?, self._reference))
    }
}

/// A mutably borrowed state value which points to the state variable that it came from.
///
/// Changes stay in this local copy until [`save`](BorrowedMut::save) writes them back. End
/// every `BorrowedMut` with [`save`](BorrowedMut::save), [`delete`](BorrowedMut::delete) or
/// [`discard`](BorrowedMut::discard):
/// - `#[must_use]` catches a borrow that is never bound;
/// - dropping a borrow whose value was mutably accessed (through `DerefMut`) is a bug (a lost
///   write), so **debug builds panic** on it. Release builds (and the zk guest) discard the
///   changes, like `discard`. Dropping a borrow that was only read is fine.
///
/// Upstream used `nearly_linear::DropGuard` (`unsafe`) plus an external lint for this.
#[must_use = "changes are written back only by `save` (or removed by `delete`); call `discard` to drop them explicitly"]
pub struct BorrowedMut<'a, T, U> {
    key: SlotKey,
    value: T,
    reference: &'a mut U,
    guard: UnsavedChangesGuard,
}

/// Records whether a [`BorrowedMut`] was mutably accessed, and asserts (debug builds only) that
/// such a borrow is not dropped without being saved, deleted or discarded.
///
/// A separate field so that [`BorrowedMut`] itself has no `Drop` impl and its consuming methods
/// can move out of it.
struct UnsavedChangesGuard {
    dirty: bool,
}

impl UnsavedChangesGuard {
    /// The borrow was ended explicitly: nothing to check.
    fn defuse(mut self) {
        self.dirty = false;
    }
}

impl Drop for UnsavedChangesGuard {
    fn drop(&mut self) {
        // Not while unwinding: a second panic would abort.
        debug_assert!(
            !self.dirty || std::thread::panicking(),
            "a `BorrowedMut` was modified and then dropped: the change is lost. \
             Call `save`, `delete` or `discard`"
        );
    }
}

impl<T: std::fmt::Debug, U> std::fmt::Debug for BorrowedMut<'_, T, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.value)
    }
}

impl<T: std::fmt::Display, U> std::fmt::Display for BorrowedMut<'_, T, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<T, U> std::ops::Deref for BorrowedMut<'_, T, U> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T, U> std::ops::DerefMut for BorrowedMut<'_, T, U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard.dirty = true;
        &mut self.value
    }
}

impl<'a, T, U> BorrowedMut<'a, T, U> {
    /// Builds a mutably borrowed state value.
    pub(crate) fn new(key: SlotKey, value: T, reference: &'a mut U) -> Self {
        Self {
            key,
            value,
            reference,
            guard: UnsavedChangesGuard { dirty: false },
        }
    }

    /// Replaces the value, keeping the key, the container and whether it was modified.
    fn map_value<T2>(self, f: impl FnOnce(T) -> T2) -> BorrowedMut<'a, T2, U> {
        BorrowedMut {
            key: self.key,
            value: f(self.value),
            reference: self.reference,
            guard: self.guard,
        }
    }

    /// Ends the borrow, returning the key, the value and the container.
    fn finish(self) -> (SlotKey, T, &'a mut U) {
        self.guard.defuse();
        (self.key, self.value, self.reference)
    }

    /// Discards the mutably borrowed value without saving it. This reverts any changes made
    /// while it was borrowed.
    pub fn discard(self) {
        self.guard.defuse();
    }
}

impl<'a, T, U> BorrowedMut<'a, Option<T>, U> {
    /// Unwraps the `Option`.
    ///
    /// # Panics
    /// If the value is `None`.
    pub fn unwrap(self) -> BorrowedMut<'a, T, U> {
        self.map_value(Option::unwrap)
    }

    /// Unwraps the `Option`.
    ///
    /// # Panics
    /// With the provided message if the value is `None`.
    pub fn expect(self, msg: &str) -> BorrowedMut<'a, T, U> {
        self.map_value(|value| value.expect(msg))
    }

    /// Unwraps the `Option`, returning the provided default value if the value is `None`.
    pub fn unwrap_or(self, default: T) -> BorrowedMut<'a, T, U> {
        self.map_value(|value| value.unwrap_or(default))
    }

    /// Unwraps the `Option`, returning an error if the value is `None`.
    pub fn ok_or_else<E>(self, err: impl FnOnce() -> E) -> Result<BorrowedMut<'a, T, U>, E> {
        let Self {
            key,
            value,
            reference,
            guard,
        } = self;
        match value {
            Some(value) => Ok(BorrowedMut {
                key,
                value,
                reference,
                guard,
            }),
            // `guard` is dropped here: an error only if the caller had set the value to `None`
            // (a change that is now lost).
            None => Err(err()),
        }
    }

    /// Unwraps the `Option`, returning an error if the value is `None`.
    pub fn ok_or<E>(self, err: E) -> Result<BorrowedMut<'a, T, U>, E> {
        self.ok_or_else(|| err)
    }
}

impl<N, V, Codec> BorrowedMut<'_, V, NamespacedStateValue<N, V, Codec>>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V>,
    N: CompileTimeNamespace,
{
    /// Saves a mutably borrowed value back to the state value.
    pub fn save<Writer: StateWriter<N>>(
        self,
        state: &mut Writer,
    ) -> Result<(), <Writer as StateWriter<N>>::Error> {
        let (key, value, container) = self.finish();
        state.set(&key, container.slot_value(&value))
    }

    /// Deletes the state value.
    pub fn delete<Writer: StateWriter<N>>(
        self,
        state: &mut Writer,
    ) -> Result<(), <Writer as StateWriter<N>>::Error> {
        let (key, _, _) = self.finish();
        state.delete(&key)
    }
}

impl<N, K, V, Codec> BorrowedMut<'_, V, NamespacedStateMap<N, K, V, Codec>>
where
    K: FromStr + Display,
    Codec: StateCodec,
    Codec::ValueCodec: StateItemCodec<V>,
    Codec::KeyCodec: StateItemCodec<K>,
    N: CompileTimeNamespace,
{
    /// Saves a mutably borrowed value back to the map.
    pub fn save<Writer: StateWriter<N>>(
        self,
        state: &mut Writer,
    ) -> Result<(), <Writer as StateWriter<N>>::Error> {
        let (key, value, container) = self.finish();
        state.set(&key, container.slot_value(&value))
    }

    /// Deletes the borrowed entry from the map.
    pub fn delete<Writer: StateWriter<N>>(
        self,
        state: &mut Writer,
    ) -> Result<(), <Writer as StateWriter<N>>::Error> {
        let (key, _, _) = self.finish();
        state.delete(&key)
    }
}

#[cfg(all(test, feature = "native"))]
mod native_tests;
#[cfg(test)]
mod tests;

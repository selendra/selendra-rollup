//! Metered utilities: hashing ([`MeteredHasher`]) and borsh decoding
//! ([`MeteredBorshDeserialize`]) that charge gas to a [`GasMeter`] before doing the work.

use std::marker::PhantomData;

use borsh::BorshDeserialize;
use digest::Digest;
use selendra_state::StateHasher;
use selendra_state::metered::StateGas;

use crate::{GasMeter, Spec, TxStateError};

/// A SHA-256 hasher (the state hasher, [`StateHasher`]) that charges gas: `hash_per_byte` per
/// byte for each [`update`](Self::update), and `hash_update` for the
/// [`finalize`](Self::finalize). So hashing `n` bytes costs `hash_update + hash_per_byte·n`,
/// the same as hashing a state value (`docs/serialization.md`, "Metered state access"),
/// however the input is split. Each charge comes before the work it pays for.
///
/// Upstream charged a fixed cost plus the bytes per update and nothing for the finalization
/// (P5-19: whatever the finalization computes, the last compression and the padding, was free).
pub struct MeteredHasher<'a, S: Spec, M: GasMeter<S>> {
    inner: StateHasher,
    meter: &'a mut M,
    hash_update: S::Gas,
    hash_per_byte: S::Gas,
    spec: PhantomData<fn() -> S>,
}

impl<S: Spec, M: GasMeter<S>> std::fmt::Debug for MeteredHasher<'_, S, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeteredHasher")
            .field("hash_update", &self.hash_update)
            .field("hash_per_byte", &self.hash_per_byte)
            .finish_non_exhaustive()
    }
}

impl<'a, S: Spec, M: GasMeter<S>> MeteredHasher<'a, S, M> {
    /// A hasher charging `meter` with the spec's `hash_update` and `hash_per_byte`.
    pub fn new(meter: &'a mut M) -> Self {
        let costs = &S::GAS_SCHEDULE.state;
        Self::new_with_custom_price(meter, costs.hash_update, costs.hash_per_byte)
    }

    /// A hasher charging `meter` with `hash_update` for the finalization and `hash_per_byte`
    /// per byte hashed.
    pub fn new_with_custom_price(
        meter: &'a mut M,
        hash_update: S::Gas,
        hash_per_byte: S::Gas,
    ) -> Self {
        Self {
            inner: StateHasher::new(),
            meter,
            hash_update,
            hash_per_byte,
            spec: PhantomData,
        }
    }

    /// Charges `hash_per_byte·data.len()`, then hashes `data`.
    ///
    /// # Errors
    /// The charge was refused or overflows (more than `u32::MAX` bytes at once included): `data`
    /// is not hashed, and the phase is poisoned.
    pub fn update(&mut self, data: &[u8]) -> Result<(), TxStateError<S>> {
        let units = u64::try_from(data.len()).unwrap_or(u64::MAX);
        self.meter
            .metered()
            .charge_linear(S::Gas::ZERO, self.hash_per_byte, units)?;
        self.inner.update(data);
        Ok(())
    }

    /// Charges `hash_update`, then returns the hash.
    ///
    /// # Errors
    /// The charge was refused: no hash, and the phase is poisoned.
    pub fn finalize(self) -> Result<[u8; 32], TxStateError<S>> {
        self.meter.charge_gas(self.hash_update)?;
        Ok(self.inner.finalize().into())
    }

    /// The hash of `data`, charging `meter` `hash_update + hash_per_byte·data.len()` (the
    /// spec's costs).
    ///
    /// # Errors
    /// As [`update`](Self::update) and [`finalize`](Self::finalize).
    pub fn digest(data: &[u8], meter: &'a mut M) -> Result<[u8; 32], TxStateError<S>> {
        let mut hasher = Self::new(meter);
        hasher.update(data)?;
        hasher.finalize()
    }
}

/// Why a metered borsh decode failed ([`MeteredBorshDeserialize`]). `G` is the gas error.
#[derive(Debug, thiserror::Error)]
pub enum MeteredBorshDeserializeError<G> {
    /// The charge was refused or overflows (nothing was decoded; the phase is poisoned).
    #[error("gas error while decoding: {0}")]
    Gas(#[source] G),
    /// The bytes are not the borsh encoding of a value (trailing bytes included). They were
    /// charged.
    #[error("invalid borsh encoding: {0}")]
    Decode(#[source] borsh::io::Error),
}

/// Borsh decoding that charges gas first: `per_byte·len` for the whole input, then
/// `borsh::from_slice`, which rejects trailing bytes. Implemented for every
/// [`BorshDeserialize`] type.
///
/// Upstream charged per read call through a [`MeteredReader`](crate::MeteredReader) while
/// decoding, a fixed bias, and advanced the input past the value (leaving trailing bytes to the
/// caller). Charging the whole input up front costs the same per byte whatever the decoder does,
/// is charged before any work (and any allocation the encoding claims), and is the same rule as
/// a state read's `decode_per_byte` (`get_decoded`).
pub trait MeteredBorshDeserialize: BorshDeserialize {
    /// Charges the spec's `decode_per_byte` per byte of `bytes`, then decodes them.
    ///
    /// # Errors
    /// See [`MeteredBorshDeserializeError`].
    fn metered_from_slice<S: Spec, M: GasMeter<S>>(
        bytes: &[u8],
        meter: &mut M,
    ) -> Result<Self, MeteredBorshDeserializeError<TxStateError<S>>> {
        Self::metered_from_slice_with_price(bytes, meter, S::GAS_SCHEDULE.state.decode_per_byte)
    }

    /// Charges `per_byte` per byte of `bytes`, then decodes them.
    ///
    /// # Errors
    /// See [`MeteredBorshDeserializeError`].
    fn metered_from_slice_with_price<S: Spec, M: GasMeter<S>>(
        bytes: &[u8],
        meter: &mut M,
        per_byte: S::Gas,
    ) -> Result<Self, MeteredBorshDeserializeError<TxStateError<S>>> {
        let units = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        meter
            .metered()
            .charge_linear(S::Gas::ZERO, per_byte, units)
            .map_err(MeteredBorshDeserializeError::Gas)?;
        borsh::from_slice(bytes).map_err(MeteredBorshDeserializeError::Decode)
    }
}

impl<T: BorshDeserialize> MeteredBorshDeserialize for T {}

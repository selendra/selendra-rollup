//! [`MeteredReader`]: an `io::Read` adapter that charges gas for the bytes it delivers.

use std::io;
use std::marker::PhantomData;

use selendra_state::metered::StateGas;

use crate::{GasMeter, Spec};

/// An `io::Read` adapter that charges `per_read_bias + per_byte·n` to a [`GasMeter`] for each
/// call that delivers `n > 0` bytes (a call that delivers none, e.g. at the end of the input,
/// is not charged). The charge comes right after the inner read (unlike the other metered
/// utilities, which charge before the work), so only the bytes delivered are charged; when it
/// is refused, those bytes are already in the caller's buffer, but the phase is poisoned.
///
/// A refused charge is returned as an `io::Error` wrapping the typed
/// [`TxStateError`](crate::TxStateError) (recover it with [`io::Error::downcast`]), and
/// poisons the phase like any refused charge.
///
/// [`read_exact`](io::Read::read_exact) charges once for the bytes it consumed, also when it
/// fails (the input ended, or the inner reader failed): a refused charge then takes precedence
/// over that error. Upstream discarded it (`let _ =`), so a reader that hit the end of its input
/// or an error delivered the bytes it had consumed for free (P5-20).
pub struct MeteredReader<'a, R, S: Spec, M: GasMeter<S>> {
    inner: R,
    meter: &'a mut M,
    per_byte: S::Gas,
    per_read_bias: S::Gas,
    spec: PhantomData<fn() -> S>,
}

impl<R, S: Spec, M: GasMeter<S>> std::fmt::Debug for MeteredReader<'_, R, S, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeteredReader")
            .field("per_byte", &self.per_byte)
            .field("per_read_bias", &self.per_read_bias)
            .finish_non_exhaustive()
    }
}

impl<'a, R: io::Read, S: Spec, M: GasMeter<S>> MeteredReader<'a, R, S, M> {
    /// Wraps `inner`, charging the spec's `decode_per_byte` per byte delivered and nothing per
    /// call (the gas schedule has no per-call cost).
    pub fn new(inner: R, meter: &'a mut M) -> Self {
        Self::with_prices(
            inner,
            meter,
            S::GAS_SCHEDULE.state.decode_per_byte,
            S::Gas::ZERO,
        )
    }

    /// Wraps `inner`, charging `per_read_bias + per_byte·n` per call delivering `n > 0` bytes.
    pub fn with_prices(
        inner: R,
        meter: &'a mut M,
        per_byte: S::Gas,
        per_read_bias: S::Gas,
    ) -> Self {
        Self {
            inner,
            meter,
            per_byte,
            per_read_bias,
            spec: PhantomData,
        }
    }

    /// Charges for `n` delivered bytes (nothing for none).
    fn charge(&mut self, n: usize) -> io::Result<()> {
        if n == 0 {
            return Ok(());
        }
        let units = u64::try_from(n).unwrap_or(u64::MAX);
        self.meter
            .metered()
            .charge_linear(self.per_read_bias, self.per_byte, units)
            .map_err(io::Error::other)
    }
}

impl<R: io::Read, S: Spec, M: GasMeter<S>> io::Read for MeteredReader<'_, R, S, M> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Charged after the inner read, so a short read or the end of the input is charged only
        // for the bytes delivered.
        let n = self.inner.read(buf)?;
        self.charge(n)?;
        Ok(n)
    }

    fn read_exact(&mut self, mut buf: &mut [u8]) -> io::Result<()> {
        let mut consumed = 0usize;
        while !buf.is_empty() {
            match self.inner.read(buf) {
                Ok(0) => {
                    // P5-20: the bytes consumed are charged; a refused charge is the error.
                    self.charge(consumed)?;
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                Ok(n) => {
                    consumed = consumed.saturating_add(n);
                    buf = buf.get_mut(n..).unwrap_or_default();
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => {
                    self.charge(consumed)?;
                    return Err(err);
                }
            }
        }
        self.charge(consumed)
    }
}

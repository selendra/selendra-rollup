//! [`UnlimitedGasMeter`]: a meter that charges nothing.

use std::fmt;
use std::marker::PhantomData;

use selendra_state::metered::StateGasMeter;

use crate::{GasMeteringError, Spec};

/// A gas meter that accepts every charge and records nothing (genesis, tests, fuzzing).
pub struct UnlimitedGasMeter<S>(PhantomData<fn() -> S>);

impl<S> UnlimitedGasMeter<S> {
    /// The meter.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<S> Default for UnlimitedGasMeter<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Clone for UnlimitedGasMeter<S> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<S> fmt::Debug for UnlimitedGasMeter<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnlimitedGasMeter")
    }
}

impl<S: Spec> StateGasMeter for UnlimitedGasMeter<S> {
    type Gas = S::Gas;
    type Error = GasMeteringError<S::Gas>;

    fn charge(&mut self, _gas: S::Gas) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestSpec;
    use crate::{GasArray, GasUnit};

    #[test]
    fn charges_nothing() {
        let mut meter = UnlimitedGasMeter::<TestSpec>::default();
        assert!(meter.charge(GasUnit::MAX).is_ok());
        assert!(meter.clone().charge(GasUnit::MAX).is_ok());
        assert_eq!(format!("{meter:?}"), "UnlimitedGasMeter");
    }
}

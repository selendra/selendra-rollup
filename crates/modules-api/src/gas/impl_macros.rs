//! The per-dimension arithmetic behind [`GasArray`](super::GasArray), shared by
//! [`GasUnit`](crate::GasUnit) and [`GasPrice`](crate::GasPrice).

use crate::Amount;

/// The value of one gas dimension.
pub(crate) trait Scalar: Copy + Ord {
    const ZERO: Self;
    const MAX: Self;
    fn checked_add(self, rhs: Self) -> Option<Self>;
    fn checked_sub(self, rhs: Self) -> Option<Self>;
    fn checked_mul(self, rhs: Self) -> Option<Self>;
    fn checked_div(self, rhs: Self) -> Option<Self>;
}

impl Scalar for u64 {
    const ZERO: Self = 0;
    const MAX: Self = u64::MAX;

    fn checked_add(self, rhs: Self) -> Option<Self> {
        u64::checked_add(self, rhs)
    }

    fn checked_sub(self, rhs: Self) -> Option<Self> {
        u64::checked_sub(self, rhs)
    }

    fn checked_mul(self, rhs: Self) -> Option<Self> {
        u64::checked_mul(self, rhs)
    }

    fn checked_div(self, rhs: Self) -> Option<Self> {
        u64::checked_div(self, rhs)
    }
}

impl Scalar for Amount {
    const ZERO: Self = Amount::ZERO;
    const MAX: Self = Amount::MAX;

    fn checked_add(self, rhs: Self) -> Option<Self> {
        Amount::checked_add(self, rhs)
    }

    fn checked_sub(self, rhs: Self) -> Option<Self> {
        Amount::checked_sub(self, rhs)
    }

    fn checked_mul(self, rhs: Self) -> Option<Self> {
        Amount::checked_mul(self, rhs)
    }

    fn checked_div(self, rhs: Self) -> Option<Self> {
        Amount::checked_div(self, rhs)
    }
}

/// `op` on each pair of dimensions, or `None` if it fails in one.
pub(crate) fn zip_checked<T: Scalar, const N: usize>(
    lhs: [T; N],
    rhs: [T; N],
    op: impl Fn(T, T) -> Option<T>,
) -> Option<[T; N]> {
    let mut out = lhs;
    for (value, r) in out.iter_mut().zip(rhs) {
        *value = op(*value, r)?;
    }
    Some(out)
}

/// `op` on each dimension with the same scalar, or `None` if it fails in one.
pub(crate) fn map_checked<T: Scalar, const N: usize>(
    values: [T; N],
    scalar: T,
    op: impl Fn(T, T) -> Option<T>,
) -> Option<[T; N]> {
    zip_checked(values, [scalar; N], op)
}

/// Implements [`GasArray`](super::GasArray) for `$t` (a wrapper of `[$s; GAS_DIMENSIONS]` with
/// `from_dimensions`/`dimensions`).
macro_rules! impl_gas_array {
    ($t:ty, $s:ty) => {
        impl $crate::gas::GasArray for $t {
            type Scalar = $s;

            const ZEROED: Self = Self::from_dimensions(
                [<$s as $crate::gas::impl_macros::Scalar>::ZERO; $crate::gas::GAS_DIMENSIONS],
            );

            const MAX: Self = Self::from_dimensions(
                [<$s as $crate::gas::impl_macros::Scalar>::MAX; $crate::gas::GAS_DIMENSIONS],
            );

            fn checked_combine(self, rhs: Self) -> Option<Self> {
                $crate::gas::impl_macros::zip_checked(
                    self.dimensions(),
                    rhs.dimensions(),
                    $crate::gas::impl_macros::Scalar::checked_add,
                )
                .map(Self::from_dimensions)
            }

            fn checked_sub(self, rhs: Self) -> Option<Self> {
                $crate::gas::impl_macros::zip_checked(
                    self.dimensions(),
                    rhs.dimensions(),
                    $crate::gas::impl_macros::Scalar::checked_sub,
                )
                .map(Self::from_dimensions)
            }

            fn checked_scalar_product(self, scalar: $s) -> Option<Self> {
                $crate::gas::impl_macros::map_checked(
                    self.dimensions(),
                    scalar,
                    $crate::gas::impl_macros::Scalar::checked_mul,
                )
                .map(Self::from_dimensions)
            }

            fn checked_scalar_division(self, scalar: $s) -> Option<Self> {
                $crate::gas::impl_macros::map_checked(
                    self.dimensions(),
                    scalar,
                    $crate::gas::impl_macros::Scalar::checked_div,
                )
                .map(Self::from_dimensions)
            }

            fn dim_is_less_than(self, rhs: Self) -> bool {
                self.dimensions()
                    .iter()
                    .zip(rhs.dimensions().iter())
                    .all(|(l, r)| l < r)
            }

            fn dim_is_less_or_eq(self, rhs: Self) -> bool {
                self.dimensions()
                    .iter()
                    .zip(rhs.dimensions().iter())
                    .all(|(l, r)| l <= r)
            }

            fn calculate_min(lhs: Self, rhs: Self) -> Self {
                let mut out = lhs.dimensions();
                for (value, r) in out.iter_mut().zip(rhs.dimensions()) {
                    *value = ::core::cmp::min(*value, r);
                }
                Self::from_dimensions(out)
            }
        }
    };
}

pub(crate) use impl_gas_array;

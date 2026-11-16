//! [`ConsensusType`]: the marker for types allowed in consensus data.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

/// A type that may appear in consensus data: stored in state, signed, sent in a call
/// message or event, or committed to by a proof.
///
/// Every value of a consensus type must encode and decode the same way natively and in the
/// 32-bit zk guest, and have one encoding. So a consensus type never contains, at any depth:
/// - `usize` or `isize`: borsh encodes them as 64 bits, and the 32-bit guest fails to decode
///   a value above `u32::MAX` that a native node accepts, which makes the block unprovable;
/// - `f32` or `f64`: banned in consensus code (borsh refuses NaN, and float arithmetic is not
///   reproducible everywhere);
/// - `HashMap` or `HashSet`: their iteration order depends on a per-process seed.
///
/// The trait is implemented for the primitive and collection types that are allowed, and for
/// every consensus type of the Selendra crates. Containers implement it only when their
/// contents do, so the check is transitive: it sees through type aliases, nested structs and
/// generic parameters. Module crates derive it (`#[derive(ConsensusType)]`); a hand-written
/// impl outside the Selendra crates is a review flag. Types not listed here (e.g. a foreign
/// crate's types) need a newtype.
///
/// It is not a check of everything consensus data needs: `BorshSerialize` must still be
/// infallible, and decoding must accept everything encoding produces (the round-trip
/// precondition, `docs/serialization.md`).
///
/// ```
/// use std::collections::BTreeMap;
///
/// use selendra_interface::common::ConsensusType;
///
/// fn stored<T: ConsensusType>() {}
///
/// type Len = u64;
/// stored::<u64>();
/// stored::<Len>();
/// stored::<Vec<u32>>();
/// stored::<BTreeMap<u8, u8>>();
/// stored::<(bool, Option<String>, [u8; 32])>();
/// ```
///
/// Each of these fails with E0277 (`usize`, `f64`, `HashMap`, and the same types nested or
/// behind an alias):
///
/// ```compile_fail,E0277
/// fn stored<T: selendra_interface::common::ConsensusType>() {}
/// stored::<usize>();
/// ```
///
/// ```compile_fail,E0277
/// fn stored<T: selendra_interface::common::ConsensusType>() {}
/// stored::<f64>();
/// ```
///
/// ```compile_fail,E0277
/// fn stored<T: selendra_interface::common::ConsensusType>() {}
/// stored::<std::collections::HashMap<u8, u8>>();
/// ```
///
/// ```compile_fail,E0277
/// fn stored<T: selendra_interface::common::ConsensusType>() {}
/// stored::<Vec<usize>>();
/// ```
///
/// ```compile_fail,E0277
/// fn stored<T: selendra_interface::common::ConsensusType>() {}
/// type Len = usize;
/// stored::<Len>();
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a consensus type",
    label = "not allowed in consensus data",
    note = "consensus data must not contain `usize`, `isize`, `f32`, `f64`, `HashMap` or `HashSet` at any depth (use `u64`/`u32`, integers, `BTreeMap`/`BTreeSet`)",
    note = "for your own types made only of consensus types, derive `ConsensusType`"
)]
pub trait ConsensusType {}

/// Implements [`ConsensusType`] for non-generic types (Selendra crates only).
///
/// Use it only for a type whose every field is a consensus type: the macro does not check the
/// fields. Generic types write the impl by hand, bounded on their parameters.
#[doc(hidden)]
#[macro_export]
macro_rules! impl_consensus_type {
    ($($ty:ty),+ $(,)?) => {
        $(impl $crate::common::ConsensusType for $ty {})+
    };
}

impl_consensus_type!(
    bool,
    u8,
    u16,
    u32,
    u64,
    u128,
    i8,
    i16,
    i32,
    i64,
    i128,
    String,
    str,
    (),
    bytes::Bytes,
);

impl<T: ConsensusType> ConsensusType for Vec<T> {}
impl<T: ConsensusType> ConsensusType for [T] {}
impl<T: ConsensusType, const N: usize> ConsensusType for [T; N] {}
impl<T: ConsensusType> ConsensusType for Option<T> {}
impl<T: ConsensusType + ?Sized> ConsensusType for Box<T> {}
impl<K: ConsensusType, V: ConsensusType> ConsensusType for BTreeMap<K, V> {}
impl<T: ConsensusType> ConsensusType for BTreeSet<T> {}
/// A `PhantomData` stores nothing, whatever its parameter.
impl<T: ?Sized> ConsensusType for PhantomData<T> {}

macro_rules! impl_for_tuples {
    ($(($($name:ident),+))+) => {
        $(impl<$($name: ConsensusType),+> ConsensusType for ($($name,)+) {})+
    };
}

impl_for_tuples! {
    (A)
    (A, B)
    (A, B, C)
    (A, B, C, D)
    (A, B, C, D, E)
    (A, B, C, D, E, F)
    (A, B, C, D, E, F, G)
    (A, B, C, D, E, F, G, H)
    (A, B, C, D, E, F, G, H, I)
    (A, B, C, D, E, F, G, H, I, J)
    (A, B, C, D, E, F, G, H, I, J, K)
    (A, B, C, D, E, F, G, H, I, J, K, L)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consensus<T: ConsensusType + ?Sized>() {}

    #[test]
    fn allowed_types_are_consensus_types() {
        consensus::<bool>();
        consensus::<u128>();
        consensus::<i8>();
        consensus::<str>();
        consensus::<[u8]>();
        consensus::<Box<[u64]>>();
        consensus::<PhantomData<usize>>();
        consensus::<PhantomData<f64>>();
        consensus::<(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, bool, ())>();
        consensus::<BTreeMap<String, BTreeSet<Vec<Option<[u8; 4]>>>>>();
        consensus::<crate::Bytes>();
    }
}

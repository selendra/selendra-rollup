//! Selendra state: the namespaces state is partitioned into, the storage keys and values
//! ([`SlotKey`], [`SlotValue`]), the codecs that turn typed items into those bytes, and the
//! typed containers modules keep their state in ([`StateValue`], [`StateMap`], [`StateVec`] and
//! their kernel and accessory variants).
//!
//! Containers do not hold data: they compute keys and encode values, and read and write through
//! an accessor ([`StateReader`] / [`StateWriter`]) for their namespace. The storage key layout
//! is specified in `docs/serialization.md` ("State keys").

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod accessors;
pub mod codec;
pub mod containers;
pub mod namespaces;
mod slot;
#[cfg(test)]
mod test_state;

pub use accessors::{
    AccessoryStateReaderAndWriter, InfallibleStateReaderAndWriter, StateReader,
    StateReaderAndWriter, StateWriter,
};
pub use codec::{
    BorshCodec, EncodeLike, StateCodec, StateItemCodec, StateItemDecoder, StateItemEncoder,
};
pub use containers::{
    AccessoryStateMap, AccessoryStateValue, AccessoryStateVec, Borrowed, BorrowedMut,
    KernelStateMap, KernelStateValue, KernelStateVec, NamespacedStateMap, NamespacedStateValue,
    NamespacedStateVec, StateMap, StateMapError, StateValue, StateValueError, StateVec,
    StateVecError, StateVecIter,
};
pub use namespaces::{
    Accessory, CompileTimeNamespace, Kernel, Namespace, ProvableCompileTimeNamespace,
    ProvableNamespace, User,
};
pub use slot::{Prefix, SlotKey, SlotKeyTooShort, SlotValue};

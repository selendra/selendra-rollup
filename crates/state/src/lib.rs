//! Selendra state: the namespaces state is partitioned into, the storage keys and values
//! ([`SlotKey`], [`SlotValue`]), the codecs that turn typed items into those bytes, the typed
//! containers modules keep their state in ([`StateValue`], [`StateMap`], [`StateVec`] and their
//! kernel and accessory variants), and the layer under them: the [`Storage`] interface, the
//! [`Witness`] the native prover records for the zk guest, and the [`StateCheckpoint`] holding
//! a block's reads and writes.
//!
//! Containers do not hold data: they compute keys and encode values, and read and write through
//! an accessor ([`StateReader`] / [`StateWriter`]) for their namespace. The storage key layout
//! is specified in `docs/serialization.md` ("State keys").
//!
//! # Features
//! - `native`: node-only code, never compiled into the zk guest: `NativeStorage`, accessory
//!   reads, storage proofs (`get_with_proof`), raw container APIs and historical reads.
//! - `arbitrary`: `NamespacedStateMap::arbitrary_state_map`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod accessors;
mod cache;
mod checkpoint;
pub mod codec;
pub mod containers;
pub mod namespaces;
mod slot;
mod storage;
#[cfg(test)]
mod test_state;
#[cfg(test)]
mod test_storage;
mod witness;

// `selendra-interface/native` marks a node build, where this crate's node-only items
// (`NativeStorage`, accessory reads, proofs) are expected too. Cargo cannot make the first imply
// the second (the dependency points the other way), so say what to do instead of failing later
// with missing items.
#[cfg(not(feature = "native"))]
selendra_interface::__if_native! {
    compile_error!(
        "`selendra-interface/native` is enabled but `selendra-state/native` is not: enable both"
    );
}

#[cfg(feature = "native")]
pub use accessors::ProvenStateAccessor;
pub use accessors::{
    AccessoryStateReaderAndWriter, InfallibleStateReaderAndWriter, StateReader,
    StateReaderAndWriter, StateWriter,
};
pub use cache::{
    AccessSize, IsValueCached, OrderedReadsAndWrites, ProvableStorageCache, StateAccesses,
};
#[cfg(feature = "native")]
pub use checkpoint::AccessoryStateCheckpoint;
pub use checkpoint::{AccessoryDelta, FirstTimeReads, StateCheckpoint};
pub use codec::{
    BorshCodec, EncodeLike, StateCodec, StateItemCodec, StateItemDecoder, StateItemEncoder,
};
pub use containers::{
    AccessoryStateMap, AccessoryStateValue, AccessoryStateVec, Borrowed, BorrowedMut,
    KernelStateMap, KernelStateValue, KernelStateVec, NamespacedStateMap, NamespacedStateValue,
    NamespacedStateVec, StateMap, StateMapError, StateValue, StateValueError, StateVec,
    StateVecError, StateVecIter,
};
#[cfg(feature = "native")]
pub use containers::{RawMapEntry, StateVecRawIter};
pub use namespaces::{
    Accessory, CompileTimeNamespace, Kernel, Namespace, ProvableCompileTimeNamespace,
    ProvableNamespace, User,
};
pub use slot::{Prefix, SlotKey, SlotKeyTooShort, SlotValue};
pub use storage::{
    DefaultStorageSpec, MerkleProofSpec, NodeLeaf, NodeLeafAndMaybeValue, StateRoot, StateUpdate,
    Storage, StorageProof, VAL_HASH_AND_SIZE_LEN, val_hash_and_size,
};
#[cfg(feature = "native")]
pub use storage::{NativeStorage, ProofOutput};
pub use witness::{ArrayWitness, InvalidWitness, Witness};

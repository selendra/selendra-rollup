//! Selendra state: the namespaces state is partitioned into, the storage keys and values
//! ([`SlotKey`], [`SlotValue`]), the codecs that turn typed items into those bytes, the typed
//! containers modules keep their state in ([`StateValue`], [`StateMap`], [`StateVec`] and their
//! kernel and accessory variants), and the layer under them: the [`Storage`] interface, the
//! [`Witness`] the native prover records for the zk guest, and the [`StateCheckpoint`] holding
//! a block's reads and writes.
//!
//! The NOMT state trees: their root ([`StorageRoot`]), the canonical multi-proof
//! ([`NomtProof`]), proof verification ([`verify_storage_proof`], [`verify_namespace`]) and the
//! zk-guest storage ([`NomtVerifierStorage`]). All of it is in the guest build too. The native
//! prover storage, which needs the NOMT database, is `NomtProverStorage` in the node-only
//! `selendra-db` crate.
//!
//! Containers do not hold data: they compute keys and encode values, and read and write through
//! an accessor ([`StateReader`] / [`StateWriter`]) for their namespace. The storage key layout
//! is specified in `docs/serialization.md` ("State keys").
//!
//! # Features
//! - `native`: node-only code, never compiled into the zk guest: `NativeStorage`, accessory
//!   reads, storage proofs (`get_with_proof`), raw container APIs and historical reads.
//! - `rockbound` (implies `native`): rockbound's `VersionedSchemaKeyMarker` and `HasPrefix` for
//!   [`SlotKey`], so the node's flat store (RocksDB) can key values by it.
//! - `arbitrary`: `NamespacedStateMap::arbitrary_state_map`.
//! - `test-utils`: [`test_utils`], helpers for the node's storage tests (random container
//!   operations, a model of a checkpoint, witness helpers). Never in a node or guest build.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod accessors;
mod cache;
mod checkpoint;
pub mod codec;
pub mod containers;
pub mod namespaces;
mod nomt;
mod slot;
mod storage;
mod storage_root;
#[cfg(test)]
mod test_state;
#[cfg(test)]
mod test_storage;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
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
// `self::`: in test builds the `nomt` crate (a dev-dependency) has the same name.
pub use self::nomt::{
    InvalidNomtProof, NomtProof, NomtVerifierStorage, namespace_needs_proof, verify_namespace,
    verify_storage_proof,
};
pub use slot::{Prefix, SlotKey, SlotKeyTooShort, SlotValue};
pub use storage::{
    DefaultStorageSpec, MerkleProofSpec, NodeLeaf, NodeLeafAndMaybeValue, StateRoot, StateUpdate,
    Storage, StorageProof, VAL_HASH_AND_SIZE_LEN, val_hash_and_size,
};
#[cfg(feature = "native")]
pub use storage::{NativeStorage, ProofOutput};
pub use storage_root::{GLOBAL_ROOT_TAG, StorageRoot};
pub use witness::{ArrayWitness, InvalidWitness, Witness};

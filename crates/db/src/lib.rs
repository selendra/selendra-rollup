//! The node's state databases (node-only, never in the zk guest; Unix-only, like NOMT).
//!
//! - [`NomtStateDb`]: the state trees, one [NOMT](https://github.com/thrumdev/nomt) database per
//!   provable namespace (user, kernel). NOMT stores only `H(key) → val_hash_and_size` per slot
//!   and computes the roots and the witnesses; sessions on it come from [`NomtSessionBuilder`].
//! - [`FlatStateDb`]: the values, versioned (RocksDB through rockbound), read as of a version
//!   through [`HistoricalStateReader`].
//! - [`AccessoryDb`]: accessory state (not provable), versioned.
//! - [`DbGroup`]: all of them, committed in a fixed order ([`DbGroup::commit`]). Opening them
//!   checks that they were written with the same hasher (the hasher guard, [`DbGroup::open`]):
//!   the chain's is `selendra_state::StateHasher`.
//!
//! Every version's root ([`NomtRoots`], `user ‖ kernel` as in
//! [`StorageRoot`](selendra_state::StorageRoot)) is stored in each database that records
//! versions, so they can be checked against each other when opened.
//!
//! Stored data that does not decode, and databases that disagree, are errors, never panics.
//!
//! - [`NomtProverStorage`]: the native [`Storage`](selendra_state::Storage) and
//!   [`NativeStorage`](selendra_state::NativeStorage) on [`DbGroup::readers`]: it executes blocks
//!   natively and records the witness the zk guest's
//!   [`NomtVerifierStorage`](selendra_state::NomtVerifierStorage) verifies.
//!
//! Not here yet: the storage manager (forks, uncommitted snapshots, finalization, startup crash
//! recovery, pruning); the ledger DB.
//!
//! # Features
//! - `test-utils`: [`harness`] (the databases in a temporary directory, for tests).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(not(unix))]
compile_error!("selendra-db is Unix-only: NOMT supports only Unix systems");

mod accessory;
mod config;
mod flat;
mod group;
#[cfg(any(test, feature = "test-utils"))]
pub mod harness;
mod historical;
mod nomt_state;
mod prover;
pub mod schema;
#[cfg(any(test, feature = "test-utils"))]
mod test_utils;

pub use accessory::{AccessoryDb, DbOptions};
pub use config::{NomtNamespaceConfig, StateDbConfig};
pub use flat::{DbCache, FlatStateDb};
pub use group::{DbGroup, NomtChangeSet, StorageReaders};
pub use historical::{HistoricalStateReader, KvPair, StateChanges};
pub(crate) use nomt_state::SessionsContainer;
pub use nomt_state::{
    NomtRoots, NomtSessionBuilder, NomtStateDb, SharedOverlays, StateFinishedSession, StateOverlay,
    WitnessMode,
};
pub use prover::{NomtProverStorage, NomtStateUpdate};
pub use rockbound::versioned_db::HistoricalValueError;

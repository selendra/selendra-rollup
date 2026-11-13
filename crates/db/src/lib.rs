//! The node's state databases (node-only, never in the zk guest; Unix-only, like NOMT).
//!
//! - [`NomtStateDb`]: the state trees, one [NOMT](https://github.com/thrumdev/nomt) database per
//!   provable namespace (user, kernel). NOMT stores only `H(key) → val_hash_and_size` per slot
//!   and computes the roots and the witnesses; sessions on it come from [`NomtSessionBuilder`].
//! - [`FlatStateDb`]: the values, versioned (RocksDB through rockbound), read as of a version
//!   through [`HistoricalStateReader`].
//! - [`AccessoryDb`]: accessory state (not provable), versioned.
//! - The [`ledger`] DB: the chain's history (slots, batches, transactions, events, proofs, STF
//!   info), one slot per committed version; [`LedgerReader`] reads it and builds a slot's
//!   writes ([`LedgerChangeSet`]).
//! - [`DbGroup`]: all of them, committed in a fixed order ([`DbGroup::commit`]). Opening them
//!   checks that they were written with the same hasher (the hasher guard, [`DbGroup::open`]):
//!   the chain's is `selendra_state::StateHasher`; then startup crash recovery rolls back what
//!   an interrupted commit wrote ([`RecoveryReport`]). A commit that fails once it started
//!   writing poisons the group until it is reopened ([`DbGroup::is_poisoned`]).
//!
//! Every version's root ([`NomtRoots`], `user ‖ kernel` as in
//! [`StorageRoot`](selendra_state::StorageRoot)) is stored in each database that records
//! versions, so they can be checked against each other when opened.
//!
//! Stored data that does not decode, and databases that disagree, are errors, never panics.
//!
//! - [`NomtProverStorage`]: the native [`Storage`](selendra_state::Storage) and
//!   [`NativeStorage`](selendra_state::NativeStorage) on the databases' readers: it executes
//!   blocks natively and records the witness the zk guest's
//!   [`NomtVerifierStorage`](selendra_state::NomtVerifierStorage) verifies. A storage that can
//!   no longer compute (a newer version committed, or its blocks discarded) fails with a typed
//!   [`StaleStorage`] error.
//! - [`NomtStorageManager`]: the node's
//!   [`HierarchicalStorageManager`](selendra_interface::node::storage::HierarchicalStorageManager):
//!   forks of uncommitted blocks (NOMT overlays and snapshots of the other databases) on top of
//!   the committed state, and their finalization ([`StorageManagerConfig`]).
//!
//! Not here yet: pruning.
//!
//! # Features
//! - `test-utils`: `harness` (the databases and the storage manager in a temporary directory,
//!   a test block header, for tests) and fault injection: a per-instance `CommitHook` called at
//!   every [`CommitPoint`] of a commit, of a finalization and of crash recovery
//!   (`DbGroup::open_with_hook`, `NomtStorageManager::open_with_hook`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(not(unix))]
compile_error!("selendra-db is Unix-only: NOMT supports only Unix systems");

mod accessory;
mod config;
mod faults;
mod flat;
mod group;
#[cfg(any(test, feature = "test-utils"))]
pub mod harness;
mod historical;
pub mod ledger;
mod manager;
mod nomt_state;
mod prover;
mod recovery;
pub mod schema;
#[cfg(any(test, feature = "test-utils"))]
mod test_utils;

pub use accessory::{AccessoryDb, DbOptions};
pub use config::{NomtNamespaceConfig, StateDbConfig};
pub use faults::CommitPoint;
#[cfg(any(test, feature = "test-utils"))]
pub use faults::{CommitHook, fail_at};
pub use flat::{DbCache, FlatStateDb};
pub use group::{DbGroup, NomtChangeSet, StorageReaders};
pub use historical::{HistoricalStateReader, KvPair, StateChanges};
pub use ledger::{LedgerChangeSet, LedgerReader};
pub use manager::{NomtStorageManager, StorageManagerConfig};
pub(crate) use nomt_state::SessionsContainer;
pub use nomt_state::{
    NomtRoots, NomtSessionBuilder, NomtStateDb, SharedOverlays, StateFinishedSession, StateOverlay,
    WitnessMode,
};
pub use prover::{NomtProverStorage, NomtStateUpdate, StaleStorage};
pub use recovery::{RecoveryReport, RecoveryStep};
pub use rockbound::versioned_db::HistoricalValueError;

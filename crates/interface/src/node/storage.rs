//! The storage manager the full node drives: a tree of states mapped one to one to DA blocks,
//! forks included ([`HierarchicalStorageManager`]).

use crate::common::SlotNumber;
use crate::da::BlockHeaderTrait;

/// A storage manager that keeps a tree of rollup states, one per DA block, forks included.
///
/// The node executes each DA block on the state after its parent
/// ([`create_state_for`](Self::create_state_for)), saves the block's changes
/// ([`save_change_set`](Self::save_change_set)), and commits a block once the DA layer finalizes
/// it ([`finalize`](Self::finalize)): its uncommitted ancestors with it, and every other fork is
/// discarded.
///
/// Generic over the DA block header (upstream: over the whole `DaSpec`, which left the spec
/// unconstrained in implementations generic over the header alone).
pub trait HierarchicalStorageManager<Hdr: BlockHeaderTrait>: Send + Sync {
    /// The state the state transition function executes on (natively).
    type StfState: Clone + Send + Sync;
    /// The changes the state transition function produces for one block.
    type StfChangeSet: Send;
    /// The state the ledger (the chain's history) is read from and its next slot built on.
    type LedgerState: Clone + Send + Sync;
    /// The ledger changes of one block.
    type LedgerChangeSet: Send;

    /// The state before `hdr`, to execute it on: the state after its parent, which must be the
    /// finalized block or a block whose changes were saved. Registers `hdr` on its parent, so
    /// that its changes can be saved.
    ///
    /// # Errors
    /// If the parent is neither (unknown, older than the finalized block, discarded, or not
    /// saved), or `hdr` does not fit on it.
    fn create_state_for(
        &mut self,
        hdr: &Hdr,
    ) -> anyhow::Result<(Self::StfState, Self::LedgerState)>;

    /// The state after `hdr`, which must be a block whose changes were saved, or the finalized
    /// block (for APIs and the sequencer). Its changes cannot be saved: it is not the state
    /// before any registered block.
    ///
    /// # Errors
    /// If `hdr` is neither. (Upstream returned the finalized state for any other header.)
    fn create_state_after(
        &mut self,
        hdr: &Hdr,
    ) -> anyhow::Result<(Self::StfState, Self::LedgerState)>;

    /// The state of the finalized (committed) block: the only view of an empty database, and
    /// what a node resumes from after a restart.
    fn create_finalized_state(&mut self) -> anyhow::Result<(Self::StfState, Self::LedgerState)>;

    /// Saves the changes of `hdr`, which must have been registered by
    /// [`create_state_for`](Self::create_state_for) and executed on the state it returned.
    ///
    /// # Errors
    /// If `hdr` was not registered, was saved already, or the changes were not built on its
    /// parent.
    fn save_change_set(
        &mut self,
        hdr: &Hdr,
        stf_change_set: Self::StfChangeSet,
        ledger_change_set: Self::LedgerChangeSet,
    ) -> anyhow::Result<()>;

    /// Commits `hdr` and its uncommitted ancestors, and discards every other fork. Finalizing
    /// the finalized block (or one of its committed ancestors) is a no-op.
    ///
    /// # Errors
    /// If `hdr` is not a saved block, or a commit fails.
    fn finalize(&mut self, hdr: &Hdr) -> anyhow::Result<()>;

    /// The finalized block (`None`: nothing is finalized, the database is empty).
    fn finalized(&self) -> Option<FinalizedBlock<Hdr::Hash>>;
}

/// The finalized block of a [`HierarchicalStorageManager`]: the newest committed one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedBlock<H> {
    /// The DA block's hash.
    pub hash: H,
    /// The DA block's height.
    pub da_height: u64,
    /// The rollup slot it was committed as.
    pub slot: SlotNumber,
}

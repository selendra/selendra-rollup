//! The storage manager ([`NomtStorageManager`]): forks of uncommitted blocks on top of the
//! committed state databases ([`DbGroup`]), and their finalization. The fork tree's rules are
//! in [`forks`].

mod forks;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::marker::PhantomData;
use std::num::NonZeroU64;

use anyhow::Context;
use selendra_interface::common::{HexString, SlotNumber};
use selendra_interface::da::BlockHeaderTrait;
use selendra_interface::node::storage::{FinalizedBlock, HierarchicalStorageManager};
use selendra_state::MerkleProofSpec;

#[cfg(any(test, feature = "test-utils"))]
use crate::faults::CommitHook;
use crate::faults::{CommitPoint, Faults};
use crate::group::SnapshotGroup;
use crate::historical::next_version_after;
use crate::ledger::{self, LedgerChangeSet, LedgerReader, StoredSlot};
use crate::nomt_state::SharedOverlays;
use crate::pruner::{PruneStats, PrunerConfig};
use crate::recovery::RecoveryReport;
use crate::{DbGroup, NomtChangeSet, NomtProverStorage, NomtRoots, StateDbConfig, WitnessMode};

use self::forks::ForkTree;

/// Configuration of a [`NomtStorageManager`]. Build it with [`new`](Self::new) (more fields
/// come later, with defaults), then change fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StorageManagerConfig {
    /// The state databases.
    pub state: StateDbConfig,
    /// Whether storages to execute blocks on
    /// ([`create_state_for`](HierarchicalStorageManager::create_state_for)) record a witness
    /// (for proving). Other storages never do.
    pub witness: WitnessMode,
    /// At most this many uncommitted blocks (executed or being executed, on every fork) are
    /// kept; more is an error of `create_state_for` (finalize first). Upstream had no bound.
    pub max_unfinalized_blocks: NonZeroU64,
    /// When old versions are pruned ([`PrunerConfig`]; default: never).
    pub pruning: PrunerConfig,
}

impl StorageManagerConfig {
    /// The default [`max_unfinalized_blocks`](Self::max_unfinalized_blocks).
    pub const DEFAULT_MAX_UNFINALIZED_BLOCKS: NonZeroU64 = match NonZeroU64::new(4096) {
        Some(max) => max,
        None => NonZeroU64::MIN,
    };

    /// A configuration with the state databases `state`, witness `witness`, and the defaults
    /// (no pruning).
    pub fn new(state: StateDbConfig, witness: WitnessMode) -> Self {
        Self {
            state,
            witness,
            max_unfinalized_blocks: Self::DEFAULT_MAX_UNFINALIZED_BLOCKS,
            pruning: PrunerConfig::Off,
        }
    }
}

/// The storage manager of the NOMT backend: a [`HierarchicalStorageManager`] whose storages are
/// [`NomtProverStorage`]s and whose ledger states are [`LedgerReader`]s, on top of the
/// committed state databases ([`DbGroup`]).
///
/// The node executes each DA block on the state after its parent
/// ([`create_state_for`](HierarchicalStorageManager::create_state_for)), saves the block's
/// changes ([`save_change_set`](HierarchicalStorageManager::save_change_set)) and, once the DA
/// layer finalizes a block, commits it with its uncommitted ancestors and discards every other
/// fork ([`finalize`](HierarchicalStorageManager::finalize)). Until then, a saved block's changes
/// are kept in memory: a NOMT overlay (in a map shared with the storages, behind a lock) and
/// snapshots of the flat store, the accessory DB and the ledger, which storages of later blocks
/// read.
///
/// What upstream's manager did not check, and this one does (before changing anything):
/// - a block must be executed on the finalized block or a saved block, one DA height above it,
///   and registered once (upstream executed a block with an unknown or old parent on the
///   finalized state, and a cycle of headers made its walks loop forever);
/// - saved changes must be the registered block's, built on its parent's version, roots and
///   ledger, for the block's DA hash and height (upstream checked only that the parent had a
///   child);
/// - a finalization validates its whole chain before it writes (upstream committed segment by
///   segment and lost the overlay of a failed one), and finalizing the finalized block or a
///   committed ancestor is a no-op;
/// - the state "after" a block exists only for a saved block or the finalized one (upstream
///   silently returned the finalized state for any other header).
///
/// **Locking.** A finalization commits its blocks one by one, each under the overlays write
/// lock (taken per block, not across the whole chain as upstream did, so readers go on between
/// the commits of a long catch-up). A NOMT session is opened under the read lock, so a session
/// sees a block either as an overlay on the old trees or committed. NOMT's commit waits for
/// every open session: never call `finalize` while this thread holds a NOMT session (it would
/// deadlock), and drop sessions before opening others on threads that may run during a
/// finalization. A storage's prefix iterator (`maybe_iter_*`) holds the flat store's lock,
/// which the commit's flat-store write waits for while it holds the overlays write lock: while
/// one is alive on a thread, do not open NOMT sessions there (`get_with_proof`,
/// `compute_state_update`: they wait for the overlays lock, the finalization for the iterator,
/// a deadlock) and do not call `finalize` there; collect the iterator or drop it first.
///
/// **Restart.** Only finalized blocks are committed. On open, the finalized block (DA hash,
/// height and slot) is the ledger's newest slot, which every commit writes: no caller input.
/// Unfinalized blocks are lost and re-executed.
///
/// **Poisoning.** A commit that fails once it started writing poisons the databases
/// ([`DbGroup::is_poisoned`]), and the manager with them: every method fails until the manager
/// is dropped and opened again (crash recovery repairs the databases). Failures before anything
/// is written (any check) leave the manager usable and unchanged.
///
/// **Pruning** ([`StorageManagerConfig::pruning`], [`pruner`](crate::pruner)): synchronous, no
/// background thread (upstream ran a pruner thread whose batch a later finalization committed,
/// and could fail a finalization after its commit). [`PrunerConfig::OnceAtStartup`] prunes
/// while the manager is opened, until nothing is left; [`PrunerConfig::Periodic`] runs one pass
/// at the end of a finalization, after the commits, bounded by its budget. A failed pass does
/// not fail the finalization (its blocks are committed: upstream returned an `Err` the runner
/// stopped on) and poisons nothing: it is kept in [`last_prune_error`](Self::last_prune_error),
/// logged, and retried at the next finalization. Every storage the manager hands out pins the
/// committed version it is based on, so pruning never removes what a live storage reads
/// (upstream's storages older than the pruning window panicked on their next read).
pub struct NomtStorageManager<S: MerkleProofSpec, Hdr: BlockHeaderTrait> {
    group: DbGroup<S::Hasher>,
    /// The NOMT overlays of the saved blocks, shared with the storages built on them.
    overlays: SharedOverlays<Hdr::Hash>,
    /// The other changes of the saved blocks (the same keys as `overlays`).
    snapshots: HashMap<Hdr::Hash, SnapshotGroup>,
    tree: ForkTree<Hdr::Hash>,
    finalized: Option<FinalizedBlock<Hdr::Hash>>,
    witness: WitnessMode,
    max_unfinalized_blocks: NonZeroU64,
    /// Set when the manager's own state can no longer be trusted (an overlay lost).
    poisoned: bool,
    pruning: PrunerConfig,
    /// The committed version at the last periodic pass that left no backlog.
    pruned_at: Option<SlotNumber>,
    last_prune: Option<PruneStats>,
    last_prune_error: Option<anyhow::Error>,
    /// Pruning passes run (tests).
    prune_runs: u64,
    _spec: PhantomData<fn() -> S>,
}

impl<S: MerkleProofSpec, Hdr: BlockHeaderTrait> core::fmt::Debug for NomtStorageManager<S, Hdr> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NomtStorageManager")
            .field("finalized", &self.finalized)
            .field("unfinalized", &self.tree.len())
            .field("saved", &self.snapshots.len())
            .field("poisoned", &self.is_poisoned())
            .field("pruning", &self.pruning)
            .finish_non_exhaustive()
    }
}

/// What a block builds on: its parent's version and roots, and its parent's ledger slot.
struct Parent {
    version: Option<SlotNumber>,
    roots: NomtRoots,
    slot: Option<StoredSlot>,
    /// The parent, for errors.
    what: &'static str,
}

impl<S: MerkleProofSpec, Hdr: BlockHeaderTrait> NomtStorageManager<S, Hdr> {
    /// Opens the state databases ([`DbGroup::open`]: crash recovery included) and takes the
    /// finalized block from the ledger's newest slot. With [`PrunerConfig::OnceAtStartup`], then
    /// prunes until nothing is left (before any storage exists; this blocks for as long as it
    /// takes).
    ///
    /// # Errors
    /// If the databases fail to open, the ledger's newest slot's DA hash is not a valid
    /// `Hdr::Hash`, or the startup pruning fails.
    pub fn open(config: StorageManagerConfig) -> anyhow::Result<Self> {
        Self::open_with_faults(config, Faults::default())
    }

    /// [`open`](Self::open), with a commit hook (fault injection) for the databases' crash
    /// recovery and commits.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn open_with_hook(
        config: StorageManagerConfig,
        hook: Option<CommitHook>,
    ) -> anyhow::Result<Self> {
        Self::open_with_faults(config, Faults::new(hook))
    }

    fn open_with_faults(config: StorageManagerConfig, faults: Faults) -> anyhow::Result<Self> {
        let group = DbGroup::open_with_faults(&config.state, faults)?;
        let finalized = match group.ledger_reader()?.committed_head()? {
            None => None,
            Some((slot, stored)) => {
                let hash = Hdr::Hash::try_from(stored.da_hash).map_err(|error| {
                    anyhow::anyhow!(
                        "the ledger's newest slot {slot} is for the DA block {}, which is not a \
                         valid block hash: {error}",
                        HexString(stored.da_hash)
                    )
                })?;
                Some(FinalizedBlock {
                    hash,
                    da_height: stored.da_height,
                    slot,
                })
            }
        };
        let tree = ForkTree::new(
            finalized
                .as_ref()
                .map(|block| (block.hash.clone(), block.da_height)),
        );
        let mut manager = Self {
            group,
            overlays: SharedOverlays::default(),
            snapshots: HashMap::new(),
            tree,
            finalized,
            witness: config.witness,
            max_unfinalized_blocks: config.max_unfinalized_blocks,
            poisoned: false,
            pruning: config.pruning,
            pruned_at: None,
            last_prune: None,
            last_prune_error: None,
            prune_runs: 0,
            _spec: PhantomData,
        };
        if let PrunerConfig::OnceAtStartup {
            versions_to_keep,
            max_keys_per_run,
        } = config.pruning
        {
            manager
                .prune_to_completion(versions_to_keep, max_keys_per_run)
                .context("one-time startup pruning failed")?;
        }
        Ok(manager)
    }

    /// Prunes until no store has a backlog. Every pass consumes the index entries it inspects,
    /// so this ends (B13: upstream looped while a pass hit its size limit, forever if a pass did
    /// not consume what it inspected); and it does not stop at a pass that deleted nothing
    /// (critique #7: a batch of first writes deletes nothing, with prunable rows after it).
    fn prune_to_completion(
        &mut self,
        versions_to_keep: NonZeroU64,
        max_keys_per_run: NonZeroU64,
    ) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        let (mut passes, mut rows) = (0u64, 0u64);
        loop {
            let stats = self.run_prune(versions_to_keep, max_keys_per_run)?;
            passes = passes.saturating_add(1);
            rows = rows.saturating_add(stats.rows_deleted());
            if !stats.has_backlog() {
                break;
            }
        }
        tracing::info!(
            passes,
            rows_deleted = rows,
            elapsed = ?start.elapsed(),
            "Startup pruning done"
        );
        Ok(())
    }

    /// One pruning pass, recorded.
    fn run_prune(
        &mut self,
        versions_to_keep: NonZeroU64,
        max_keys_per_run: NonZeroU64,
    ) -> anyhow::Result<PruneStats> {
        self.prune_runs = self.prune_runs.saturating_add(1);
        let stats = self.group.prune(versions_to_keep, max_keys_per_run)?;
        self.last_prune = Some(stats);
        Ok(stats)
    }

    /// The periodic pass after a finalization that committed up to `hdr`, if one is due: once
    /// `every_versions` versions were committed since the last pass that left no backlog (or
    /// if none ran yet), and after any pass that left a backlog. Errors are kept, not returned.
    fn prune_after_finalize(&mut self, hdr: &Hdr) {
        let PrunerConfig::Periodic {
            every_versions,
            versions_to_keep,
            max_keys_per_run,
        } = self.pruning
        else {
            return;
        };
        let Some(latest) = self.latest_version() else {
            return;
        };
        // `>=`: upstream's `>` ran an interval-1 pruner every second block.
        let due = self.pruned_at.is_none_or(|pruned_at| {
            latest.get().saturating_sub(pruned_at.get()) >= every_versions.get()
        });
        if !due {
            return;
        }
        match self.run_prune(versions_to_keep, max_keys_per_run) {
            Ok(stats) => {
                if !stats.has_backlog() {
                    self.pruned_at = Some(latest);
                }
                self.last_prune_error = None;
            }
            Err(error) => {
                let error = error.context(format!(
                    "block {} is finalized and committed, but pruning after it failed (retried \
                     at the next finalization)",
                    hdr.display()
                ));
                tracing::warn!(error = format!("{error:#}"), "Pruning failed");
                self.last_prune_error = Some(error);
            }
        }
    }

    /// The newest committed version: the finalized block's slot (`None`: nothing committed).
    pub fn latest_version(&self) -> Option<SlotNumber> {
        self.finalized.as_ref().map(|block| block.slot)
    }

    /// The number of uncommitted blocks (registered by `create_state_for`, saved or not).
    pub fn unfinalized_count(&self) -> usize {
        self.tree.len()
    }

    /// Whether a failed commit poisoned the manager (see the type docs).
    pub fn is_poisoned(&self) -> bool {
        self.poisoned || self.group.is_poisoned()
    }

    /// What startup crash recovery did when the databases were opened.
    pub fn last_recovery(&self) -> &RecoveryReport {
        self.group.last_recovery()
    }

    /// What the last pruning pass did (`None`: none ran).
    pub fn last_prune(&self) -> Option<&PruneStats> {
        self.last_prune.as_ref()
    }

    /// Why the last periodic pruning pass failed, if it did (cleared by the next one that
    /// succeeds). A failed pass does not fail the finalization it ran in.
    pub fn last_prune_error(&self) -> Option<&anyhow::Error> {
        self.last_prune_error.as_ref()
    }

    /// The oldest committed version a live storage of this manager is based on: pruning keeps
    /// it and everything after it.
    pub fn oldest_pinned_version(&self) -> Option<SlotNumber> {
        self.group.oldest_pinned_version()
    }

    /// One pruning pass now, with the configured `versions_to_keep` and budget (tests).
    ///
    /// # Errors
    /// If pruning is off, the manager is poisoned, or the pass fails.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn prune_now(&mut self) -> anyhow::Result<PruneStats> {
        self.ensure_not_poisoned()?;
        let (versions_to_keep, max_keys_per_run) = self
            .pruning
            .settings()
            .ok_or_else(|| anyhow::anyhow!("pruning is off"))?;
        self.run_prune(versions_to_keep, max_keys_per_run)
    }

    /// The number of pruning passes run since the manager was opened (tests).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn prune_runs(&self) -> u64 {
        self.prune_runs
    }

    /// Replaces the databases' commit hook (fault injection).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_commit_hook(&mut self, hook: Option<CommitHook>) {
        self.group.set_commit_hook(hook);
    }

    /// The overlays map shared with the storages (tests: they check the lock is held).
    #[cfg(test)]
    pub(crate) fn overlays(&self) -> &SharedOverlays<Hdr::Hash> {
        &self.overlays
    }

    /// The databases (tests).
    #[cfg(test)]
    pub(crate) fn group(&self) -> &DbGroup<S::Hasher> {
        &self.group
    }

    /// Checks that the manager's maps agree (tests): the saved blocks of the tree, the
    /// snapshots and the overlays have the same keys. Returns how many blocks are saved.
    #[cfg(test)]
    pub(crate) fn check_invariants(&self) -> usize {
        use std::collections::HashSet;
        self.tree.check_invariants();
        let saved: HashSet<&Hdr::Hash> = self.tree.saved().collect();
        let snapshots: HashSet<&Hdr::Hash> = self.snapshots.keys().collect();
        let overlays = self.overlays.read().expect("overlays lock");
        let overlay_keys: HashSet<&Hdr::Hash> = overlays.keys().collect();
        assert_eq!(saved, snapshots, "saved blocks and snapshots differ");
        assert_eq!(saved, overlay_keys, "saved blocks and overlays differ");
        assert_eq!(
            self.tree.finalized().map(|(hash, height)| (hash, *height)),
            self.finalized
                .as_ref()
                .map(|block| (&block.hash, block.da_height))
        );
        saved.len()
    }

    fn ensure_not_poisoned(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.is_poisoned(),
            "the storage manager is poisoned by a failed commit: reopen it (startup crash \
             recovery repairs the databases)"
        );
        Ok(())
    }

    /// A storage and a ledger reader on the saved blocks `chain` (oldest first, from the
    /// finalized block on).
    fn storage_on(
        &self,
        chain: &[Hdr::Hash],
        witness: WitnessMode,
    ) -> anyhow::Result<(NomtProverStorage<S, Hdr::Hash>, LedgerReader)> {
        let blocks = chain
            .iter()
            .map(|hash| {
                let snapshot = self
                    .snapshots
                    .get(hash)
                    .ok_or_else(|| anyhow::anyhow!("bug: saved block {hash} has no snapshot"))?;
                Ok((hash.clone(), snapshot))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let (readers, ledger) = self.group.readers_at(&blocks, self.overlays.clone())?;
        Ok((NomtProverStorage::create(readers, witness), ledger))
    }

    /// The saved blocks from the oldest uncommitted one to `hash` (oldest first): empty if
    /// `hash` is not a saved block (the finalized block, or the parent of genesis).
    fn chain_to(&self, hash: &Hdr::Hash) -> anyhow::Result<Vec<Hdr::Hash>> {
        if self.tree.contains(hash) {
            self.tree.chain_to_finalized(hash)
        } else {
            Ok(Vec::new())
        }
    }

    /// What a block with parent `prev` builds on (`prev` must be saved or finalized, or nothing
    /// may be finalized).
    fn parent(&self, prev: &Hdr::Hash) -> anyhow::Result<Parent> {
        if let Some(snapshot) = self.snapshots.get(prev) {
            return Ok(Parent {
                version: Some(snapshot.version()),
                roots: snapshot.roots(),
                slot: Some(snapshot.ledger().slot().clone()),
                what: "its parent block's ledger slot",
            });
        }
        match &self.finalized {
            Some(finalized) => {
                anyhow::ensure!(
                    finalized.hash == *prev,
                    "the parent block {prev} is neither saved nor the finalized block"
                );
                let (slot_number, slot) = self
                    .group
                    .ledger_reader()?
                    .committed_head()?
                    .ok_or_else(|| anyhow::anyhow!("bug: the finalized block has no slot"))?;
                anyhow::ensure!(
                    slot_number == finalized.slot,
                    "bug: the ledger's newest slot {slot_number} is not the finalized slot {}",
                    finalized.slot
                );
                Ok(Parent {
                    version: Some(slot_number),
                    roots: slot.roots,
                    slot: Some(slot),
                    what: "the finalized slot",
                })
            }
            None => Ok(Parent {
                version: None,
                roots: NomtRoots::PRE_GENESIS,
                slot: None,
                what: "the empty ledger",
            }),
        }
    }

    /// Checks that `stf` and `ledger` are the changes of block `hdr` on `parent` (B2, critique
    /// #5): the version after the parent's, built on its roots, the ledger slot for the same
    /// version and roots, numbered after the parent's slot, for `hdr`'s DA hash and height.
    fn check_change_set(
        hdr: &Hdr,
        parent: &Parent,
        stf: &NomtChangeSet,
        ledger: &LedgerChangeSet,
    ) -> anyhow::Result<()> {
        let expected = next_version_after(parent.version)?;
        anyhow::ensure!(
            stf.version() == expected,
            "the changes of block {} are for version {}, but its parent's next version is \
             {expected}",
            hdr.hash(),
            stf.version()
        );
        anyhow::ensure!(
            stf.prev_roots() == parent.roots,
            "the changes of block {} build on roots ({}) other than its parent's ({}): they were \
             not executed on its parent",
            hdr.hash(),
            stf.prev_roots(),
            parent.roots
        );
        anyhow::ensure!(
            ledger.version() == expected && ledger.roots() == stf.roots(),
            "the ledger slot of block {} is for version {} with roots ({}), its changes for \
             version {expected} with roots ({})",
            hdr.hash(),
            ledger.version(),
            ledger.roots(),
            stf.roots()
        );
        let hash: [u8; 32] = hdr.hash().into();
        let slot = ledger.slot();
        anyhow::ensure!(
            slot.da_hash == hash && slot.da_height == hdr.height(),
            "the ledger slot is for the DA block {} at height {}, not block {} at height {} (the \
             finalized block is restored from the ledger after a restart)",
            HexString(slot.da_hash),
            slot.da_height,
            hdr.hash(),
            hdr.height()
        );
        ledger::check_numbered_after(parent.slot.as_ref(), ledger, parent.what)
    }

    /// Commits the saved block `hash` (a child of the finalized block) and discards the forks
    /// it rules out, under the overlays write lock. Then `hash` is the finalized block.
    fn commit_block(&mut self, hash: &Hdr::Hash) -> anyhow::Result<()> {
        let snapshot = self
            .snapshots
            .get(hash)
            .ok_or_else(|| anyhow::anyhow!("bug: saved block {hash} has no snapshot"))?;
        let (_, height, _) = self
            .tree
            .get(hash)
            .ok_or_else(|| anyhow::anyhow!("bug: block {hash} is not in the tree"))?;
        let block = FinalizedBlock {
            hash: hash.clone(),
            da_height: height,
            slot: snapshot.version(),
        };
        let mut overlays = self
            .overlays
            .write()
            .map_err(|_| anyhow::anyhow!("the NOMT overlays lock is poisoned"))?;
        let overlay = overlays
            .get(hash)
            .ok_or_else(|| anyhow::anyhow!("bug: saved block {hash} has no NOMT overlay"))?;
        // Before anything is written: on an error, the block is kept (critique: upstream took
        // its overlay out first, and a refused commit lost it).
        self.group.check_snapshot(overlay, snapshot)?;
        let overlay = overlays
            .remove(hash)
            .ok_or_else(|| anyhow::anyhow!("bug: saved block {hash} has no NOMT overlay"))?;
        if let Err(error) = self.group.commit_snapshot(overlay, snapshot) {
            // Either the databases are poisoned (the write failed), or the overlay is gone
            // although nothing was written: the manager cannot go on either way.
            self.poisoned = true;
            return Err(error.context(format!("committing block {hash}")));
        }
        // Discard what the committed block rules out, under the same lock: no session sees a
        // committed block next to an overlay of its sibling.
        let discarded = match self.tree.finalize_child(hash) {
            Ok(discarded) => discarded,
            Err(error) => {
                self.poisoned = true;
                return Err(error.context("bug: the committed block is not finalizable"));
            }
        };
        for key in &discarded {
            overlays.remove(key);
        }
        drop(overlays);
        self.snapshots.remove(hash);
        for key in &discarded {
            self.snapshots.remove(key);
        }
        tracing::debug!(
            block = %hash,
            slot = %block.slot,
            discarded = discarded.len(),
            "Committed a finalized block"
        );
        self.finalized = Some(block);
        Ok(())
    }
}

impl<S: MerkleProofSpec, Hdr: BlockHeaderTrait> HierarchicalStorageManager<Hdr>
    for NomtStorageManager<S, Hdr>
{
    type StfState = NomtProverStorage<S, Hdr::Hash>;
    type StfChangeSet = NomtChangeSet;
    type LedgerState = LedgerReader;
    type LedgerChangeSet = LedgerChangeSet;

    /// Registers `hdr` on its parent and returns the state after the parent, with the witness
    /// as configured. Again for the same header (same parent): the same state.
    ///
    /// # Errors
    /// While poisoned; if the parent is neither the finalized block nor a saved block, or `hdr`
    /// is not one DA height above it, is its own parent, is the finalized block, or was
    /// registered with another parent; past `max_unfinalized_blocks` (B1, B4, A7).
    fn create_state_for(
        &mut self,
        hdr: &Hdr,
    ) -> anyhow::Result<(Self::StfState, Self::LedgerState)> {
        self.ensure_not_poisoned()?;
        let hash = hdr.hash();
        let prev = hdr.prev_hash();
        if !self.tree.contains(&hash) {
            let count = u64::try_from(self.tree.len()).unwrap_or(u64::MAX);
            anyhow::ensure!(
                count < self.max_unfinalized_blocks.get(),
                "{count} blocks are not finalized, the most the storage manager keeps: finalize \
                 before executing block {hash}"
            );
        }
        self.tree
            .register(hash, prev.clone(), hdr.height())
            .with_context(|| format!("cannot execute block {}", hdr.display()))?;
        let chain = self.chain_to(&prev)?;
        self.storage_on(&chain, self.witness)
    }

    /// The state after the saved block or the finalized block `hdr`, without a witness (for
    /// APIs and the sequencer; its changes cannot be saved).
    ///
    /// # Errors
    /// While poisoned, and if `hdr` is neither saved nor the finalized block (B5: upstream
    /// returned the finalized state for any other header; use
    /// [`create_finalized_state`](HierarchicalStorageManager::create_finalized_state)).
    fn create_state_after(
        &mut self,
        hdr: &Hdr,
    ) -> anyhow::Result<(Self::StfState, Self::LedgerState)> {
        self.ensure_not_poisoned()?;
        let hash = hdr.hash();
        if let Some(finalized) = &self.finalized
            && finalized.hash == hash
        {
            anyhow::ensure!(
                finalized.da_height == hdr.height(),
                "block {} has the finalized block's hash but not its height {}",
                hdr.display(),
                finalized.da_height
            );
            return self.storage_on(&[], WitnessMode::Off);
        }
        match self.tree.get(&hash) {
            Some((prev, height, true)) => {
                anyhow::ensure!(
                    *prev == hdr.prev_hash() && height == hdr.height(),
                    "block {} was saved with parent {prev} at height {height}",
                    hdr.display()
                );
            }
            Some((_, _, false)) => {
                anyhow::bail!(
                    "block {} is not saved: there is no state after it",
                    hdr.display()
                )
            }
            None => anyhow::bail!(
                "block {} is neither a saved block nor the finalized block: there is no state \
                 after it (it may be unknown, discarded, or older than the finalized block)",
                hdr.display()
            ),
        }
        let chain = self.tree.chain_to_finalized(&hash)?;
        self.storage_on(&chain, WitnessMode::Off)
    }

    /// The finalized (committed) state, without a witness: the only view of empty databases.
    ///
    /// # Errors
    /// While poisoned, and on read errors.
    fn create_finalized_state(&mut self) -> anyhow::Result<(Self::StfState, Self::LedgerState)> {
        self.ensure_not_poisoned()?;
        self.storage_on(&[], WitnessMode::Off)
    }

    /// Keeps the changes of the registered block `hdr` until it is finalized or discarded.
    ///
    /// # Errors
    /// While poisoned; if `hdr` was not registered by `create_state_for` (or with another parent
    /// or height), is saved already, or its parent is no longer valid; if the changes are not
    /// built on its parent (version, roots, ledger numbering) or the ledger slot is not for
    /// `hdr`, the changes' version and roots (B2, critique #5); if a batch has a range delete.
    /// Nothing is kept then.
    fn save_change_set(
        &mut self,
        hdr: &Hdr,
        stf: Self::StfChangeSet,
        ledger: Self::LedgerChangeSet,
    ) -> anyhow::Result<()> {
        self.ensure_not_poisoned()?;
        let hash = hdr.hash();
        let Some((prev, height, saved)) = self.tree.get(&hash) else {
            anyhow::bail!(
                "block {} was not registered: create its state with `create_state_for` first",
                hdr.display()
            );
        };
        anyhow::ensure!(
            *prev == hdr.prev_hash() && height == hdr.height(),
            "block {} was registered with parent {prev} at height {height}",
            hdr.display()
        );
        anyhow::ensure!(
            !saved,
            "the changes of block {} are saved already",
            hdr.display()
        );
        let parent = self.parent(&hdr.prev_hash())?;
        Self::check_change_set(hdr, &parent, &stf, &ledger)
            .with_context(|| format!("cannot save the changes of block {}", hdr.display()))?;
        let (overlay, snapshot) = stf.into_parts(ledger)?;

        let mut overlays = self
            .overlays
            .write()
            .map_err(|_| anyhow::anyhow!("the NOMT overlays lock is poisoned"))?;
        self.tree.mark_saved(&hash)?;
        overlays.insert(hash.clone(), overlay);
        drop(overlays);
        self.snapshots.insert(hash, snapshot);
        Ok(())
    }

    /// Commits `hdr` and its uncommitted ancestors, oldest first, and discards every other
    /// fork. Finalizing the finalized block or one of its committed ancestors is a no-op.
    ///
    /// The whole chain is checked first (saved, versions, roots and heights following each
    /// other from the finalized block). Each block is then committed under the overlays write
    /// lock, released between blocks ([`CommitPoint::BetweenSegments`]).
    ///
    /// With [`PrunerConfig::Periodic`], a pruning pass follows the commits when one is due
    /// (see [`NomtStorageManager`], Pruning); its failure does not fail the finalization.
    ///
    /// Blocking: it writes every database (synced) and prunes. From async code, call it on a
    /// blocking thread (`spawn_blocking`). Never call it while this thread holds a NOMT session
    /// or a storage's prefix iterator (see [`NomtStorageManager`], Locking).
    ///
    /// # Errors
    /// While poisoned; if `hdr` is not a saved block (unknown, discarded, not saved) or not
    /// committed; if the chain fails its checks (nothing is written then); if a commit fails:
    /// before writing (checks), with the older blocks committed and the manager usable; while
    /// writing, poisoned (B3).
    fn finalize(&mut self, hdr: &Hdr) -> anyhow::Result<()> {
        self.ensure_not_poisoned()?;
        let hash = hdr.hash();
        if let Some(finalized) = &self.finalized
            && finalized.hash == hash
        {
            anyhow::ensure!(
                finalized.da_height == hdr.height(),
                "block {} has the finalized block's hash but not its height {}",
                hdr.display(),
                finalized.da_height
            );
            return Ok(());
        }
        if !self.tree.contains(&hash) {
            // A committed ancestor of the finalized block (after a restart, or a retry):
            // nothing to do (critique #12).
            let ledger = self.group.ledger_reader()?;
            if let Some(slot) = ledger.slot_by_hash(&hash.clone().into())? {
                let stored = ledger
                    .slot(slot)?
                    .ok_or_else(|| anyhow::anyhow!("bug: slot {slot} is indexed but missing"))?;
                anyhow::ensure!(
                    stored.da_height == hdr.height(),
                    "block {} is committed as slot {slot} at DA height {}, not at height {}",
                    hdr.display(),
                    stored.da_height,
                    hdr.height()
                );
                tracing::debug!(block = %hash, %slot, "Block already finalized");
                return Ok(());
            }
        }
        let chain = self
            .tree
            .chain_to_finalized(&hash)
            .with_context(|| format!("cannot finalize block {}", hdr.display()))?;
        let leaf_height = self.tree.get(&hash).map(|(_, height, _)| height);
        anyhow::ensure!(
            leaf_height == Some(hdr.height()),
            "block {} was saved at height {leaf_height:?}",
            hdr.display()
        );

        // B3: check the whole chain before writing anything.
        let mut version = self.latest_version();
        let mut roots = self.group.roots();
        let mut height = self.finalized.as_ref().map(|block| block.da_height);
        {
            let overlays = self
                .overlays
                .read()
                .map_err(|_| anyhow::anyhow!("the NOMT overlays lock is poisoned"))?;
            for block in &chain {
                let snapshot = self
                    .snapshots
                    .get(block)
                    .ok_or_else(|| anyhow::anyhow!("bug: saved block {block} has no snapshot"))?;
                anyhow::ensure!(
                    overlays.contains_key(block),
                    "bug: saved block {block} has no NOMT overlay"
                );
                let expected = next_version_after(version)?;
                anyhow::ensure!(
                    snapshot.version() == expected && snapshot.prev_roots() == roots,
                    "cannot finalize block {}: block {block} is for version {} on roots ({}), \
                     not version {expected} on roots ({roots})",
                    hdr.display(),
                    snapshot.version(),
                    snapshot.prev_roots()
                );
                let (_, block_height, _) = self
                    .tree
                    .get(block)
                    .ok_or_else(|| anyhow::anyhow!("bug: block {block} is not in the tree"))?;
                if let Some(height) = height {
                    anyhow::ensure!(
                        height.checked_add(1) == Some(block_height),
                        "cannot finalize block {}: block {block} is at height {block_height} \
                         after height {height}",
                        hdr.display()
                    );
                }
                version = Some(snapshot.version());
                roots = snapshot.roots();
                height = Some(block_height);
            }
        }

        let last = chain.len().saturating_sub(1);
        for (index, block) in chain.iter().enumerate() {
            self.commit_block(block)?;
            if index < last {
                self.group.hit(CommitPoint::BetweenSegments)?;
            }
        }
        self.prune_after_finalize(hdr);
        Ok(())
    }

    fn finalized(&self) -> Option<FinalizedBlock<Hdr::Hash>> {
        self.finalized.clone()
    }
}

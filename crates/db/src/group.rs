//! All state databases together ([`DbGroup`]): the NOMT trees, the flat value store, the ledger
//! DB and the accessory DB; the order they are committed in, and how they are opened (hasher
//! guard, startup crash recovery).

use std::num::NonZeroU64;
use std::sync::Arc;

use anyhow::Context;
use rockbound::SchemaBatch;
use rockbound::cache::delta_reader::DeltaReader;
use rockbound::versioned_db::VersionedDeltaReader;
use selendra_interface::common::{HexString, SlotNumber};
use selendra_interface::reexports::digest::Digest;
use selendra_interface::reexports::digest::typenum::U32;

use crate::accessory::AccessoryDb;
use crate::config::StateDbConfig;
#[cfg(any(test, feature = "test-utils"))]
use crate::faults::CommitHook;
use crate::faults::{CommitPoint, Faults};
use crate::flat::FlatStateDb;
use crate::historical::{HistoricalStateReader, StateChanges, next_version_after};
use crate::ledger::{self, LedgerChangeSet, LedgerReader};
use crate::nomt_state::{
    CommittedRoots, NomtRoots, NomtSessionBuilder, NomtStateDb, OverlayRef, SharedOverlays,
    StateFinishedSession, StateOverlay,
};
use crate::pruner::{self, PruneStats, VersionPins};
use crate::recovery::{Head, RecoveryReport, root_of};
use crate::schema::{DbMetadata, MetadataKey};

/// What the hasher guard hashes: the databases record `H(STATE_HASHER_PROBE)` when they are
/// created and compare it with the configured hasher's on every open ([`DbGroup::open`]).
const STATE_HASHER_PROBE: &[u8] = b"SELENDRA/state-hasher/v1";

/// Everything one block changes in the state databases: the NOMT trees, the flat value store
/// and the accessory store. (Its ledger slot is a separate [`LedgerChangeSet`].)
pub struct NomtChangeSet {
    state: StateFinishedSession,
    historical_state: StateChanges,
    accessory: SchemaBatch,
}

impl NomtChangeSet {
    /// Combines a block's changes: the finished NOMT sessions, the flat-store changes (with the
    /// version and the roots) and the accessory batch (materialized for the same version).
    pub fn new(
        state: StateFinishedSession,
        historical_state: StateChanges,
        accessory: SchemaBatch,
    ) -> Self {
        Self {
            state,
            historical_state,
            accessory,
        }
    }

    /// The version these changes are for.
    pub fn version(&self) -> SlotNumber {
        self.historical_state.version()
    }

    /// The roots after these changes.
    pub fn roots(&self) -> NomtRoots {
        self.state.roots()
    }

    /// The roots these changes build on.
    pub fn prev_roots(&self) -> NomtRoots {
        self.state.prev_roots()
    }

    /// The NOMT part alone (tests that write the trees past the other databases).
    #[cfg(test)]
    pub(crate) fn into_nomt_overlay(self) -> crate::StateOverlay {
        self.state.into_state_overlay()
    }

    /// Splits a block's changes and its ledger slot into the NOMT overlay and the rest, which
    /// readers see as snapshots until the block is committed.
    ///
    /// # Errors
    /// If a batch has a range delete: a snapshot reader cannot see one, so the block would read
    /// differently before and after its commit. (Range deletes are written only straight to the
    /// databases, by crash recovery's rollbacks and by pruning, never through a change set.)
    pub(crate) fn into_parts(
        self,
        ledger: LedgerChangeSet,
    ) -> anyhow::Result<(StateOverlay, SnapshotGroup)> {
        let Self {
            state,
            historical_state,
            accessory,
        } = self;
        anyhow::ensure!(
            !accessory.has_range_ops()
                && !historical_state.root_hash_batch.has_range_ops()
                && !ledger.batch().has_range_ops(),
            "the changes of version {} have a range delete, which readers of uncommitted \
             snapshots cannot see",
            historical_state.version()
        );
        let overlay = state.into_state_overlay();
        let snapshot = SnapshotGroup {
            prev_roots: overlay.prev_roots(),
            historical: historical_state,
            accessory: Arc::new(accessory),
            ledger,
        };
        Ok((overlay, snapshot))
    }
}

/// One block's changes besides its NOMT overlay, as a storage manager keeps them until the
/// block is committed: readers of later blocks see them as snapshots (the flat store, the
/// accessory DB, the ledger DB), and [`DbGroup::commit_snapshot`] writes them.
///
/// Only point writes and deletes ([`NomtChangeSet::into_parts`] refuses range deletes): a
/// snapshot reader cannot see a range delete, so crash recovery's rollbacks and pruning, which
/// use them, write straight to the databases and are never kept here.
#[derive(Clone)]
pub(crate) struct SnapshotGroup {
    historical: StateChanges,
    accessory: Arc<SchemaBatch>,
    ledger: LedgerChangeSet,
    prev_roots: NomtRoots,
}

impl SnapshotGroup {
    /// The block's version.
    pub(crate) fn version(&self) -> SlotNumber {
        self.historical.version()
    }

    /// The roots after the block.
    pub(crate) fn roots(&self) -> NomtRoots {
        self.historical.root()
    }

    /// The roots the block builds on.
    pub(crate) fn prev_roots(&self) -> NomtRoots {
        self.prev_roots
    }

    /// The block's ledger slot.
    pub(crate) fn ledger(&self) -> &LedgerChangeSet {
        &self.ledger
    }
}

/// The readers a storage needs, all at the same version: the newest committed one, plus the
/// same chain of uncommitted blocks (snapshots and NOMT overlays) if a storage manager built
/// them on one.
///
/// The flat-store and accessory readers each pin the committed version they are based on
/// against pruning while they (or clones) live ([`pruner`](crate::pruner)).
pub struct StorageReaders<H, K> {
    /// Opens NOMT sessions on the committed trees and the blocks' overlays.
    pub session_builder: NomtSessionBuilder<H, K>,
    /// Reads the flat value store.
    pub historical_state: HistoricalStateReader,
    /// Reads the accessory store.
    pub accessory: AccessoryDb,
}

impl<H, K> core::fmt::Debug for StorageReaders<H, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StorageReaders")
            .field("session_builder", &self.session_builder)
            .finish_non_exhaustive()
    }
}

/// The state databases: the NOMT trees, the flat value store, the ledger DB and the accessory
/// store.
///
/// Commits are linear (one version after the other, `&mut self`), each with its ledger slot.
/// The storage manager ([`NomtStorageManager`](crate::NomtStorageManager)) builds forks of
/// uncommitted blocks on top (readers of the committed state plus uncommitted snapshots) and
/// commits the finalized ones.
///
/// **Poisoning.** A commit that fails after it started writing (an I/O error, or an injected
/// fault) leaves the databases at different versions, and the NOMT trees' in-memory roots may
/// already have moved. The group is then poisoned: [`commit`](Self::commit),
/// [`readers`](Self::readers), [`ledger_reader`](Self::ledger_reader) and
/// [`prune`](Self::prune) fail until the databases are closed and reopened, which repairs them
/// ([`open`](Self::open)). Upstream went on with the databases out of step.
///
/// **Pruning.** [`prune`](Self::prune) deletes old versions of the flat store and the accessory
/// store, keeping every version a live reader of this group is based on ([`pruner`]).
pub struct DbGroup<H> {
    nomt: Arc<NomtStateDb<H>>,
    flat: FlatStateDb,
    ledger: Arc<rockbound::DB>,
    accessory: Arc<rockbound::DB>,
    /// The versions the readers handed out are based on.
    pins: VersionPins,
    faults: Faults,
    poisoned: bool,
    last_recovery: RecoveryReport,
}

impl<H> core::fmt::Debug for DbGroup<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DbGroup")
            .field("poisoned", &self.poisoned)
            .field("last_recovery", &self.last_recovery)
            .finish_non_exhaustive()
    }
}

impl<H: Digest<OutputSize = U32> + Send + Sync> DbGroup<H> {
    /// Opens (or creates) all state databases under [`StateDbConfig::path`], repairing an
    /// interrupted commit.
    ///
    /// In this order:
    /// 1. Open the databases, without growing the NOMT hash tables.
    /// 2. **Hasher guard.** The first open of empty databases records which hasher `H` they are
    ///    written with (the tag `H(b"SELENDRA/state-hasher/v1")`, [`MetadataKey::StateHasher`]
    ///    in the accessory DB); every later open must use the same one. Otherwise a node built
    ///    with another `H` would extend the trees with nodes hashed differently from the ones
    ///    already stored. It runs before anything writes data hashed with `H` (crash recovery's
    ///    NOMT rollback rewrites the trees with `H`).
    /// 3. **Startup crash recovery**: the databases written before the flat live DB by an
    ///    interrupted commit are rolled back by one version, so that all are at the live DB's
    ///    version and roots again ([`last_recovery`](Self::last_recovery) says what was rolled
    ///    back; it is also logged). Versioned databases (the ledger, whose version is its newest
    ///    slot; the accessory DB; the flat archival DB) are rolled back only if they are exactly
    ///    one version ahead of the live DB (never decided by root alone: a block can leave the
    ///    roots unchanged), and a NOMT tree only if its root is that next version's (or, when no
    ///    database recorded it, unchecked), and it must then be at the live DB's root.
    /// 4. The consistency check: every database at the live DB's version and roots.
    /// 5. Grow the NOMT hash tables to the configured bucket count. A refused open grows
    ///    nothing.
    ///
    /// Opening the databases (step 1) already writes to disk, but nothing hashed with `H`: NOMT
    /// creates a new tree's files and finishes its own write-ahead-log replay or an interrupted
    /// rehash (none of which uses `H`; NOMT hashes with `H` only to recompute the root in
    /// memory), and RocksDB creates missing column families.
    ///
    /// # Errors
    /// - If a database fails to open.
    /// - If the databases were written with another hasher, or hold data but no hasher tag
    ///   (written before the guard existed, or the tag was removed): no state and no tag is
    ///   written then, beyond what opening the databases writes (above).
    /// - If the databases are in a state an interrupted commit cannot leave (e.g. a database
    ///   two versions ahead of the live DB, or behind it, or a NOMT tree at a root that is
    ///   neither the live DB's nor the one a database recorded for the next version): nothing is
    ///   rolled back then, with one exception. When no database records the next version, a
    ///   NOMT tree not at the live DB's root is rolled back unchecked (nothing to check its root
    ///   against) and checked afterwards, so each failed open rolls a tree that is several
    ///   commits ahead, behind the live DB or diverged back by one more logged commit (see the
    ///   `recovery` module docs). Upstream panicked.
    /// - If a rollback fails, or does not restore the live DB's roots.
    pub fn open(config: &StateDbConfig) -> anyhow::Result<Self> {
        Self::open_with_faults(config, Faults::default())
    }

    /// [`open`](Self::open), with a commit hook (fault injection) for this instance's crash
    /// recovery and commits.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn open_with_hook(
        config: &StateDbConfig,
        hook: Option<CommitHook>,
    ) -> anyhow::Result<Self> {
        Self::open_with_faults(config, Faults::new(hook))
    }

    pub(crate) fn open_with_faults(config: &StateDbConfig, faults: Faults) -> anyhow::Result<Self> {
        let nomt = NomtStateDb::open_no_grow(config)?;
        let mut flat = FlatStateDb::new(
            &config.path,
            config.user_state_cache_size,
            config.kernel_state_cache_size,
        )?;
        let ledger = Arc::new(ledger::options().open_in(&config.path)?);
        let accessory = Arc::new(AccessoryDb::options().open_in(&config.path)?);
        // First: nothing may write data hashed with `H` before it.
        check_state_hasher(&nomt, &flat, &ledger, &accessory)?;
        let last_recovery =
            crate::recovery::recover(&nomt, &mut flat, &ledger, &accessory, &faults)?;
        check_consistency(&nomt, &flat, &ledger, &accessory)?;
        let nomt = Arc::new(nomt.grow_to_config(config, &faults)?);
        if !last_recovery.rolled_back.is_empty() {
            tracing::warn!(
                rolled_back = ?last_recovery.rolled_back,
                live_version = ?last_recovery.live,
                "The last commit of the state databases was interrupted: rolled back the \
                 databases it had written"
            );
        }
        Ok(Self {
            nomt,
            flat,
            ledger,
            accessory,
            pins: VersionPins::default(),
            faults,
            poisoned: false,
            last_recovery,
        })
    }

    /// Replaces this instance's commit hook (fault injection).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_commit_hook(&mut self, hook: Option<CommitHook>) {
        self.faults = Faults::new(hook);
    }

    /// What startup crash recovery did when these databases were opened.
    pub fn last_recovery(&self) -> &RecoveryReport {
        &self.last_recovery
    }

    /// Whether a failed commit poisoned the databases: then nothing can be committed or read
    /// through [`readers`](Self::readers) or [`ledger_reader`](Self::ledger_reader) until they
    /// are reopened.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Runs this instance's commit hook at `point` (points of the storage manager's
    /// finalization, between the commits of its blocks).
    pub(crate) fn hit(&self, point: CommitPoint) -> anyhow::Result<()> {
        self.faults.hit(point)
    }

    fn ensure_not_poisoned(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.poisoned,
            "the state databases are poisoned by a failed commit: reopen them (startup crash \
             recovery repairs them)"
        );
        Ok(())
    }

    /// The newest committed version (`None`: nothing committed).
    pub fn latest_version(&self) -> anyhow::Result<Option<SlotNumber>> {
        Ok(self
            .flat
            .latest_version_and_root_live()?
            .map(|(version, _)| version))
    }

    /// The roots of the NOMT trees (the committed ones, unless a failed commit poisoned the
    /// databases: then possibly ahead of them).
    pub fn roots(&self) -> NomtRoots {
        self.nomt.root_hashes()
    }

    /// The NOMT trees (tests only: outside this crate, the trees are written only through
    /// [`commit`](Self::commit); see [`NomtStateDb`]).
    #[cfg(test)]
    pub(crate) fn nomt(&self) -> &Arc<NomtStateDb<H>> {
        &self.nomt
    }

    /// The flat store (tests only).
    #[cfg(test)]
    pub(crate) fn flat(&self) -> &FlatStateDb {
        &self.flat
    }

    /// The accessory DB (tests only).
    #[cfg(test)]
    pub(crate) fn accessory_db(&self) -> &Arc<rockbound::DB> {
        &self.accessory
    }

    /// The ledger DB (tests only).
    #[cfg(test)]
    pub(crate) fn ledger_db(&self) -> &Arc<rockbound::DB> {
        &self.ledger
    }

    /// The oldest version a live reader of these databases is based on (pruning keeps it).
    pub fn oldest_pinned_version(&self) -> Option<SlotNumber> {
        self.pins.oldest()
    }

    /// Readers of the committed state, all at the newest committed version. They see later
    /// commits only through their unbound reads. (The storage manager's readers add uncommitted
    /// blocks.) They pin that version against pruning while they live.
    ///
    /// # Errors
    /// If the databases are poisoned ([`is_poisoned`](Self::is_poisoned)), or on read errors.
    pub fn readers<K: Clone>(&self) -> anyhow::Result<StorageReaders<H, K>> {
        let (readers, _ledger) = self.readers_at(&[], SharedOverlays::default())?;
        Ok(readers)
    }

    /// Readers of the newest committed state plus the uncommitted blocks `chain_oldest_first`
    /// (each block's key in `overlays`, the map of NOMT overlays shared with the storage manager,
    /// and its snapshot), and a ledger reader with the same blocks. The blocks' versions must
    /// follow the newest committed version one by one (from genesis if nothing is committed),
    /// each building on the roots of the one before it, the first on the committed roots.
    ///
    /// The flat-store and accessory readers pin the newest committed version (their base:
    /// they read a key the blocks do not write there) until they and their clones are dropped,
    /// so [`prune`](Self::prune) keeps it.
    ///
    /// # Errors
    /// If the databases are poisoned, if the blocks are not such a chain (upstream did not
    /// check: a gap or a wrong order made the readers see wrong versions, and their version
    /// computation could overflow), or on read errors.
    pub(crate) fn readers_at<K: Clone>(
        &self,
        chain_oldest_first: &[(K, &SnapshotGroup)],
        overlays: SharedOverlays<K>,
    ) -> anyhow::Result<(StorageReaders<H, K>, LedgerReader)> {
        self.ensure_not_poisoned()?;
        let live = self.flat.latest_version_and_root_live()?;
        let base = live.map(|(version, _)| version);
        let mut prev_roots = root_of(live);
        for (index, (_, snapshot)) in chain_oldest_first.iter().enumerate() {
            let index = u64::try_from(index).context("chain length overflow")?;
            // Genesis is the first version if nothing is committed (critique: not `base + 1`).
            let expected = match base {
                Some(base) => index.checked_add(1).and_then(|n| base.checked_add(n)),
                None => Some(SlotNumber::new(index)),
            };
            anyhow::ensure!(
                Some(snapshot.version()) == expected,
                "block {index} of the uncommitted chain is for version {}, but the version after \
                 the newest committed one ({:?}) and the {index} blocks before it is {:?}",
                snapshot.version(),
                base.map(|v| v.get()),
                expected.map(|v| v.get())
            );
            anyhow::ensure!(
                snapshot.prev_roots() == prev_roots,
                "block {index} of the uncommitted chain (version {}) builds on roots ({}) other \
                 than those of the block before it ({prev_roots})",
                snapshot.version(),
                snapshot.prev_roots()
            );
            prev_roots = snapshot.roots();
        }

        // Oldest first, as the rockbound readers expect.
        let count = chain_oldest_first.len();
        let (mut user, mut kernel, mut roots, mut accessory, mut ledger) = (
            Vec::with_capacity(count),
            Vec::with_capacity(count),
            Vec::with_capacity(count),
            Vec::with_capacity(count),
            Vec::with_capacity(count),
        );
        for (_, snapshot) in chain_oldest_first {
            user.push(snapshot.historical.user.clone());
            kernel.push(snapshot.historical.kernel.clone());
            roots.push(snapshot.historical.root_hash_batch.clone());
            accessory.push(snapshot.accessory.clone());
            ledger.push(snapshot.ledger.batch().clone());
        }
        // Newest first, as NOMT expects.
        let refs = chain_oldest_first
            .iter()
            .rev()
            .map(|(key, snapshot)| OverlayRef {
                key: key.clone(),
                version: snapshot.version(),
                roots: snapshot.roots(),
            })
            .collect();
        let base_version = base.map(|version| version.get());
        // Not racing a pruning pass: `prune` takes `&mut self`.
        let pin = base.map(|base| self.pins.pin(base));
        let historical_state = HistoricalStateReader::new(
            VersionedDeltaReader::new(self.flat.user_db().clone(), base_version, user),
            VersionedDeltaReader::new(self.flat.kernel_db().clone(), base_version, kernel),
            DeltaReader::new(self.flat.live_db().clone(), roots),
        )?
        .with_pin(pin.clone());
        let readers = StorageReaders {
            session_builder: NomtSessionBuilder::new(
                self.nomt.clone(),
                refs,
                overlays,
                CommittedRoots::new(self.flat.live_db().clone()),
            ),
            historical_state,
            accessory: AccessoryDb::with_snapshots(self.accessory.clone(), base, accessory, pin),
        };
        Ok((readers, LedgerReader::new(self.ledger.clone(), ledger)))
    }

    /// A reader of the committed ledger (no uncommitted snapshots): its newest slot is the
    /// newest committed version, and it builds the next version's slot
    /// ([`LedgerReader::materialize_slot`]).
    ///
    /// # Errors
    /// If the databases are poisoned ([`is_poisoned`](Self::is_poisoned)): the ledger DB may
    /// then hold a slot that was never committed.
    pub fn ledger_reader(&self) -> anyhow::Result<LedgerReader> {
        self.ensure_not_poisoned()?;
        Ok(LedgerReader::new(self.ledger.clone(), Vec::new()))
    }

    /// Commits one block's changes and its ledger slot, which must be for the version after the
    /// newest committed one and build on the committed roots and the committed ledger.
    ///
    /// Order (upstream's; proofs of the newest committed state rely on it): the NOMT kernel
    /// tree, the NOMT user tree, the ledger DB (the slot, one write batch), the accessory DB
    /// (values and root in one write), the flat archival DB, the flat live DB last. The live DB
    /// says which version is committed; after a crash, the databases written before it are at
    /// most one version ahead, and reopening rolls them back ([`open`](Self::open)). Each write
    /// is synced to disk before the next. (Upstream's comment that the ledger "goes after last"
    /// was stale: it wrote the ledger right after the NOMT trees, as here.)
    ///
    /// Drop every NOMT session and flat-store iterator of this thread first: a commit waits
    /// for them.
    ///
    /// # Errors
    /// - If the databases are poisoned; if the change set is for another version, does not
    ///   build on the committed roots, or carries a root other than its NOMT sessions'; if the
    ///   ledger DB or the accessory DB is not at the committed version and roots; if the ledger
    ///   slot is for another version or roots, numbers its items from other numbers than the
    ///   ledger's next ones, or is for a DA block that is already a slot (all checked before
    ///   anything is written; the databases stay usable).
    /// - If a write fails (or a fault is injected) once writing started: the databases may be
    ///   out of step, and they are poisoned until reopened.
    pub fn commit(
        &mut self,
        change_set: NomtChangeSet,
        ledger: LedgerChangeSet,
    ) -> anyhow::Result<()> {
        self.ensure_not_poisoned()?;
        let (overlay, snapshot) = change_set.into_parts(ledger)?;
        self.commit_snapshot(overlay, &snapshot)
    }

    /// [`commit`](Self::commit) of a block kept by the storage manager: its NOMT overlay and its
    /// snapshot. Runs [`check_snapshot`](Self::check_snapshot) first.
    pub(crate) fn commit_snapshot(
        &mut self,
        overlay: StateOverlay,
        snapshot: &SnapshotGroup,
    ) -> anyhow::Result<()> {
        self.check_snapshot(&overlay, snapshot)?;
        let version = snapshot.version();
        let written = self.write(overlay, snapshot);
        if let Err(error) = &written {
            self.poisoned = true;
            tracing::error!(
                %version,
                error = format!("{error:#}"),
                "A commit of the state databases failed after it started writing: they are \
                 poisoned until reopened"
            );
        }
        written
    }

    /// The checks of [`commit`](Self::commit) before anything is written (see its errors): a
    /// block that fails them can be kept and committed later.
    pub(crate) fn check_snapshot(
        &self,
        overlay: &StateOverlay,
        snapshot: &SnapshotGroup,
    ) -> anyhow::Result<()> {
        self.ensure_not_poisoned()?;
        let historical_state = &snapshot.historical;
        let ledger = &snapshot.ledger;
        let live = self.flat.latest_version_and_root_live()?;
        let expected = next_version_after(live.map(|(version, _)| version))?;
        anyhow::ensure!(
            historical_state.version() == expected,
            "the change set is for version {} but the next version is {expected}",
            historical_state.version()
        );
        let ledger_head = ledger::latest_version_and_root(&self.ledger)?;
        anyhow::ensure!(
            ledger_head == live,
            "the ledger DB is at version {:?} (roots {}), the flat store at {:?} (roots {})",
            ledger_head.map(|(version, _)| version),
            root_of(ledger_head),
            live.map(|(version, _)| version),
            root_of(live)
        );
        let accessory_version =
            AccessoryDb::latest_version_and_root(&self.accessory)?.map(|(version, _)| version);
        anyhow::ensure!(
            accessory_version == live.map(|(version, _)| version),
            "the accessory DB is at version {accessory_version:?}, the flat store at {:?}",
            live.map(|(version, _)| version)
        );
        anyhow::ensure!(
            overlay.prev_roots() == root_of(live),
            "the change set builds on roots ({}) other than the committed ones ({})",
            overlay.prev_roots(),
            root_of(live)
        );
        anyhow::ensure!(
            overlay.roots() == historical_state.root(),
            "the change set's root ({}) is not its NOMT sessions' ({})",
            historical_state.root(),
            overlay.roots()
        );
        anyhow::ensure!(
            ledger.version() == expected && ledger.roots() == historical_state.root(),
            "the ledger slot is for version {} with roots ({}), the change set for version \
             {expected} with roots ({})",
            ledger.version(),
            ledger.roots(),
            historical_state.root()
        );
        ledger::check_builds_on_head(&self.ledger, ledger)
    }

    /// One pruning pass (see [`pruner`] for what it deletes and why reads stay exact): the
    /// cutoff is `min(L - versions_to_keep, oldest pinned version)` (`L`: the newest committed
    /// version); every version from the cutoff on reads as before, older ones may fail with
    /// [`HistoricalValueError::PrunedVersion`](crate::HistoricalValueError). It consumes at
    /// most `max_keys_per_run` index entries of each of the user values, the kernel values and
    /// the accessory store, and writes each store's part in one write (the flat store's first,
    /// [`CommitPoint::BeforePruneFlat`], then the accessory store's,
    /// [`CommitPoint::BeforePruneAccessory`]). Run it again while
    /// [`PruneStats::has_backlog`].
    ///
    /// # Errors
    /// If the databases are poisoned, on read or write errors (nothing is poisoned: the pass's
    /// writes are each atomic, and the next pass goes on), or if a store's versions disagree
    /// with the committed version.
    pub fn prune(
        &mut self,
        versions_to_keep: NonZeroU64,
        max_keys_per_run: NonZeroU64,
    ) -> anyhow::Result<PruneStats> {
        self.ensure_not_poisoned()?;
        let latest = self.latest_version()?;
        let oldest_pin = self.pins.oldest();
        if let (Some(latest), Some(pin)) = (latest, oldest_pin) {
            let age = latest.get().saturating_sub(pin.get());
            if age > versions_to_keep.get().saturating_mul(10) {
                tracing::warn!(
                    pinned = %pin,
                    %latest,
                    versions_to_keep = versions_to_keep.get(),
                    "A storage based on an old version is still alive: pruning keeps that \
                     version and everything after it until the storage is dropped"
                );
            }
        }
        let Some((latest, cutoff)) =
            latest.zip(pruner::cutoff(latest, versions_to_keep, oldest_pin))
        else {
            return Ok(PruneStats::default());
        };
        let (flat_batch, flat_user, flat_kernel) =
            pruner::collect_flat(&self.flat, latest, cutoff, max_keys_per_run)?;
        self.faults.hit(CommitPoint::BeforePruneFlat)?;
        if !flat_batch.is_empty() {
            self.flat
                .archival_db()
                .write_schemas(&flat_batch)
                .context("writing the flat store's pruning batch")?;
        }
        let (accessory_batch, accessory) =
            pruner::collect_accessory(&self.accessory, cutoff, max_keys_per_run)?;
        self.faults.hit(CommitPoint::BeforePruneAccessory)?;
        if !accessory_batch.is_empty() {
            self.accessory
                .write_schemas(&accessory_batch)
                .context("writing the accessory store's pruning batch")?;
        }
        let stats = PruneStats {
            cutoff: Some(cutoff),
            flat_user,
            flat_kernel,
            accessory,
        };
        tracing::debug!(?stats, "Pruned old versions");
        Ok(stats)
    }

    /// The writes of [`commit`](Self::commit), in order, with the fault points in between.
    fn write(&mut self, overlay: StateOverlay, snapshot: &SnapshotGroup) -> anyhow::Result<()> {
        // ======================= DANGER ZONE ======================
        // The commit order (NOMT kernel, NOMT user, ledger, accessory, flat archival, flat
        // live) is relied on by the prover's proofs of the newest committed state and by
        // startup crash recovery: change it only together with them. An error from here on
        // poisons the databases.
        self.faults.hit(CommitPoint::BeforeKernelNomt)?;
        self.nomt
            .commit(overlay, &self.faults)
            .context("NOMT commit")?;
        self.faults.hit(CommitPoint::BeforeLedger)?;
        ledger::commit(&self.ledger, &snapshot.ledger).context("ledger DB commit")?;
        self.faults.hit(CommitPoint::BeforeAccessory)?;
        AccessoryDb::commit(
            &self.accessory,
            &snapshot.accessory,
            &snapshot.historical.root_hash_batch,
        )
        .context("accessory DB commit")?;
        self.faults.hit(CommitPoint::BeforeArchival)?;
        self.flat
            .commit_with_faults(&snapshot.historical, &self.faults)
            .context("flat state commit")?;
        self.faults.hit(CommitPoint::AfterLive)
        // ===================== END DANGER ZONE ====================
    }
}

/// The hasher guard (see [`DbGroup::open`]): checks the recorded hasher tag, or records it if
/// every database is empty.
fn check_state_hasher<H: Digest<OutputSize = U32> + Send + Sync>(
    nomt: &NomtStateDb<H>,
    flat: &FlatStateDb,
    ledger: &Arc<rockbound::DB>,
    accessory: &Arc<rockbound::DB>,
) -> anyhow::Result<()> {
    let tag: [u8; 32] = H::digest(STATE_HASHER_PROBE).into();
    match accessory.get::<DbMetadata>(&MetadataKey::StateHasher)? {
        Some(stored) => anyhow::ensure!(
            stored == tag,
            "the state databases were written with another state hasher (stored tag {}, this \
             node's {}): opening them would mix two hashers in one tree",
            HexString(&stored),
            HexString(tag)
        ),
        None => {
            anyhow::ensure!(
                is_empty(nomt, flat, ledger, accessory)?,
                "the state databases hold data but no state hasher tag (written before the \
                 hasher guard existed, or the tag was removed): cannot check which hasher wrote \
                 them"
            );
            accessory
                .put::<DbMetadata>(&MetadataKey::StateHasher, &tag.to_vec())
                .context("recording the state hasher tag")?;
        }
    }
    Ok(())
}

/// Whether no database holds any state: the NOMT trees are empty and no version is committed to
/// the flat store (live or archival), the ledger DB or the accessory DB.
fn is_empty<H: Digest<OutputSize = U32> + Send + Sync>(
    nomt: &NomtStateDb<H>,
    flat: &FlatStateDb,
    ledger: &Arc<rockbound::DB>,
    accessory: &Arc<rockbound::DB>,
) -> anyhow::Result<bool> {
    Ok(nomt.root_hashes() == NomtRoots::PRE_GENESIS
        && flat.latest_version_and_root_live()?.is_none()
        && flat.latest_version_and_root_archival()?.is_none()
        && ledger::latest_version_and_root(ledger)?.is_none()
        && AccessoryDb::latest_version_and_root(accessory)?.is_none())
}

/// Fails unless the NOMT trees, the live and archival flat DBs, the ledger DB and the accessory
/// DB are at the same version and root (after crash recovery, which repairs an interrupted
/// commit).
fn check_consistency<H: Digest<OutputSize = U32> + Send + Sync>(
    nomt: &NomtStateDb<H>,
    flat: &FlatStateDb,
    ledger: &Arc<rockbound::DB>,
    accessory: &Arc<rockbound::DB>,
) -> anyhow::Result<()> {
    let live = flat.latest_version_and_root_live()?;
    let archival = flat.latest_version_and_root_archival()?;
    let ledger = ledger::latest_version_and_root(ledger)?;
    let accessory = AccessoryDb::latest_version_and_root(accessory)?;
    let nomt = nomt.root_hashes();
    let version = |head: Head| head.map(|(version, _)| version);
    anyhow::ensure!(
        nomt == root_of(live) && archival == live && ledger == live && accessory == live,
        "the state databases are inconsistent after crash recovery: NOMT roots {nomt}; flat \
         live DB at version {:?}, roots {}; flat archival DB at version {:?}, roots {}; ledger \
         DB at version {:?}, roots {}; accessory DB at version {:?}, roots {}",
        version(live),
        root_of(live),
        version(archival),
        root_of(archival),
        version(ledger),
        root_of(ledger),
        version(accessory),
        root_of(accessory),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use nomt::trie::KeyPath;
    use selendra_interface::reexports::digest;
    use selendra_state::namespaces::ProvableNamespace;
    use sha2::Sha256;

    use super::*;
    use crate::harness::{empty_slot, test_slot_info};
    use crate::ledger::SlotContents;
    use crate::test_utils::blocks::{block, change_set, change_set_on, key, value};
    use crate::{RecoveryStep, WitnessMode, fail_at};

    type H = Sha256;

    fn open(dir: &crate::test_utils::TestDir) -> DbGroup<H> {
        DbGroup::open(&StateDbConfig::for_tests(dir.path())).unwrap()
    }

    #[test]
    fn commits_and_reopens() {
        let tempdir = crate::test_utils::tempdir();
        let (k_user, k_kernel, k_acc) = (key(b"u1"), key(b"k1"), key(b"a1"));
        let roots = {
            let mut group = open(&tempdir);
            assert_eq!(group.latest_version().unwrap(), None);
            assert_eq!(group.roots(), NomtRoots::PRE_GENESIS);

            let change_set = block(
                &group,
                0,
                vec![(k_user.clone(), value(b"user0"))],
                vec![(k_kernel.clone(), value(b"kernel0"))],
                vec![(k_acc.clone(), value(b"acc0"))],
            );
            change_set.commit(&mut group).unwrap();
            // A user-only block.
            let change_set = block(
                &group,
                1,
                vec![(k_user.clone(), value(b"user1"))],
                vec![],
                vec![],
            );
            change_set.commit(&mut group).unwrap();
            assert_ne!(group.roots().user, NomtRoots::PRE_GENESIS.user);
            group.roots()
        };

        let group = open(&tempdir);
        assert_eq!(group.latest_version().unwrap(), Some(SlotNumber::new(1)));
        assert_eq!(group.roots(), roots);
        // The ledger's newest slot is the committed version, with its roots.
        let (head, slot) = group.ledger_reader().unwrap().head().unwrap().unwrap();
        assert_eq!((head, slot.roots), (SlotNumber::new(1), roots));
        assert_eq!(slot.da_hash, test_slot_info(SlotNumber::new(1)).da_hash);
        let readers = group.readers::<u64>().unwrap();
        let historical = &readers.historical_state;
        assert_eq!(historical.last_version(), Some(SlotNumber::new(1)));
        assert_eq!(
            historical.get_root_hash(SlotNumber::new(1)).unwrap(),
            Some((SlotNumber::new(1), roots))
        );
        assert_eq!(
            historical
                .get_value(ProvableNamespace::User, &k_user)
                .unwrap(),
            value(b"user1")
        );
        assert_eq!(
            historical
                .get_value(ProvableNamespace::Kernel, &k_kernel)
                .unwrap(),
            value(b"kernel0")
        );
        assert_eq!(
            readers
                .accessory
                .get_value_option(&k_acc, SlotNumber::new(1))
                .unwrap(),
            value(b"acc0")
        );
        // NOMT holds the value hashes.
        let session = readers
            .session_builder
            .begin_user_session_without_witness()
            .unwrap();
        let key_path: KeyPath = H::digest(k_user.as_ref()).into();
        assert_eq!(
            session.read(key_path).unwrap(),
            Some(
                value(b"user1")
                    .unwrap()
                    .combine_val_hash_and_size::<H>()
                    .to_vec()
            )
        );
    }

    #[test]
    fn commit_rejects_bad_change_sets_before_writing() {
        let tempdir = crate::test_utils::tempdir();
        let mut group = open(&tempdir);
        let writes = || vec![(key(b"k1"), value(b"v"))];

        // Wrong version (with a valid ledger slot: the version is checked first).
        let state = change_set(&group, 1, writes(), writes(), vec![]);
        let ledger = block(&group, 0, writes(), writes(), vec![]).ledger;
        let err = group.commit(state, ledger).unwrap_err();
        assert!(
            err.to_string()
                .contains("is for version 1 but the next version is 0"),
            "{err}"
        );

        // A root other than the sessions'.
        let mut change_set = block(&group, 0, writes(), writes(), vec![]);
        change_set.state.historical_state.root = NomtRoots::PRE_GENESIS;
        let err = change_set.commit(&mut group).unwrap_err();
        assert!(
            err.to_string().contains("is not its NOMT sessions'"),
            "{err}"
        );

        // Two blocks on the same state: the second does not build on the committed roots.
        let first = block(&group, 0, writes(), writes(), vec![]);
        let second = block(&group, 0, vec![(key(b"k2"), value(b"w"))], writes(), vec![]);
        first.commit(&mut group).unwrap();
        let roots = group.roots();
        let mut second = second;
        second.state.historical_state.version = SlotNumber::new(1);
        let err = second.commit(&mut group).unwrap_err();
        assert!(
            err.to_string().contains("other than the committed"),
            "{err}"
        );

        // Nothing was written by the rejected change sets, and the databases stay usable (not
        // poisoned: the checks run before the first write).
        assert_eq!(group.roots(), roots);
        assert_eq!(group.latest_version().unwrap(), Some(SlotNumber::GENESIS));
        assert!(!group.is_poisoned());
        let change_set = block(&group, 1, writes(), vec![], vec![]);
        change_set.commit(&mut group).unwrap();
        drop(group);
        let group = open(&tempdir);
        assert_eq!(group.last_recovery().rolled_back, []);
        assert_eq!(group.latest_version().unwrap(), Some(SlotNumber::new(1)));
    }

    /// A commit whose ledger slot does not fit is refused before anything is written, and the
    /// databases stay usable: a slot for another version or roots, and a ledger DB not at the
    /// committed version (a slot written past the commits: without the check, the commit would
    /// write its slot over that one and leave the other's DA-hash index row behind).
    #[test]
    fn commit_rejects_bad_ledger_slots_before_writing() {
        let tempdir = crate::test_utils::tempdir();
        let mut group = open(&tempdir);
        let writes = || vec![(key(b"k1"), value(b"v"))];
        let genesis_slot = block(&group, 0, writes(), vec![], vec![]).ledger;
        let genesis_roots = {
            let genesis = block(&group, 0, writes(), vec![], vec![]);
            let roots = genesis.roots();
            genesis.commit(&mut group).unwrap();
            roots
        };
        let state = |group: &DbGroup<H>| {
            change_set(group, 1, vec![(key(b"k2"), value(b"w"))], vec![], vec![])
        };

        // A slot for another version.
        let err = group.commit(state(&group), genesis_slot).unwrap_err();
        assert!(
            format!("{err:#}").contains("the ledger slot is for version 0"),
            "{err:#}"
        );

        // A slot with other roots.
        let ledger = group
            .ledger_reader()
            .unwrap()
            .materialize_slot(
                SlotNumber::new(1),
                genesis_roots,
                test_slot_info(SlotNumber::new(1)),
                SlotContents::default(),
            )
            .unwrap();
        let err = group.commit(state(&group), ledger).unwrap_err();
        assert!(format!("{err:#}").contains("with roots"), "{err:#}");

        // The ledger DB ahead of the committed version (critique: the accessory DB was checked
        // against the live DB, the ledger DB was not).
        let valid = block(&group, 1, vec![(key(b"k2"), value(b"w"))], vec![], vec![]);
        let mut info = test_slot_info(SlotNumber::new(1));
        info.da_hash = [0xEE; 32];
        let stray = group
            .ledger_reader()
            .unwrap()
            .materialize_slot(
                SlotNumber::new(1),
                valid.roots(),
                info,
                SlotContents::default(),
            )
            .unwrap();
        ledger::commit(&group.ledger, &stray).unwrap();
        let err = valid.commit(&mut group).unwrap_err();
        assert!(
            format!("{err:#}").contains("the ledger DB is at version Some(1)"),
            "{err:#}"
        );
        assert!(!group.is_poisoned());
        assert_eq!(group.roots(), genesis_roots);
        assert_eq!(group.latest_version().unwrap(), Some(SlotNumber::GENESIS));
        assert_eq!(
            group
                .ledger_reader()
                .unwrap()
                .slot_by_hash(&[0xEE; 32])
                .unwrap(),
            Some(SlotNumber::new(1))
        );
    }

    /// A commit interrupted before the flat live DB (everything else written) is rolled back
    /// when the databases are reopened (upstream's `validate_commit_flag_and_rollback_if_
    /// necessary`; our first port only refused to open them). Every crash point and kind of
    /// block: `recovery::tests`.
    #[test]
    fn open_repairs_an_interrupted_commit() {
        let tempdir = crate::test_utils::tempdir();
        let config = StateDbConfig::for_tests(tempdir.path());
        let (genesis_roots, block_roots) = {
            let mut group = open(&tempdir);
            let genesis_roots = commit_genesis(&mut group);
            let change_set = block(
                &group,
                1,
                vec![(key(b"u1"), value(b"user1"))],
                vec![(key(b"k1"), value(b"kernel1"))],
                vec![(key(b"a1"), value(b"acc1"))],
            );
            let block_roots = change_set.roots();
            group.set_commit_hook(Some(fail_at(CommitPoint::BeforeLive)));
            let err = change_set.commit(&mut group).unwrap_err();
            assert!(format!("{err:#}").contains("injected fault"), "{err:#}");
            (genesis_roots, block_roots)
        };

        let mut group = DbGroup::<H>::open(&config).unwrap();
        assert_eq!(
            group.last_recovery(),
            &RecoveryReport {
                rolled_back: vec![
                    RecoveryStep::KernelNomt,
                    RecoveryStep::UserNomt,
                    RecoveryStep::Ledger,
                    RecoveryStep::Accessory,
                    RecoveryStep::Archival,
                ],
                live: Some(SlotNumber::GENESIS),
            }
        );
        assert_eq!(group.roots(), genesis_roots);
        assert_eq!(group.latest_version().unwrap(), Some(SlotNumber::GENESIS));
        let readers = group.readers::<u64>().unwrap();
        assert_eq!(
            readers
                .historical_state
                .get_value(ProvableNamespace::User, &key(b"u1"))
                .unwrap(),
            value(b"user0")
        );
        assert_eq!(
            readers
                .accessory
                .get_value_option(&key(b"a1"), SlotNumber::new(1))
                .unwrap(),
            value(b"acc0")
        );
        drop(readers);

        // The same block commits again, to the same roots; the next open has nothing to do.
        let change_set = block(
            &group,
            1,
            vec![(key(b"u1"), value(b"user1"))],
            vec![(key(b"k1"), value(b"kernel1"))],
            vec![(key(b"a1"), value(b"acc1"))],
        );
        change_set.commit(&mut group).unwrap();
        assert_eq!(group.roots(), block_roots);
        drop(group);
        assert_eq!(open(&tempdir).last_recovery().rolled_back, []);
    }

    /// A commit that fails once it started writing poisons the databases: no commit and no new
    /// readers until they are reopened (the NOMT trees may be ahead of the flat store). Upstream
    /// went on writing on top of the half-written commit.
    #[test]
    fn poisoned_group_refuses_commit_and_readers() {
        for point in CommitPoint::COMMIT {
            let tempdir = crate::test_utils::tempdir();
            let mut group = open(&tempdir);
            commit_genesis(&mut group);
            let writes = || {
                (
                    vec![(key(b"u1"), value(b"user1"))],
                    vec![(key(b"k1"), value(b"kernel1"))],
                    vec![(key(b"a1"), value(b"acc1"))],
                )
            };
            let (user, kernel, accessory) = writes();
            let first = block(&group, 1, user, kernel, accessory);
            let (user, kernel, accessory) = writes();
            let retry = block(&group, 1, user, kernel, accessory);

            group.set_commit_hook(Some(fail_at(point)));
            let err = first.commit(&mut group).unwrap_err();
            assert!(
                format!("{err:#}").contains("injected fault"),
                "{point:?}: {err:#}"
            );
            assert!(group.is_poisoned(), "{point:?}");
            // Even with the fault gone, and even where nothing was written yet.
            group.set_commit_hook(None);
            let err = retry.commit(&mut group).unwrap_err();
            assert!(err.to_string().contains("poisoned"), "{point:?}: {err}");
            let err = group.readers::<u64>().unwrap_err();
            assert!(err.to_string().contains("poisoned"), "{point:?}: {err}");
            let err = group.ledger_reader().unwrap_err();
            assert!(err.to_string().contains("poisoned"), "{point:?}: {err}");
            drop(group);

            let mut group = open(&tempdir);
            assert!(!group.is_poisoned());
            let expected = if point == CommitPoint::AfterLive {
                SlotNumber::new(1)
            } else {
                SlotNumber::GENESIS
            };
            assert_eq!(group.latest_version().unwrap(), Some(expected), "{point:?}");
            let next = expected.get().checked_add(1).unwrap();
            let change_set = block(
                &group,
                next,
                vec![(key(b"u2"), value(b"v"))],
                vec![],
                vec![],
            );
            change_set.commit(&mut group).unwrap();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Uncommitted blocks.

    /// Three uncommitted blocks on `group` (versions after the committed one), each on the one
    /// before, writing `[version]` at `k`: their overlays (in `overlays`) and snapshots.
    fn uncommitted_chain(
        group: &DbGroup<H>,
        overlays: &SharedOverlays<u64>,
        first: u64,
    ) -> Vec<(u64, SnapshotGroup)> {
        let mut snapshots: Vec<(u64, SnapshotGroup)> = Vec::new();
        for version in first..first + 3 {
            let chain: Vec<(u64, &SnapshotGroup)> = snapshots
                .iter()
                .map(|(key, snapshot)| (*key, snapshot))
                .collect();
            let (readers, ledger) = group.readers_at(&chain, overlays.clone()).unwrap();
            let byte = u8::try_from(version).unwrap();
            let state = change_set_on(
                &readers,
                version,
                vec![(key(b"k1"), value(&[byte]))],
                vec![],
                vec![(key(b"a1"), value(&[byte]))],
            );
            let slot = empty_slot(&ledger, SlotNumber::new(version), state.roots());
            let (overlay, snapshot) = state.into_parts(slot).unwrap();
            overlays.write().unwrap().insert(version, overlay);
            snapshots.push((version, snapshot));
        }
        snapshots
    }

    /// B15: `readers_at` takes uncommitted blocks only as a chain whose versions follow the
    /// committed one by one, each on the roots of the one before (upstream checked neither: a
    /// gap or a wrong order gave readers of wrong versions, and their version computation could
    /// overflow). On empty databases the chain starts at genesis (critique #3: not at
    /// `base + 1`).
    #[test]
    fn readers_at_rejects_non_consecutive_snapshots() {
        let tempdir = crate::test_utils::tempdir();
        let mut group = open(&tempdir);
        let overlays: SharedOverlays<u64> = Arc::default();
        let chain = uncommitted_chain(&group, &overlays, 0);
        let block = |i: usize| (chain[i].0, &chain[i].1);
        let read = |group: &DbGroup<H>, blocks: &[(u64, &SnapshotGroup)]| {
            let (readers, ledger) = group.readers_at(blocks, overlays.clone()).unwrap();
            let user = readers
                .historical_state
                .get_value(ProvableNamespace::User, &key(b"k1"))
                .unwrap();
            let accessory = readers
                .accessory
                .get_value_bound(&key(b"a1"), SlotNumber::MAX)
                .unwrap();
            assert_eq!(user, accessory);
            let session = readers
                .session_builder
                .begin_both_sessions(WitnessMode::Off);
            let nomt_root = session.unwrap().user.prev_root().into_inner();
            (
                readers.historical_state.last_version(),
                user,
                ledger.head().unwrap().map(|(slot, _)| slot),
                nomt_root,
            )
        };
        assert_eq!(
            read(&group, &[block(0), block(1), block(2)]),
            (
                Some(SlotNumber::new(2)),
                value(&[2]),
                Some(SlotNumber::new(2)),
                chain[2].1.roots().user
            )
        );
        assert_eq!(read(&group, &[block(0)]).0, Some(SlotNumber::GENESIS));
        assert_eq!(read(&group, &[]).0, None);

        // A block on other roots than the one before it, at the right version.
        let (readers, ledger) = group.readers_at(&[], overlays.clone()).unwrap();
        let other = change_set_on(&readers, 1, vec![(key(b"x1"), value(b"x"))], vec![], vec![]);
        let slot = empty_slot(&ledger, SlotNumber::new(0), other.roots());
        let (_, other) = other.into_parts(slot).unwrap();
        let err = group
            .readers_at(&[block(0), (9, &other)], overlays.clone())
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("other than those of the block before"),
            "{err:#}"
        );

        for blocks in [
            vec![block(1)],
            vec![block(0), block(2)],
            vec![block(1), block(0)],
            vec![block(0), block(0)],
            vec![block(0), block(1), block(2), block(2)],
        ] {
            let err = group.readers_at(&blocks, overlays.clone()).unwrap_err();
            assert!(
                format!("{err:#}").contains("of the uncommitted chain is for version"),
                "{err:#}"
            );
        }

        // Block 0 committed: the chain starts at version 1 now.
        let overlay = overlays.write().unwrap().remove(&0).unwrap();
        group.commit_snapshot(overlay, &chain[0].1).unwrap();
        assert_eq!(read(&group, &[block(1), block(2)]).1, value(&[2]));
        assert!(group.readers_at(&[block(0)], overlays.clone()).is_err());
        assert!(group.readers_at(&[block(2)], overlays.clone()).is_err());
    }

    /// Critique #21: a change set with a range delete is refused before anything is written: a
    /// reader of the block's snapshot would not see the range delete (range deletes are
    /// written only straight to the databases, by rollbacks and pruning).
    #[test]
    fn change_set_with_range_delete_is_refused() {
        let tempdir = crate::test_utils::tempdir();
        let mut group = open(&tempdir);
        let mut block = block(&group, 0, vec![(key(b"k1"), value(b"v"))], vec![], vec![]);
        block
            .state
            .accessory
            .delete_range::<crate::schema::ModuleAccessoryState>(
                &(b"a".as_slice(), SlotNumber::GENESIS),
                &(b"b".as_slice(), SlotNumber::GENESIS),
            )
            .unwrap();
        let err = block.commit(&mut group).unwrap_err();
        assert!(format!("{err:#}").contains("range delete"), "{err:#}");
        assert!(!group.is_poisoned());
        assert_eq!(group.latest_version().unwrap(), None);
    }

    // ---------------------------------------------------------------------------------------
    // The hasher guard.

    /// SHA-256 of a `0` byte followed by the input: a valid 32-byte `Digest`, but not the state
    /// hasher (what a node built with another hasher would open the databases with).
    struct OtherHasher(Sha256);

    impl Default for OtherHasher {
        fn default() -> Self {
            let mut inner = Sha256::default();
            digest::Update::update(&mut inner, &[0]);
            Self(inner)
        }
    }

    impl digest::HashMarker for OtherHasher {}

    impl digest::OutputSizeUser for OtherHasher {
        type OutputSize = U32;
    }

    impl digest::Update for OtherHasher {
        fn update(&mut self, data: &[u8]) {
            digest::Update::update(&mut self.0, data);
        }
    }

    impl digest::FixedOutput for OtherHasher {
        fn finalize_into(self, out: &mut digest::Output<Self>) {
            digest::FixedOutput::finalize_into(self.0, out);
        }
    }

    fn config(dir: &crate::test_utils::TestDir) -> StateDbConfig {
        StateDbConfig::for_tests(dir.path())
    }

    /// The stored hasher tag, read from the accessory DB directly (the databases closed).
    fn stored_tag(dir: &crate::test_utils::TestDir) -> Option<Vec<u8>> {
        let accessory = AccessoryDb::options().open_in(dir.path()).unwrap();
        accessory
            .get::<DbMetadata>(&MetadataKey::StateHasher)
            .unwrap()
    }

    fn assert_hasher_error(err: &anyhow::Error, what: &str) {
        let err = format!("{err:#}");
        assert!(err.contains(what), "{err}");
    }

    /// Commits block 0 (user, kernel and accessory writes) and returns the roots.
    fn commit_genesis(group: &mut DbGroup<H>) -> NomtRoots {
        let change_set = block(
            group,
            0,
            vec![(key(b"u1"), value(b"user0"))],
            vec![(key(b"k1"), value(b"kernel0"))],
            vec![(key(b"a1"), value(b"acc0"))],
        );
        change_set.commit(group).unwrap();
        group.roots()
    }

    /// Databases written with the state hasher do not open with another one, and the failed
    /// open changes nothing: they reopen with the state hasher at the same version and roots.
    #[test]
    fn open_rejects_db_written_with_another_hasher() {
        let tempdir = crate::test_utils::tempdir();
        let roots = commit_genesis(&mut open(&tempdir));
        // Without the guard, the trees' roots (recomputed with the other hasher) would differ
        // from the live DB's, taken for an interrupted commit that recovery cannot repair.
        let err = DbGroup::<OtherHasher>::open(&config(&tempdir)).unwrap_err();
        assert_hasher_error(&err, "written with another state hasher");

        let group = open(&tempdir);
        assert_eq!(group.roots(), roots);
        assert_eq!(group.latest_version().unwrap(), Some(SlotNumber::GENESIS));
        let readers = group.readers::<u64>().unwrap();
        assert_eq!(
            readers
                .historical_state
                .get_value(ProvableNamespace::User, &key(b"u1"))
                .unwrap(),
            value(b"user0")
        );
    }

    /// The tag alone decides, even before anything is committed: empty databases created with
    /// one hasher do not open with another (in both directions).
    #[test]
    fn open_rejects_empty_db_created_with_another_hasher() {
        let tempdir = crate::test_utils::tempdir();
        drop(DbGroup::<OtherHasher>::open(&config(&tempdir)).unwrap());
        let err = DbGroup::<H>::open(&config(&tempdir)).unwrap_err();
        assert_hasher_error(&err, "written with another state hasher");
        // The other hasher still opens them: the failed open did not re-tag them.
        drop(DbGroup::<OtherHasher>::open(&config(&tempdir)).unwrap());
    }

    /// The first open of empty databases records `SHA-256("SELENDRA/state-hasher/v1")` (pinned,
    /// Python's `hashlib`); later opens check it and never rewrite it. Databases that hold data
    /// but no tag are refused and stay untagged.
    #[test]
    fn hasher_tag_written_on_first_open_only() {
        const TAG: &str = "0x83500e863799fb8a52f07a55b6360bc1e83f638c765875a926ea0fd7ac582aaf";
        let tempdir = crate::test_utils::tempdir();
        let hex = |tag: Option<Vec<u8>>| tag.map(|tag| HexString(tag).to_string());
        {
            let mut group = open(&tempdir);
            assert_eq!(
                hex(group
                    .accessory
                    .get::<DbMetadata>(&MetadataKey::StateHasher)
                    .unwrap()),
                Some(TAG.into())
            );
            commit_genesis(&mut group);
        }
        drop(open(&tempdir));
        assert_eq!(hex(stored_tag(&tempdir)), Some(TAG.to_string()));

        // Remove the tag: the databases now look written before the guard existed.
        AccessoryDb::options()
            .open_in(tempdir.path())
            .unwrap()
            .delete::<DbMetadata>(&MetadataKey::StateHasher)
            .unwrap();
        let err = DbGroup::<H>::open(&config(&tempdir)).unwrap_err();
        assert_hasher_error(&err, "hold data but no state hasher tag");
        assert_eq!(stored_tag(&tempdir), None);
    }

    /// The guard runs before anything writes data hashed with `H`: after an interrupted commit
    /// (the NOMT trees one block ahead), opening with another hasher fails on the hasher, and
    /// the NOMT trees keep their roots. (Crash recovery rolls the trees back with the
    /// configured hasher: it must never run with the wrong one.)
    #[test]
    fn open_with_wrong_hasher_after_interrupted_commit_is_error_and_leaves_nomt_untouched() {
        let tempdir = crate::test_utils::tempdir();
        let nomt_roots = {
            let mut group = open(&tempdir);
            commit_genesis(&mut group);
            let change_set = block(
                &group,
                1,
                vec![(key(b"u1"), value(b"user1"))],
                vec![],
                vec![],
            );
            let NomtChangeSet { state, .. } = change_set.state;
            group
                .nomt
                .commit(state.into_state_overlay(), &Faults::default())
                .unwrap();
            group.roots()
        };
        let err = DbGroup::<OtherHasher>::open(&config(&tempdir)).unwrap_err();
        assert_hasher_error(&err, "written with another state hasher");

        let nomt = NomtStateDb::<H>::open_no_grow(&config(&tempdir)).unwrap();
        assert_eq!(nomt.root_hashes(), nomt_roots);
        drop(nomt);
        // With the state hasher, recovery rolls the trees back.
        let group = open(&tempdir);
        assert_eq!(group.last_recovery().rolled_back, [RecoveryStep::UserNomt]);
        assert_eq!(group.latest_version().unwrap(), Some(SlotNumber::GENESIS));
    }

    /// A refused open grows no NOMT hash table: growing comes after the hasher guard, crash
    /// recovery and the consistency check (it used to run first, when the trees were opened).
    #[test]
    fn refused_open_does_not_grow_hashtable() {
        let small_count =
            usize::try_from(StateDbConfig::for_tests("").user.hashtable_buckets.get()).unwrap();
        let large_count = small_count.checked_mul(2).unwrap();
        let large = |dir: &crate::test_utils::TestDir| {
            let mut config = config(dir);
            let buckets =
                core::num::NonZeroU32::try_from(u32::try_from(large_count).unwrap()).unwrap();
            config.user.hashtable_buckets = buckets;
            config.kernel.hashtable_buckets = buckets;
            config
        };
        {
            let tempdir = crate::test_utils::tempdir();
            let bucket_counts = || {
                NomtStateDb::<H>::open_no_grow(&large(&tempdir))
                    .unwrap()
                    .bucket_counts()
            };
            {
                let mut group = open(&tempdir);
                commit_genesis(&mut group);
                let change_set = block(&group, 1, vec![(key(b"u1"), value(b"v1"))], vec![], vec![]);
                change_set.commit(&mut group).unwrap();
            }

            // Refused by the hasher guard.
            let err = DbGroup::<OtherHasher>::open(&large(&tempdir)).unwrap_err();
            assert_hasher_error(&err, "written with another state hasher");
            assert_eq!(bucket_counts(), (small_count, small_count));

            // Refused by crash recovery: the accessory DB is behind the live DB.
            let accessory = Arc::new(AccessoryDb::options().open_in(tempdir.path()).unwrap());
            AccessoryDb::rollback(&accessory).unwrap();
            drop(accessory);
            let err = DbGroup::<H>::open(&large(&tempdir)).unwrap_err();
            assert!(
                format!("{err:#}").contains("cannot be recovered"),
                "{err:#}"
            );
            assert_eq!(bucket_counts(), (small_count, small_count));
        }

        // An open that succeeds grows them.
        let tempdir = crate::test_utils::tempdir();
        drop(open(&tempdir));
        let group = DbGroup::<H>::open(&large(&tempdir)).unwrap();
        assert_eq!(group.nomt().bucket_counts(), (large_count, large_count));
    }
}

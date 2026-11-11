//! All state databases together ([`DbGroup`]), the order they are committed in, and how they
//! are opened (hasher guard, startup crash recovery).

use std::sync::Arc;

use anyhow::Context;
use rockbound::SchemaBatch;
use rockbound::cache::delta_reader::DeltaReader;
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
use crate::nomt_state::{NomtRoots, NomtSessionBuilder, NomtStateDb, StateFinishedSession};
use crate::recovery::{Head, RecoveryReport, root_of};
use crate::schema::{DbMetadata, MetadataKey};

/// What the hasher guard hashes: the databases record `H(STATE_HASHER_PROBE)` when they are
/// created and compare it with the configured hasher's on every open ([`DbGroup::open`]).
const STATE_HASHER_PROBE: &[u8] = b"SELENDRA/state-hasher/v1";

/// Everything one block changes in the state databases: the NOMT trees, the flat value store
/// and the accessory store.
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

    /// The NOMT part alone (tests that write the trees past the other databases).
    #[cfg(test)]
    pub(crate) fn into_nomt_overlay(self) -> crate::StateOverlay {
        self.state.into_state_overlay()
    }
}

/// The readers a storage needs, all at the same committed version (no uncommitted snapshots).
pub struct StorageReaders<H, K> {
    /// Opens NOMT sessions on the committed trees.
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

/// The state databases: the NOMT trees, the flat value store and the accessory store.
///
/// Commits are linear (one version after the other, `&mut self`). A storage manager with forks,
/// uncommitted snapshots, the ledger DB and pruning builds on this (later).
///
/// **Poisoning.** A commit that fails after it started writing (an I/O error, or an injected
/// fault) leaves the databases at different versions, and the NOMT trees' in-memory roots may
/// already have moved. The group is then poisoned: [`commit`](Self::commit) and
/// [`readers`](Self::readers) fail until the databases are closed and reopened, which repairs
/// them ([`open`](Self::open)). Upstream went on with the databases out of step.
pub struct DbGroup<H> {
    nomt: Arc<NomtStateDb<H>>,
    flat: FlatStateDb,
    accessory: Arc<rockbound::DB>,
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
    ///    back; it is also logged). Versioned databases are rolled back only if they are exactly
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

    fn open_with_faults(config: &StateDbConfig, faults: Faults) -> anyhow::Result<Self> {
        let nomt = NomtStateDb::open_no_grow(config)?;
        let mut flat = FlatStateDb::new(
            &config.path,
            config.user_state_cache_size,
            config.kernel_state_cache_size,
        )?;
        let accessory = Arc::new(AccessoryDb::options().open_in(&config.path)?);
        // First: nothing may write data hashed with `H` before it.
        check_state_hasher(&nomt, &flat, &accessory)?;
        let last_recovery = crate::recovery::recover(&nomt, &mut flat, &accessory, &faults)?;
        check_consistency(&nomt, &flat, &accessory)?;
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
            accessory,
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
    /// through [`readers`](Self::readers) until they are reopened.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
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

    /// Readers of the committed state, all at the newest committed version. They see later
    /// commits only through their unbound reads.
    ///
    /// # Errors
    /// If the databases are poisoned ([`is_poisoned`](Self::is_poisoned)), or on read errors.
    pub fn readers<K>(&self) -> anyhow::Result<StorageReaders<H, K>> {
        self.ensure_not_poisoned()?;
        Ok(StorageReaders {
            session_builder: NomtSessionBuilder::from_committed(self.nomt.clone()),
            historical_state: self.flat.reader()?,
            accessory: AccessoryDb::with_reader(DeltaReader::new(
                self.accessory.clone(),
                Vec::new(),
            )),
        })
    }

    /// Commits one block's changes, which must be for the version after the newest committed
    /// one and build on the committed roots.
    ///
    /// Order (upstream's; proofs of the newest committed state rely on it): the NOMT kernel
    /// tree, the NOMT user tree, the accessory DB (values and root in one write), the flat
    /// archival DB, the flat live DB last. The live DB says which version is committed; after a
    /// crash, the databases written before it are at most one version ahead, and reopening
    /// rolls them back ([`open`](Self::open)). Each write is synced to disk before the next.
    ///
    /// Drop every NOMT session and flat-store iterator of this thread first: a commit waits
    /// for them.
    ///
    /// # Errors
    /// - If the databases are poisoned, if the change set is for another version, does not
    ///   build on the committed roots, or carries a root other than its NOMT sessions' (all
    ///   checked before anything is written; the databases stay usable).
    /// - If a write fails (or a fault is injected) once writing started: the databases may be
    ///   out of step, and they are poisoned until reopened.
    pub fn commit(&mut self, change_set: NomtChangeSet) -> anyhow::Result<()> {
        self.ensure_not_poisoned()?;
        let NomtChangeSet {
            state,
            historical_state,
            accessory,
        } = change_set;

        let live = self.flat.latest_version_and_root_live()?;
        let expected = next_version_after(live.map(|(version, _)| version))?;
        anyhow::ensure!(
            historical_state.version() == expected,
            "the change set is for version {} but the next version is {expected}",
            historical_state.version()
        );
        let accessory_version =
            AccessoryDb::latest_version_and_root(&self.accessory)?.map(|(version, _)| version);
        anyhow::ensure!(
            accessory_version == live.map(|(version, _)| version),
            "the accessory DB is at version {accessory_version:?}, the flat store at {:?}",
            live.map(|(version, _)| version)
        );
        anyhow::ensure!(
            state.prev_roots() == root_of(live),
            "the change set builds on roots ({}) other than the committed ones ({})",
            state.prev_roots(),
            root_of(live)
        );
        anyhow::ensure!(
            state.roots() == historical_state.root(),
            "the change set's root ({}) is not its NOMT sessions' ({})",
            historical_state.root(),
            state.roots()
        );

        let written = self.write(state, historical_state, &accessory);
        if let Err(error) = &written {
            self.poisoned = true;
            tracing::error!(
                version = %expected,
                error = format!("{error:#}"),
                "A commit of the state databases failed after it started writing: they are \
                 poisoned until reopened"
            );
        }
        written
    }

    /// The writes of [`commit`](Self::commit), in order, with the fault points in between.
    fn write(
        &mut self,
        state: StateFinishedSession,
        historical_state: StateChanges,
        accessory: &SchemaBatch,
    ) -> anyhow::Result<()> {
        // ======================= DANGER ZONE ======================
        // The commit order is relied on by the prover's proofs of the newest committed state
        // and by startup crash recovery: change it only together with them. An error from here
        // on poisons the databases.
        self.faults.hit(CommitPoint::BeforeKernelNomt)?;
        self.nomt
            .commit(state.into_state_overlay(), &self.faults)
            .context("NOMT commit")?;
        self.faults.hit(CommitPoint::BeforeAccessory)?;
        AccessoryDb::commit(
            &self.accessory,
            accessory,
            &historical_state.root_hash_batch,
        )
        .context("accessory DB commit")?;
        self.faults.hit(CommitPoint::BeforeArchival)?;
        self.flat
            .commit_with_faults(historical_state, &self.faults)
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
                is_empty(nomt, flat, accessory)?,
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
/// the flat store (live or archival) or the accessory DB.
fn is_empty<H: Digest<OutputSize = U32> + Send + Sync>(
    nomt: &NomtStateDb<H>,
    flat: &FlatStateDb,
    accessory: &Arc<rockbound::DB>,
) -> anyhow::Result<bool> {
    Ok(nomt.root_hashes() == NomtRoots::PRE_GENESIS
        && flat.latest_version_and_root_live()?.is_none()
        && flat.latest_version_and_root_archival()?.is_none()
        && AccessoryDb::latest_version_and_root(accessory)?.is_none())
}

/// Fails unless the NOMT trees, the live and archival flat DBs and the accessory DB are at the
/// same version and root (after crash recovery, which repairs an interrupted commit).
fn check_consistency<H: Digest<OutputSize = U32> + Send + Sync>(
    nomt: &NomtStateDb<H>,
    flat: &FlatStateDb,
    accessory: &Arc<rockbound::DB>,
) -> anyhow::Result<()> {
    let live = flat.latest_version_and_root_live()?;
    let archival = flat.latest_version_and_root_archival()?;
    let accessory = AccessoryDb::latest_version_and_root(accessory)?;
    let nomt = nomt.root_hashes();
    let version = |head: Head| head.map(|(version, _)| version);
    anyhow::ensure!(
        nomt == root_of(live) && archival == live && accessory == live,
        "the state databases are inconsistent after crash recovery: NOMT roots {nomt}; flat \
         live DB at version {:?}, roots {}; flat archival DB at version {:?}, roots {}; \
         accessory DB at version {:?}, roots {}",
        version(live),
        root_of(live),
        version(archival),
        root_of(archival),
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
    use crate::test_utils::blocks::{block, key, value};
    use crate::{RecoveryStep, fail_at};

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
            group.commit(change_set).unwrap();
            // A user-only block.
            let change_set = block(
                &group,
                1,
                vec![(k_user.clone(), value(b"user1"))],
                vec![],
                vec![],
            );
            group.commit(change_set).unwrap();
            assert_ne!(group.roots().user, NomtRoots::PRE_GENESIS.user);
            group.roots()
        };

        let group = open(&tempdir);
        assert_eq!(group.latest_version().unwrap(), Some(SlotNumber::new(1)));
        assert_eq!(group.roots(), roots);
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

        // Wrong version.
        let change_set = block(&group, 1, writes(), writes(), vec![]);
        let err = group.commit(change_set).unwrap_err();
        assert!(
            err.to_string()
                .contains("is for version 1 but the next version is 0"),
            "{err}"
        );

        // A root other than the sessions'.
        let mut change_set = block(&group, 0, writes(), writes(), vec![]);
        change_set.historical_state.root = NomtRoots::PRE_GENESIS;
        let err = group.commit(change_set).unwrap_err();
        assert!(
            err.to_string().contains("is not its NOMT sessions'"),
            "{err}"
        );

        // Two blocks on the same state: the second does not build on the committed roots.
        let first = block(&group, 0, writes(), writes(), vec![]);
        let second = block(&group, 0, vec![(key(b"k2"), value(b"w"))], writes(), vec![]);
        group.commit(first).unwrap();
        let roots = group.roots();
        let mut second = second;
        second.historical_state.version = SlotNumber::new(1);
        let err = group.commit(second).unwrap_err();
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
        group.commit(change_set).unwrap();
        drop(group);
        let group = open(&tempdir);
        assert_eq!(group.last_recovery().rolled_back, []);
        assert_eq!(group.latest_version().unwrap(), Some(SlotNumber::new(1)));
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
            let err = group.commit(change_set).unwrap_err();
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
        group.commit(change_set).unwrap();
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
            let err = group.commit(first).unwrap_err();
            assert!(
                format!("{err:#}").contains("injected fault"),
                "{point:?}: {err:#}"
            );
            assert!(group.is_poisoned(), "{point:?}");
            // Even with the fault gone, and even where nothing was written yet.
            group.set_commit_hook(None);
            let err = group.commit(retry).unwrap_err();
            assert!(err.to_string().contains("poisoned"), "{point:?}: {err}");
            let err = group.readers::<u64>().unwrap_err();
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
            group.commit(change_set).unwrap();
        }
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
        group.commit(change_set).unwrap();
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
            let NomtChangeSet { state, .. } = change_set;
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
                group.commit(change_set).unwrap();
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

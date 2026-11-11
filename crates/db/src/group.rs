//! All state databases together ([`DbGroup`]) and the order they are committed in.

use std::sync::Arc;

use anyhow::Context;
use rockbound::SchemaBatch;
use rockbound::cache::delta_reader::DeltaReader;
use selendra_interface::common::{HexString, SlotNumber};
use selendra_interface::reexports::digest::Digest;
use selendra_interface::reexports::digest::typenum::U32;

use crate::accessory::AccessoryDb;
use crate::config::StateDbConfig;
use crate::flat::FlatStateDb;
use crate::historical::{HistoricalStateReader, StateChanges, next_version_after};
use crate::nomt_state::{NomtRoots, NomtSessionBuilder, NomtStateDb, StateFinishedSession};
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

/// The state databases: the NOMT trees, the flat value store and the accessory store.
///
/// Commits are linear (one version after the other, `&mut self`). A storage manager with forks,
/// uncommitted snapshots, the ledger DB and pruning builds on this (later).
pub struct DbGroup<H> {
    nomt: Arc<NomtStateDb<H>>,
    flat: FlatStateDb,
    accessory: Arc<rockbound::DB>,
}

impl<H> core::fmt::Debug for DbGroup<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DbGroup")
    }
}

/// The version and root a database holds (`None`: empty, at the pre-genesis root).
type Head = Option<(SlotNumber, NomtRoots)>;

fn root_of(head: Head) -> NomtRoots {
    head.map_or(NomtRoots::PRE_GENESIS, |(_, root)| root)
}

impl<H: Digest<OutputSize = U32> + Send + Sync> DbGroup<H> {
    /// Opens (or creates) all state databases under [`StateDbConfig::path`].
    ///
    /// **Hasher guard.** The first open of empty databases records which hasher `H` they are
    /// written with (the tag `H(b"SELENDRA/state-hasher/v1")`, [`MetadataKey::StateHasher`] in
    /// the accessory DB); every later open must use the same one. Otherwise a node built with
    /// another `H` would extend the trees with nodes hashed differently from the ones already
    /// stored. The guard runs right after the databases are opened, before anything writes
    /// data hashed with `H` (crash recovery's NOMT rollback must come after it: a rollback
    /// rewrites the trees with the configured hasher).
    ///
    /// Opening the databases already writes to disk, but nothing hashed with `H`: NOMT creates
    /// a new tree's files, finishes its own write-ahead-log replay or an interrupted rehash, and
    /// grows a tree's hash table when more buckets are configured than it has (none of which
    /// uses `H`; NOMT hashes with `H` only to recompute the root in memory), and RocksDB creates
    /// missing column families. So a refused open can leave a tree's hash table grown to the
    /// configured bucket count. (Growing moves after the guard and the consistency check
    /// together with startup crash recovery.)
    ///
    /// # Errors
    /// - If a database fails to open.
    /// - If the databases were written with another hasher, or hold data but no hasher tag
    ///   (written before the guard existed, or the tag was removed): no state and no tag is
    ///   written then, beyond what opening the databases writes (above).
    /// - If the databases are not all at the same version and root, i.e. the last commit was
    ///   interrupted. Repairing that (rolling the newer databases back) is not implemented
    ///   yet: upstream's startup recovery comes with the storage manager.
    pub fn open(config: &StateDbConfig) -> anyhow::Result<Self> {
        let nomt = Arc::new(NomtStateDb::new(config)?);
        let flat = FlatStateDb::new(
            &config.path,
            config.user_state_cache_size,
            config.kernel_state_cache_size,
        )?;
        let accessory = Arc::new(AccessoryDb::options().open_in(&config.path)?);
        let group = Self {
            nomt,
            flat,
            accessory,
        };
        // First: nothing may write data hashed with `H` before it.
        group.check_state_hasher()?;
        group.check_consistency()?;
        Ok(group)
    }

    /// The hasher guard (see [`open`](Self::open)): checks the recorded hasher tag, or records
    /// it if every database is empty.
    fn check_state_hasher(&self) -> anyhow::Result<()> {
        let tag: [u8; 32] = H::digest(STATE_HASHER_PROBE).into();
        match self
            .accessory
            .get::<DbMetadata>(&MetadataKey::StateHasher)?
        {
            Some(stored) => anyhow::ensure!(
                stored == tag,
                "the state databases were written with another state hasher (stored tag {}, \
                 this node's {}): opening them would mix two hashers in one tree",
                HexString(&stored),
                HexString(tag)
            ),
            None => {
                anyhow::ensure!(
                    self.is_empty()?,
                    "the state databases hold data but no state hasher tag (written before the \
                     hasher guard existed, or the tag was removed): cannot check which hasher \
                     wrote them"
                );
                self.accessory
                    .put::<DbMetadata>(&MetadataKey::StateHasher, &tag.to_vec())
                    .context("recording the state hasher tag")?;
            }
        }
        Ok(())
    }

    /// Whether no database holds any state: the NOMT trees are empty and no version is
    /// committed to the flat store (live or archival) or the accessory DB.
    fn is_empty(&self) -> anyhow::Result<bool> {
        Ok(self.nomt.root_hashes() == NomtRoots::PRE_GENESIS
            && self.flat.latest_version_and_root_live()?.is_none()
            && self.flat.latest_version_and_root_archival()?.is_none()
            && AccessoryDb::latest_version_and_root(&self.accessory)?.is_none())
    }

    /// Fails unless the NOMT trees, the live and archival flat DBs and the accessory DB are at
    /// the same version and root.
    fn check_consistency(&self) -> anyhow::Result<()> {
        let live = self.flat.latest_version_and_root_live()?;
        let archival = self.flat.latest_version_and_root_archival()?;
        let accessory = AccessoryDb::latest_version_and_root(&self.accessory)?;
        let nomt = self.nomt.root_hashes();
        let version = |head: Head| head.map(|(version, _)| version);
        anyhow::ensure!(
            nomt == root_of(live) && archival == live && accessory == live,
            "the state databases are inconsistent (the last commit was interrupted; repairing \
             it is not implemented yet): NOMT roots {nomt}; flat live DB at version {:?}, roots \
             {}; flat archival DB at version {:?}, roots {}; accessory DB at version {:?}, roots \
             {}",
            version(live),
            root_of(live),
            version(archival),
            root_of(archival),
            version(accessory),
            root_of(accessory),
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

    /// The committed roots of the NOMT trees.
    pub fn roots(&self) -> NomtRoots {
        self.nomt.root_hashes()
    }

    /// The NOMT trees (tests only: outside this crate, the trees are written only through
    /// [`commit`](Self::commit); see [`NomtStateDb`]).
    #[cfg(test)]
    pub(crate) fn nomt(&self) -> &Arc<NomtStateDb<H>> {
        &self.nomt
    }

    /// Readers of the committed state, all at the newest committed version. They see later
    /// commits only through their unbound reads.
    pub fn readers<K>(&self) -> anyhow::Result<StorageReaders<H, K>> {
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
    /// crash, the databases written before it are at most one version ahead.
    ///
    /// Drop every NOMT session and flat-store iterator of this thread first: a commit waits
    /// for them.
    ///
    /// # Errors
    /// If the change set is for another version, does not build on the committed roots, or
    /// carries a root other than its NOMT sessions' (all checked before anything is written);
    /// or if a write fails. After a failed write the databases may be inconsistent: stop, and
    /// reopen (which detects it).
    pub fn commit(&mut self, change_set: NomtChangeSet) -> anyhow::Result<()> {
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

        // ======================= DANGER ZONE ======================
        // The commit order is relied on by the prover's proofs of the newest committed state:
        // change it only together with them.
        self.nomt
            .commit(state.into_state_overlay())
            .context("NOMT commit")?;
        AccessoryDb::commit(
            &self.accessory,
            &accessory,
            &historical_state.root_hash_batch,
        )
        .context("accessory DB commit")?;
        self.flat
            .commit(historical_state)
            .context("flat state commit")?;
        // ===================== END DANGER ZONE ====================
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use nomt::KeyReadWrite;
    use nomt::trie::KeyPath;
    use selendra_interface::reexports::digest;
    use selendra_state::namespaces::ProvableNamespace;
    use selendra_state::{SlotKey, SlotValue};
    use sha2::Sha256;

    use super::*;
    use crate::WitnessMode;

    type H = Sha256;
    type Writes = Vec<(SlotKey, Option<SlotValue>)>;

    fn key(bytes: &[u8]) -> SlotKey {
        SlotKey::try_from_bytes(bytes).unwrap()
    }

    fn value(bytes: &[u8]) -> Option<SlotValue> {
        Some(SlotValue::from(bytes.to_vec()))
    }

    fn open(dir: &crate::test_utils::TestDir) -> DbGroup<H> {
        DbGroup::open(&StateDbConfig::for_tests(dir.path())).unwrap()
    }

    fn nomt_writes(writes: &Writes) -> Vec<(KeyPath, KeyReadWrite)> {
        let sorted: BTreeMap<KeyPath, KeyReadWrite> = writes
            .iter()
            .map(|(key, value)| {
                let key_path: KeyPath = H::digest(key.as_ref()).into();
                let value = value
                    .as_ref()
                    .map(|v| v.combine_val_hash_and_size::<H>().to_vec());
                (key_path, KeyReadWrite::Write(value))
            })
            .collect();
        sorted.into_iter().collect()
    }

    /// A block's change set on top of the committed state of `group`.
    fn block(
        group: &DbGroup<H>,
        version: u64,
        user: Writes,
        kernel: Writes,
        accessory: Writes,
    ) -> NomtChangeSet {
        let sessions = group
            .readers::<u64>()
            .unwrap()
            .session_builder
            .begin_both_sessions(WitnessMode::Off)
            .unwrap();
        let state = StateFinishedSession::new(
            sessions.user.finish(nomt_writes(&user)).unwrap(),
            sessions.kernel.finish(nomt_writes(&kernel)).unwrap(),
        );
        let version = SlotNumber::new(version);
        let historical_state =
            HistoricalStateReader::materialize_values(user, kernel, state.roots(), version)
                .unwrap();
        let accessory = AccessoryDb::materialize_values(accessory, version).unwrap();
        NomtChangeSet::new(state, historical_state, accessory)
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
        assert!(group.commit(change_set).is_err());

        // A root other than the sessions'.
        let mut change_set = block(&group, 0, writes(), writes(), vec![]);
        change_set.historical_state.root = NomtRoots::PRE_GENESIS;
        assert!(group.commit(change_set).is_err());

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

        // Nothing was written by the rejected change sets.
        assert_eq!(group.roots(), roots);
        assert_eq!(group.latest_version().unwrap(), Some(SlotNumber::GENESIS));
        drop(group);
        open(&tempdir);
    }

    /// A commit interrupted after the NOMT trees (here: only the flat store is behind) is
    /// detected when reopening.
    #[test]
    fn open_detects_an_interrupted_commit() {
        let tempdir = crate::test_utils::tempdir();
        {
            let mut group = open(&tempdir);
            let change_set = block(&group, 0, vec![(key(b"k1"), value(b"v"))], vec![], vec![]);
            let NomtChangeSet { state, .. } = change_set;
            group.nomt.commit(state.into_state_overlay()).unwrap();
            // A flat-only commit makes it worse, not better.
            let changes = HistoricalStateReader::materialize_values(
                vec![],
                vec![],
                NomtRoots::PRE_GENESIS,
                SlotNumber::GENESIS,
            )
            .unwrap();
            group.flat.commit(changes).unwrap();
        }
        let err = DbGroup::<H>::open(&StateDbConfig::for_tests(tempdir.path())).unwrap_err();
        assert!(err.to_string().contains("inconsistent"), "{err}");
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
        // Without the guard, the trees' roots (recomputed with the other hasher) would be the
        // first mismatch found, reported as an interrupted commit.
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
            group.nomt.commit(state.into_state_overlay()).unwrap();
            group.roots()
        };
        let err = DbGroup::<OtherHasher>::open(&config(&tempdir)).unwrap_err();
        assert_hasher_error(&err, "written with another state hasher");

        let nomt = NomtStateDb::<H>::new(&config(&tempdir)).unwrap();
        assert_eq!(nomt.root_hashes(), nomt_roots);
    }
}

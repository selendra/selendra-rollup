//! All state databases together ([`DbGroup`]) and the order they are committed in.

use std::sync::Arc;

use anyhow::Context;
use rockbound::SchemaBatch;
use rockbound::cache::delta_reader::DeltaReader;
use selendra_interface::common::SlotNumber;
use selendra_interface::reexports::digest::Digest;
use selendra_interface::reexports::digest::typenum::U32;

use crate::accessory::AccessoryDb;
use crate::config::StateDbConfig;
use crate::flat::FlatStateDb;
use crate::historical::{HistoricalStateReader, StateChanges, next_version_after};
use crate::nomt_state::{NomtRoots, NomtSessionBuilder, NomtStateDb, StateFinishedSession};

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
    /// # Errors
    /// If a database fails to open, or if the databases are not all at the same version and
    /// root, i.e. the last commit was interrupted. Repairing that (rolling the newer databases
    /// back) is not implemented yet: upstream's startup recovery comes with the storage
    /// manager.
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
        group.check_consistency()?;
        Ok(group)
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

    /// The NOMT trees.
    pub fn nomt(&self) -> &Arc<NomtStateDb<H>> {
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
}

//! Test helpers.

use std::path::Path;
use std::sync::{Condvar, Mutex, PoisonError};

/// How many tests may have databases open at once.
///
/// A test's directory holds four RocksDB instances (flat live and archival, ledger, accessory)
/// and two NOMT databases, and each open RocksDB instance preallocates a write-ahead log of
/// about 75 MB: about 300 MB per open directory (measured). At most 3 at once stay under about
/// 0.9 GB, which a 1.2 GB tmpfs holds (4 filled it once the ledger DB was added).
const MAX_CONCURRENT: usize = 3;

static RUNNING: Mutex<usize> = Mutex::new(0);
static FREED: Condvar = Condvar::new();

/// A temporary directory for a test's databases; holds one of the [`MAX_CONCURRENT`] slots
/// until dropped.
pub(crate) struct TestDir {
    // Dropped (deleted) before the slot is freed.
    dir: tempfile::TempDir,
    _slot: Slot,
}

impl TestDir {
    pub(crate) fn path(&self) -> &Path {
        self.dir.path()
    }
}

struct Slot;

impl Drop for Slot {
    fn drop(&mut self) {
        let mut running = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
        *running = running.saturating_sub(1);
        // Every waiter: one may need several slots, another fewer.
        FREED.notify_all();
    }
}

/// A new [`TestDir`], once a slot is free.
pub(crate) fn tempdir() -> TestDir {
    tempdirs(1).pop().expect("one directory was created")
}

/// `n` new [`TestDir`]s, once `n` slots are free: all taken at once, so that tests needing
/// several directories never hold some slots while waiting for more (with every slot held by
/// such tests, all would wait forever).
///
/// # Panics
/// If `n` is more than [`MAX_CONCURRENT`].
pub(crate) fn tempdirs(n: usize) -> Vec<TestDir> {
    assert!(
        n <= MAX_CONCURRENT,
        "at most {MAX_CONCURRENT} test directories exist at once"
    );
    let mut running = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
    while running.saturating_add(n) > MAX_CONCURRENT {
        running = FREED.wait(running).unwrap_or_else(PoisonError::into_inner);
    }
    *running = running.saturating_add(n);
    drop(running);
    // The slots first: each frees itself when dropped, also if creating a directory panics.
    let slots: Vec<Slot> = (0..n).map(|_| Slot).collect();
    slots
        .into_iter()
        .map(|slot| TestDir {
            dir: tempfile::tempdir().expect("create a temporary directory"),
            _slot: slot,
        })
        .collect()
}

/// Blocks with explicit writes for the state databases' own tests (change sets built from NOMT
/// sessions directly, without a storage, with their ledger slots), and a dump of every RocksDB
/// column family.
#[cfg(test)]
pub(crate) mod blocks {
    use std::collections::BTreeMap;
    use std::path::Path;

    use nomt::KeyReadWrite;
    use nomt::trie::KeyPath;
    use rockbound::rocksdb;
    use selendra_interface::common::{HexHash, SlotNumber};
    use selendra_interface::reexports::digest::Digest;
    use selendra_interface::reexports::digest::typenum::U32;
    use selendra_interface::stf::{BlobDiscardReason, DiscardedBlob, StoredEvent};
    use selendra_state::{SlotKey, SlotValue};

    use crate::harness::test_slot_info;
    use crate::ledger::{BatchContents, LedgerChangeSet, SlotContents, TxContents};
    use crate::{
        AccessoryDb, DbGroup, FlatStateDb, HistoricalStateReader, NomtChangeSet, NomtRoots,
        StateFinishedSession, WitnessMode,
    };

    /// One namespace's writes (`None`: delete).
    pub(crate) type Writes = Vec<(SlotKey, Option<SlotValue>)>;

    pub(crate) fn key(bytes: &[u8]) -> SlotKey {
        SlotKey::try_from_bytes(bytes).expect("a valid key")
    }

    pub(crate) fn value(bytes: &[u8]) -> Option<SlotValue> {
        Some(SlotValue::from(bytes.to_vec()))
    }

    /// The writes as NOMT takes them: `H(key) → val_hash ‖ size`, sorted by key path.
    fn nomt_writes<H: Digest<OutputSize = U32>>(writes: &Writes) -> Vec<(KeyPath, KeyReadWrite)> {
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

    /// A block's changes: the state change set and its ledger slot.
    pub(crate) struct Block {
        pub(crate) state: NomtChangeSet,
        pub(crate) ledger: LedgerChangeSet,
    }

    impl Block {
        /// The roots after the block.
        pub(crate) fn roots(&self) -> NomtRoots {
            self.state.roots()
        }

        /// Commits the block to `group`.
        pub(crate) fn commit<H: Digest<OutputSize = U32> + Send + Sync>(
            self,
            group: &mut DbGroup<H>,
        ) -> anyhow::Result<()> {
            group.commit(self.state, self.ledger)
        }
    }

    /// A block on top of the committed state of `group`, with an empty ledger slot.
    pub(crate) fn block<H: Digest<OutputSize = U32> + Send + Sync>(
        group: &DbGroup<H>,
        version: u64,
        user: Writes,
        kernel: Writes,
        accessory: Writes,
    ) -> Block {
        block_with_slot(
            group,
            version,
            user,
            kernel,
            accessory,
            SlotContents::default(),
        )
    }

    /// A block on top of the committed state of `group`, with `slot` in its ledger slot (DA
    /// block [`test_slot_info`]).
    pub(crate) fn block_with_slot<H: Digest<OutputSize = U32> + Send + Sync>(
        group: &DbGroup<H>,
        version: u64,
        user: Writes,
        kernel: Writes,
        accessory: Writes,
        slot: SlotContents,
    ) -> Block {
        let state = change_set(group, version, user, kernel, accessory);
        let ledger = group
            .ledger_reader()
            .expect("a ledger reader")
            .materialize_slot(
                state.version(),
                state.roots(),
                test_slot_info(state.version()),
                slot,
            )
            .expect("materialize the ledger slot");
        Block { state, ledger }
    }

    /// Ledger contents with every kind of item: a batch of two transactions (the first with
    /// one event per key of `event_keys`, the second without events), a discarded blob, an
    /// aggregated proof, a proof receipt and STF info. Hashes are derived from `seed`.
    pub(crate) fn slot_contents(seed: u8, event_keys: &[&str]) -> SlotContents {
        let tx_hash = [seed, 1].repeat(16).try_into().expect("32 bytes");
        let events = event_keys
            .iter()
            .map(|key| StoredEvent::new(key.as_bytes(), &[seed], tx_hash))
            .collect();
        SlotContents {
            batches: vec![BatchContents {
                hash: [seed; 32],
                receipt: vec![seed, 0xBA],
                txs: vec![
                    TxContents {
                        hash: tx_hash,
                        body: Some(vec![seed, 0xB0]),
                        receipt: vec![seed, 0x01],
                        events,
                    },
                    TxContents {
                        hash: [seed, 2].repeat(16).try_into().expect("32 bytes"),
                        body: None,
                        receipt: vec![seed, 0x02],
                        events: Vec::new(),
                    },
                ],
            }],
            discarded_blobs: vec![DiscardedBlob {
                hash: HexHash::new([seed, 3].repeat(16).try_into().expect("32 bytes")),
                reason: BlobDiscardReason::OutOfCapacity,
            }],
            aggregated_proofs: vec![vec![seed, 0xA9]],
            proof_receipts: vec![(
                [seed, 4].repeat(16).try_into().expect("32 bytes"),
                vec![seed],
            )],
            stf_info: Some(vec![seed, 0x5F]),
            stf_info_prune_below: None,
        }
    }

    /// A block's state change set on top of the committed state of `group`.
    pub(crate) fn change_set<H: Digest<OutputSize = U32> + Send + Sync>(
        group: &DbGroup<H>,
        version: u64,
        user: Writes,
        kernel: Writes,
        accessory: Writes,
    ) -> NomtChangeSet {
        let sessions = group
            .readers::<u64>()
            .expect("readers")
            .session_builder
            .begin_both_sessions(WitnessMode::Off)
            .expect("NOMT sessions");
        let state = StateFinishedSession::new(
            sessions
                .user
                .finish(nomt_writes::<H>(&user))
                .expect("finish"),
            sessions
                .kernel
                .finish(nomt_writes::<H>(&kernel))
                .expect("finish"),
        );
        let version = SlotNumber::new(version);
        let historical_state =
            HistoricalStateReader::materialize_values(user, kernel, state.roots(), version)
                .expect("materialize the flat-store changes");
        let accessory =
            AccessoryDb::materialize_values(accessory, version).expect("materialize accessory");
        NomtChangeSet::new(state, historical_state, accessory)
    }

    /// Every row of every column family of the RocksDB databases under `path`, by database
    /// directory and column family (read through read-only instances: the databases may be
    /// open).
    pub(crate) type Dump = BTreeMap<(String, String), Vec<(Vec<u8>, Vec<u8>)>>;

    /// See [`Dump`].
    pub(crate) fn dump(path: &Path) -> Dump {
        let mut dump = Dump::new();
        for dir in [
            FlatStateDb::LIVE_DB_PATH_SUFFIX,
            FlatStateDb::ARCHIVAL_DB_PATH_SUFFIX,
            crate::ledger::DB_PATH_SUFFIX,
            AccessoryDb::DB_PATH_SUFFIX,
        ] {
            let path = path.join(dir);
            if !path.exists() {
                continue;
            }
            let options = rocksdb::Options::default();
            let column_families = rocksdb::DB::list_cf(&options, &path).expect("list CFs");
            let db = rocksdb::DB::open_cf_for_read_only(&options, &path, &column_families, false)
                .expect("open read-only");
            for name in column_families {
                let cf = db.cf_handle(&name).expect("a listed CF");
                let rows = db
                    .iterator_cf(cf, rocksdb::IteratorMode::Start)
                    .map(|row| {
                        let (key, value) = row.expect("read a row");
                        (key.to_vec(), value.to_vec())
                    })
                    .collect();
                dump.insert((dir.to_owned(), name), rows);
            }
        }
        dump
    }
}

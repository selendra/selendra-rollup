//! Tests of the ledger DB: upstream's `ledger_db.rs` integration tests (on a ledger DB alone),
//! regression tests of upstream's bugs, reads through uncommitted snapshots, STF-info pruning,
//! and the ledger inside the state databases ([`DbGroup`](crate::DbGroup)).

use rockbound::Schema;
use selendra_interface::common::HexHash;
use selendra_interface::stf::{BlobDiscardReason, DiscardedBlob};
use selendra_state::StateStorageSpec;
use selendra_state::test_utils::map;

use super::*;
use crate::harness::{TestDbs, test_slot_info};
use crate::schema::MAX_EVENT_KEY_LEN;
use crate::test_utils::blocks::{change_set, dump, key, value};
use crate::test_utils::{TestDir, tempdir, tempdirs};
use crate::{DbGroup, StateDbConfig, WitnessMode};

/// A ledger DB alone in a temporary directory (upstream's `SimpleLedgerStorageManager`).
struct TestLedger {
    // Closed before the directory is deleted.
    db: Arc<DB>,
    dir: TestDir,
}

impl TestLedger {
    fn new() -> Self {
        Self::new_in(tempdir())
    }

    /// A ledger DB in `dir` (from [`tempdirs`] when a test needs two: taking one directory,
    /// then waiting for another, can wait forever).
    fn new_in(dir: TestDir) -> Self {
        let db = Arc::new(options().open_in(dir.path()).unwrap());
        Self { db, dir }
    }

    fn reader(&self) -> LedgerReader {
        LedgerReader::new(self.db.clone(), Vec::new())
    }

    /// Materializes the next slot (roots [`roots`], DA block [`info`]) with `contents`.
    fn materialize(&self, contents: SlotContents) -> anyhow::Result<LedgerChangeSet> {
        let reader = self.reader();
        let slot = reader.next_slot()?;
        reader.materialize_slot(slot, roots(slot.get()), info(slot.get()), contents)
    }

    /// Materializes and commits the next slot; returns its number.
    fn commit(&self, contents: SlotContents) -> SlotNumber {
        let change_set = self.materialize(contents).unwrap();
        commit(&self.db, &change_set).unwrap();
        change_set.version()
    }

    fn rollback(&self) -> Option<SlotNumber> {
        rollback_head(&self.db).unwrap()
    }

    fn rows<S: Schema>(&self) -> usize {
        let mut rows = self.db.iter::<S>().unwrap();
        rows.seek_to_first();
        rows.count()
    }

    fn dump(&self) -> crate::test_utils::blocks::Dump {
        dump(self.dir.path())
    }
}

/// The roots of test slot `n`: 64 bytes `n`.
fn roots(n: u64) -> NomtRoots {
    NomtRoots::from_bytes([u8::try_from(n % 256).unwrap(); NomtRoots::LENGTH])
}

fn info(n: u64) -> SlotInfo {
    test_slot_info(SlotNumber::new(n))
}

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn event(key: &str, tx: [u8; 32]) -> StoredEvent {
    StoredEvent::new(key.as_bytes(), b"value", tx)
}

/// A transaction with hash `hash` and one event per key of `keys`.
fn tx(hash: [u8; 32], keys: &[&str]) -> TxContents {
    TxContents {
        hash,
        body: None,
        receipt: vec![1],
        events: keys.iter().map(|key| event(key, hash)).collect(),
    }
}

/// A slot of one batch holding one transaction with one event per key of `keys` (upstream's
/// `create_slot_with_keys`).
fn slot_with_keys(seed: u8, keys: &[&str]) -> SlotContents {
    SlotContents {
        batches: vec![BatchContents {
            hash: hash(seed),
            receipt: vec![seed],
            txs: vec![tx(hash(seed.wrapping_add(100)), keys)],
        }],
        ..SlotContents::default()
    }
}

fn key_of(name: &str) -> EventKey {
    EventKey::new(name.as_bytes())
}

/// Every event key's count (a scan of the whole committed table).
fn event_key_counts(ledger: &TestLedger) -> BTreeMap<String, u64> {
    let mut rows = ledger.db.iter::<EventCountByKey>().unwrap();
    rows.seek_to_first();
    rows.map(|row| {
        let (key, count) = row.unwrap().into_tuple();
        (String::from_utf8(key.inner().clone()).unwrap(), count)
    })
    .collect()
}

// ---------------------------------------------------------------------------------------------
// Upstream's tests (`sov-db/tests/integration/ledger_db.rs`).

/// Upstream `test_save_aggregated_proof`: the newest aggregated proof after each slot.
#[test]
fn save_aggregated_proof() {
    let ledger = TestLedger::new();
    assert_eq!(ledger.reader().latest_aggregated_proof().unwrap(), None);
    for i in 0..10u8 {
        let proof = vec![i, 0xA9];
        let slot = ledger.commit(SlotContents {
            aggregated_proofs: vec![proof.clone()],
            ..SlotContents::default()
        });
        let reader = ledger.reader();
        assert_eq!(
            reader.latest_aggregated_proof().unwrap(),
            Some((slot, proof.clone()))
        );
        assert_eq!(reader.aggregated_proofs(slot).unwrap(), [proof]);
    }
}

/// Upstream `test_stf_info`.
#[test]
fn stf_info() {
    let ledger = TestLedger::new();
    assert_eq!(ledger.reader().oldest_stf_info_slot().unwrap(), None);
    ledger.commit(SlotContents {
        stf_info: Some(vec![1, 2, 3]),
        ..SlotContents::default()
    });
    let reader = ledger.reader();
    assert_eq!(
        reader.stf_info(SlotNumber::GENESIS).unwrap(),
        Some(vec![1, 2, 3])
    );
    assert_eq!(reader.stf_info(SlotNumber::new(1)).unwrap(), None);
    assert_eq!(
        reader.oldest_stf_info_slot().unwrap(),
        Some(SlotNumber::GENESIS)
    );
}

/// Upstream `test_rollback`: rolling back the newest slot, one at a time, down to an empty
/// ledger (then a rollback does nothing). The newest slot's roots are the ledger's version
/// marker. (Upstream also moved its separate finalized-slot row back: finalized is now the
/// committed head itself.)
#[test]
fn rollback() {
    let ledger = TestLedger::new();
    for _ in 0..3 {
        ledger.commit(SlotContents::default());
    }
    for (rolled_back, head) in [(2, Some(1)), (1, Some(0)), (0, None)] {
        assert_eq!(ledger.rollback(), Some(SlotNumber::new(rolled_back)));
        let expected = head.map(|head| (SlotNumber::new(head), roots(head)));
        assert_eq!(latest_version_and_root(&ledger.db).unwrap(), expected);
        assert_eq!(
            ledger
                .reader()
                .head()
                .unwrap()
                .map(|(n, slot)| (n, slot.roots)),
            expected
        );
    }
    assert_eq!(ledger.rollback(), None);
    assert_eq!(ledger.reader().next_slot().unwrap(), SlotNumber::GENESIS);
}

/// Upstream's `create_slot_schema_batch`: 2 batches of 3 transactions with 2 events each, and 3
/// discarded blobs.
fn slot_with_data(slot: u8) -> SlotContents {
    let batches = (0..2u8)
        .map(|batch| BatchContents {
            hash: [slot.wrapping_mul(10).wrapping_add(batch); 32],
            receipt: vec![batch],
            txs: (0..3u8)
                .map(|tx_index| {
                    tx(
                        hash(batch.wrapping_mul(10).wrapping_add(tx_index)),
                        &["k1", "k2"],
                    )
                })
                .collect(),
        })
        .collect();
    let discarded_blobs = (0..3u8)
        .map(|i| DiscardedBlob {
            hash: HexHash::new(hash(slot.wrapping_add(i))),
            reason: BlobDiscardReason::OutOfCapacity,
        })
        .collect();
    SlotContents {
        batches,
        discarded_blobs,
        ..SlotContents::default()
    }
}

/// The next numbers after slot `slot` of [`slot_with_data`] slots.
fn assert_next_numbers(ledger: &TestLedger, slot: u64) {
    let (head, stored) = ledger.reader().head().unwrap().unwrap();
    assert_eq!(head, SlotNumber::new(slot));
    let next = slot + 1;
    assert_eq!(stored.batches.end, BatchNumber::new(next * 2));
    assert_eq!(stored.txs.end, TxNumber::new(next * 6));
    assert_eq!(stored.events.end, EventNumber::new(next * 12));
    assert_eq!(
        stored.discarded_blobs.end,
        DiscardedBlobNumber::new(next * 3)
    );
    assert_eq!(stored.batches.end.get() - stored.batches.start.get(), 2);
}

/// Upstream `test_rollback_with_data`; also, each rollback leaves every column family exactly
/// as it was before the slot was committed (a dump of every row).
#[test]
fn rollback_with_data() {
    let ledger = TestLedger::new();
    let mut dumps = Vec::new();
    for slot in 0..3 {
        dumps.push(ledger.dump());
        ledger.commit(slot_with_data(slot));
    }
    assert_next_numbers(&ledger, 2);
    for slot in [2, 1] {
        assert_eq!(ledger.rollback(), Some(SlotNumber::new(slot)));
        assert_next_numbers(&ledger, slot - 1);
        assert!(ledger.dump() == dumps[usize::try_from(slot).unwrap()]);
    }
    assert_eq!(ledger.rollback(), Some(SlotNumber::GENESIS));
    assert!(ledger.dump() == dumps[0]);
}

/// Upstream `test_event_key_counts_basic`.
#[test]
fn event_key_counts_basic() {
    let ledger = TestLedger::new();
    ledger.commit(slot_with_keys(0, &["alpha", "alpha", "beta"]));
    let counts = event_key_counts(&ledger);
    assert_eq!(
        counts,
        BTreeMap::from([("alpha".into(), 2), ("beta".into(), 1)])
    );
    let reader = ledger.reader();
    assert_eq!(reader.event_key_count(&key_of("alpha")).unwrap(), 2);
    assert_eq!(reader.event_key_count(&key_of("gamma")).unwrap(), 0);
    assert_eq!(
        reader.event_numbers_by_key(&key_of("alpha")).unwrap(),
        [
            (TxNumber::ZERO, EventNumber::new(0)),
            (TxNumber::ZERO, EventNumber::new(1))
        ]
    );
}

/// Upstream `test_event_key_counts_across_slots`.
#[test]
fn event_key_counts_across_slots() {
    let ledger = TestLedger::new();
    ledger.commit(slot_with_keys(0, &["alpha", "beta"]));
    ledger.commit(slot_with_keys(1, &["alpha", "alpha", "gamma"]));
    assert_eq!(
        event_key_counts(&ledger),
        BTreeMap::from([("alpha".into(), 3), ("beta".into(), 1), ("gamma".into(), 1)])
    );
}

/// Upstream `test_event_key_counts_after_rollback`: counts are decremented, and deleted at 0.
#[test]
fn event_key_counts_after_rollback() {
    let ledger = TestLedger::new();
    ledger.commit(slot_with_keys(0, &["alpha", "beta"]));
    ledger.commit(slot_with_keys(1, &["alpha", "alpha", "beta"]));
    assert_eq!(
        event_key_counts(&ledger),
        BTreeMap::from([("alpha".into(), 3), ("beta".into(), 2)])
    );
    ledger.rollback();
    assert_eq!(
        event_key_counts(&ledger),
        BTreeMap::from([("alpha".into(), 1), ("beta".into(), 1)])
    );
    ledger.rollback();
    assert_eq!(event_key_counts(&ledger), BTreeMap::new());
    assert_eq!(ledger.rows::<EventByKey>(), 0);
}

// ---------------------------------------------------------------------------------------------
// Regression tests of upstream's bugs (L-B1 to L-B10 of the plan) and of new checks.

/// L-B1: an event count that does not read (here: corrupt) is an error, for the reader and for
/// the next slot with that key. Upstream read it as 0 and wrote a count of 1 over it.
#[test]
fn event_key_count_read_error_propagates() {
    let ledger = TestLedger::new();
    ledger.commit(slot_with_keys(0, &["alpha"]));
    let mut corrupt = SchemaBatch::new();
    corrupt
        .put_raw::<EventCountByKey>(b"alpha".to_vec(), vec![0, 1, 2])
        .unwrap();
    ledger.db.write_schemas(&corrupt).unwrap();

    let err = ledger
        .reader()
        .event_key_count(&key_of("alpha"))
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("event count must be 8 bytes"),
        "{err:#}"
    );
    let err = ledger
        .materialize(slot_with_keys(1, &["alpha"]))
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("reading an event key's count"),
        "{err:#}"
    );
    // Other keys are unaffected.
    ledger.commit(slot_with_keys(1, &["beta"]));
}

/// L-B2: the slot number is the caller's and must be the next one (upstream derived it from
/// the DB; only the runner's `assert_eq!` caught a mismatch). The slot after it must exist.
#[test]
fn materialize_slot_rejects_wrong_slot_number() {
    let ledger = TestLedger::new();
    let reader = ledger.reader();
    let materialize = |reader: &LedgerReader, n: u64| {
        reader.materialize_slot(
            SlotNumber::new(n),
            roots(n),
            info(n),
            SlotContents::default(),
        )
    };
    let err = materialize(&reader, 1).unwrap_err();
    assert!(
        err.to_string()
            .contains("cannot materialize slot 1: the ledger's next slot is 0"),
        "{err}"
    );
    ledger.commit(SlotContents::default());
    let reader = ledger.reader();
    for wrong in [0, 2, u64::MAX] {
        let err = materialize(&reader, wrong).unwrap_err();
        assert!(err.to_string().contains("next slot is 1"), "{err}");
    }
    materialize(&reader, 1).unwrap();
    drop((reader, ledger));

    // The last slot number: the slot after it would overflow.
    let ledger = TestLedger::new();
    let last = SlotNumber::new(u64::MAX - 1);
    let stored = StoredSlot {
        da_hash: hash(1),
        da_height: 0,
        roots: roots(0),
        timestamp: info(0).timestamp,
        batches: BatchNumber::ZERO..BatchNumber::ZERO,
        txs: TxNumber::ZERO..TxNumber::ZERO,
        events: EventNumber::ZERO..EventNumber::ZERO,
        discarded_blobs: DiscardedBlobNumber::ZERO..DiscardedBlobNumber::ZERO,
    };
    ledger.db.put::<SlotByNumber>(&last, &stored).unwrap();
    let err = ledger.materialize(SlotContents::default()).unwrap_err();
    assert!(err.to_string().contains("slot number overflow"), "{err}");
}

/// L-B3: hash indexes are `hash ‖ number`, so batches, transactions, discarded blobs and proof
/// receipts with the same hash all stay indexed, also within one slot; rolling back the newer
/// slot removes only its own rows. (Upstream keyed batches, blobs and receipts by the hash
/// alone: the newer row replaced the older, and its rollback deleted the older slot's row.)
#[test]
fn duplicate_batch_hash_keeps_both_and_rollback_keeps_older() {
    let ledger = TestLedger::new();
    let blob = DiscardedBlob {
        hash: HexHash::new(hash(7)),
        reason: BlobDiscardReason::OutOfCapacity,
    };
    let contents = |batches: usize| SlotContents {
        batches: vec![
            BatchContents {
                hash: hash(1),
                receipt: Vec::new(),
                txs: vec![tx(hash(2), &[])],
            };
            batches
        ],
        discarded_blobs: vec![blob.clone(); batches],
        proof_receipts: vec![(hash(3), vec![9]); batches],
        ..SlotContents::default()
    };
    ledger.commit(contents(1));
    ledger.commit(contents(2));
    let reader = ledger.reader();
    let numbers = |n: &[u64]| n.to_vec();
    let get = |reader: &LedgerReader| {
        (
            reader
                .batch_numbers_by_hash(&hash(1))
                .unwrap()
                .iter()
                .map(|n| n.get())
                .collect::<Vec<_>>(),
            reader
                .tx_numbers_by_hash(&hash(2))
                .unwrap()
                .iter()
                .map(|n| n.get())
                .collect::<Vec<_>>(),
            reader
                .discarded_blob_numbers_by_hash(&hash(7))
                .unwrap()
                .iter()
                .map(|n| n.get())
                .collect::<Vec<_>>(),
            reader.proof_receipts_by_hash(&hash(3)).unwrap(),
        )
    };
    let one = SlotNumber::new(1);
    assert_eq!(
        get(&reader),
        (
            numbers(&[0, 1, 2]),
            numbers(&[0, 1, 2]),
            numbers(&[0, 1, 2]),
            vec![(SlotNumber::GENESIS, 0), (one, 0), (one, 1)]
        )
    );
    assert_eq!(ledger.rollback(), Some(one));
    let reader = ledger.reader();
    assert_eq!(
        get(&reader),
        (
            numbers(&[0]),
            numbers(&[0]),
            numbers(&[0]),
            vec![(SlotNumber::GENESIS, 0)]
        )
    );
    assert_eq!(
        reader.batch(BatchNumber::ZERO).unwrap().unwrap().hash,
        hash(1)
    );
    assert_eq!(
        reader
            .discarded_blob(DiscardedBlobNumber::ZERO)
            .unwrap()
            .unwrap(),
        StoredDiscardedBlob {
            blob,
            slot: SlotNumber::GENESIS
        }
    );
}

/// L-B4: aggregated proofs are keyed `slot ‖ index`: several per slot are all kept, and a
/// rollback removes the slot's. (Upstream wrote every proof at id 0: one per ledger, which a
/// rollback never removed.)
#[test]
fn several_aggregated_proofs_per_slot_and_rollback_removes_them() {
    let ledger = TestLedger::new();
    let proofs = |proofs: &[&[u8]]| SlotContents {
        aggregated_proofs: proofs.iter().map(|proof| proof.to_vec()).collect(),
        ..SlotContents::default()
    };
    ledger.commit(proofs(&[b"a"]));
    ledger.commit(proofs(&[b"b", b"c"]));
    ledger.commit(proofs(&[]));
    let reader = ledger.reader();
    let one = SlotNumber::new(1);
    assert_eq!(
        reader.aggregated_proofs(one).unwrap(),
        [b"b".to_vec(), b"c".to_vec()]
    );
    assert_eq!(
        reader.latest_aggregated_proof().unwrap(),
        Some((one, b"c".to_vec()))
    );
    ledger.rollback();
    ledger.rollback();
    let reader = ledger.reader();
    assert_eq!(
        reader.aggregated_proofs(one).unwrap(),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(
        reader.latest_aggregated_proof().unwrap(),
        Some((SlotNumber::GENESIS, b"a".to_vec()))
    );
    assert_eq!(ledger.rows::<AggregatedProofBySlot>(), 1);
}

/// L-B5: a rollback removes the slot's STF info (upstream left it, visible to the prover).
#[test]
fn rollback_removes_stf_info() {
    let ledger = TestLedger::new();
    for i in 0..2u8 {
        ledger.commit(SlotContents {
            stf_info: Some(vec![i]),
            ..SlotContents::default()
        });
    }
    ledger.rollback();
    let reader = ledger.reader();
    assert_eq!(reader.stf_info(SlotNumber::new(1)).unwrap(), None);
    assert_eq!(reader.stf_info(SlotNumber::GENESIS).unwrap(), Some(vec![0]));
    assert_eq!(ledger.rows::<StfInfoBySlot>(), 1);
}

/// L-B6: proof receipts are keyed `slot ‖ index` (no per-slot list of hashes, which upstream
/// wrote for every slot, empty ones included), and a rollback removes the slot's receipts and
/// their hash rows.
#[test]
fn rollback_removes_proof_receipts() {
    let ledger = TestLedger::new();
    ledger.commit(SlotContents::default());
    assert_eq!(ledger.rows::<ProofReceiptBySlot>(), 0);
    ledger.commit(SlotContents {
        proof_receipts: vec![(hash(1), vec![10])],
        ..SlotContents::default()
    });
    ledger.commit(SlotContents {
        proof_receipts: vec![(hash(1), vec![20]), (hash(2), vec![21])],
        ..SlotContents::default()
    });
    let two = SlotNumber::new(2);
    assert_eq!(
        ledger.reader().proof_receipts(two).unwrap(),
        [(hash(1), vec![20]), (hash(2), vec![21])]
    );
    ledger.rollback();
    let reader = ledger.reader();
    assert_eq!(reader.proof_receipts(two).unwrap(), []);
    assert_eq!(
        reader.proof_receipts_by_hash(&hash(1)).unwrap(),
        [(SlotNumber::new(1), 0)]
    );
    assert_eq!(reader.proof_receipts_by_hash(&hash(2)).unwrap(), []);
    assert_eq!(
        (
            ledger.rows::<ProofReceiptBySlot>(),
            ledger.rows::<ProofReceiptByHash>()
        ),
        (1, 1)
    );
}

/// L-B9: every ledger codec rejects trailing bytes (upstream decoded values with borsh's
/// `deserialize_reader` and keys with bincode, both ignoring them), and inverted ranges.
#[test]
fn ledger_codecs_reject_trailing_bytes() {
    use rockbound::schema::{KeyDecoder, KeyEncoder, ValueCodec};

    fn value_round_trip<S: Schema, V: ValueCodec<S> + PartialEq + core::fmt::Debug>(value: &V) {
        let bytes = value.encode_value().unwrap();
        assert_eq!(&V::decode_value(&bytes).unwrap(), value);
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(
            V::decode_value(&longer).is_err(),
            "{}",
            S::COLUMN_FAMILY_NAME
        );
        assert!(V::decode_value(&bytes[..bytes.len() - 1]).is_err());
    }
    fn key_round_trip<S: Schema, K: KeyEncoder<S> + KeyDecoder<S> + PartialEq>(key: &K) {
        let bytes = key.encode_key().unwrap();
        assert_eq!(&K::decode_key(&bytes).unwrap(), key);
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(K::decode_key(&longer).is_err(), "{}", S::COLUMN_FAMILY_NAME);
        assert!(K::decode_key(&bytes[..bytes.len() - 1]).is_err());
    }

    let ledger = TestLedger::new();
    ledger.commit(slot_with_data(0));
    ledger.commit(SlotContents {
        aggregated_proofs: vec![vec![1]],
        proof_receipts: vec![(hash(1), vec![2])],
        stf_info: Some(vec![3]),
        ..slot_with_data(1)
    });
    let reader = ledger.reader();
    let (one, slot) = reader.head().unwrap().unwrap();
    value_round_trip::<SlotByNumber, _>(&slot);
    value_round_trip::<BatchByNumber, _>(&reader.batch(slot.batches.start).unwrap().unwrap());
    value_round_trip::<TxByNumber, _>(&reader.tx(slot.txs.start).unwrap().unwrap());
    value_round_trip::<EventByNumber, _>(&reader.event(slot.events.start).unwrap().unwrap());
    value_round_trip::<DiscardedBlobByNumber, _>(
        &reader
            .discarded_blob(slot.discarded_blobs.start)
            .unwrap()
            .unwrap(),
    );
    value_round_trip::<SlotByHash, _>(&one);
    value_round_trip::<ProofReceiptBySlot, _>(&(hash(1), vec![2]));
    value_round_trip::<EventCountByKey, _>(&7u64);

    key_round_trip::<SlotByNumber, _>(&one);
    key_round_trip::<SlotByHash, _>(&hash(1));
    key_round_trip::<BatchByNumber, _>(&BatchNumber::new(3));
    key_round_trip::<BatchByHash, _>(&(hash(1), BatchNumber::new(3)));
    key_round_trip::<TxByNumber, _>(&TxNumber::new(3));
    key_round_trip::<TxByHash, _>(&(hash(1), TxNumber::new(3)));
    key_round_trip::<EventByNumber, _>(&EventNumber::new(3));
    key_round_trip::<EventByKey, _>(&(key_of("k"), TxNumber::new(1), EventNumber::new(2)));
    key_round_trip::<DiscardedBlobByNumber, _>(&DiscardedBlobNumber::new(3));
    key_round_trip::<DiscardedBlobByHash, _>(&(hash(1), DiscardedBlobNumber::new(3)));
    key_round_trip::<AggregatedProofBySlot, _>(&(one, 2u32));
    key_round_trip::<ProofReceiptBySlot, _>(&(one, 2u32));
    key_round_trip::<ProofReceiptByHash, _>(&(hash(1), one, 2u32));
    key_round_trip::<StfInfoBySlot, _>(&one);

    // An index row's value is empty: anything else is corruption.
    fn index_value<S: Schema>() {
        S::Value::decode_value(&[]).unwrap();
        let err = S::Value::decode_value(&[0]).unwrap_err();
        assert!(
            format!("{err:#}").contains("an index row must be empty, got 1 bytes"),
            "{}: {err:#}",
            S::COLUMN_FAMILY_NAME
        );
    }
    index_value::<BatchByHash>();
    index_value::<TxByHash>();
    index_value::<EventByKey>();
    index_value::<DiscardedBlobByHash>();
    index_value::<ProofReceiptByHash>();

    // A stored slot, batch or transaction with an inverted range is corruption.
    fn inverted<S: Schema, V: ValueCodec<S>>(value: &V, what: &str) {
        let bytes = value.encode_value().unwrap();
        let err = V::decode_value(&bytes).unwrap_err();
        assert!(
            format!("{err:#}").contains(&format!("inverted {what} range")),
            "{}: {err:#}",
            S::COLUMN_FAMILY_NAME
        );
    }
    let mut stored = slot.clone();
    stored.txs = stored.txs.end..stored.txs.start;
    inverted::<SlotByNumber, _>(&stored, "transaction");
    let mut stored = reader.batch(slot.batches.start).unwrap().unwrap();
    assert!(!stored.txs.is_empty());
    stored.txs = stored.txs.end..stored.txs.start;
    inverted::<BatchByNumber, _>(&stored, "transaction");
    let mut stored = reader.tx(slot.txs.start).unwrap().unwrap();
    assert!(!stored.events.is_empty());
    stored.events = stored.events.end..stored.events.start;
    inverted::<TxByNumber, _>(&stored, "event");
}

/// L-B10: item numbers only add with a check: a slot whose items would need the number after
/// `u64::MAX` is an error (upstream's `Add` panicked; our release builds check overflows).
#[test]
fn item_number_overflow_is_error() {
    assert!(BatchNumber::new(u64::MAX).next().is_err());
    assert_eq!(TxNumber::new(u64::MAX).checked_add(1), None);
    assert_eq!(
        EventNumber::new(1).checked_add(2),
        Some(EventNumber::new(3))
    );
    let cases: [(&str, SlotContents); 4] = [
        ("batch number overflow", slot_with_keys(0, &[])),
        ("transaction number overflow", slot_with_keys(0, &[])),
        ("event number overflow", slot_with_keys(0, &["k"])),
        (
            "discarded blob number overflow",
            SlotContents {
                discarded_blobs: vec![DiscardedBlob {
                    hash: HexHash::new(hash(1)),
                    reason: BlobDiscardReason::OutOfCapacity,
                }],
                ..SlotContents::default()
            },
        ),
    ];
    for (index, (expected, contents)) in cases.into_iter().enumerate() {
        let ledger = TestLedger::new();
        let mut head = StoredSlot {
            da_hash: hash(1),
            da_height: 0,
            roots: roots(0),
            timestamp: info(0).timestamp,
            batches: BatchNumber::ZERO..BatchNumber::ZERO,
            txs: TxNumber::ZERO..TxNumber::ZERO,
            events: EventNumber::ZERO..EventNumber::ZERO,
            discarded_blobs: DiscardedBlobNumber::ZERO..DiscardedBlobNumber::ZERO,
        };
        // The newest slot's items end at `u64::MAX` (its last item, if any, was `u64::MAX - 1`):
        // the next item gets `u64::MAX`, and the end of its range would overflow.
        let last = u64::MAX;
        match index {
            0 => head.batches = BatchNumber::new(last)..BatchNumber::new(last),
            1 => head.txs = TxNumber::new(last)..TxNumber::new(last),
            2 => head.events = EventNumber::new(last)..EventNumber::new(last),
            _ => {
                head.discarded_blobs =
                    DiscardedBlobNumber::new(last)..DiscardedBlobNumber::new(last);
            }
        }
        ledger
            .db
            .put::<SlotByNumber>(&SlotNumber::GENESIS, &head)
            .unwrap();
        // A slot without items still fits.
        ledger.materialize(SlotContents::default()).unwrap();
        let err = ledger.materialize(contents).unwrap_err();
        assert!(err.to_string().contains(expected), "{expected}: {err}");
    }
}

/// An event key longer than [`MAX_EVENT_KEY_LEN`] is refused when materializing and by the key
/// encoders and decoders (the `u16` length prefix of `event_by_key` stays exact).
#[test]
fn event_key_too_long_is_error() {
    use rockbound::schema::{KeyDecoder, KeyEncoder};

    let ledger = TestLedger::new();
    let longest = "k".repeat(MAX_EVENT_KEY_LEN);
    let too_long = "k".repeat(MAX_EVENT_KEY_LEN + 1);
    let err = ledger
        .materialize(slot_with_keys(0, &[&too_long]))
        .unwrap_err();
    assert!(err.to_string().contains("more than 256"), "{err}");
    ledger.commit(slot_with_keys(0, &[&longest]));
    assert_eq!(
        ledger.reader().event_key_count(&key_of(&longest)).unwrap(),
        1
    );

    let key = key_of(&too_long);
    assert!(<_ as KeyEncoder<EventCountByKey>>::encode_key(&key).is_err());
    assert!(
        <_ as KeyEncoder<EventByKey>>::encode_key(&(key, TxNumber::ZERO, EventNumber::ZERO))
            .is_err()
    );
    assert!(<EventKey as KeyDecoder<EventCountByKey>>::decode_key(too_long.as_bytes()).is_err());
    let mut encoded = 257u16.to_be_bytes().to_vec();
    encoded.extend_from_slice(too_long.as_bytes());
    encoded.extend_from_slice(&[0; 16]);
    assert!(
        <(EventKey, TxNumber, EventNumber) as KeyDecoder<EventByKey>>::decode_key(&encoded)
            .is_err()
    );
}

/// An event must carry its transaction's hash (the ledger stores it per event).
#[test]
fn event_must_carry_its_transaction_hash() {
    let ledger = TestLedger::new();
    let mut contents = slot_with_keys(0, &["k"]);
    contents.batches[0].txs[0].events[0] = event("k", hash(0xEE));
    let err = ledger.materialize(contents).unwrap_err();
    assert!(err.to_string().contains("not its transaction's"), "{err}");
}

/// A DA block can be a slot of a chain only once (critique 25): a second one would replace the
/// older slot's `slot_by_hash` row, and rolling the newer back would delete it. Checked when
/// materializing (through the snapshots) and again when committing (the committed DB).
#[test]
fn materialize_slot_rejects_duplicate_da_hash() {
    let ledger = TestLedger::new();
    ledger.commit(SlotContents::default());
    let reader = ledger.reader();
    let one = SlotNumber::new(1);
    let err = reader
        .materialize_slot(one, roots(1), info(0), SlotContents::default())
        .unwrap_err();
    assert!(err.to_string().contains("is already slot 0"), "{err}");

    let mut change_set = reader
        .materialize_slot(one, roots(1), info(1), SlotContents::default())
        .unwrap();
    // The DA block of an uncommitted slot (a snapshot), and of a committed one below it.
    let two = SlotNumber::new(2);
    let on_top = LedgerReader::new(ledger.db.clone(), vec![change_set.batch.clone()]);
    for (da_block, slot) in [(1, "1"), (0, "0")] {
        let err = on_top
            .materialize_slot(two, roots(2), info(da_block), SlotContents::default())
            .unwrap_err();
        assert!(
            err.to_string().contains(&format!("is already slot {slot}")),
            "{err}"
        );
    }
    on_top
        .materialize_slot(two, roots(2), info(2), SlotContents::default())
        .unwrap();

    check_builds_on_head(&ledger.db, &change_set).unwrap();
    change_set.slot.da_hash = info(0).da_hash;
    let err = check_builds_on_head(&ledger.db, &change_set).unwrap_err();
    assert!(err.to_string().contains("already slot 0"), "{err}");
}

/// [`LedgerReader::committed_head`] reads the committed DB alone (critique 25: the finalized
/// slot, apart from the snapshots); [`LedgerReader::head`] reads through them.
#[test]
fn committed_head_ignores_snapshots() {
    let ledger = TestLedger::new();
    assert_eq!(ledger.reader().committed_head().unwrap(), None);
    ledger.commit(SlotContents::default());
    let next = ledger.materialize(SlotContents::default()).unwrap();
    let reader = LedgerReader::new(ledger.db.clone(), vec![next.batch.clone()]);
    assert_eq!(reader.head().unwrap().unwrap().0, SlotNumber::new(1));
    assert_eq!(
        reader.committed_head().unwrap().unwrap().0,
        SlotNumber::GENESIS
    );
    assert_eq!(reader.next_slot().unwrap(), SlotNumber::new(2));
}

/// Everything a reader can read about slots `0..=last` (and the event keys `keys`).
fn view(reader: &LedgerReader, last: u64, keys: &[&str]) -> Vec<String> {
    let mut out = vec![
        format!("{:?}", reader.head().unwrap()),
        format!("{:?}", reader.latest_aggregated_proof().unwrap()),
        format!("{:?}", reader.oldest_stf_info_slot().unwrap()),
    ];
    for key in keys {
        let key = key_of(key);
        out.push(format!(
            "{key:?}: {} {:?}",
            reader.event_key_count(&key).unwrap(),
            reader.event_numbers_by_key(&key).unwrap()
        ));
    }
    for n in 0..=last {
        let number = SlotNumber::new(n);
        let slot = reader.slot(number).unwrap();
        out.push(format!("slot {n}: {slot:?}"));
        let receipts = reader.proof_receipts(number).unwrap();
        out.push(format!(
            "{:?} {:?} {receipts:?} {:?}",
            reader.slot_by_hash(&info(n).da_hash).unwrap(),
            reader.aggregated_proofs(number).unwrap(),
            reader.stf_info(number).unwrap()
        ));
        for (hash, _) in &receipts {
            out.push(format!(
                "receipts of {}: {:?}",
                HexString(*hash),
                reader.proof_receipts_by_hash(hash).unwrap()
            ));
        }
        let Some(slot) = slot else { continue };
        for b in slot.batches.start.get()..slot.batches.end.get() {
            let batch = reader.batch(BatchNumber::new(b)).unwrap().unwrap();
            out.push(format!(
                "{batch:?} {:?}",
                reader.batch_numbers_by_hash(&batch.hash).unwrap()
            ));
        }
        for t in slot.txs.start.get()..slot.txs.end.get() {
            let tx = reader.tx(TxNumber::new(t)).unwrap().unwrap();
            out.push(format!(
                "{tx:?} {:?}",
                reader.tx_numbers_by_hash(&tx.hash).unwrap()
            ));
        }
        for e in slot.events.start.get()..slot.events.end.get() {
            out.push(format!("{:?}", reader.event(EventNumber::new(e)).unwrap()));
        }
        for d in slot.discarded_blobs.start.get()..slot.discarded_blobs.end.get() {
            let blob = reader
                .discarded_blob(DiscardedBlobNumber::new(d))
                .unwrap()
                .unwrap();
            out.push(format!(
                "{blob:?} {:?}",
                reader
                    .discarded_blob_numbers_by_hash(&blob.blob.hash.0)
                    .unwrap()
            ));
        }
    }
    out
}

/// Slots read the same through uncommitted snapshots as once committed (the storage manager
/// keeps executed slots as snapshots until they are finalized): numbering, event counts, hash
/// indexes, proofs and STF info, with an STF-info prune (point deletes) included. A slot's
/// writes have no range deletes, which a snapshot reader would not see.
#[test]
fn uncommitted_slots_read_like_committed() {
    let mut dirs = tempdirs(2);
    let committed = TestLedger::new_in(dirs.pop().unwrap());
    let ledger = TestLedger::new_in(dirs.pop().unwrap());
    let keys = ["e1", "e2", "e3"];
    let contents = [
        SlotContents {
            stf_info: Some(vec![0]),
            ..crate::test_utils::blocks::slot_contents(10, &["e1", "e2"])
        },
        // The same hashes again, and a prune of slot 1's STF info.
        SlotContents {
            stf_info_prune_below: Some(SlotNumber::new(2)),
            ..crate::test_utils::blocks::slot_contents(10, &["e1", "e3"])
        },
        crate::test_utils::blocks::slot_contents(12, &["e1"]),
    ];
    ledger.commit(SlotContents::default());
    let mut snapshots = Vec::new();
    for contents in &contents {
        let reader = LedgerReader::new(ledger.db.clone(), snapshots.clone());
        let next = reader.next_slot().unwrap();
        let change_set = reader
            .materialize_slot(next, roots(next.get()), info(next.get()), contents.clone())
            .unwrap();
        snapshots.push(change_set.batch.clone());
    }
    let reader = LedgerReader::new(ledger.db.clone(), snapshots);
    assert_eq!(
        reader.oldest_stf_info_slot().unwrap(),
        Some(SlotNumber::new(2))
    );
    assert_eq!(
        reader.stf_info(SlotNumber::new(2)).unwrap(),
        Some(vec![10, 0x5F])
    );
    assert_eq!(reader.event_key_count(&key_of("e1")).unwrap(), 3);
    let uncommitted = view(&reader, 3, &keys);

    committed.commit(SlotContents::default());
    for contents in contents {
        committed.commit(contents);
    }
    // The pruning slot deleted slot 1's STF info.
    assert_eq!(
        committed.reader().stf_info(SlotNumber::new(1)).unwrap(),
        None
    );
    assert_eq!(uncommitted, view(&committed.reader(), 3, &keys));
}

/// Critique 24: a slot can prune the STF info below a slot (point deletes, at most
/// [`STF_INFO_PRUNE_BUDGET`] rows per slot, oldest first); the next pruning slot goes on from
/// [`LedgerReader::oldest_stf_info_slot`]. Pruning only earlier slots, and not undone by a
/// rollback.
#[test]
fn stf_info_prune_below_deletes_old_rows_within_budget() {
    let ledger = TestLedger::new();
    // Slots 0..=299 with STF info, written at once.
    let total = 300u64;
    let mut batch = SchemaBatch::new();
    for n in 0..total {
        batch
            .put::<StfInfoBySlot>(&SlotNumber::new(n), &vec![1])
            .unwrap();
    }
    ledger.db.write_schemas(&batch).unwrap();
    for _ in 0..total {
        ledger.commit(SlotContents::default());
    }
    let reader = ledger.reader();
    let slot = reader.next_slot().unwrap();
    let err = reader
        .materialize_slot(
            slot,
            roots(0),
            info(slot.get()),
            SlotContents {
                stf_info_prune_below: Some(slot.checked_add(1).unwrap()),
                ..SlotContents::default()
            },
        )
        .unwrap_err();
    assert!(err.to_string().contains("only earlier slots"), "{err}");

    let prune = |below: u64| SlotContents {
        stf_info: Some(vec![2]),
        stf_info_prune_below: Some(SlotNumber::new(below)),
        ..SlotContents::default()
    };
    let before = ledger.dump();
    let pruning = ledger.commit(prune(total));
    let budget = u64::try_from(STF_INFO_PRUNE_BUDGET).unwrap();
    let reader = ledger.reader();
    assert_eq!(
        reader.oldest_stf_info_slot().unwrap(),
        Some(SlotNumber::new(budget))
    );
    // The rows left, and the pruning slot's own.
    let left = usize::try_from(total - budget).unwrap();
    assert_eq!(ledger.rows::<StfInfoBySlot>(), left + 1);

    // A rollback of the pruning slot removes its own STF info, not the rows it pruned.
    assert_eq!(ledger.rollback(), Some(pruning));
    assert_eq!(ledger.rows::<StfInfoBySlot>(), left);
    assert!(ledger.dump() != before);

    // The next pruning slots finish the job (the pruning slot's own row is not below).
    let pruning = ledger.commit(prune(total));
    assert_eq!(
        ledger.reader().oldest_stf_info_slot().unwrap(),
        Some(pruning)
    );
    assert_eq!(ledger.reader().stf_info(pruning).unwrap(), Some(vec![2]));
    assert_eq!(ledger.rows::<StfInfoBySlot>(), 1);
}

/// The oldest STF info's slot, and the STF info of slots `slots` (`None`: no row).
fn stf_infos(
    reader: &LedgerReader,
    slots: core::ops::RangeInclusive<u64>,
) -> (Option<SlotNumber>, Vec<Option<Vec<u8>>>) {
    let rows = slots
        .map(|n| reader.stf_info(SlotNumber::new(n)).unwrap())
        .collect();
    (reader.oldest_stf_info_slot().unwrap(), rows)
}

/// A slot pruning the STF info below `below` deletes only the rows before `below`: the rows
/// from `below` on stay (the prover still needs them), committed or through snapshots (the
/// rows to prune both committed and uncommitted). The pruning does not read the rows it keeps:
/// a corrupt key after `below` (it does not decode) leaves it unaffected.
#[test]
fn stf_info_prune_below_keeps_the_rows_from_below_on() {
    let mut dirs = tempdirs(2);
    let committed = TestLedger::new_in(dirs.pop().unwrap());
    let ledger = TestLedger::new_in(dirs.pop().unwrap());
    let with_stf_info = |n: u8| SlotContents {
        stf_info: Some(vec![n]),
        ..SlotContents::default()
    };
    let prune = |below: u64, n: u8| SlotContents {
        stf_info_prune_below: Some(SlotNumber::new(below)),
        ..with_stf_info(n)
    };
    // Slots 0..=9 with STF info, then slot 10 prunes below 5: slots 5..=10 are left.
    let expected = (
        Some(SlotNumber::new(5)),
        (0..=10u8)
            .map(|n| (n >= 5).then(|| vec![n]))
            .collect::<Vec<_>>(),
    );

    for n in 0..10 {
        committed.commit(with_stf_info(n));
    }
    committed.commit(prune(5, 10));
    assert_eq!(stf_infos(&committed.reader(), 0..=10), expected);
    assert_eq!(committed.rows::<StfInfoBySlot>(), 6);

    // Slots 0..=2 committed, 3..=10 snapshots.
    for n in 0..3 {
        ledger.commit(with_stf_info(n));
    }
    let mut snapshots = Vec::new();
    for contents in (3..10).map(with_stf_info).chain([prune(5, 10)]) {
        let reader = LedgerReader::new(ledger.db.clone(), snapshots.clone());
        let next = reader.next_slot().unwrap();
        let change_set = reader
            .materialize_slot(next, roots(next.get()), info(next.get()), contents)
            .unwrap();
        snapshots.push(change_set.batch.clone());
    }
    let reader = LedgerReader::new(ledger.db.clone(), snapshots);
    assert_eq!(stf_infos(&reader, 0..=10), expected);

    // A row the pruning keeps is not read: a key after slot 7's that does not decode (9
    // bytes) is left alone by a prune below 7. (Not counted with `rows`: a schema iterator
    // yields the decode error again and again.)
    let mut corrupt = SchemaBatch::new();
    let mut key = 7u64.to_be_bytes().to_vec();
    key.push(0);
    corrupt.put_raw::<StfInfoBySlot>(key, vec![0xC0]).unwrap();
    committed.db.write_schemas(&corrupt).unwrap();
    assert_eq!(committed.commit(prune(7, 11)), SlotNumber::new(11));
    assert_eq!(
        stf_infos(&committed.reader(), 0..=11),
        (
            Some(SlotNumber::new(7)),
            (0..=11u8)
                .map(|n| (n >= 7).then(|| vec![n]))
                .collect::<Vec<_>>(),
        )
    );
}

/// A rollback checks every row of the slot first: a missing one is an `Err`, and nothing is
/// written.
#[test]
fn rollback_of_a_corrupt_slot_is_error_and_writes_nothing() {
    let ledger = TestLedger::new();
    ledger.commit(slot_with_data(0));
    ledger.db.delete::<TxByNumber>(&TxNumber::new(4)).unwrap();
    let before = ledger.dump();
    let err = rollback_head(&ledger.db).unwrap_err();
    assert!(
        format!("{err:#}").contains("cannot roll back slot 0: transaction 4 is missing"),
        "{err:#}"
    );
    assert!(ledger.dump() == before);
    let err = rollback_version(&ledger.db, SlotNumber::new(1)).unwrap_err();
    assert!(
        err.to_string().contains("its newest slot is Some(0)"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------------------------
// The ledger in the state databases.

/// After every commit of the state databases, the ledger's newest slot (committed head
/// included) is the committed version with the committed roots.
#[test]
fn ledger_head_matches_state_after_every_commit() {
    let mut dbs = TestDbs::<StateStorageSpec>::new();
    assert_eq!(dbs.ledger().head().unwrap(), None);
    for value in 1..=3u32 {
        let root = dbs.commit_with(WitnessMode::Off, |state| {
            let Ok(()) = map().set(&1, &value, state);
        });
        let ledger = dbs.ledger();
        let version = dbs.group().latest_version().unwrap().unwrap();
        for (number, slot) in [
            ledger.head().unwrap().unwrap(),
            ledger.committed_head().unwrap().unwrap(),
        ] {
            assert_eq!(number, version);
            assert_eq!(slot.roots, NomtRoots::from(root));
            assert_eq!(slot.da_hash, test_slot_info(version).da_hash);
        }
    }
    let dbs = dbs.reopen();
    assert_eq!(dbs.ledger().head().unwrap().unwrap().0, SlotNumber::new(2));
}

/// A ledger slot that does not continue the committed ledger is refused by
/// [`DbGroup::commit`] before anything is written: items numbered from a slot that is not the
/// committed one (here: an uncommitted fork's slot 0), or a DA block that is already a slot.
#[test]
fn commit_rejects_ledger_slots_not_on_the_committed_ledger() {
    let tempdir = tempdir();
    let mut group =
        DbGroup::<sha2::Sha256>::open(&StateDbConfig::for_tests(tempdir.path())).unwrap();
    let ledger_db = group.ledger_db().clone();
    let write = || vec![(key(b"k1"), value(b"v"))];
    let genesis = change_set(&group, 0, write(), vec![], vec![]);
    let genesis_slot = group
        .ledger_reader()
        .unwrap()
        .materialize_slot(
            SlotNumber::GENESIS,
            genesis.roots(),
            info(0),
            SlotContents::default(),
        )
        .unwrap();
    // Another slot 0 with a batch, uncommitted.
    let fork_slot = group
        .ledger_reader()
        .unwrap()
        .materialize_slot(
            SlotNumber::GENESIS,
            genesis.roots(),
            SlotInfo {
                da_hash: hash(0xF0),
                ..info(0)
            },
            slot_with_keys(1, &[]),
        )
        .unwrap();
    group.commit(genesis, genesis_slot).unwrap();

    let state = change_set(&group, 1, write(), vec![(key(b"k2"), value(b"w"))], vec![]);
    let on_fork = LedgerReader::new(ledger_db.clone(), vec![fork_slot.batch.clone()])
        .materialize_slot(
            SlotNumber::new(1),
            state.roots(),
            info(1),
            SlotContents::default(),
        )
        .unwrap();
    let err = group.commit(state, on_fork).unwrap_err();
    assert!(
        format!("{err:#}").contains("was not built on the committed ledger"),
        "{err:#}"
    );

    let state = change_set(&group, 1, write(), vec![(key(b"k2"), value(b"w"))], vec![]);
    let mut duplicate = group
        .ledger_reader()
        .unwrap()
        .materialize_slot(
            SlotNumber::new(1),
            state.roots(),
            info(1),
            SlotContents::default(),
        )
        .unwrap();
    duplicate.slot.da_hash = info(0).da_hash;
    let err = group.commit(state, duplicate).unwrap_err();
    assert!(format!("{err:#}").contains("already slot 0"), "{err:#}");

    assert!(!group.is_poisoned());
    assert_eq!(
        latest_version_and_root(&ledger_db).unwrap().unwrap().0,
        SlotNumber::GENESIS
    );
    let state = change_set(&group, 1, write(), vec![(key(b"k2"), value(b"w"))], vec![]);
    let slot = crate::harness::empty_slot(
        &group.ledger_reader().unwrap(),
        SlotNumber::new(1),
        state.roots(),
    );
    group.commit(state, slot).unwrap();
}

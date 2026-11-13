//! The ledger DB: the chain's history for the node and its APIs (slots, batches, transactions,
//! events, discarded blobs, aggregated proofs, proof receipts, STF info), one RocksDB instance
//! (`ledger/`) committed with the state databases ([`DbGroup::commit`](crate::DbGroup::commit)).
//!
//! - [`LedgerReader`] reads it (the committed DB plus uncommitted snapshots) and builds a slot's
//!   writes ([`LedgerReader::materialize_slot`] → [`LedgerChangeSet`]).
//! - Every commit of the state databases writes exactly one slot, numbered like the state
//!   version, and the slot records the state roots: the ledger's newest slot is its version
//!   marker, checked against the other databases when they are opened and rolled back by
//!   startup crash recovery like them (`rollback_version`).
//!
//! Numbers are checked, never wrapped: item numbers ([`BatchNumber`] and the others) come from
//! the newest slot's ranges and are `< u64::MAX` (a range's end is the next number), and slot
//! numbers are `< u64::MAX` (the slot after must exist), so every range of keys has an
//! exclusive end.
//!
//! What a slot writes holds only point writes and deletes (no range deletes): a snapshot reader
//! ([`DeltaReader`]) cannot see a range delete, so a slot not yet committed reads the same
//! through snapshots as once committed. Rollbacks use range deletes: they are written straight
//! to the DB, never kept as a snapshot.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::Arc;

use anyhow::Context;
use rockbound::cache::delta_reader::DeltaReader;
use rockbound::{DB, SchemaBatch};
use selendra_interface::common::{HexString, SlotNumber};
use selendra_interface::stf::{EventKey, StoredEvent};

use crate::accessory::DbOptions;
use crate::historical::next_version_after;
use crate::nomt_state::NomtRoots;
use crate::recovery::Head;
use crate::schema::{
    AggregatedProofBySlot, BatchByHash, BatchByNumber, DiscardedBlobByHash, DiscardedBlobByNumber,
    EventByKey, EventByNumber, EventCountByKey, LEDGER_TABLES, MAX_EVENT_KEY_LEN,
    ProofReceiptByHash, ProofReceiptBySlot, SlotByHash, SlotByNumber, StfInfoBySlot, TxByHash,
    TxByNumber,
};

mod types;

#[cfg(test)]
mod tests;

pub use types::{
    BatchContents, BatchNumber, DiscardedBlobNumber, EventNumber, SlotContents, SlotInfo,
    StoredBatch, StoredDiscardedBlob, StoredSlot, StoredTransaction, TxContents, TxNumber,
};

/// The ledger DB's directory under [`StateDbConfig::path`](crate::StateDbConfig::path).
pub(crate) const DB_PATH_SUFFIX: &str = "ledger";
const DB_NAME: &str = "ledger-db";

/// At most this many STF-info rows are deleted by one slot's
/// [`stf_info_prune_below`](SlotContents::stf_info_prune_below); the rest by later slots.
///
/// It bounds the reads too: the pruning reads the keys of the rows it deletes and nothing else
/// (no value, each a prover witness of MBs, and no row it keeps).
pub const STF_INFO_PRUNE_BUDGET: usize = 256;

/// The options to open the ledger DB with.
pub fn options() -> DbOptions {
    DbOptions {
        name: DB_NAME,
        path_suffix: DB_PATH_SUFFIX,
        columns: LEDGER_TABLES
            .iter()
            .map(|cf| rockbound::default_cf_descriptor(*cf))
            .collect(),
    }
}

/// One slot's writes to the ledger DB, for the state version it is committed with
/// ([`DbGroup::commit`](crate::DbGroup::commit)). Only built by
/// [`LedgerReader::materialize_slot`].
#[derive(Clone)]
pub struct LedgerChangeSet {
    slot_number: SlotNumber,
    slot: StoredSlot,
    batch: Arc<SchemaBatch>,
}

impl core::fmt::Debug for LedgerChangeSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LedgerChangeSet")
            .field("slot_number", &self.slot_number)
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

impl LedgerChangeSet {
    /// The slot number, which is the state version these writes are committed with.
    pub fn version(&self) -> SlotNumber {
        self.slot_number
    }

    /// The state roots after the slot.
    pub fn roots(&self) -> NomtRoots {
        self.slot.roots
    }

    /// The slot as it is stored.
    pub fn slot(&self) -> &StoredSlot {
        &self.slot
    }

    /// The slot's writes (kept as a snapshot until committed).
    pub(crate) fn batch(&self) -> &Arc<SchemaBatch> {
        &self.batch
    }
}

/// The first number of each kind of item of the slot after `head` (zeros on an empty ledger).
fn next_numbers(
    head: Option<&StoredSlot>,
) -> (BatchNumber, TxNumber, EventNumber, DiscardedBlobNumber) {
    head.map_or(
        (
            BatchNumber::ZERO,
            TxNumber::ZERO,
            EventNumber::ZERO,
            DiscardedBlobNumber::ZERO,
        ),
        |slot| {
            (
                slot.batches.end,
                slot.txs.end,
                slot.events.end,
                slot.discarded_blobs.end,
            )
        },
    )
}

/// Reads the ledger DB plus uncommitted snapshots (slots executed but not committed, oldest
/// first): a read sees the newest write of a key in the snapshots, else the committed DB.
///
/// Reads of the committed DB alone ([`committed_head`](Self::committed_head)) ignore the
/// snapshots. A commit in progress is visible to a reader from the ledger write on (before
/// the state's flat live DB says the version is committed).
#[derive(Clone)]
pub struct LedgerReader {
    db: Arc<DB>,
    reader: DeltaReader,
}

impl core::fmt::Debug for LedgerReader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LedgerReader").finish_non_exhaustive()
    }
}

impl LedgerReader {
    /// A reader of `db` with `snapshots` (each slot's [`LedgerChangeSet`] batch, oldest first)
    /// on top.
    pub(crate) fn new(db: Arc<DB>, snapshots: Vec<Arc<SchemaBatch>>) -> Self {
        let reader = DeltaReader::new(db.clone(), snapshots);
        Self { db, reader }
    }

    /// The newest slot (through the snapshots), `None` if the ledger is empty.
    pub fn head(&self) -> anyhow::Result<Option<(SlotNumber, StoredSlot)>> {
        self.reader.get_largest::<SlotByNumber>()
    }

    /// The newest committed slot: the ledger DB alone, ignoring the snapshots (the finalized
    /// slot, once the storage manager commits only finalized slots).
    pub fn committed_head(&self) -> anyhow::Result<Option<(SlotNumber, StoredSlot)>> {
        DeltaReader::new(self.db.clone(), Vec::new()).get_largest::<SlotByNumber>()
    }

    /// The number of the next slot: the one after [`head`](Self::head), genesis if the ledger
    /// is empty.
    pub fn next_slot(&self) -> anyhow::Result<SlotNumber> {
        next_version_after(self.head()?.map(|(number, _)| number))
    }

    /// Slot `n`.
    pub fn slot(&self, n: SlotNumber) -> anyhow::Result<Option<StoredSlot>> {
        self.reader.get::<SlotByNumber>(&n)
    }

    /// The slot of the DA block with hash `hash`.
    pub fn slot_by_hash(&self, hash: &[u8; 32]) -> anyhow::Result<Option<SlotNumber>> {
        self.reader.get::<SlotByHash>(hash)
    }

    /// Batch `n`.
    pub fn batch(&self, n: BatchNumber) -> anyhow::Result<Option<StoredBatch>> {
        self.reader.get::<BatchByNumber>(&n)
    }

    /// The numbers of the batches with hash `hash`, in order.
    pub fn batch_numbers_by_hash(&self, hash: &[u8; 32]) -> anyhow::Result<Vec<BatchNumber>> {
        Ok(self
            .reader
            .collect_in_range::<BatchByHash, _>(
                (*hash, BatchNumber::ZERO)..(*hash, BatchNumber::new(u64::MAX)),
            )?
            .into_iter()
            .map(|((_, number), ())| number)
            .collect())
    }

    /// Transaction `n`.
    pub fn tx(&self, n: TxNumber) -> anyhow::Result<Option<StoredTransaction>> {
        self.reader.get::<TxByNumber>(&n)
    }

    /// The numbers of the transactions with hash `hash`, in order.
    pub fn tx_numbers_by_hash(&self, hash: &[u8; 32]) -> anyhow::Result<Vec<TxNumber>> {
        Ok(self
            .reader
            .collect_in_range::<TxByHash, _>(
                (*hash, TxNumber::ZERO)..(*hash, TxNumber::new(u64::MAX)),
            )?
            .into_iter()
            .map(|((_, number), ())| number)
            .collect())
    }

    /// Event `n`.
    pub fn event(&self, n: EventNumber) -> anyhow::Result<Option<StoredEvent>> {
        self.reader.get::<EventByNumber>(&n)
    }

    /// The `(transaction, event)` numbers of the events with key `key`, in order.
    ///
    /// # Errors
    /// If `key` is longer than [`MAX_EVENT_KEY_LEN`], or on read errors.
    pub fn event_numbers_by_key(
        &self,
        key: &EventKey,
    ) -> anyhow::Result<Vec<(TxNumber, EventNumber)>> {
        Ok(self
            .reader
            .collect_in_range::<EventByKey, _>(
                (key.clone(), TxNumber::ZERO, EventNumber::ZERO)
                    ..(key.clone(), TxNumber::new(u64::MAX), EventNumber::ZERO),
            )?
            .into_iter()
            .map(|((_, tx, event), ())| (tx, event))
            .collect())
    }

    /// How many events with key `key` the ledger holds (0 if none).
    ///
    /// # Errors
    /// On read or decode errors (upstream read those as 0, so a slot materialized after a
    /// failed read reset the count).
    pub fn event_key_count(&self, key: &EventKey) -> anyhow::Result<u64> {
        Ok(self.reader.get::<EventCountByKey>(key)?.unwrap_or(0))
    }

    /// Discarded blob `n`.
    pub fn discarded_blob(
        &self,
        n: DiscardedBlobNumber,
    ) -> anyhow::Result<Option<StoredDiscardedBlob>> {
        self.reader.get::<DiscardedBlobByNumber>(&n)
    }

    /// The numbers of the discarded blobs with hash `hash`, in order.
    pub fn discarded_blob_numbers_by_hash(
        &self,
        hash: &[u8; 32],
    ) -> anyhow::Result<Vec<DiscardedBlobNumber>> {
        Ok(self
            .reader
            .collect_in_range::<DiscardedBlobByHash, _>(
                (*hash, DiscardedBlobNumber::ZERO)..(*hash, DiscardedBlobNumber::new(u64::MAX)),
            )?
            .into_iter()
            .map(|((_, number), ())| number)
            .collect())
    }

    /// The aggregated proofs accepted in slot `slot`, in order.
    pub fn aggregated_proofs(&self, slot: SlotNumber) -> anyhow::Result<Vec<Vec<u8>>> {
        Ok(self
            .reader
            .collect_in_range::<AggregatedProofBySlot, _>(slot_rows(slot)?)?
            .into_iter()
            .map(|(_, proof)| proof)
            .collect())
    }

    /// The newest aggregated proof (the last one of the newest slot that has one) and its slot.
    pub fn latest_aggregated_proof(&self) -> anyhow::Result<Option<(SlotNumber, Vec<u8>)>> {
        Ok(self
            .reader
            .get_largest::<AggregatedProofBySlot>()?
            .map(|((slot, _), proof)| (slot, proof)))
    }

    /// The proof receipts of slot `slot`, in order: the proof blob's hash and the receipt.
    pub fn proof_receipts(&self, slot: SlotNumber) -> anyhow::Result<Vec<([u8; 32], Vec<u8>)>> {
        Ok(self
            .reader
            .collect_in_range::<ProofReceiptBySlot, _>(slot_rows(slot)?)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect())
    }

    /// Where the proof receipts of the proof blob with hash `hash` are: `(slot, index)`, in
    /// order.
    pub fn proof_receipts_by_hash(
        &self,
        hash: &[u8; 32],
    ) -> anyhow::Result<Vec<(SlotNumber, u32)>> {
        Ok(self
            .reader
            .collect_in_range::<ProofReceiptByHash, _>(
                (*hash, SlotNumber::GENESIS, 0)..(*hash, SlotNumber::MAX, 0),
            )?
            .into_iter()
            .map(|((_, slot, index), ())| (slot, index))
            .collect())
    }

    /// The STF info of slot `slot`.
    pub fn stf_info(&self, slot: SlotNumber) -> anyhow::Result<Option<Vec<u8>>> {
        self.reader.get::<StfInfoBySlot>(&slot)
    }

    /// The slot of the oldest STF info the ledger holds (what the next pruning starts from),
    /// read without the STF info itself ([`stf_info`](Self::stf_info) reads it).
    pub fn oldest_stf_info_slot(&self) -> anyhow::Result<Option<SlotNumber>> {
        // No slot `u64::MAX` can be materialized, so no row is at `SlotNumber::MAX`.
        Ok(self
            .reader
            .collect_keys_in_range::<StfInfoBySlot, _>(SlotNumber::GENESIS..SlotNumber::MAX, 1)?
            .pop())
    }

    /// Builds the writes of slot `slot` on top of this reader's newest slot: the DA block
    /// `info`, the state roots after the slot `roots`, and `contents`, whose items get the next
    /// numbers in order. Nothing is written.
    ///
    /// # Errors
    /// - If `slot` is not the next slot ([`next_slot`](Self::next_slot); upstream took the
    ///   number from the DB and only the runner's `assert_eq!` caught a mismatch), or is
    ///   `u64::MAX`.
    /// - If the DA block's hash is already a slot of this chain (a second row would replace the
    ///   older slot's index row, and a rollback of the newer slot would delete it).
    /// - If an event does not carry its transaction's hash, or its key is longer than
    ///   [`MAX_EVENT_KEY_LEN`].
    /// - If [`stf_info_prune_below`](SlotContents::stf_info_prune_below) is after `slot`.
    /// - On a number overflow, and on read errors (an event count that does not read is an
    ///   error: upstream counted it as 0).
    pub fn materialize_slot(
        &self,
        slot: SlotNumber,
        roots: NomtRoots,
        info: SlotInfo,
        contents: SlotContents,
    ) -> anyhow::Result<LedgerChangeSet> {
        let head = self.head()?;
        let next = next_version_after(head.as_ref().map(|(number, _)| *number))?;
        anyhow::ensure!(
            slot == next,
            "cannot materialize slot {slot}: the ledger's next slot is {next}"
        );
        anyhow::ensure!(
            slot.checked_add(1).is_some(),
            "cannot materialize slot {slot}: slot number overflow"
        );
        if let Some(existing) = self.slot_by_hash(&info.da_hash)? {
            anyhow::bail!(
                "cannot materialize slot {slot}: the DA block {} is already slot {existing}",
                HexString(info.da_hash)
            );
        }
        let SlotContents {
            batches,
            discarded_blobs,
            aggregated_proofs,
            proof_receipts,
            stf_info,
            stf_info_prune_below,
        } = contents;

        let mut batch = SchemaBatch::new();
        let (first_batch, first_tx, first_event, first_blob) =
            next_numbers(head.as_ref().map(|(_, slot)| slot));
        let (mut batch_number, mut tx_number, mut event_number, mut blob_number) =
            (first_batch, first_tx, first_event, first_blob);
        let mut event_counts: BTreeMap<EventKey, u64> = BTreeMap::new();
        for contents in batches {
            let batch_txs = tx_number;
            for tx in contents.txs {
                let tx_events = event_number;
                for event in tx.events {
                    anyhow::ensure!(
                        *event.tx_hash() == tx.hash,
                        "event {event_number} carries the transaction hash {}, not its \
                         transaction's {}",
                        HexString(*event.tx_hash()),
                        HexString(tx.hash)
                    );
                    let key = event.key();
                    anyhow::ensure!(
                        key.inner().len() <= MAX_EVENT_KEY_LEN,
                        "event {event_number}'s key is {} bytes, more than {MAX_EVENT_KEY_LEN}",
                        key.inner().len()
                    );
                    let count = match event_counts.entry(key.clone()) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) => entry.insert(
                            self.event_key_count(key)
                                .context("reading an event key's count")?,
                        ),
                    };
                    *count = count
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("event count overflow"))?;
                    batch.put::<EventByKey>(&(key.clone(), tx_number, event_number), &())?;
                    batch.put::<EventByNumber>(&event_number, &event)?;
                    event_number = event_number.next()?;
                }
                batch.put::<TxByHash>(&(tx.hash, tx_number), &())?;
                batch.put::<TxByNumber>(
                    &tx_number,
                    &StoredTransaction {
                        hash: tx.hash,
                        events: tx_events..event_number,
                        body: tx.body,
                        receipt: tx.receipt,
                        batch: batch_number,
                    },
                )?;
                tx_number = tx_number.next()?;
            }
            batch.put::<BatchByHash>(&(contents.hash, batch_number), &())?;
            batch.put::<BatchByNumber>(
                &batch_number,
                &StoredBatch {
                    hash: contents.hash,
                    txs: batch_txs..tx_number,
                    receipt: contents.receipt,
                    slot,
                },
            )?;
            batch_number = batch_number.next()?;
        }
        for (key, count) in &event_counts {
            batch.put::<EventCountByKey>(key, count)?;
        }
        for blob in discarded_blobs {
            batch.put::<DiscardedBlobByHash>(&(blob.hash.0, blob_number), &())?;
            batch
                .put::<DiscardedBlobByNumber>(&blob_number, &StoredDiscardedBlob { blob, slot })?;
            blob_number = blob_number.next()?;
        }
        for (index, proof) in aggregated_proofs.iter().enumerate() {
            batch.put::<AggregatedProofBySlot>(&(slot, slot_index(index)?), proof)?;
        }
        for (index, (hash, receipt)) in proof_receipts.into_iter().enumerate() {
            let index = slot_index(index)?;
            batch.put::<ProofReceiptByHash>(&(hash, slot, index), &())?;
            batch.put::<ProofReceiptBySlot>(&(slot, index), &(hash, receipt))?;
        }
        if let Some(stf_info) = &stf_info {
            batch.put::<StfInfoBySlot>(&slot, stf_info)?;
        }
        if let Some(below) = stf_info_prune_below {
            anyhow::ensure!(
                below <= slot,
                "cannot prune the STF info below slot {below} in slot {slot}: only earlier slots \
                 can be pruned"
            );
            // Keys only, and only below `below`: no value (a prover witness, MBs each) and no
            // row kept is read.
            for pruned in self.reader.collect_keys_in_range::<StfInfoBySlot, _>(
                SlotNumber::GENESIS..below,
                STF_INFO_PRUNE_BUDGET,
            )? {
                batch.delete::<StfInfoBySlot>(&pruned)?;
            }
        }

        let stored = StoredSlot {
            da_hash: info.da_hash,
            da_height: info.da_height,
            roots,
            timestamp: info.timestamp,
            batches: first_batch..batch_number,
            txs: first_tx..tx_number,
            events: first_event..event_number,
            discarded_blobs: first_blob..blob_number,
        };
        batch.put::<SlotByHash>(&stored.da_hash, &slot)?;
        batch.put::<SlotByNumber>(&slot, &stored)?;
        Ok(LedgerChangeSet {
            slot_number: slot,
            slot: stored,
            batch: Arc::new(batch),
        })
    }
}

/// The index of an item of a slot (`u32`).
fn slot_index(index: usize) -> anyhow::Result<u32> {
    u32::try_from(index).map_err(|_| anyhow::anyhow!("more than u32::MAX items in one slot"))
}

/// The keys `[(slot, 0), (slot + 1, 0))`: every row of `slot` in a `slot ‖ index` table.
fn slot_rows(slot: SlotNumber) -> anyhow::Result<core::ops::Range<(SlotNumber, u32)>> {
    let end = slot
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("slot number overflow"))?;
    Ok((slot, 0)..(end, 0))
}

/// The ledger's newest slot number and its roots (`None`: empty).
pub(crate) fn latest_version_and_root(db: &Arc<DB>) -> anyhow::Result<Head> {
    Ok(DeltaReader::new(db.clone(), Vec::new())
        .get_largest::<SlotByNumber>()?
        .map(|(number, slot)| (number, slot.roots)))
}

/// The roots of exactly slot `version` (`None` if the ledger has no such slot).
pub(crate) fn root_at(db: &DB, version: SlotNumber) -> anyhow::Result<Option<NomtRoots>> {
    Ok(db.get::<SlotByNumber>(&version)?.map(|slot| slot.roots))
}

/// Checks that `change_set` numbers its items from the next numbers after `parent` (the slot it
/// was built on; `None`: the empty ledger). `what` names the parent in the error.
pub(crate) fn check_numbered_after(
    parent: Option<&StoredSlot>,
    change_set: &LedgerChangeSet,
    what: &str,
) -> anyhow::Result<()> {
    let expected = next_numbers(parent);
    let slot = &change_set.slot;
    let first = (
        slot.batches.start,
        slot.txs.start,
        slot.events.start,
        slot.discarded_blobs.start,
    );
    anyhow::ensure!(
        first == expected,
        "the ledger change set of slot {} numbers its (batches, transactions, events, discarded \
         blobs) from {first:?}, but the next numbers after {what} are {expected:?}: it was not \
         built on {what}",
        change_set.slot_number
    );
    Ok(())
}

/// Checks, before anything of a commit is written, that `change_set` is the slot after the
/// ledger DB's newest one: its items numbered from the newest slot's ranges on, and its DA
/// block not already a slot.
pub(crate) fn check_builds_on_head(
    db: &Arc<DB>,
    change_set: &LedgerChangeSet,
) -> anyhow::Result<()> {
    let head = DeltaReader::new(db.clone(), Vec::new()).get_largest::<SlotByNumber>()?;
    check_numbered_after(
        head.as_ref().map(|(_, slot)| slot),
        change_set,
        "the committed ledger DB's newest slot",
    )?;
    let slot = &change_set.slot;
    if let Some(existing) = db.get::<SlotByHash>(&slot.da_hash)? {
        anyhow::bail!(
            "the ledger change set of slot {} is for the DA block {}, already slot {existing}",
            change_set.slot_number,
            HexString(slot.da_hash)
        );
    }
    Ok(())
}

/// Writes one slot (one synced RocksDB write batch).
pub(crate) fn commit(db: &DB, change_set: &LedgerChangeSet) -> anyhow::Result<()> {
    db.write_schemas(&change_set.batch)
}

/// Removes slot `version`, which must be the newest one, from the ledger DB (startup crash
/// recovery).
pub(crate) fn rollback_version(db: &Arc<DB>, version: SlotNumber) -> anyhow::Result<()> {
    let head = DeltaReader::new(db.clone(), Vec::new()).get_largest::<SlotByNumber>()?;
    let newest = head.as_ref().map(|(number, _)| *number);
    let Some((number, slot)) = head.filter(|(number, _)| *number == version) else {
        anyhow::bail!(
            "cannot roll back slot {version} of the ledger DB: its newest slot is {newest:?}"
        );
    };
    rollback_slot(db, number, &slot)
}

/// Removes the newest slot from the ledger DB, and returns its number; does nothing if the
/// ledger is empty (`None`).
#[cfg(test)]
pub(crate) fn rollback_head(db: &Arc<DB>) -> anyhow::Result<Option<SlotNumber>> {
    let head = DeltaReader::new(db.clone(), Vec::new()).get_largest::<SlotByNumber>()?;
    let Some((number, slot)) = head else {
        return Ok(None);
    };
    rollback_slot(db, number, &slot)?;
    Ok(Some(number))
}

/// Removes slot `number` (`slot`, the newest) in one synced write: everything it wrote, its
/// index rows and its STF info; the event counts are decremented (a count reaching 0 is
/// deleted). Every row is read and checked first: a slot whose rows are missing or belong to
/// another slot is an `Err`, with nothing written.
///
/// The write batch has range deletes: it is written straight to the DB, never kept as a
/// snapshot (a snapshot reader cannot see a range delete).
fn rollback_slot(db: &Arc<DB>, number: SlotNumber, slot: &StoredSlot) -> anyhow::Result<()> {
    let corrupt = |what: String| {
        anyhow::anyhow!("ledger DB corruption: cannot roll back slot {number}: {what}")
    };
    let mut batch = SchemaBatch::new();

    // Batches, then their transactions, then their events: each tiles its parent's range.
    let mut next_tx = slot.txs.start;
    for n in slot.batches.start.get()..slot.batches.end.get() {
        let n = BatchNumber::new(n);
        let stored = db
            .get::<BatchByNumber>(&n)?
            .ok_or_else(|| corrupt(format!("batch {n} is missing")))?;
        if stored.slot != number || stored.txs.start != next_tx {
            return Err(corrupt(format!(
                "batch {n} (slot {}, transactions {:?}) does not follow the slot's previous \
                 batch",
                stored.slot, stored.txs
            )));
        }
        next_tx = stored.txs.end;
        batch.delete::<BatchByHash>(&(stored.hash, n))?;
    }
    if next_tx != slot.txs.end {
        return Err(corrupt(format!(
            "its batches hold the transactions up to {next_tx}, the slot's end at {}",
            slot.txs.end
        )));
    }

    let mut next_event = slot.events.start;
    let mut deleted_events: BTreeMap<EventKey, u64> = BTreeMap::new();
    for n in slot.txs.start.get()..slot.txs.end.get() {
        let n = TxNumber::new(n);
        let tx = db
            .get::<TxByNumber>(&n)?
            .ok_or_else(|| corrupt(format!("transaction {n} is missing")))?;
        if !slot.batches.contains(&tx.batch) || tx.events.start != next_event {
            return Err(corrupt(format!(
                "transaction {n} (batch {}, events {:?}) does not follow the slot's previous \
                 transaction",
                tx.batch, tx.events
            )));
        }
        next_event = tx.events.end;
        for e in tx.events.start.get()..tx.events.end.get() {
            let e = EventNumber::new(e);
            let event = db
                .get::<EventByNumber>(&e)?
                .ok_or_else(|| corrupt(format!("event {e} is missing")))?;
            batch.delete::<EventByKey>(&(event.key().clone(), n, e))?;
            let deleted = deleted_events.entry(event.key().clone()).or_default();
            *deleted = deleted
                .checked_add(1)
                .ok_or_else(|| corrupt("event count overflow".to_owned()))?;
        }
        batch.delete::<TxByHash>(&(tx.hash, n))?;
    }
    if next_event != slot.events.end {
        return Err(corrupt(format!(
            "its transactions hold the events up to {next_event}, the slot's end at {}",
            slot.events.end
        )));
    }
    for (key, deleted) in deleted_events {
        let count = db.get::<EventCountByKey>(&key)?.unwrap_or(0);
        let left = count.checked_sub(deleted).ok_or_else(|| {
            corrupt(format!(
                "the event key {} has a count of {count}, below its {deleted} events in the slot",
                HexString(key.inner())
            ))
        })?;
        if left == 0 {
            batch.delete::<EventCountByKey>(&key)?;
        } else {
            batch.put::<EventCountByKey>(&key, &left)?;
        }
    }

    for n in slot.discarded_blobs.start.get()..slot.discarded_blobs.end.get() {
        let n = DiscardedBlobNumber::new(n);
        let stored = db
            .get::<DiscardedBlobByNumber>(&n)?
            .ok_or_else(|| corrupt(format!("discarded blob {n} is missing")))?;
        if stored.slot != number {
            return Err(corrupt(format!(
                "discarded blob {n} belongs to slot {}",
                stored.slot
            )));
        }
        batch.delete::<DiscardedBlobByHash>(&(stored.blob.hash.0, n))?;
    }

    let (from, to) = {
        let rows = slot_rows(number)?;
        (rows.start, rows.end)
    };
    let mut receipts = db.iter_range::<ProofReceiptBySlot>(&from, &to)?;
    receipts.seek_to_first();
    for receipt in receipts {
        let ((receipt_slot, index), (hash, _)) = receipt?.into_tuple();
        if receipt_slot != number {
            return Err(corrupt(format!(
                "the proof receipt range of the slot returned slot {receipt_slot}"
            )));
        }
        batch.delete::<ProofReceiptByHash>(&(hash, number, index))?;
    }
    batch.delete_range::<ProofReceiptBySlot>(&from, &to)?;
    batch.delete_range::<AggregatedProofBySlot>(&from, &to)?;
    batch.delete::<StfInfoBySlot>(&number)?;

    // Ranges of numbers: one tombstone each (empty ranges are skipped).
    if !slot.batches.is_empty() {
        batch.delete_range::<BatchByNumber>(&slot.batches.start, &slot.batches.end)?;
    }
    if !slot.txs.is_empty() {
        batch.delete_range::<TxByNumber>(&slot.txs.start, &slot.txs.end)?;
    }
    if !slot.events.is_empty() {
        batch.delete_range::<EventByNumber>(&slot.events.start, &slot.events.end)?;
    }
    if !slot.discarded_blobs.is_empty() {
        batch.delete_range::<DiscardedBlobByNumber>(
            &slot.discarded_blobs.start,
            &slot.discarded_blobs.end,
        )?;
    }

    let indexed = db.get::<SlotByHash>(&slot.da_hash)?;
    if indexed != Some(number) {
        return Err(corrupt(format!(
            "its DA block {} is indexed as slot {indexed:?}",
            HexString(slot.da_hash)
        )));
    }
    batch.delete::<SlotByHash>(&slot.da_hash)?;
    batch.delete::<SlotByNumber>(&number)?;

    db.write_schemas(&batch)
        .with_context(|| format!("rolling back slot {number} of the ledger DB"))?;
    tracing::info!(
        slot = %number,
        batches = slot.batches.end.get().saturating_sub(slot.batches.start.get()),
        txs = slot.txs.end.get().saturating_sub(slot.txs.start.get()),
        events = slot.events.end.get().saturating_sub(slot.events.start.get()),
        "Rolled back a slot of the ledger database"
    );
    Ok(())
}

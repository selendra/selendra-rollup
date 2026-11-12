//! The ledger's stored types ([`StoredSlot`], [`StoredBatch`], [`StoredTransaction`],
//! [`StoredDiscardedBlob`]), its item numbers ([`BatchNumber`], [`TxNumber`], [`EventNumber`],
//! [`DiscardedBlobNumber`]) and what a slot writes ([`SlotInfo`], [`SlotContents`]).
//!
//! Receipts, transaction bodies, STF info and proofs are opaque bytes: their encoding is chosen
//! by the node (Phase 10, borsh: `docs/serialization.md`), not by the ledger.

use core::fmt;
use core::ops::Range;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::SlotNumber;
use selendra_interface::da::Time;
use selendra_interface::stf::{DiscardedBlob, StoredEvent};

use crate::nomt_state::NomtRoots;

/// Defines a ledger item number: a `u64` newtype with checked arithmetic only (upstream's
/// `Add`/`Sub` impls panicked on overflow).
macro_rules! item_number {
    ($(#[$docs:meta])* $name:ident, $what:literal) => {
        $(#[$docs])*
        #[derive(
            Clone,
            Copy,
            Default,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            BorshSerialize,
            BorshDeserialize,
        )]
        pub struct $name(u64);

        impl $name {
            /// The first number.
            pub const ZERO: Self = Self(0);

            /// Wraps a raw number.
            pub const fn new(number: u64) -> Self {
                Self(number)
            }

            /// The raw number.
            pub const fn get(self) -> u64 {
                self.0
            }

            /// `self + n`, or `None` on overflow.
            pub fn checked_add(self, n: u64) -> Option<Self> {
                self.0.checked_add(n).map(Self)
            }

            /// The next number.
            ///
            /// # Errors
            /// On overflow. A stored range's end is the number after its last item, so the
            /// largest number ever stored is `u64::MAX - 1`.
            pub(crate) fn next(self) -> anyhow::Result<Self> {
                self.checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!(concat!($what, " number overflow")))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }
    };
}

item_number!(
    /// The number of a batch: batches are numbered in order across all slots, from 0.
    BatchNumber,
    "batch"
);
item_number!(
    /// The number of a transaction: transactions are numbered in order across all slots, from 0.
    TxNumber,
    "transaction"
);
item_number!(
    /// The number of an event: events are numbered in order across all slots, from 0.
    EventNumber,
    "event"
);
item_number!(
    /// The number of a discarded blob: discarded blobs are numbered in order across all slots,
    /// from 0.
    DiscardedBlobNumber,
    "discarded blob"
);

/// Fails unless `range` is not inverted (stored data that is not a valid range is corruption).
fn check_range<T: Ord + fmt::Debug>(what: &str, range: &Range<T>) -> anyhow::Result<()> {
    anyhow::ensure!(
        range.start <= range.end,
        "DB corruption: inverted {what} range {range:?}"
    );
    Ok(())
}

/// A slot (one DA block) as the ledger stores it.
///
/// It records the ranges of every item it holds, so the next numbers come from the newest slot
/// alone, and its state roots: the ledger's newest slot is its version marker, checked against
/// the state databases when they are opened.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StoredSlot {
    /// The DA block's hash.
    pub da_hash: [u8; 32],
    /// The DA block's height.
    pub da_height: u64,
    /// The state roots after this slot (`user ‖ kernel`: 64 bytes, as the state databases
    /// store them; not the global root).
    pub roots: NomtRoots,
    /// The DA block's timestamp.
    pub timestamp: Time,
    /// The batches of this slot.
    pub batches: Range<BatchNumber>,
    /// The transactions of this slot's batches.
    pub txs: Range<TxNumber>,
    /// The events of this slot's transactions.
    pub events: Range<EventNumber>,
    /// The blobs this slot discarded.
    pub discarded_blobs: Range<DiscardedBlobNumber>,
}

impl StoredSlot {
    pub(crate) fn check(&self) -> anyhow::Result<()> {
        check_range("batch", &self.batches)?;
        check_range("transaction", &self.txs)?;
        check_range("event", &self.events)?;
        check_range("discarded blob", &self.discarded_blobs)
    }
}

/// A batch as the ledger stores it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StoredBatch {
    /// The batch's hash.
    pub hash: [u8; 32],
    /// The batch's transactions.
    pub txs: Range<TxNumber>,
    /// The batch receipt (opaque bytes).
    pub receipt: Vec<u8>,
    /// The slot of the batch.
    pub slot: SlotNumber,
}

impl StoredBatch {
    pub(crate) fn check(&self) -> anyhow::Result<()> {
        check_range("transaction", &self.txs)
    }
}

/// A transaction as the ledger stores it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StoredTransaction {
    /// The transaction's hash.
    pub hash: [u8; 32],
    /// The transaction's events.
    pub events: Range<EventNumber>,
    /// The transaction's body, if the node keeps it (opaque bytes).
    pub body: Option<Vec<u8>>,
    /// The transaction receipt (opaque bytes).
    pub receipt: Vec<u8>,
    /// The batch of the transaction.
    pub batch: BatchNumber,
}

impl StoredTransaction {
    pub(crate) fn check(&self) -> anyhow::Result<()> {
        check_range("event", &self.events)
    }
}

/// A discarded blob as the ledger stores it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StoredDiscardedBlob {
    /// The blob's hash and why it was discarded.
    pub blob: DiscardedBlob,
    /// The slot that discarded it.
    pub slot: SlotNumber,
}

/// The DA block of a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotInfo {
    /// The DA block's hash. Unique on a chain: a slot whose hash is already a slot of the chain
    /// is refused.
    pub da_hash: [u8; 32],
    /// The DA block's height.
    pub da_height: u64,
    /// The DA block's timestamp.
    pub timestamp: Time,
}

/// What one slot writes to the ledger besides its DA block ([`SlotInfo`]): its items get the
/// next numbers in order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SlotContents {
    /// The slot's batches, in order.
    pub batches: Vec<BatchContents>,
    /// The blobs the slot discarded, in order.
    pub discarded_blobs: Vec<DiscardedBlob>,
    /// The aggregated proofs accepted in the slot, in order (opaque bytes).
    pub aggregated_proofs: Vec<Vec<u8>>,
    /// The proof receipts of the slot, in order: the proof blob's hash and the receipt (opaque
    /// bytes).
    pub proof_receipts: Vec<([u8; 32], Vec<u8>)>,
    /// The slot's STF info (the witness the prover needs; opaque bytes).
    pub stf_info: Option<Vec<u8>>,
    /// Deletes the STF info of the slots before this one, at most
    /// [`STF_INFO_PRUNE_BUDGET`](crate::ledger::STF_INFO_PRUNE_BUDGET) of them (the oldest
    /// first): the rest is deleted by a later slot that prunes again. Must not be after the
    /// slot being written. Only the keys of the rows deleted are read: no STF info, and no row
    /// from this slot on.
    ///
    /// Pruning is not undone by a rollback of the slot (startup crash recovery): the rows are
    /// rows the node had already decided to drop, and executing the slot again prunes them
    /// again.
    pub stf_info_prune_below: Option<SlotNumber>,
}

/// A batch of a slot.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BatchContents {
    /// The batch's hash (not unique: two batches may have the same hash).
    pub hash: [u8; 32],
    /// The batch receipt (opaque bytes).
    pub receipt: Vec<u8>,
    /// The batch's transactions, in order.
    pub txs: Vec<TxContents>,
}

/// A transaction of a batch.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TxContents {
    /// The transaction's hash (not unique: two transactions may have the same hash).
    pub hash: [u8; 32],
    /// The transaction's body, if the node keeps it (opaque bytes).
    pub body: Option<Vec<u8>>,
    /// The transaction receipt (opaque bytes).
    pub receipt: Vec<u8>,
    /// The transaction's events, in order. Each must carry this transaction's hash, and a key
    /// of at most [`MAX_EVENT_KEY_LEN`](crate::schema::MAX_EVENT_KEY_LEN) bytes.
    pub events: Vec<StoredEvent>,
}

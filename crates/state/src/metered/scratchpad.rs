//! [`TxScratchpad`]: one transaction's writes over a block's [`StateCheckpoint`].

use std::convert::Infallible;

use selendra_interface::common::{RollupHeight, SlotNumber, VisibleSlotNumber};

use super::journal::Journal;
use crate::namespaces::{Accessory, Kernel, Namespace, ProvableNamespace, User};
use crate::{
    SlotKey, SlotValue, StateCheckpoint, StateReader, StateWriter, Storage, VersionReader,
};

/// One transaction's writes over a block's [`StateCheckpoint`]: a journal the state transition
/// function owns, holding the transaction-level writes (the pre-execution results, the gas
/// reservation and its settlement) and, through [`MeteredTx`](super::MeteredTx), the metered
/// phases' writes.
///
/// Reads go to the journal first, then to the checkpoint, so every read of storage is recorded
/// and verified like any other. [`commit`](Self::commit) applies the journal to the checkpoint
/// in key order; [`revert`](Self::revert) drops it. Either way the reads stay in the
/// checkpoint's caches, so they are still verified against the state root (upstream's
/// alternative, discarding the checkpoint's revertable cache, unverifies them).
///
/// # Access
/// Unmetered and infallible, like upstream's: [`StateReader`] for [`User`] and [`Kernel`],
/// [`StateWriter`] for [`User`], and [`VersionReader`]. Gas is charged by the
/// [`MeteredTx`](super::MeteredTx) built on it, never here: a `TxScratchpad` never implements
/// [`Metered`](super::Metered) (the blanket impls would overlap these, E0119), and modules
/// never hold one.
///
/// A scratchpad is built only from an owned checkpoint, which only the state transition function
/// holds, so module code cannot build another one.
pub struct TxScratchpad<St: Storage> {
    checkpoint: StateCheckpoint<St>,
    journal: Journal,
}

impl<St: Storage> std::fmt::Debug for TxScratchpad<St> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxScratchpad")
            .field("journal", &self.journal)
            .finish_non_exhaustive()
    }
}

impl<St: Storage> TxScratchpad<St> {
    /// Starts a transaction on `checkpoint`.
    pub fn new(checkpoint: StateCheckpoint<St>) -> Self {
        Self {
            checkpoint,
            journal: Journal::default(),
        }
    }

    /// Applies the transaction's writes to the checkpoint, in key order (by namespace, then
    /// key), and returns it.
    pub fn commit(self) -> StateCheckpoint<St> {
        let Self {
            mut checkpoint,
            journal,
        } = self;
        for ((namespace, key), value) in journal.into_writes() {
            let Ok(()) = match (namespace, value) {
                (Namespace::User, Some(value)) => {
                    StateWriter::<User>::set(&mut checkpoint, &key, value)
                }
                (Namespace::User, None) => StateWriter::<User>::delete(&mut checkpoint, &key),
                (Namespace::Kernel, Some(value)) => {
                    StateWriter::<Kernel>::set(&mut checkpoint, &key, value)
                }
                (Namespace::Kernel, None) => StateWriter::<Kernel>::delete(&mut checkpoint, &key),
                (Namespace::Accessory, Some(value)) => {
                    StateWriter::<Accessory>::set(&mut checkpoint, &key, value)
                }
                (Namespace::Accessory, None) => {
                    StateWriter::<Accessory>::delete(&mut checkpoint, &key)
                }
            };
        }
        checkpoint
    }

    /// Drops the transaction's writes (accessory writes included) and returns the checkpoint.
    /// Its reads stay recorded and verified.
    pub fn revert(self) -> StateCheckpoint<St> {
        self.checkpoint
    }

    /// The versions of the checkpoint.
    pub(crate) fn versions(&self) -> crate::CheckpointVersions {
        self.checkpoint.versions()
    }

    pub(crate) fn journal_mut(&mut self) -> &mut Journal {
        &mut self.journal
    }

    pub(crate) fn journal(&self) -> &Journal {
        &self.journal
    }

    /// The size of the value of `key`: journal first, then the checkpoint (which, on a first
    /// read, fetches only the value's leaf).
    pub(crate) fn size(&mut self, namespace: ProvableNamespace, key: &SlotKey) -> Option<u32> {
        match self.journal.get(namespace_of(namespace), key) {
            Some(value) => value.as_ref().map(SlotValue::size),
            None => self.checkpoint.get_size(namespace, key),
        }
    }

    /// The value of `key`: journal first, then the checkpoint.
    pub(crate) fn get(&mut self, namespace: ProvableNamespace, key: &SlotKey) -> Option<SlotValue> {
        match self.journal.get(namespace_of(namespace), key) {
            Some(value) => value.clone(),
            None => self.checkpoint.get_value(namespace, key),
        }
    }
}

/// The namespace of a provable namespace.
pub(crate) fn namespace_of(namespace: ProvableNamespace) -> Namespace {
    match namespace {
        ProvableNamespace::User => Namespace::User,
        ProvableNamespace::Kernel => Namespace::Kernel,
    }
}

macro_rules! impl_scratchpad_read {
    ($namespace:ty, $provable:expr) => {
        impl<St: Storage> StateReader<$namespace> for TxScratchpad<St> {
            type Error = Infallible;

            fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error> {
                Ok(TxScratchpad::get(self, $provable, key))
            }
        }
    };
}

impl_scratchpad_read!(User, ProvableNamespace::User);
impl_scratchpad_read!(Kernel, ProvableNamespace::Kernel);

impl<St: Storage> StateWriter<User> for TxScratchpad<St> {
    type Error = Infallible;

    fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Self::Error> {
        crate::checkpoint::debug_assert_unmetered_size(key, &value);
        self.journal.set(Namespace::User, key, Some(value));
        Ok(())
    }

    fn delete(&mut self, key: &SlotKey) -> Result<(), Self::Error> {
        self.journal.set(Namespace::User, key, None);
        Ok(())
    }
}

/// The checkpoint's versions.
impl<St: Storage> VersionReader for TxScratchpad<St> {
    fn max_allowed_slot_number_to_access(&self) -> SlotNumber {
        self.checkpoint.max_allowed_slot_number_to_access()
    }

    fn current_visible_slot_number(&self) -> VisibleSlotNumber {
        self.checkpoint.current_visible_slot_number()
    }

    fn rollup_height_to_access(&self) -> RollupHeight {
        self.checkpoint.rollup_height_to_access()
    }
}

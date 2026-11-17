//! The versions a [`StateCheckpoint`] executes at (the visible slot number and the rollup
//! height), the [`VersionReader`] trait that exposes them, and the [`BootstrapReader`] through
//! which they are read from the checkpoint's own state.
//!
//! The versions are never passed in from outside: [`StateCheckpoint::new_with`] and
//! [`StateCheckpoint::refresh_versions`] take a closure that reads them through a
//! [`BootstrapReader`] on the checkpoint itself, in the same order natively and in the zk guest;
//! a value passed in from another checkpoint or from the storage would be unverified in the
//! guest.
//! - In [`new_with`](StateCheckpoint::new_with) the checkpoint is empty, so those reads are its
//!   first reads: recorded, their hints first in the witness, verified against the prior state
//!   root.
//! - In [`refresh_versions`](StateCheckpoint::refresh_versions) they read the checkpoint's
//!   current state: a value written earlier in the block (typically the kernel's new versions)
//!   comes from the checkpoint's write cache, with no hint and no first read; only a key not yet
//!   read or written is a first read, verified like any other.
//!
//! Either way the values come from the checkpoint's own (written or verified) state.
//!
//! A refresh commits everything revertable in the checkpoint, so it happens between
//! transactions. For transactions run on a [`TxScratchpad`](crate::TxScratchpad) (and its
//! [`MeteredTx`](crate::MeteredTx) phases) the compiler enforces it: they own the checkpoint
//! until the transaction ends, so a refresh in between does not compile (see
//! [`refresh_versions`](StateCheckpoint::refresh_versions), which also says what this does not
//! cover).

use std::convert::Infallible;

use selendra_interface::common::{RollupHeight, SlotNumber, VisibleSlotNumber};

use crate::namespaces::{Kernel, User};
use crate::{SlotKey, SlotValue, StateCheckpoint, StateReader, Storage};

/// A state accessor that knows the versions it executes at.
pub trait VersionReader {
    /// Returns the largest slot number that the accessor is allowed to access. During
    /// transaction execution this is the same as
    /// [`current_visible_slot_number`](Self::current_visible_slot_number); with kernel
    /// permissions it is the true slot number.
    fn max_allowed_slot_number_to_access(&self) -> SlotNumber;

    /// Returns the current visible slot number.
    fn current_visible_slot_number(&self) -> VisibleSlotNumber;

    /// Returns the rollup height the accessor executes at.
    fn rollup_height_to_access(&self) -> RollupHeight;
}

/// The versions of a [`StateCheckpoint`], read from its own state by the closure given to
/// [`StateCheckpoint::new_with`] or [`StateCheckpoint::refresh_versions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointVersions {
    /// The slot number visible to user-space modules.
    pub visible_slot_number: VisibleSlotNumber,
    /// The rollup height.
    pub rollup_height: RollupHeight,
}

impl CheckpointVersions {
    /// The versions before the first block: both zero.
    pub const GENESIS: Self = Self {
        visible_slot_number: VisibleSlotNumber::GENESIS,
        rollup_height: RollupHeight::GENESIS,
    };
}

/// Read-only access to a [`StateCheckpoint`] while its versions are read
/// ([`StateCheckpoint::new_with`], [`StateCheckpoint::refresh_versions`]).
///
/// It implements [`StateReader`] for [`User`] and [`Kernel`] (infallible, unmetered) and
/// nothing else: no writer in any namespace, and no accessory reads. Upstream's bootstrap
/// accessor had a writer that was `unimplemented!()`, so a write compiled and then panicked at
/// runtime, in the zk guest too. Only the checkpoint builds one, and only for the duration of
/// the closure.
///
/// Reads compile:
///
/// ```
/// use selendra_state::{
///     BootstrapReader, BorshCodec, KernelStateValue, Prefix, StateValue, Storage,
/// };
///
/// fn read<St: Storage>(reader: &mut BootstrapReader<'_, St>) -> (Option<u64>, Option<u64>) {
///     let kernel = KernelStateValue::<u64>::with_codec(Prefix::new(1, 0), BorshCodec);
///     let user = StateValue::<u64>::with_codec(Prefix::new(1, 1), BorshCodec);
///     let Ok(kernel) = kernel.get(reader);
///     let Ok(user) = user.get(reader);
///     (kernel, user)
/// }
/// ```
///
/// P5-10: writes do not (E0277, no `StateWriter`):
///
/// ```compile_fail,E0277
/// use selendra_state::{BootstrapReader, BorshCodec, KernelStateValue, Prefix, Storage};
///
/// fn write<St: Storage>(reader: &mut BootstrapReader<'_, St>) {
///     let mut kernel = KernelStateValue::<u64>::with_codec(Prefix::new(1, 0), BorshCodec);
///     let _ = kernel.set(&1, reader);
/// }
/// ```
pub struct BootstrapReader<'a, St: Storage> {
    checkpoint: &'a mut StateCheckpoint<St>,
}

impl<St: Storage> std::fmt::Debug for BootstrapReader<'_, St> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapReader").finish_non_exhaustive()
    }
}

impl<'a, St: Storage> BootstrapReader<'a, St> {
    pub(crate) fn new(checkpoint: &'a mut StateCheckpoint<St>) -> Self {
        Self { checkpoint }
    }
}

macro_rules! impl_bootstrap_read {
    ($namespace:ty) => {
        impl<St: Storage> StateReader<$namespace> for BootstrapReader<'_, St> {
            type Error = Infallible;

            fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error> {
                StateReader::<$namespace>::get(self.checkpoint, key)
            }
        }
    };
}

impl_bootstrap_read!(User);
impl_bootstrap_read!(Kernel);

#[cfg(test)]
mod tests;

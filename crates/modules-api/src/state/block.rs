//! [`BlockState`]: the state block hooks run on.

use std::convert::Infallible;
use std::fmt;

use selendra_interface::common::{RollupHeight, SlotNumber, VisibleSlotNumber};
use selendra_state::{
    Accessory, Kernel, SlotKey, SlotValue, StateReader, StateWriter, User, VersionReader,
};

use super::SpecCheckpoint;
use crate::Spec;

/// The state the begin- and end-of-block hooks run on (S7): the block's checkpoint, unmetered
/// and infallible. User and Kernel state read and write, Accessory state write only, and the
/// versions ([`VersionReader`]).
///
/// The state transition function lends it over the checkpoint it owns ([`new`](Self::new));
/// modules never hold the checkpoint itself. So module code cannot reach the storage (to build
/// a second, unrecorded checkpoint over it: a native/zk divergence), start a transaction
/// (`TxScratchpad::new` takes the checkpoint by value), or refresh the versions. There is no
/// `storage()` (E0599):
///
/// ```compile_fail,E0599
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
///
/// fn storage(state: &mut BlockState<'_, TestSpec>) {
///     let _ = state.storage();
/// }
/// ```
///
/// ```
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_state::{BorshCodec, KernelStateValue, Prefix};
///
/// fn read(state: &mut BlockState<'_, TestSpec>) -> Option<u64> {
///     let height = KernelStateValue::<u64>::with_codec(Prefix::new(1, 0), BorshCodec);
///     let Ok(height) = height.get(state);
///     height
/// }
/// ```
///
/// Its writes are not bounded in release builds yet (a debug assertion checks
/// `MAX_STATE_VALUE_SIZE`): Phase 8 adds a release-mode error.
pub struct BlockState<'a, S: Spec> {
    checkpoint: &'a mut SpecCheckpoint<S>,
}

impl<S: Spec> fmt::Debug for BlockState<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockState")
            .field("versions", &self.checkpoint.versions())
            .finish_non_exhaustive()
    }
}

impl<'a, S: Spec> BlockState<'a, S> {
    /// The block state over `checkpoint` (the state transition function's).
    pub fn new(checkpoint: &'a mut SpecCheckpoint<S>) -> Self {
        Self { checkpoint }
    }
}

macro_rules! impl_block_read {
    ($namespace:ty) => {
        impl<S: Spec> StateReader<$namespace> for BlockState<'_, S> {
            type Error = Infallible;

            fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Infallible> {
                StateReader::<$namespace>::get(self.checkpoint, key)
            }
        }
    };
}

impl_block_read!(User);
impl_block_read!(Kernel);

macro_rules! impl_block_write {
    ($namespace:ty) => {
        impl<S: Spec> StateWriter<$namespace> for BlockState<'_, S> {
            type Error = Infallible;

            fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Infallible> {
                StateWriter::<$namespace>::set(self.checkpoint, key, value)
            }

            fn delete(&mut self, key: &SlotKey) -> Result<(), Infallible> {
                StateWriter::<$namespace>::delete(self.checkpoint, key)
            }
        }
    };
}

impl_block_write!(User);
impl_block_write!(Kernel);
impl_block_write!(Accessory);

/// The checkpoint's versions.
impl<S: Spec> VersionReader for BlockState<'_, S> {
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

//! [`MockKernel`]: a kernel for tests that keeps the versions in kernel state.

use std::convert::Infallible;

use selendra_interface::common::{RollupHeight, VisibleSlotNumber};
use selendra_state::{
    BootstrapReader, BorshCodec, CheckpointVersions, Kernel, KernelStateValue, Prefix,
    StateCheckpoint, StateReader, StateWriter, Storage,
};

/// A kernel for tests: it keeps the visible slot number and the rollup height in two kernel
/// state values at fixed prefixes ([`MockKernel::VISIBLE_SLOT_NUMBER`],
/// [`MockKernel::ROLLUP_HEIGHT`]; module byte `0`, which no module may use), and supplies the
/// closures that read them on a checkpoint ([`StateCheckpoint::new_with`],
/// [`StateCheckpoint::refresh_versions`]), like Phase 8's kernel will.
///
/// Upstream's `MockKernel` held the slot numbers in fields and handed them to the checkpoint
/// from outside; here they are read from the checkpoint's own state, so the reads are recorded
/// and verified like a real kernel's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MockKernel;

impl MockKernel {
    /// The prefix of the visible slot number (a `VisibleSlotNumber`, borsh).
    pub const VISIBLE_SLOT_NUMBER: Prefix = Prefix::new(0, 0);
    /// The prefix of the rollup height (a `RollupHeight`, borsh).
    pub const ROLLUP_HEIGHT: Prefix = Prefix::new(0, 1);

    fn visible_slot_number() -> KernelStateValue<VisibleSlotNumber> {
        KernelStateValue::with_codec(Self::VISIBLE_SLOT_NUMBER, BorshCodec)
    }

    fn rollup_height() -> KernelStateValue<RollupHeight> {
        KernelStateValue::with_codec(Self::ROLLUP_HEIGHT, BorshCodec)
    }

    /// Reads the versions from kernel state ([`CheckpointVersions::GENESIS`]'s values where
    /// absent): the closure for [`StateCheckpoint::new_with`] and
    /// [`StateCheckpoint::refresh_versions`].
    pub fn read_versions<St: Storage>(reader: &mut BootstrapReader<'_, St>) -> CheckpointVersions {
        let Ok(visible_slot_number) = Self::visible_slot_number().get(reader);
        let Ok(rollup_height) = Self::rollup_height().get(reader);
        CheckpointVersions {
            visible_slot_number: visible_slot_number
                .unwrap_or(CheckpointVersions::GENESIS.visible_slot_number),
            rollup_height: rollup_height.unwrap_or(CheckpointVersions::GENESIS.rollup_height),
        }
    }

    /// A checkpoint over `storage` and `witness` whose versions are read from its kernel state.
    pub fn checkpoint<St: Storage>(storage: St, witness: St::Witness) -> StateCheckpoint<St> {
        StateCheckpoint::new_with(storage, witness, Self::read_versions)
    }

    /// Writes `versions` to kernel state (e.g. through a checkpoint or a
    /// [`BlockState`](crate::BlockState)).
    pub fn write_versions<A>(state: &mut A, versions: CheckpointVersions)
    where
        A: StateReader<Kernel, Error = Infallible> + StateWriter<Kernel, Error = Infallible>,
    {
        let Ok(()) = Self::visible_slot_number().set(&versions.visible_slot_number, state);
        let Ok(()) = Self::rollup_height().set(&versions.rollup_height, state);
    }

    /// Moves `checkpoint` to `versions`: writes them to its kernel state, then refreshes its
    /// versions from there (between transactions).
    pub fn advance<St: Storage>(
        checkpoint: &mut StateCheckpoint<St>,
        versions: CheckpointVersions,
    ) {
        Self::write_versions(checkpoint, versions);
        checkpoint.refresh_versions(Self::read_versions);
    }
}

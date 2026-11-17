//! The metered accessors' [`StateReader`]/[`StateWriter`]/[`VersionReader`] impls: one blanket
//! impl per trait and namespace over [`Metered`], keyed on the rights.
//!
//! They must live in this crate: `impl<T: Metered> StateReader<User> for T` implements a trait
//! of this crate for an uncovered `T`, which no other crate may do (E0210). They are coherent
//! with this crate's concrete impls (`StateCheckpoint`, `TxScratchpad`, `BootstrapReader`, the
//! test accessors) because none of those types implements [`Metered`]: implementing it for one
//! of them would fail with E0119, as would a hand-written `StateReader`/`StateWriter` impl for a
//! [`Metered`] type in another crate.

use selendra_interface::common::{RollupHeight, SlotNumber, VisibleSlotNumber};

use super::Metered;
use super::costs::StateGasMeter;
use super::error::StateAccessError;
use super::rights::{ReadsKernel, ReadsUser, WritesAccessory, WritesKernel, WritesUser};
use crate::codec::{StateCodec, StateItemCodec};
use crate::namespaces::{Accessory, CompileTimeNamespace, Kernel, ProvableNamespace, User};
use crate::{SlotKey, SlotValue, StateReader, StateWriter, VersionReader};

macro_rules! impl_metered_reader {
    ($namespace:ty, $rights:ident, $provable:expr) => {
        /// Metered reads (see [`costs`](super::costs) for the gas).
        impl<T> StateReader<$namespace> for T
        where
            T: Metered,
            T::Rights: $rights,
        {
            type Error = StateAccessError<<T::Meter as StateGasMeter>::Error>;

            fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error> {
                self.metered().read($provable, key, false)
            }

            /// Also charges `decode_per_byte` per byte of a present value, before decoding it.
            fn get_decoded<V, Codec>(
                &mut self,
                key: &SlotKey,
                codec: &Codec,
            ) -> Result<Option<V>, Self::Error>
            where
                Codec: StateCodec,
                Codec::ValueCodec: StateItemCodec<V>,
            {
                self.metered().read_decoded($provable, key, codec)
            }
        }
    };
}

impl_metered_reader!(User, ReadsUser, ProvableNamespace::User);
impl_metered_reader!(Kernel, ReadsKernel, ProvableNamespace::Kernel);

macro_rules! impl_metered_writer {
    ($namespace:ty, $rights:ident) => {
        /// Metered writes and deletes (see [`costs`](super::costs) for the gas).
        impl<T> StateWriter<$namespace> for T
        where
            T: Metered,
            T::Rights: $rights,
        {
            type Error = StateAccessError<<T::Meter as StateGasMeter>::Error>;

            fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Self::Error> {
                self.metered()
                    .write(<$namespace>::NAMESPACE, key, Some(value))
            }

            fn delete(&mut self, key: &SlotKey) -> Result<(), Self::Error> {
                self.metered().write(<$namespace>::NAMESPACE, key, None)
            }
        }
    };
}

impl_metered_writer!(User, WritesUser);
impl_metered_writer!(Kernel, WritesKernel);
impl_metered_writer!(Accessory, WritesAccessory);

/// The versions of the checkpoint the phase runs on; the largest slot number it may access is
/// the visible one.
impl<T: Metered> VersionReader for T {
    fn max_allowed_slot_number_to_access(&self) -> SlotNumber {
        self.metered_view().versions().visible_slot_number.as_true()
    }

    fn current_visible_slot_number(&self) -> VisibleSlotNumber {
        self.metered_view().versions().visible_slot_number
    }

    fn rollup_height_to_access(&self) -> RollupHeight {
        self.metered_view().versions().rollup_height
    }
}

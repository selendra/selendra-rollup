//! The state accessor traits module code is written against: [`TxState`] (a transaction),
//! [`GenesisState`] (genesis), [`StateAccessor`] and the infallible accessors.

use std::convert::Infallible;

use selendra_interface::common::SlotNumber;
use selendra_state::metered::{Metered, StateAccessError, TxRights};
use selendra_state::{
    Kernel, StateCheckpoint, StateReader, StateReaderAndWriter, StateWriter, User, VersionReader,
};

use super::events::EventContainer;
use super::revertable::RevertableTxState;
use crate::{GasMeter, GasMeteringError, Spec, TxMeter};

/// The error of every metered state access and charge of a spec's transaction accessors: a
/// [`StateAccessError`] over the meters' [`GasMeteringError`].
pub type TxStateError<S> = StateAccessError<GasMeteringError<<S as Spec>::Gas>>;

/// The checkpoint of a spec's storage (upstream `StateCheckpoint<S>`).
pub type SpecCheckpoint<S> = StateCheckpoint<<S as Spec>::Storage>;

/// An accessor that reads and writes [`User`] state (implemented for every such accessor).
///
/// ```
/// use selendra_modules_api::*;
/// use selendra_state::{BorshCodec, Prefix, StateValue, User};
///
/// fn delete_state_string<A: StateAccessor>(
///     value: &mut StateValue<String>,
///     state: &mut A,
/// ) -> Result<(), <A as StateWriter<User>>::Error> {
///     if let Some(original) = value.get(state)? {
///         assert!(!original.is_empty());
///     }
///     value.delete(state)
/// }
/// ```
///
/// Upstream's `to_unmetered` (only the EVM uses it) is not ported: Phase 7 designs it with
/// its user.
pub trait StateAccessor: StateReaderAndWriter<User> {}

impl<T: StateReaderAndWriter<User>> StateAccessor for T {}

/// A [`StateAccessor`] whose accesses never fail (e.g. [`BlockState`](crate::BlockState)).
pub trait InfallibleStateAccessor:
    StateReader<User, Error = Infallible> + StateWriter<User, Error = Infallible>
{
}

impl<T> InfallibleStateAccessor for T where
    T: StateReader<User, Error = Infallible> + StateWriter<User, Error = Infallible>
{
}

/// Like [`InfallibleStateAccessor`], for [`Kernel`] state.
pub trait InfallibleKernelStateAccessor:
    StateReader<Kernel, Error = Infallible> + StateWriter<Kernel, Error = Infallible>
{
}

impl<T> InfallibleKernelStateAccessor for T where
    T: StateReader<Kernel, Error = Infallible> + StateWriter<Kernel, Error = Infallible>
{
}

/// The state a transaction's call (and its hooks) runs on: [`User`] and [`Kernel`] state read
/// and write, [`Accessory`](selendra_state::Accessory) state write only, all metered; the gas
/// meter ([`GasMeter`]); events ([`EventContainer`]); the versions ([`VersionReader`]).
///
/// It is a [`Metered`] accessor with the transaction rights ([`TxRights`]) over the spec's
/// storage: the readers and writers come from `selendra-state`'s blanket impls over
/// [`Metered`], so every access is charged and a failed one poisons the phase (the phase is
/// then reverted whatever the module returns). Implemented for every such accessor:
/// [`WorkingSet`](crate::WorkingSet), [`RevertableTxState`] and
/// [`GenesisStateAccessor`](crate::GenesisStateAccessor).
///
/// ```
/// use selendra_modules_api::*;
/// use selendra_state::{BorshCodec, KernelStateValue, Prefix, StateValue};
///
/// fn call<S: Spec>(state: &mut impl TxState<S>) -> Result<(), TxStateError<S>> {
///     let mut count = StateValue::<u64>::with_codec(Prefix::new(1, 0), BorshCodec);
///     let height = KernelStateValue::<u64>::with_codec(Prefix::new(1, 1), BorshCodec);
///     let n = count.get(state)?.unwrap_or(0);
///     count.set(&(n + 1), state)?;
///     let _ = height.get(state)?;
///     state.add_event(1, "Counted", n)?;
///     state.charge_gas(S::GAS_SCHEDULE.encode_per_byte)
/// }
/// ```
///
/// No transaction accessor reads [`Accessory`](selendra_state::Accessory) state (the zk guest
/// cannot: it is not provable), not even with this crate's `test-utils` feature, which `make
/// test` turns on (upstream's `test-utils` added the reads, P5-23b; E0277):
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_state::{AccessoryStateValue, BorshCodec, Prefix};
///
/// fn read(state: &mut WorkingSet<TestSpec>) {
///     let value = AccessoryStateValue::<u8>::with_codec(Prefix::new(1, 0), BorshCodec);
///     let _ = value.get(state);
/// }
/// ```
///
/// It writes it:
///
/// ```
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_state::{AccessoryStateValue, BorshCodec, Prefix};
///
/// fn write(state: &mut WorkingSet<TestSpec>) {
///     let mut value = AccessoryStateValue::<u8>::with_codec(Prefix::new(1, 0), BorshCodec);
///     let _ = value.set(&1, state);
/// }
/// ```
pub trait TxState<S: Spec>:
    Metered<Storage = S::Storage, Rights = TxRights, Meter: TxMeter<S>>
    + GasMeter<S>
    + EventContainer<S>
    + VersionReader
    + Sized
{
    /// A nested scope over this state: its writes and events are kept only if it is
    /// [committed](RevertableTxState::commit); dropping it (or
    /// [`revert`](RevertableTxState::revert)ing it) drops them.
    ///
    /// Infallible, like upstream's: opening the scope is charged `scope_open`, and if that
    /// fails the phase is poisoned, so every access through the result (and through this state)
    /// fails with `Poisoned`.
    fn to_revertable(&mut self) -> RevertableTxState<'_, S, Self> {
        RevertableTxState::new(self)
    }
}

impl<S: Spec, T> TxState<S> for T where
    T: Metered<Storage = S::Storage, Rights = TxRights, Meter: TxMeter<S>>
        + GasMeter<S>
        + EventContainer<S>
        + VersionReader
        + Sized
{
}

/// An accessor that knows the true slot number and writes [`Kernel`] state with it.
///
/// Implement it with extreme care: a wrong true slot number breaks soft confirmations. It is
/// never part of [`TxState`]; [`GenesisState`] has it.
pub trait PrivilegedKernelAccessor: StateWriter<Kernel> {
    /// The current true slot number.
    fn true_slot_number(&self) -> SlotNumber;
}

/// The state genesis runs on: a [`TxState`] that also knows the true slot number
/// ([`SlotNumber::GENESIS`]). Implemented by [`GenesisStateAccessor`](crate::GenesisStateAccessor).
///
/// (The `StateWriter<Kernel>` bound repeats the one [`PrivilegedKernelAccessor`] brings, with
/// its error: generic code would otherwise see that bound's unnamed error instead of
/// [`TxStateError`].)
pub trait GenesisState<S: Spec>:
    TxState<S> + PrivilegedKernelAccessor + StateWriter<Kernel, Error = TxStateError<S>>
{
}

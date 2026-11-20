//! [`PreExecWorkingSet`]: the state a transaction's pre-execution checks run on.

use std::fmt;

use selendra_state::metered::{
    Finalized, Metered, MeteredRef, MeteredTx, MeteredView, PreExecRights, TxScratchpad,
};

use crate::{BasicGasMeter, Spec};

/// What [`PreExecWorkingSet::finalize`] returns: the scratchpad (with the pre-execution writes
/// iff committed), the meter and the outcome.
pub type FinalizedPreExec<S, E> = Finalized<<S as Spec>::Storage, BasicGasMeter<S>, E>;

/// The state a transaction's pre-execution checks run on (authentication, the gas
/// reservation): a metered phase ([`MeteredTx`]) with the pre-execution rights ([`User`]
/// state read and write only: E0277 on Kernel or Accessory state) over the transaction's
/// [`TxScratchpad`], charging a [`BasicGasMeter`] with the spec's gas schedule. It has its own
/// phase, so its writes do not depend on the call's: a reservation written here and committed
/// survives a reverted call.
///
/// [`User`]: selendra_state::User
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_state::{BorshCodec, KernelStateValue, Prefix};
///
/// fn read(state: &mut PreExecWorkingSet<TestSpec>) {
///     let value = KernelStateValue::<u8>::with_codec(Prefix::new(1, 0), BorshCodec);
///     let _ = value.get(state);
/// }
/// ```
///
/// ```
/// use selendra_modules_api::*;
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_state::{BorshCodec, Prefix, StateValue};
///
/// fn read(state: &mut PreExecWorkingSet<TestSpec>) {
///     let value = StateValue::<u8>::with_codec(Prefix::new(1, 0), BorshCodec);
///     let _ = value.get(state);
/// }
/// ```
pub struct PreExecWorkingSet<S: Spec> {
    tx: MeteredTx<S::Storage, BasicGasMeter<S>, PreExecRights>,
}

impl<S: Spec> fmt::Debug for PreExecWorkingSet<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreExecWorkingSet")
            .field("tx", &self.tx)
            .finish()
    }
}

impl<S: Spec> PreExecWorkingSet<S> {
    /// Starts the pre-execution of a transaction on `scratchpad`, charging `meter` with the
    /// spec's state-access costs.
    pub fn new(scratchpad: TxScratchpad<S::Storage>, meter: BasicGasMeter<S>) -> Self {
        Self {
            tx: MeteredTx::new(scratchpad, meter, S::GAS_SCHEDULE.state),
        }
    }

    /// Ends the pre-execution: commits its writes into the scratchpad iff no access failed and
    /// `result` is `Ok`, and reverts them otherwise (see [`MeteredTx::finalize`]).
    pub fn finalize<E>(self, result: Result<(), E>) -> FinalizedPreExec<S, E> {
        self.tx.finalize(result)
    }
}

impl<S: Spec> Metered for PreExecWorkingSet<S> {
    type Storage = S::Storage;
    type Meter = BasicGasMeter<S>;
    type Rights = PreExecRights;

    fn metered(&mut self) -> MeteredRef<'_, S::Storage, BasicGasMeter<S>, PreExecRights> {
        self.tx.metered()
    }

    fn metered_view(&self) -> MeteredView<'_, BasicGasMeter<S>> {
        self.tx.metered_view()
    }
}

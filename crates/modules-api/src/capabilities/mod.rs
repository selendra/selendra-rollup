//! The capabilities a runtime provides to the state transition function: gas enforcement
//! ([`GasEnforcer`]), authentication ([`TransactionAuthenticator`]) and authorization
//! ([`TransactionAuthorizer`]) of transactions, the sequencer's authorization
//! ([`SequencerAuthorization`]) and pay ([`SequencerRemuneration`]), and proof processing
//! ([`ProofProcessor`]). A runtime hands them out through [`HasCapabilities`].
//!
//! Some capabilities are coupled: the gas enforcer, the sequencer's pay and the blob selector
//! (Phase 8) move the same funds. Overriding one is allowed, and dangerous: test the whole
//! flow.
//!
//! Not ported (Phase 5 plan, 1.3): the attester capabilities (no optimistic mode), the
//! timelock (Phase 6/11), sequencing data (Phase 11), the kernel, chain state and blob selector
//! (`HasKernel`, Phase 8).

pub mod authentication;
mod authorization;
mod gas;
mod proof;
mod sequencer;

#[cfg(test)]
mod tests;

pub use authentication::{
    AuthenticationError, AuthenticationOutput, AuthenticatorState, BatchFromUnregisteredSequencer,
    FatalError, TransactionAuthenticator, UnregisteredAuthenticationError, calculate_hash,
    calculate_hash_metered,
};
pub use authorization::TransactionAuthorizer;
pub use gas::{GasEnforcer, Rewards};
pub use proof::{ProofProcessor, SpecAggregatedProofPublicData};
pub use sequencer::{AllowedSequencer, SequencerAuthorization, SequencerRemuneration};

use crate::Spec;

/// A value only [`HasCapabilities`]' provided methods can open: what
/// [`HasCapabilities::capabilities`] returns.
///
/// It keeps code outside the trait from reaching the default capabilities directly: a runtime
/// that overrides one capability (say [`HasCapabilities::gas_enforcer`]) could otherwise be
/// called through the default one by mistake. The field is private (E0616):
///
/// ```compile_fail,E0616
/// use selendra_modules_api::capabilities::{GasEnforcer, HasCapabilities};
/// use selendra_modules_api::Spec;
///
/// fn default_enforcer<S: Spec, H: HasCapabilities<S>>(runtime: &mut H) {
///     let _bypass = runtime.capabilities().inner;
/// }
/// ```
///
/// Code gets each capability through its accessor, the override if there is one:
///
/// ```
/// use selendra_modules_api::capabilities::{GasEnforcer, HasCapabilities};
/// use selendra_modules_api::Spec;
///
/// fn enforcer<S: Spec, H: HasCapabilities<S>>(runtime: &mut H) {
///     let _enforcer = runtime.gas_enforcer();
/// }
/// ```
#[derive(Debug)]
pub struct Guard<T> {
    inner: T,
}

impl<T> Guard<T> {
    /// Guards `inner`.
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }
}

/// A runtime's capabilities: one type implementing every capability
/// ([`Capabilities`](Self::Capabilities)), and one accessor per capability, each of which a
/// runtime may override.
///
/// Take great care when overriding a capability: some are coupled with others (the gas
/// enforcer and the sequencer's pay move the same escrow), and a non-standard implementation
/// can break them in subtle ways. Phase 8 provides the standard capabilities
/// (TODO.md, Phase 8: "Standard capabilities struct"), over Phase 6's bank, sequencer registry
/// and prover incentives modules.
pub trait HasCapabilities<S: Spec> {
    /// The type implementing every capability.
    type Capabilities<'a>: GasEnforcer<S>
        + SequencerAuthorization<S>
        + TransactionAuthorizer<S>
        + ProofProcessor<S>
        + SequencerRemuneration<S>
    where
        Self: 'a;

    /// The capabilities, guarded: only the accessors below open the [`Guard`], so code that
    /// needs a capability calls its accessor and gets the runtime's override if there is one.
    fn capabilities(&mut self) -> Guard<Self::Capabilities<'_>>;

    /// The [`GasEnforcer`]: [`Capabilities`](Self::Capabilities) unless overridden.
    fn gas_enforcer(&mut self) -> impl GasEnforcer<S> {
        self.capabilities().inner
    }

    /// The [`SequencerAuthorization`]: [`Capabilities`](Self::Capabilities) unless
    /// overridden.
    fn sequencer_authorization(&mut self) -> impl SequencerAuthorization<S> {
        self.capabilities().inner
    }

    /// The [`TransactionAuthorizer`]: [`Capabilities`](Self::Capabilities) unless overridden.
    fn transaction_authorizer(&mut self) -> impl TransactionAuthorizer<S> {
        self.capabilities().inner
    }

    /// The [`ProofProcessor`]: [`Capabilities`](Self::Capabilities) unless overridden.
    fn proof_processor(&mut self) -> impl ProofProcessor<S> {
        self.capabilities().inner
    }

    /// The [`SequencerRemuneration`]: [`Capabilities`](Self::Capabilities) unless overridden.
    fn sequencer_remuneration(&mut self) -> impl SequencerRemuneration<S> {
        self.capabilities().inner
    }
}

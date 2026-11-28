//! [`TransactionAuthorizer`]: whether an authenticated transaction may run, and as whom.

use selendra_interface::Bytes;
use selendra_interface::da::DaSpec;
use selendra_interface::stf::ExecutionContext;
use selendra_state::{StateReader, User};

use crate::transaction::AuthorizationData;
use crate::{Context, SequencerType, Spec, StateAccessor};

/// Authorizes authenticated transactions: resolves the [`Context`] a transaction runs with (its
/// sender, from the credential that signed it and the address it asked for), and keeps a
/// transaction from running twice.
///
/// Authentication ([`TransactionAuthenticator`](super::TransactionAuthenticator)) establishes
/// who signed; this decides whether that signer may act as the sender. A credential's default
/// address ([`AuthorizationData::default_address`]) is derived from its kind of key (an EVM
/// key's account is its `0x…` address, P5-08), so an implementation that falls back to it
/// needs no conversion of its own.
pub trait TransactionAuthorizer<S: Spec> {
    /// The context of a transaction included by `sequencer` (`sequencer_rollup_address` on the
    /// rollup, of kind `sequencer_type`).
    ///
    /// # Errors
    /// The credential may not act as the sender (e.g. an address override with no entry for
    /// it): the transaction is skipped.
    #[allow(clippy::too_many_arguments)]
    fn resolve_context(
        &mut self,
        auth_data: &AuthorizationData<S>,
        sequencer: &<S::Da as DaSpec>::Address,
        sequencer_rollup_address: S::Address,
        state: &mut impl StateReader<User>,
        sequencing_data: Option<Bytes>,
        execution_context: ExecutionContext,
        sequencer_type: SequencerType,
    ) -> anyhow::Result<Context<S>>;

    /// The context of a transaction sent by an unregistered sequencer (a forced registration).
    ///
    /// # Errors
    /// As [`resolve_context`](Self::resolve_context).
    fn resolve_unregistered_context(
        &mut self,
        auth_data: &AuthorizationData<S>,
        sequencer: &<S::Da as DaSpec>::Address,
        state: &mut impl StateReader<User>,
        execution_context: ExecutionContext,
    ) -> anyhow::Result<Context<S>>;

    /// Checks that the transaction has not run (its uniqueness data and non-malleable hash).
    ///
    /// # Errors
    /// It is a duplicate, or its uniqueness data is not accepted (e.g. a stale nonce).
    fn check_uniqueness(
        &self,
        auth_data: &AuthorizationData<S>,
        context: &Context<S>,
        execution_context: &ExecutionContext,
        state: &mut impl StateReader<User>,
    ) -> anyhow::Result<()>;

    /// Marks the transaction as attempted, so it never runs again.
    ///
    /// # Errors
    /// The state could not be updated.
    fn mark_tx_attempted(
        &mut self,
        auth_data: &AuthorizationData<S>,
        sequencer: &<S::Da as DaSpec>::Address,
        state: &mut impl StateAccessor,
    ) -> anyhow::Result<()>;
}

impl<S: Spec, T: TransactionAuthorizer<S> + ?Sized> TransactionAuthorizer<S> for &mut T {
    fn resolve_context(
        &mut self,
        auth_data: &AuthorizationData<S>,
        sequencer: &<S::Da as DaSpec>::Address,
        sequencer_rollup_address: S::Address,
        state: &mut impl StateReader<User>,
        sequencing_data: Option<Bytes>,
        execution_context: ExecutionContext,
        sequencer_type: SequencerType,
    ) -> anyhow::Result<Context<S>> {
        (**self).resolve_context(
            auth_data,
            sequencer,
            sequencer_rollup_address,
            state,
            sequencing_data,
            execution_context,
            sequencer_type,
        )
    }

    fn resolve_unregistered_context(
        &mut self,
        auth_data: &AuthorizationData<S>,
        sequencer: &<S::Da as DaSpec>::Address,
        state: &mut impl StateReader<User>,
        execution_context: ExecutionContext,
    ) -> anyhow::Result<Context<S>> {
        (**self).resolve_unregistered_context(auth_data, sequencer, state, execution_context)
    }

    fn check_uniqueness(
        &self,
        auth_data: &AuthorizationData<S>,
        context: &Context<S>,
        execution_context: &ExecutionContext,
        state: &mut impl StateReader<User>,
    ) -> anyhow::Result<()> {
        (**self).check_uniqueness(auth_data, context, execution_context, state)
    }

    fn mark_tx_attempted(
        &mut self,
        auth_data: &AuthorizationData<S>,
        sequencer: &<S::Da as DaSpec>::Address,
        state: &mut impl StateAccessor,
    ) -> anyhow::Result<()> {
        (**self).mark_tx_attempted(auth_data, sequencer, state)
    }
}

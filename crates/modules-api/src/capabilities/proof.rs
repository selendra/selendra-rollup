//! [`ProofProcessor`]: processing the aggregated proofs submitted to the rollup.

use selendra_interface::stf::{ExecutionContext, InvalidProofError};
use selendra_interface::zk::aggregated_proof::{
    AggregatedProofPublicData, SerializedAggregatedProof,
};
use selendra_state::Storage;

use crate::{Spec, TxState};

/// The public data of an aggregated proof of a spec's rollup.
pub type SpecAggregatedProofPublicData<S> = AggregatedProofPublicData<
    <S as Spec>::Address,
    <S as Spec>::Da,
    <<S as Spec>::Storage as Storage>::Root,
>;

/// Processes the proofs the state transition function receives, and pays the prover.
///
/// Coupled with the [`GasEnforcer`](super::GasEnforcer): it pays the prover out of the gas
/// fees. Only aggregated zk proofs: upstream's attestations and challenges (optimistic mode)
/// are not ported.
pub trait ProofProcessor<S: Spec> {
    /// Processes `proof`, submitted by `prover_address`: verifies it, records it and rewards
    /// the prover. Returns its public data and the proof.
    ///
    /// # Errors
    /// The proof is invalid or a precondition does not hold ([`InvalidProofError`]; some
    /// errors slash or penalize the prover, whose state changes are then kept).
    fn process_aggregated_proof<ST: TxState<S>>(
        &mut self,
        proof: SerializedAggregatedProof,
        prover_address: &S::Address,
        execution_context: ExecutionContext,
        state: &mut ST,
    ) -> Result<(SpecAggregatedProofPublicData<S>, SerializedAggregatedProof), InvalidProofError>;
}

impl<S: Spec, T: ProofProcessor<S> + ?Sized> ProofProcessor<S> for &mut T {
    fn process_aggregated_proof<ST: TxState<S>>(
        &mut self,
        proof: SerializedAggregatedProof,
        prover_address: &S::Address,
        execution_context: ExecutionContext,
        state: &mut ST,
    ) -> Result<(SpecAggregatedProofPublicData<S>, SerializedAggregatedProof), InvalidProofError>
    {
        (**self).process_aggregated_proof(proof, prover_address, execution_context, state)
    }
}

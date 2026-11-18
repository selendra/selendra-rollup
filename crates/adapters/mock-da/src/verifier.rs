use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::da::{BlobReaderTrait, DaSpec, DaVerifier, RelevantBlobs, RelevantProofs};

use crate::{MockAddress, MockBlob, MockBlockHeader, MockHash};

impl BlobReaderTrait for MockBlob {
    type Address = MockAddress;
    type BlobHash = MockHash;

    fn sender(&self) -> Self::Address {
        self.address
    }

    fn hash(&self) -> Self::BlobHash {
        self.hash
    }

    fn verified_data(&self) -> &[u8] {
        self.blob.accumulator()
    }

    fn total_len(&self) -> usize {
        self.blob.total_len()
    }

    #[cfg(feature = "native")]
    fn advance(&mut self, num_bytes: usize) -> &[u8] {
        self.blob.advance(num_bytes);
        self.verified_data()
    }
}

/// The [`DaSpec`] of the mock DA layer. borsh: nothing (a unit struct).
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy, BorshSerialize, BorshDeserialize)]
pub struct MockDaSpec;

selendra_interface::impl_consensus_type!(MockDaSpec);

impl DaSpec for MockDaSpec {
    type SlotHash = MockHash;
    type BlockHeader = MockBlockHeader;
    type BlobTransaction = MockBlob;
    type TransactionId = MockHash;
    type Address = MockAddress;
    type InclusionMultiProof = [u8; 32];
    type CompletenessProof = ();
    type ChainParams = ();
}

/// The [`DaVerifier`] of the mock DA layer: it accepts every claim, whatever the header, blobs
/// and proofs. Tests and local chains only.
#[derive(Clone, Copy, Debug, Default)]
pub struct MockDaVerifier;

impl DaVerifier for MockDaVerifier {
    type Spec = MockDaSpec;
    type Error = anyhow::Error;

    fn new(_params: <Self::Spec as DaSpec>::ChainParams) -> Self {
        Self
    }

    fn verify_relevant_tx_list(
        &self,
        _block_header: &<Self::Spec as DaSpec>::BlockHeader,
        _relevant_blobs: &RelevantBlobs<<Self::Spec as DaSpec>::BlobTransaction>,
        _relevant_proofs: RelevantProofs<
            <Self::Spec as DaSpec>::InclusionMultiProof,
            <Self::Spec as DaSpec>::CompletenessProof,
        >,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use selendra_interface::common::ConsensusType;
    use selendra_interface::da::{DaProof, Time};

    use super::*;

    /// Every public borsh type of the crate can be stored and signed (D20), and so can the
    /// types modules store through the `DaSpec` (also a trait bound).
    #[test]
    fn borsh_types_are_consensus_types() {
        fn consensus<T: ConsensusType>() {}
        consensus::<MockHash>();
        consensus::<MockAddress>();
        consensus::<MockDaSpec>();
        consensus::<<MockDaSpec as DaSpec>::SlotHash>();
        consensus::<<MockDaSpec as DaSpec>::Address>();
    }

    #[test]
    fn spec_encodes_to_nothing() {
        assert!(borsh::to_vec(&MockDaSpec).unwrap().is_empty());
        assert!(borsh::from_slice::<MockDaSpec>(&[]).is_ok());
        assert!(borsh::from_slice::<MockDaSpec>(&[0]).is_err());
    }

    #[test]
    fn verifier_accepts_every_claim() {
        let verifier = MockDaVerifier::new(());
        let blob = MockBlob::new(vec![1], MockAddress::new([1; 32]), [2; 32]);
        let proof = || DaProof {
            inclusion_proof: [3; 32],
            completeness_proof: (),
        };
        let result = verifier.verify_relevant_tx_list(
            &MockBlockHeader::new(1, Time::from_millis(0)),
            &RelevantBlobs {
                proof_blobs: vec![blob.clone()],
                batch_blobs: vec![blob],
            },
            RelevantProofs {
                batch: proof(),
                proof: proof(),
            },
        );
        assert!(result.is_ok());
    }
}

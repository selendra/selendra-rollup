use std::fmt::Debug;

use borsh::BorshSerialize;
use selendra_interface::da::DaSpec;
use selendra_interface::zk::aggregated_proof::{
    BlockProof, OuterZkvmHost, SerializedAggregatedProof,
};
use selendra_interface::zk::{SerializedZkProof, ZkvmHost};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{MockCodeCommitment, MockProof, MockZkGuest, encode_hint};

/// The host of the mock zkVM: it makes [`MockProof`]s without running a guest.
///
/// [`ZkvmHost::add_hint_deferred_and_run`] returns at once a valid proof of the host's program
/// with an empty public output (there is no guest run to commit one); proofs with an output are
/// made with [`Self::create_serialized_proof`].
#[derive(Clone, Debug, Default)]
pub struct MockZkvmHost {
    code_commitment: MockCodeCommitment,
}

impl MockZkvmHost {
    /// A host of the program with the all-zero code commitment.
    pub fn new() -> Self {
        Self::default()
    }

    /// The same host, for the program `code_commitment`.
    pub fn with_code_commitment(mut self, code_commitment: MockCodeCommitment) -> Self {
        self.code_commitment = code_commitment;
        self
    }

    /// A proof of the program `code_commitment` whose public output is `pub_data`
    /// (borsh-encoded), valid or not as `is_valid` says.
    pub fn create_serialized_proof<T: BorshSerialize>(
        is_valid: bool,
        pub_data: &T,
        code_commitment: MockCodeCommitment,
    ) -> std::io::Result<SerializedZkProof> {
        MockProof::with_public_data(is_valid, pub_data, code_commitment)?.to_serialized_proof()
    }
}

impl ZkvmHost for MockZkvmHost {
    type Guest = MockZkGuest;

    fn code_commitment(&self) -> anyhow::Result<MockCodeCommitment> {
        Ok(self.code_commitment)
    }

    /// Checks that `item` encodes as a hint ([`encode_hint`]), then returns a valid proof with
    /// an empty public output. The aggregated proofs are ignored.
    fn add_hint_deferred_and_run<T: Serialize>(
        &mut self,
        item: &T,
        _agg_proofs: Vec<SerializedAggregatedProof>,
    ) -> anyhow::Result<SerializedZkProof> {
        encode_hint(item)?;
        Ok(MockProof::new(true, Vec::new(), self.code_commitment).to_serialized_proof()?)
    }
}

/// The outer (aggregation) host of the mock zkVM. There is no aggregation circuit yet
/// (Phase 12), so it refuses every aggregation.
#[derive(Clone, Copy, Debug, Default)]
pub struct MockOuterZkvmHost;

impl OuterZkvmHost for MockOuterZkvmHost {
    /// Always an error: the aggregation circuit does not exist yet.
    fn run_proof_aggregation<
        Address: Serialize + DeserializeOwned + Clone,
        Da: DaSpec,
        Root: Serialize + DeserializeOwned + Clone + PartialEq + Debug,
    >(
        &self,
        _headers_with_block_proofs: Vec<(Da::BlockHeader, BlockProof<Address, Da, Root>)>,
    ) -> anyhow::Result<SerializedAggregatedProof> {
        anyhow::bail!("the mock zkVM cannot aggregate proofs: there is no aggregation circuit yet")
    }
}

#[cfg(test)]
mod tests {
    use selendra_interface::zk::ZkVerifier;
    use selendra_interface::zk::aggregated_proof::BlockProof;

    use super::*;
    use crate::{MockProofError, MockZkVerifier};

    /// A `DaSpec` for the aggregation test (the mock DA layer is another crate).
    #[derive(
        Debug, Default, PartialEq, Eq, Clone, borsh::BorshSerialize, borsh::BorshDeserialize,
    )]
    struct TestDa;

    impl DaSpec for TestDa {
        type SlotHash = selendra_interface::common::HexHash;
        type BlockHeader = TestHeader;
        type BlobTransaction = TestBlob;
        type TransactionId = selendra_interface::common::HexHash;
        type Address = selendra_primitives::Address;
        type InclusionMultiProof = ();
        type CompletenessProof = ();
        type ChainParams = ();
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestHeader;

    impl selendra_interface::da::BlockHeaderTrait for TestHeader {
        type Hash = selendra_interface::common::HexHash;

        fn prev_hash(&self) -> Self::Hash {
            Self::Hash::new([0; 32])
        }

        fn hash(&self) -> Self::Hash {
            Self::Hash::new([1; 32])
        }

        fn height(&self) -> u64 {
            0
        }

        fn time(&self) -> selendra_interface::da::Time {
            selendra_interface::da::Time::from_millis(0)
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct TestBlob;

    impl selendra_interface::da::BlobReaderTrait for TestBlob {
        type Address = selendra_primitives::Address;
        type BlobHash = selendra_interface::common::HexHash;

        fn sender(&self) -> Self::Address {
            selendra_primitives::Address::new([0; 28])
        }

        fn hash(&self) -> Self::BlobHash {
            Self::BlobHash::new([0; 32])
        }

        fn verified_data(&self) -> &[u8] {
            &[]
        }

        fn total_len(&self) -> usize {
            0
        }

        fn advance(&mut self, _num_bytes: usize) -> &[u8] {
            &[]
        }
    }

    #[test]
    fn host_proofs_verify_against_its_program() {
        let program = MockCodeCommitment(*b"binary01binary01binary01binary01");
        let mut host = MockZkvmHost::new().with_code_commitment(program);
        assert_eq!(host.code_commitment().unwrap(), program);
        let proof = host
            .add_hint_deferred_and_run(&("hint", 1u64), Vec::new())
            .unwrap();
        MockZkVerifier::verify_with_proof::<()>(&proof, &program).unwrap();
        assert!(matches!(
            MockZkVerifier::verify_with_proof::<()>(&proof, &MockCodeCommitment::default()),
            Err(MockProofError::CodeCommitmentMismatch { .. })
        ));
    }

    #[test]
    fn created_proofs_carry_their_output() {
        let program = MockCodeCommitment([5; 32]);
        let valid = MockZkvmHost::create_serialized_proof(true, &42u64, program).unwrap();
        assert_eq!(
            MockZkVerifier::verify_with_proof::<u64>(&valid, &program).unwrap(),
            42
        );
        let invalid = MockZkvmHost::create_serialized_proof(false, &42u64, program).unwrap();
        assert!(matches!(
            MockZkVerifier::verify_with_proof::<u64>(&invalid, &program),
            Err(MockProofError::Invalid)
        ));
    }

    #[test]
    fn outer_host_refuses_to_aggregate() {
        let result = MockOuterZkvmHost
            .run_proof_aggregation::<selendra_primitives::Address, TestDa, [u8; 32]>(Vec::<(
                TestHeader,
                BlockProof<selendra_primitives::Address, TestDa, [u8; 32]>,
            )>::new(
            ));
        assert!(result.is_err());
    }
}

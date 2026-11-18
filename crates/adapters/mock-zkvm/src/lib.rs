//! A mock zkVM for tests and local chains.
//!
//! A [`MockProof`] is a claim, not a proof: it states its own validity, the program
//! ([`MockCodeCommitment`]) and the public output, and [`MockZkVerifier`] believes it. So a rollup
//! proven with the mock zkVM trusts its provers. Never use it on a network with value.
//!
//! - [`MockZkVerifier`] checks the claimed validity and code commitment and decodes the public
//!   output with borsh, rejecting trailing bytes. Malformed proofs are errors, never panics.
//! - [`MockZkGuest`] reads its hint with postcard and requires every byte to be consumed;
//!   [`ZkvmGuest::commit`](selendra_interface::zk::ZkvmGuest::commit) appends borsh bytes to the
//!   public output (like SP1's `commit_slice`).
//! - Natively, `MockZkvmHost` makes proofs without running a guest, and `MockOuterZkvmHost`
//!   refuses to aggregate (there is no aggregation circuit yet, Phase 12).
//!
//! Encodings: `docs/serialization.md`, "Mock adapters".

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod guest;
#[cfg(feature = "native")]
mod host;

use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
pub use guest::{HintError, MockZkGuest, encode_hint};
#[cfg(feature = "native")]
pub use host::{MockOuterZkvmHost, MockZkvmHost};
use selendra_interface::common::{HexHash, hex_string_serde};
use selendra_interface::zk::aggregated_proof::CodeCommitmentHash;
use selendra_interface::zk::aggregated_proof::common::SerializedPubValues;
use selendra_interface::zk::{CodeCommitmentTrait, SerializedZkProof, ZkVerifier, Zkvm};
use selendra_primitives::crypto::Ed25519CryptoSpec;

// `selendra-interface/native` adds `Zkvm::Host`/`Zkvm::OuterHost`, which this crate implements
// only with its own `native` feature. Cargo cannot make the first imply the second (the
// dependency points the other way), so say what to do instead of failing with a missing item.
#[cfg(not(feature = "native"))]
selendra_interface::__if_native! {
    compile_error!(
        "`selendra-interface/native` is enabled but `selendra-mock-zkvm/native` is not: enable both"
    );
}

/// The mock zkVM.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MockZkvm;

impl Zkvm for MockZkvm {
    type Verifier = MockZkVerifier;
    type Guest = MockZkGuest;

    #[cfg(feature = "native")]
    type Host = MockZkvmHost;

    #[cfg(feature = "native")]
    type OuterHost = MockOuterZkvmHost;
}

/// A commitment to a mock zkVM program: 32 bytes, the same as its [`CodeCommitmentHash`].
///
/// borsh: the 32 bytes. JSON: `0x` + 64 lowercase hex digits, and nothing else. Binary serde
/// formats: a sequence of 32 bytes.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct MockCodeCommitment(#[serde(with = "hex_string_serde")] pub [u8; 32]);

impl fmt::Debug for MockCodeCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MockCodeCommitment({})", HexHash::new(self.0))
    }
}

impl CodeCommitmentTrait for MockCodeCommitment {
    fn to_hash(&self) -> CodeCommitmentHash {
        CodeCommitmentHash::from_u8_array(self.0)
    }

    fn from_hash(hash: CodeCommitmentHash) -> Self {
        Self(hash.to_u8_array())
    }
}

/// A mock proof: the claim that the program `code_commitment` ran and committed `pub_data`,
/// valid if `is_valid` says so.
///
/// borsh: `is_valid` (one byte, `0` or `1`) ‖ `pub_data` (`u32` LE length, then the bytes) ‖
/// `code_commitment` (32 bytes); decoded with `borsh::from_slice` (no trailing bytes).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MockProof {
    is_valid: bool,
    pub_data: Vec<u8>,
    code_commitment: MockCodeCommitment,
}

selendra_interface::impl_consensus_type!(MockCodeCommitment, MockProof);

impl MockProof {
    /// A proof claiming that `code_commitment` committed `pub_data` (raw bytes: the borsh
    /// encoding of the public output), valid or not as `is_valid` says.
    pub fn new(is_valid: bool, pub_data: Vec<u8>, code_commitment: MockCodeCommitment) -> Self {
        Self {
            is_valid,
            pub_data,
            code_commitment,
        }
    }

    /// A proof whose public output is `pub_data`, borsh-encoded.
    pub fn with_public_data<T: BorshSerialize>(
        is_valid: bool,
        pub_data: &T,
        code_commitment: MockCodeCommitment,
    ) -> std::io::Result<Self> {
        Ok(Self::new(
            is_valid,
            borsh::to_vec(pub_data)?,
            code_commitment,
        ))
    }

    /// Whether the proof claims to be valid.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// The public output: the borsh bytes the program committed.
    pub fn pub_data(&self) -> &[u8] {
        &self.pub_data
    }

    /// The program the proof claims to be of.
    pub fn code_commitment(&self) -> &MockCodeCommitment {
        &self.code_commitment
    }

    /// The proof's borsh encoding. Fails only for public data over `u32::MAX` bytes.
    pub fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
        borsh::to_vec(self)
    }

    /// The proof's borsh encoding as a [`SerializedZkProof`].
    pub fn to_serialized_proof(&self) -> std::io::Result<SerializedZkProof> {
        Ok(SerializedZkProof {
            raw_proof: self.to_bytes()?,
        })
    }

    /// Decodes a proof, rejecting trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MockProofError> {
        borsh::from_slice(bytes).map_err(MockProofError::Malformed)
    }

    /// The public output, if the proof claims to be valid and to be of the program
    /// `code_commitment`. The output is decoded with borsh, rejecting trailing bytes.
    pub fn verify<T: BorshDeserialize>(
        &self,
        code_commitment: &MockCodeCommitment,
    ) -> Result<T, MockProofError> {
        if !self.is_valid {
            return Err(MockProofError::Invalid);
        }
        if self.code_commitment != *code_commitment {
            return Err(MockProofError::CodeCommitmentMismatch {
                claimed: self.code_commitment,
                expected: *code_commitment,
            });
        }
        self.public_data()
    }

    /// The claimed public output, decoded with borsh (rejecting trailing bytes), whether or not
    /// the proof is valid.
    pub fn public_data<T: BorshDeserialize>(&self) -> Result<T, MockProofError> {
        borsh::from_slice(&self.pub_data).map_err(MockProofError::PublicData)
    }
}

/// Why [`MockZkVerifier`] rejected a proof.
#[derive(Debug, thiserror::Error)]
pub enum MockProofError {
    /// The bytes are not a [`MockProof`].
    #[error("malformed mock proof: {0}")]
    Malformed(#[source] std::io::Error),
    /// The proof claims to be invalid.
    #[error("the mock proof is marked invalid")]
    Invalid,
    /// The proof is of another program.
    #[error("code commitment mismatch: the proof claims {claimed:?}, expected {expected:?}")]
    CodeCommitmentMismatch {
        /// The program the proof claims to be of.
        claimed: MockCodeCommitment,
        /// The program the verifier expected.
        expected: MockCodeCommitment,
    },
    /// The public output does not decode as the expected type.
    #[error("the mock proof's public data does not decode: {0}")]
    PublicData(#[source] std::io::Error),
}

/// The verifier of [`MockProof`]s. Its [`CryptoSpec`](selendra_interface::zk::CryptoSpec) is
/// the native ed25519 one.
///
/// ```
/// use selendra_interface::zk::ZkVerifier;
/// use selendra_mock_zkvm::{MockCodeCommitment, MockProof, MockProofError, MockZkVerifier};
///
/// let program = MockCodeCommitment([1; 32]);
/// let proof = MockProof::with_public_data(true, &42u64, program)?.to_serialized_proof()?;
/// assert_eq!(MockZkVerifier::verify_with_proof::<u64>(&proof, &program)?, 42);
///
/// let other = MockCodeCommitment([2; 32]);
/// assert!(matches!(
///     MockZkVerifier::verify_with_proof::<u64>(&proof, &other),
///     Err(MockProofError::CodeCommitmentMismatch { .. })
/// ));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MockZkVerifier;

impl ZkVerifier for MockZkVerifier {
    type CodeCommitment = MockCodeCommitment;
    type CryptoSpec = Ed25519CryptoSpec;
    type Error = MockProofError;

    /// The mock has no proof input channel: `pub_values` holds the whole encoded
    /// [`MockProof`] (SP1's deferred proofs, in band).
    fn verify_with_pub_values<T: BorshDeserialize>(
        pub_values: &SerializedPubValues,
        code_commitment: &Self::CodeCommitment,
    ) -> Result<T, Self::Error> {
        MockProof::from_bytes(&pub_values.pub_values)?.verify(code_commitment)
    }

    fn verify_with_proof<T: BorshDeserialize>(
        serialized_proof: &SerializedZkProof,
        code_commitment: &Self::CodeCommitment,
    ) -> Result<T, Self::Error> {
        MockProof::from_bytes(&serialized_proof.raw_proof)?.verify(code_commitment)
    }

    fn extract_public_data<T: BorshDeserialize>(
        serialized_proof: &SerializedZkProof,
    ) -> Result<T, Self::Error> {
        MockProof::from_bytes(&serialized_proof.raw_proof)?.public_data()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::any;
    use selendra_interface::common::ConsensusType;
    use selendra_interface::zk::CodeCommitmentFor;

    use super::*;

    const PROGRAM: MockCodeCommitment = MockCodeCommitment([0xc0; 32]);

    #[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq)]
    struct PublicData {
        height: u64,
        root: [u8; 4],
    }

    const PUBLIC_DATA: PublicData = PublicData {
        height: 7,
        root: [1, 2, 3, 4],
    };

    fn proof(is_valid: bool, code_commitment: MockCodeCommitment) -> SerializedZkProof {
        MockProof::with_public_data(is_valid, &PUBLIC_DATA, code_commitment)
            .unwrap()
            .to_serialized_proof()
            .unwrap()
    }

    /// With and without `native` (the guest configuration runs this too).
    #[test]
    fn mock_zkvm_is_a_zkvm() {
        fn zkvm<Vm: Zkvm>() {}
        zkvm::<MockZkvm>();
    }

    /// Every public borsh type of the crate can be stored and signed (D20), and so can the
    /// code commitment modules store through the `Zkvm` (also a trait bound).
    #[test]
    fn borsh_types_are_consensus_types() {
        fn consensus<T: ConsensusType>() {}
        consensus::<MockCodeCommitment>();
        consensus::<MockProof>();
        consensus::<CodeCommitmentFor<MockZkvm>>();
    }

    /// The verifier's signatures are the native ed25519 ones, whatever the zkVM.
    #[test]
    fn crypto_spec_is_ed25519() {
        fn same<T>(_: core::marker::PhantomData<T>, _: core::marker::PhantomData<T>) {}
        same(
            core::marker::PhantomData::<<MockZkVerifier as ZkVerifier>::CryptoSpec>,
            core::marker::PhantomData::<Ed25519CryptoSpec>,
        );
    }

    #[test]
    fn code_commitment_encodings_known_answer() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xaa;
        bytes[31] = 0x55;
        let commitment = MockCodeCommitment(bytes);
        let hex = "0xaa00000000000000000000000000000000000000000000000000000000000055";
        assert_eq!(borsh::to_vec(&commitment).unwrap(), bytes);
        assert_eq!(
            serde_json::to_string(&commitment).unwrap(),
            format!("\"{hex}\"")
        );
        assert_eq!(
            serde_json::from_str::<MockCodeCommitment>(&format!("\"{hex}\"")).unwrap(),
            commitment
        );
        assert_eq!(
            format!("{commitment:?}"),
            format!("MockCodeCommitment({hex})")
        );
        // Upstream's commitment had 8 bytes, zero-padded to the 32-byte hash.
        assert_eq!(commitment.to_hash().to_u8_array(), bytes);
        assert_eq!(
            MockCodeCommitment::from_hash(commitment.to_hash()),
            commitment
        );

        assert!(serde_json::from_str::<MockCodeCommitment>(&format!("\"{}\"", &hex[2..])).is_err());
        let upper = format!("\"0x{}\"", hex[2..].to_ascii_uppercase());
        assert!(serde_json::from_str::<MockCodeCommitment>(&upper).is_err());
        assert!(borsh::from_slice::<MockCodeCommitment>(&bytes[..31]).is_err());
    }

    #[test]
    fn proof_encoding_known_answer() {
        let proof = MockProof::new(true, vec![0xde, 0xad], MockCodeCommitment([0x11; 32]));
        let mut expected = vec![1, 2, 0, 0, 0, 0xde, 0xad];
        expected.extend([0x11; 32]);
        assert_eq!(proof.to_bytes().unwrap(), expected);
        assert_eq!(MockProof::from_bytes(&expected).unwrap(), proof);

        // `PublicData { height: 7, root: [1, 2, 3, 4] }`: u64 LE, then 4 bytes.
        let proof = MockProof::with_public_data(false, &PUBLIC_DATA, PROGRAM).unwrap();
        assert_eq!(proof.pub_data(), [7, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
        assert!(!proof.is_valid());
        assert_eq!(*proof.code_commitment(), PROGRAM);
    }

    #[test]
    fn verifier_accepts_valid_proofs() {
        let proof = proof(true, PROGRAM);
        assert_eq!(
            MockZkVerifier::verify_with_proof::<PublicData>(&proof, &PROGRAM).unwrap(),
            PUBLIC_DATA
        );
        let pub_values = SerializedPubValues {
            pub_values: proof.raw_proof.clone(),
        };
        assert_eq!(
            MockZkVerifier::verify_with_pub_values::<PublicData>(&pub_values, &PROGRAM).unwrap(),
            PUBLIC_DATA
        );
        assert_eq!(
            MockZkVerifier::extract_public_data::<PublicData>(&proof).unwrap(),
            PUBLIC_DATA
        );
    }

    #[test]
    fn verifier_rejects_invalid_proofs() {
        let invalid = proof(false, PROGRAM);
        assert!(matches!(
            MockZkVerifier::verify_with_proof::<PublicData>(&invalid, &PROGRAM),
            Err(MockProofError::Invalid)
        ));
        // The claimed output can still be read (untrusted).
        assert_eq!(
            MockZkVerifier::extract_public_data::<PublicData>(&invalid).unwrap(),
            PUBLIC_DATA
        );

        let other_program = MockCodeCommitment([0xc1; 32]);
        let err =
            MockZkVerifier::verify_with_proof::<PublicData>(&proof(true, other_program), &PROGRAM)
                .unwrap_err();
        assert!(matches!(
            err,
            MockProofError::CodeCommitmentMismatch { claimed, expected }
                if claimed == other_program && expected == PROGRAM
        ));
        assert!(err.to_string().contains("code commitment mismatch"));

        // Public data of another type: too short, and with bytes left over.
        let proof = proof(true, PROGRAM);
        assert!(matches!(
            MockZkVerifier::verify_with_proof::<(u64, [u8; 8])>(&proof, &PROGRAM),
            Err(MockProofError::PublicData(_))
        ));
        assert!(matches!(
            MockZkVerifier::verify_with_proof::<u64>(&proof, &PROGRAM),
            Err(MockProofError::PublicData(_))
        ));
    }

    // Regressions of upstream's mock zkVM bugs

    /// P5-42 (the proof side): one proof must have one encoding. Upstream's proofs were bincode
    /// (strict at c7046e2, its hints were not: `guest.rs`); ours are borsh, decoded with
    /// `from_slice`. A proof with a trailing byte is rejected by every verifier entry point
    /// (decoding with `BorshDeserialize::deserialize` on a slice would accept it).
    #[test]
    fn mock_proof_rejects_trailing_bytes() {
        let mut proof = proof(true, PROGRAM);
        proof.raw_proof.push(0);
        assert!(matches!(
            MockProof::from_bytes(&proof.raw_proof),
            Err(MockProofError::Malformed(_))
        ));
        assert!(matches!(
            MockZkVerifier::verify_with_proof::<PublicData>(&proof, &PROGRAM),
            Err(MockProofError::Malformed(_))
        ));
        assert!(matches!(
            MockZkVerifier::extract_public_data::<PublicData>(&proof),
            Err(MockProofError::Malformed(_))
        ));
        let pub_values = SerializedPubValues {
            pub_values: proof.raw_proof,
        };
        assert!(matches!(
            MockZkVerifier::verify_with_pub_values::<PublicData>(&pub_values, &PROGRAM),
            Err(MockProofError::Malformed(_))
        ));
    }

    /// P5-42 (the proof side): garbage is an error, never a panic (upstream's host `expect`ed
    /// inner proofs to decode). Includes a length prefix far beyond the input and a `bool`
    /// byte of 2.
    #[test]
    fn mock_proof_rejects_garbage() {
        let mut huge_length = vec![1, 0xff, 0xff, 0xff, 0xff];
        huge_length.extend([0; 32]);
        let mut bad_bool = proof(true, PROGRAM).raw_proof;
        bad_bool[0] = 2;
        for garbage in [vec![], vec![1], vec![0xff; 64], huge_length, bad_bool] {
            let proof = SerializedZkProof { raw_proof: garbage };
            assert!(matches!(
                MockZkVerifier::verify_with_proof::<PublicData>(&proof, &PROGRAM),
                Err(MockProofError::Malformed(_))
            ));
        }
    }

    #[test_strategy::proptest]
    fn proof_round_trips(
        is_valid: bool,
        pub_data: Vec<u8>,
        #[strategy(any::<[u8; 32]>())] commitment: [u8; 32],
    ) {
        let proof = MockProof::new(is_valid, pub_data, MockCodeCommitment(commitment));
        let bytes = proof.to_bytes().unwrap();
        assert_eq!(MockProof::from_bytes(&bytes).unwrap(), proof);
        let commitment = MockCodeCommitment(commitment);
        let json = serde_json::to_string(&commitment).unwrap();
        assert_eq!(
            serde_json::from_str::<MockCodeCommitment>(&json).unwrap(),
            commitment
        );
    }
}

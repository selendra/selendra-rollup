//! Types related to aggregated proofs.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::common::SlotNumber;
use crate::da::DaSpec;
use crate::zk::SerializedZkProof;

/// A code commitment hash used to identify ZK circuits (both inner and outer).
///
/// Always exactly [`Self::HASH_LEN`] bytes: the type enforces the length, so decoding
/// can never yield a short hash.
#[derive(
    Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Default,
)]
pub struct CodeCommitmentHash([u8; CodeCommitmentHash::HASH_LEN]);

impl From<[u8; CodeCommitmentHash::HASH_LEN]> for CodeCommitmentHash {
    fn from(bytes: [u8; CodeCommitmentHash::HASH_LEN]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for CodeCommitmentHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl CodeCommitmentHash {
    /// Byte length of every code commitment hash.
    pub const HASH_LEN: usize = 32;

    /// Creates a [`CodeCommitmentHash`] from a `[u8; HASH_LEN]` array.
    pub const fn from_u8_array(bytes: [u8; Self::HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the hash bytes.
    pub const fn to_u8_array(&self) -> [u8; Self::HASH_LEN] {
        self.0
    }

    /// Creates a [`CodeCommitmentHash`] from a `[u32; 8]` array using big-endian byte order.
    /// This matches the representation used by SP1's `HashableKey::hash_bytes`.
    pub fn from_u32_array(arr: [u32; 8]) -> Self {
        let mut bytes = [0u8; Self::HASH_LEN];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(arr) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        Self(bytes)
    }

    /// Converts this hash back to a `[u32; 8]` array using big-endian byte order.
    pub fn to_u32_array(&self) -> [u32; 8] {
        let mut arr = [0u32; 8];
        for (word, chunk) in arr.iter_mut().zip(self.0.chunks_exact(4)) {
            *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        arr
    }
}

impl core::fmt::Display for CodeCommitmentHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CodeCommitmentHash(0x{})", hex::encode(self.0))
    }
}

/// Public data of an aggregated proof.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone, BorshDeserialize, BorshSerialize)]
pub struct AggregatedProofPublicData<Address, Da: DaSpec, Root> {
    /// Initial rollup slot.
    pub initial_slot_number: SlotNumber,
    /// Final rollup slot.
    pub final_slot_number: SlotNumber,
    /// The slot number that [`Self::origin_state_root`] corresponds to: the slot
    /// at the end of which the chain's origin state root was produced. When the
    /// chain extends unbroken from the rollup's genesis, this equals
    /// [`SlotNumber::GENESIS`].
    pub origin_slot_number: SlotNumber,
    /// The origin state root of the aggregated proof: the initial state root of the
    /// first inner proof in this aggregation's chain. When the chain extends unbroken
    /// from the rollup's genesis, this equals the rollup's genesis state root.
    pub origin_state_root: Root,
    /// The initial state root of the aggregated proof.
    pub initial_state_root: Root,
    /// The final state root of the aggregated proof.
    pub final_state_root: Root,
    /// The initial slot hash of the aggregated proof.
    pub initial_slot_hash: Da::SlotHash,
    /// The final slot hash of the aggregated proof.
    pub final_slot_hash: Da::SlotHash,
    /// Inner verifying key hash of the aggregated proof circuit.
    pub inner_vkey_hash: CodeCommitmentHash,
    /// Outer verifying key hash of the aggregated proof circuit.
    pub outer_vk_hash: CodeCommitmentHash,
    /// These are the addresses of the provers who proved individual blocks.
    pub rewarded_addresses: Vec<Address>,
}

impl<Address, Da: DaSpec, Root: AsRef<[u8]>> core::fmt::Display
    for AggregatedProofPublicData<Address, Da, Root>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "AggregatedProofPublicData(initial_slot_number: {}, final_slot_number: {}, origin_slot_number: {}, origin_state_root: {}, initial_state_root: 0x{}, final_state_root: 0x{}, initial_slot_hash: 0x{}, final_slot_hash: 0x{}, inner_vkey_hash: {}, outer_vk_hash: {})",
            self.initial_slot_number,
            self.final_slot_number,
            self.origin_slot_number,
            hex::encode(self.origin_state_root.as_ref()),
            hex::encode(self.initial_state_root.as_ref()),
            hex::encode(self.final_state_root.as_ref()),
            hex::encode(self.initial_slot_hash.as_ref()),
            hex::encode(self.final_slot_hash.as_ref()),
            self.inner_vkey_hash,
            self.outer_vk_hash
        )
    }
}

/// Represents a serialized aggregated proof.
#[derive(
    Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Default,
)]
pub struct SerializedAggregatedProof {
    /// Serialized proof.
    pub raw_aggregated_proof: Vec<u8>,
}

impl SerializedAggregatedProof {
    /// Converts a [`SerializedAggregatedProof`] into a [`SerializedZkProof`].
    pub fn to_serialized_zk_proof(self) -> SerializedZkProof {
        SerializedZkProof {
            raw_proof: self.raw_aggregated_proof,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_commitment_u32_roundtrip_is_big_endian() {
        let words = [0x01020304, 0, 0, 0, 0, 0, 0, 0xa0b0c0d0];
        let hash = CodeCommitmentHash::from_u32_array(words);
        assert_eq!(&hash.as_ref()[..4], &[1, 2, 3, 4]);
        assert_eq!(&hash.as_ref()[28..], &[0xa0, 0xb0, 0xc0, 0xd0]);
        assert_eq!(hash.to_u32_array(), words);
    }

    #[test]
    fn code_commitment_borsh_is_fixed_length() {
        let hash = CodeCommitmentHash::from_u8_array([7; 32]);
        let bytes = borsh::to_vec(&hash).unwrap();
        assert_eq!(bytes.len(), CodeCommitmentHash::HASH_LEN);
        assert!(borsh::from_slice::<CodeCommitmentHash>(&bytes[..31]).is_err());
        assert_eq!(
            borsh::from_slice::<CodeCommitmentHash>(&bytes).unwrap(),
            hash
        );
    }
}

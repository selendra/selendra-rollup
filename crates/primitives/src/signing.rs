//! Domain separation for every message signed with a Selendra key.
//!
//! A signature is never made over a bare payload. The signed bytes are
//!
//! ```text
//! 0xB5 "SELENDRA" | version (1 byte) | domain (1 byte) | chain_id (u64 LE) | payload
//! ```
//!
//! The header has a fixed length, so header and payload cannot be confused, and:
//! - `domain` keeps a signature for one purpose (e.g. an off-chain login message) from
//!   being valid for another (e.g. a transaction);
//! - `chain_id` keeps a signature for one Selendra network from being replayed on another;
//! - the first byte `0xB5` is outside the ranges Ethereum signs (`0x00..=0x7f` typed
//!   transactions, `0xc0..=0xff` legacy RLP transactions, `0x19` EIP-191/EIP-712), so a
//!   Selendra message signed with a secp256k1 key is never also a valid Ethereum payload.
//!
//! Transactions (Phase 5) and sequencer blobs (Phase 9) must sign through this module.

use selendra_interface::crypto::{SigVerificationError, Signature};

/// The Selendra EVM / network chain id (registered as "Selendra Network Mainnet").
pub const SELENDRA_CHAIN_ID: u64 = 1961;

/// Magic prefix of every signed message.
pub const MAGIC: &[u8; 9] = b"\xb5SELENDRA";

/// Version of the signed-message layout. Bump it if the header ever changes.
pub const SIGNING_VERSION: u8 = 1;

/// Length of the header in front of the payload.
pub const HEADER_LEN: usize = MAGIC.len() + 1 + 1 + 8;

/// What a signature authorizes. The byte values are part of the protocol: never reuse one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SigningDomain {
    /// A rollup transaction.
    Transaction = 1,
    /// A batch blob posted to the DA layer by a sequencer.
    SequencerBlob = 2,
    /// An off-chain message (e.g. wallet sign-in). Never valid on-chain.
    OffchainMessage = 3,
}

/// Returns the exact bytes that are signed for `payload` in `domain` on `chain_id`.
pub fn signing_bytes(domain: SigningDomain, chain_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(SIGNING_VERSION);
    bytes.push(domain as u8);
    bytes.extend_from_slice(&chain_id.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// Verifies `signature` over `payload` in `domain` on `chain_id`.
pub fn verify<S: Signature>(
    signature: &S,
    public_key: &S::PublicKey,
    domain: SigningDomain,
    chain_id: u64,
    payload: &[u8],
) -> Result<(), SigVerificationError> {
    signature.verify(public_key, &signing_bytes(domain, chain_id, payload))
}

/// Signs `payload` in `domain` on `chain_id`. Only available with the `native` feature.
#[cfg(feature = "native")]
pub fn sign<K: selendra_interface::crypto::PrivateKey>(
    key: &K,
    domain: SigningDomain,
    chain_id: u64,
    payload: &[u8],
) -> K::Signature {
    key.sign(&signing_bytes(domain, chain_id, payload))
}

#[cfg(test)]
mod tests {
    use selendra_interface::crypto::PrivateKey;

    use super::*;
    use crate::crypto::{Ed25519PrivateKey, EthereumPrivateKey};

    #[test]
    fn header_layout_is_fixed() {
        let bytes = signing_bytes(SigningDomain::Transaction, SELENDRA_CHAIN_ID, b"abc");
        let mut expected = b"\xb5SELENDRA".to_vec();
        expected.push(1); // version
        expected.push(1); // Transaction
        expected.extend_from_slice(&1961u64.to_le_bytes());
        expected.extend_from_slice(b"abc");
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), HEADER_LEN + 3);
    }

    #[test]
    fn first_byte_is_not_an_ethereum_signing_prefix() {
        let first = MAGIC[0];
        assert!(first > 0x7f, "EIP-2718 typed transactions use 0x00..=0x7f");
        assert!(
            first < 0xc0,
            "legacy RLP transactions start with a list prefix 0xc0..=0xff"
        );
        assert_ne!(first, 0x19, "EIP-191 / EIP-712");
    }

    fn check_separation<K: PrivateKey>(key: K) {
        let pk = key.pub_key();
        let sig = sign(
            &key,
            SigningDomain::Transaction,
            SELENDRA_CHAIN_ID,
            b"payload",
        );

        verify(
            &sig,
            &pk,
            SigningDomain::Transaction,
            SELENDRA_CHAIN_ID,
            b"payload",
        )
        .unwrap();
        // Wrong purpose, wrong network, wrong payload, or a bare signature: all rejected.
        for domain in [SigningDomain::SequencerBlob, SigningDomain::OffchainMessage] {
            assert!(verify(&sig, &pk, domain, SELENDRA_CHAIN_ID, b"payload").is_err());
        }
        for chain_id in [0, 1, 1953, 2027, u64::MAX] {
            assert!(verify(&sig, &pk, SigningDomain::Transaction, chain_id, b"payload").is_err());
        }
        assert!(
            verify(
                &sig,
                &pk,
                SigningDomain::Transaction,
                SELENDRA_CHAIN_ID,
                b"other"
            )
            .is_err()
        );
        assert!(sig.verify(&pk, b"payload").is_err());
        // A signature over a bare payload is not valid in any domain.
        let bare = key.sign(b"payload");
        assert!(
            verify(
                &bare,
                &pk,
                SigningDomain::Transaction,
                SELENDRA_CHAIN_ID,
                b"payload"
            )
            .is_err()
        );
    }

    #[test]
    fn separation_holds_for_both_key_types() {
        check_separation(Ed25519PrivateKey::generate());
        check_separation(EthereumPrivateKey::generate());
    }
}

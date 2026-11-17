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
//! Native transactions (Phase 5) and sequencer blobs (Phase 9) must sign through this module.
//! The signed bytes are a [`SigningBytes`], which only [`signing_bytes`] can build: an API that
//! takes `&SigningBytes` (a transaction's `verify_signature`, the authenticator) cannot be
//! handed a bare payload. [`selendra_interface::crypto::Signature::verify`] and
//! `PrivateKey::sign` take any bytes: they are
//! the low-level layer below this module, for key tests and test vectors only.
//!
//! Exception: Ethereum transactions (EIP-155 legacy/typed and EIP-712 typed data) keep their
//! Ethereum signing rules, because browser and hardware Ethereum wallets cannot sign
//! `0xB5…` bytes. Their domain separation comes from Ethereum's own rules: EIP-155 chain ID
//! `SELENDRA_CHAIN_ID`, or the EIP-712 domain (chain ID, name, version, and a salt carrying
//! the runtime commitment). So native secp256k1 transactions and `OffchainMessage` are for
//! software keys only; wallet users sign transactions through EIP-712 and log in via
//! EIP-4361 / `personal_sign`. Wallets and SDKs that show a native message to the user
//! (clear signing) must show or prepend this header, not just the payload.

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
    ///
    /// The payload is a fixed-size digest, not the blob: `sha256(blob) ‖ avail_block ‖
    /// nonce`. ed25519 hashes the whole signed message with SHA-512, which SP1 does not
    /// accelerate, so signing a multi-MB blob directly would cost the guest a software
    /// SHA-512 over every byte (SHA-256 is accelerated). The Avail block number and nonce
    /// stop a blob from being re-posted.
    SequencerBlob = 2,
    /// An off-chain message (e.g. wallet sign-in). Never valid on-chain.
    OffchainMessage = 3,
}

/// The exact bytes a Selendra signature covers: the header (magic, version, domain, chain ID)
/// followed by the payload.
///
/// Only [`signing_bytes`] builds one, so holding a `SigningBytes` proves the header is there.
/// P5-07 (regression, the type part): upstream's signed bytes were a bare `Vec<u8>`, so code
/// could sign or verify a payload without the header. The field is private:
///
/// ```compile_fail,E0423
/// use selendra_primitives::signing::SigningBytes;
/// let bare = SigningBytes(b"payload".to_vec());
/// ```
///
/// ```
/// use selendra_primitives::signing::{SELENDRA_CHAIN_ID, SigningDomain, signing_bytes};
/// let bytes = signing_bytes(SigningDomain::Transaction, SELENDRA_CHAIN_ID, b"payload");
/// assert!(bytes.as_bytes().ends_with(b"payload"));
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SigningBytes(Vec<u8>);

impl SigningBytes {
    /// The signed bytes, header included.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The length of the signed bytes, header included.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: the header is never empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for SigningBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SigningBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SigningBytes(0x{})", hex::encode(&self.0))
    }
}

/// Returns the exact bytes that are signed for `payload` in `domain` on `chain_id`.
pub fn signing_bytes(domain: SigningDomain, chain_id: u64, payload: &[u8]) -> SigningBytes {
    let mut bytes = Vec::with_capacity(HEADER_LEN.saturating_add(payload.len()));
    bytes.extend_from_slice(MAGIC);
    bytes.push(SIGNING_VERSION);
    bytes.push(domain as u8);
    bytes.extend_from_slice(&chain_id.to_le_bytes());
    bytes.extend_from_slice(payload);
    SigningBytes(bytes)
}

/// Verifies `signature` over already-built signing bytes.
pub fn verify_signing_bytes<S: Signature>(
    signature: &S,
    public_key: &S::PublicKey,
    bytes: &SigningBytes,
) -> Result<(), SigVerificationError> {
    signature.verify(public_key, bytes.as_bytes())
}

/// Verifies `signature` over `payload` in `domain` on `chain_id`.
pub fn verify<S: Signature>(
    signature: &S,
    public_key: &S::PublicKey,
    domain: SigningDomain,
    chain_id: u64,
    payload: &[u8],
) -> Result<(), SigVerificationError> {
    verify_signing_bytes(
        signature,
        public_key,
        &signing_bytes(domain, chain_id, payload),
    )
}

/// Signs already-built signing bytes. Only available with the `native` feature.
#[cfg(feature = "native")]
pub fn sign_signing_bytes<K: selendra_interface::crypto::PrivateKey>(
    key: &K,
    bytes: &SigningBytes,
) -> K::Signature {
    key.sign(bytes.as_bytes())
}

/// Signs `payload` in `domain` on `chain_id`. Only available with the `native` feature.
#[cfg(feature = "native")]
pub fn sign<K: selendra_interface::crypto::PrivateKey>(
    key: &K,
    domain: SigningDomain,
    chain_id: u64,
    payload: &[u8],
) -> K::Signature {
    sign_signing_bytes(key, &signing_bytes(domain, chain_id, payload))
}

#[cfg(test)]
mod tests {
    use selendra_interface::crypto::PrivateKey;

    use super::*;
    use crate::crypto::{Ed25519PrivateKey, EthereumPrivateKey};

    #[test]
    fn header_layout_is_fixed() {
        let bytes = signing_bytes(SigningDomain::Transaction, SELENDRA_CHAIN_ID, b"abc");
        let bytes = bytes.as_bytes();
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

    fn check_signing_bytes_api<K: PrivateKey>(key: K) {
        let pk = key.pub_key();
        let bytes = signing_bytes(SigningDomain::OffchainMessage, 7, b"msg");
        let sig = sign_signing_bytes(&key, &bytes);
        verify_signing_bytes(&sig, &pk, &bytes).unwrap();
        verify(&sig, &pk, SigningDomain::OffchainMessage, 7, b"msg").unwrap();
        let other = signing_bytes(SigningDomain::OffchainMessage, 8, b"msg");
        assert!(verify_signing_bytes(&sig, &pk, &other).is_err());
        // The convenience functions sign the same bytes.
        let sig = sign(&key, SigningDomain::OffchainMessage, 7, b"msg");
        verify_signing_bytes(&sig, &pk, &bytes).unwrap();
    }

    #[test]
    fn signing_bytes_api_matches_the_convenience_functions() {
        check_signing_bytes_api(Ed25519PrivateKey::generate());
        check_signing_bytes_api(EthereumPrivateKey::generate());
        let bytes = signing_bytes(SigningDomain::SequencerBlob, 1, b"");
        assert_eq!(bytes.len(), HEADER_LEN);
        assert!(!bytes.is_empty());
        assert_eq!(bytes.as_ref(), bytes.as_bytes());
        assert_eq!(
            format!("{bytes:?}"),
            format!("SigningBytes(0x{})", hex::encode(bytes.as_bytes()))
        );
    }

    #[test]
    fn separation_holds_for_both_key_types() {
        check_separation(Ed25519PrivateKey::generate());
        check_separation(EthereumPrivateKey::generate());
    }
}

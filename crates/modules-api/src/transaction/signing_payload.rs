//! What a native transaction's signature covers: the signing payload
//! ([`TransactionSigningPayload`]) and how it becomes the signed bytes.
//!
//! The signed bytes are `signing_bytes(SigningDomain::Transaction, chain_id,
//! SHA-256(borsh(payload)))` (`selendra_primitives::signing`): the 19-byte header, then the
//! 32-byte prehash of the payload, so the signature's cost does not grow with the call (ed25519
//! hashes the whole signed message with SHA-512, which SP1 does not accelerate; the payload's
//! SHA-256 is accelerated and charged per byte). Upstream signed the payload's bare borsh
//! encoding (P5-07).

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::reexports::digest::Digest;
use selendra_primitives::signing::{SigningBytes, SigningDomain, signing_bytes};
use selendra_state::StateHasher;

use super::{
    RuntimeCommitment, TransactionCallable, TransactionError, TxCryptoSpec, UniquenessData,
    value_traits,
};
use crate::{ConsensusType, Spec, TxDetails};

/// The signing payload of a single-key (V0) transaction.
///
/// borsh: `runtime_call`, `uniqueness`, `details`, `signer` (the signing key), `address_override`
/// (an option), `runtime_commitment` (32 bytes). Committing to the signer's key keeps a signature
/// from being valid for another key (with ECDSA, a signature and message give other keys that
/// verify; upstream's V0 payload had no key, P5-36). JSON: an object with exactly these fields
/// (`address_override` `null` for none, never missing).
#[derive(BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, ConsensusType)]
#[serde(bound = "", deny_unknown_fields)]
pub struct TransactionSigningPayloadV0<R: TransactionCallable, S: Spec, C: TxCryptoSpec> {
    pub(crate) runtime_call: R::Call,
    pub(crate) uniqueness: UniquenessData,
    pub(crate) details: TxDetails<S>,
    pub(crate) signer: C::PublicKey,
    #[serde(deserialize_with = "super::required_option")]
    pub(crate) address_override: Option<S::Address>,
    pub(crate) runtime_commitment: RuntimeCommitment,
}

value_traits!(
    [R: TransactionCallable, S: Spec, C: TxCryptoSpec]
    TransactionSigningPayloadV0<R, S, C> {
        runtime_call,
        uniqueness,
        details,
        signer,
        address_override,
        runtime_commitment,
    }
);

/// The signing payload of a multisig (V1) transaction.
///
/// borsh: `runtime_call`, `uniqueness`, `details`, `credential_address` (the multisig
/// credential's default address), `address_override`, `runtime_commitment`. The credential
/// address commits to the multisig's keys and threshold, so the signatures cannot be reused in
/// an envelope with other keys or another threshold, and every subset of signers signs the same
/// bytes. JSON: an object with exactly these fields.
#[derive(BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, ConsensusType)]
#[serde(bound = "", deny_unknown_fields)]
pub struct TransactionSigningPayloadV1<R: TransactionCallable, S: Spec> {
    pub(crate) runtime_call: R::Call,
    pub(crate) uniqueness: UniquenessData,
    pub(crate) details: TxDetails<S>,
    pub(crate) credential_address: S::Address,
    #[serde(deserialize_with = "super::required_option")]
    pub(crate) address_override: Option<S::Address>,
    pub(crate) runtime_commitment: RuntimeCommitment,
}

value_traits!(
    [R: TransactionCallable, S: Spec]
    TransactionSigningPayloadV1<R, S> {
        runtime_call,
        uniqueness,
        details,
        credential_address,
        address_override,
        runtime_commitment,
    }
);

/// A native transaction's signing payload. The borsh tag is the version (`0` = V0, `1` = V1), so
/// the two versions never sign the same bytes. JSON: `{"v0": …}` or `{"v1": …}`. A consensus
/// type.
///
/// It is never sent: the signer and the verifier each build it from the transaction, the chain
/// ID and the runtime version's schema hash. It decodes only so SDKs can check their encoding
/// against the known-answer vectors.
#[derive(BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, ConsensusType)]
#[serde(bound = "", rename_all = "snake_case")]
pub enum TransactionSigningPayload<R: TransactionCallable, S: Spec, C: TxCryptoSpec> {
    /// A single-key transaction's payload.
    V0(#[borsh(bound(serialize = "", deserialize = ""))] TransactionSigningPayloadV0<R, S, C>),
    /// A multisig transaction's payload.
    V1(#[borsh(bound(serialize = "", deserialize = ""))] TransactionSigningPayloadV1<R, S>),
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> Clone
    for TransactionSigningPayload<R, S, C>
{
    fn clone(&self) -> Self {
        match self {
            Self::V0(payload) => Self::V0(payload.clone()),
            Self::V1(payload) => Self::V1(payload.clone()),
        }
    }
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> PartialEq
    for TransactionSigningPayload<R, S, C>
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::V0(a), Self::V0(b)) => a == b,
            (Self::V1(a), Self::V1(b)) => a == b,
            _ => false,
        }
    }
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> Eq for TransactionSigningPayload<R, S, C> {}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> core::fmt::Debug
    for TransactionSigningPayload<R, S, C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::V0(payload) => f.debug_tuple("V0").field(payload).finish(),
            Self::V1(payload) => f.debug_tuple("V1").field(payload).finish(),
        }
    }
}

/// A `Write` that hashes what is written, at most `remaining` bytes: the payload is hashed as it
/// is encoded, without holding its encoding. A write past `remaining` fails before hashing
/// anything of it (and sets `overflowed`), which stops the encoding.
struct HashWriter {
    hasher: StateHasher,
    remaining: usize,
    overflowed: bool,
}

impl HashWriter {
    fn new(limit: usize) -> Self {
        Self {
            hasher: StateHasher::new(),
            remaining: limit,
            overflowed: false,
        }
    }
}

impl std::io::Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(remaining) = self.remaining.checked_sub(bytes.len()) else {
            self.overflowed = true;
            return Err(std::io::Error::other(
                "the signing payload is longer than its length",
            ));
        };
        self.remaining = remaining;
        self.hasher.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A signing payload that borrows the transaction's fields instead of owning copies: what the
/// signed bytes are computed from ([`Transaction::signing_bytes`](super::Transaction) and the
/// authenticator), so the call (up to 1 MiB) is never copied, in particular not before the
/// authenticator has charged for encoding it. Its borsh encoding is
/// [`TransactionSigningPayload`]'s (the version tag, then the same fields in the same order):
/// the known-answer vectors pin both.
pub(crate) enum SigningPayloadRef<'a, R: TransactionCallable, S: Spec, C: TxCryptoSpec> {
    /// A V0 payload.
    V0 {
        runtime_call: &'a R::Call,
        uniqueness: UniquenessData,
        details: &'a TxDetails<S>,
        signer: &'a C::PublicKey,
        address_override: Option<&'a S::Address>,
        runtime_commitment: RuntimeCommitment,
    },
    /// A V1 payload.
    V1 {
        runtime_call: &'a R::Call,
        uniqueness: UniquenessData,
        details: &'a TxDetails<S>,
        credential_address: S::Address,
        address_override: Option<&'a S::Address>,
        runtime_commitment: RuntimeCommitment,
    },
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> BorshSerialize
    for SigningPayloadRef<'_, R, S, C>
{
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            Self::V0 {
                runtime_call,
                uniqueness,
                details,
                signer,
                address_override,
                runtime_commitment,
            } => {
                BorshSerialize::serialize(&0u8, writer)?;
                BorshSerialize::serialize(*runtime_call, writer)?;
                BorshSerialize::serialize(uniqueness, writer)?;
                BorshSerialize::serialize(*details, writer)?;
                BorshSerialize::serialize(*signer, writer)?;
                BorshSerialize::serialize(address_override, writer)?;
                BorshSerialize::serialize(runtime_commitment, writer)
            }
            Self::V1 {
                runtime_call,
                uniqueness,
                details,
                credential_address,
                address_override,
                runtime_commitment,
            } => {
                BorshSerialize::serialize(&1u8, writer)?;
                BorshSerialize::serialize(*runtime_call, writer)?;
                BorshSerialize::serialize(uniqueness, writer)?;
                BorshSerialize::serialize(*details, writer)?;
                BorshSerialize::serialize(credential_address, writer)?;
                BorshSerialize::serialize(address_override, writer)?;
                BorshSerialize::serialize(runtime_commitment, writer)
            }
        }
    }
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> SigningPayloadRef<'_, R, S, C> {
    /// The length of the payload's borsh encoding, without encoding it into memory.
    pub(crate) fn encoded_len(&self) -> Result<usize, TransactionError> {
        borsh::object_length(self).map_err(TransactionError::encoding)
    }

    /// `SHA-256(borsh(payload))`, hashed as it is encoded.
    pub(crate) fn prehash(&self) -> Result<[u8; 32], TransactionError> {
        let mut writer = HashWriter::new(usize::MAX);
        BorshSerialize::serialize(self, &mut writer).map_err(TransactionError::encoding)?;
        Ok(writer.hasher.finalize().into())
    }

    /// `SHA-256(borsh(payload))` of a payload whose encoding must be exactly `len` bytes (the
    /// authenticator charged for `len`, [`Version0::signing_payload_len`](super::Version0) or
    /// [`Version1::signing_payload_len`](super::Version1)): the encoding stops at the first
    /// write past `len`, so at most `len` bytes are encoded and hashed.
    ///
    /// # Errors
    /// [`TransactionError::NonCanonicalEncoding`] if the encoding is longer or shorter than
    /// `len`; [`TransactionError::Encoding`] if it fails otherwise.
    pub(crate) fn prehash_of_len(&self, len: usize) -> Result<[u8; 32], TransactionError> {
        let mut writer = HashWriter::new(len);
        let encoded = BorshSerialize::serialize(self, &mut writer);
        if writer.overflowed || (encoded.is_ok() && writer.remaining != 0) {
            return Err(TransactionError::NonCanonicalEncoding);
        }
        encoded.map_err(TransactionError::encoding)?;
        Ok(writer.hasher.finalize().into())
    }

    /// The signed bytes: `signing_bytes(SigningDomain::Transaction, chain_id, prehash)`.
    pub(crate) fn signing_bytes(&self, chain_id: u64) -> Result<SigningBytes, TransactionError> {
        Ok(signing_bytes(
            SigningDomain::Transaction,
            chain_id,
            &self.prehash()?,
        ))
    }

    /// The signed bytes, the payload's encoding being exactly `len` bytes
    /// ([`prehash_of_len`](Self::prehash_of_len)).
    pub(crate) fn signing_bytes_of_len(
        &self,
        chain_id: u64,
        len: usize,
    ) -> Result<SigningBytes, TransactionError> {
        Ok(signing_bytes(
            SigningDomain::Transaction,
            chain_id,
            &self.prehash_of_len(len)?,
        ))
    }
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> TransactionSigningPayload<R, S, C> {
    /// The payload, borrowed.
    pub(crate) fn as_ref(&self) -> SigningPayloadRef<'_, R, S, C> {
        match self {
            Self::V0(payload) => SigningPayloadRef::V0 {
                runtime_call: &payload.runtime_call,
                uniqueness: payload.uniqueness,
                details: &payload.details,
                signer: &payload.signer,
                address_override: payload.address_override.as_ref(),
                runtime_commitment: payload.runtime_commitment,
            },
            Self::V1(payload) => SigningPayloadRef::V1 {
                runtime_call: &payload.runtime_call,
                uniqueness: payload.uniqueness,
                details: &payload.details,
                credential_address: payload.credential_address,
                address_override: payload.address_override.as_ref(),
                runtime_commitment: payload.runtime_commitment,
            },
        }
    }

    /// The runtime call.
    pub fn runtime_call(&self) -> &R::Call {
        match self {
            Self::V0(payload) => &payload.runtime_call,
            Self::V1(payload) => &payload.runtime_call,
        }
    }

    /// The uniqueness data.
    pub fn uniqueness(&self) -> UniquenessData {
        match self {
            Self::V0(payload) => payload.uniqueness,
            Self::V1(payload) => payload.uniqueness,
        }
    }

    /// The transaction details.
    pub fn details(&self) -> &TxDetails<S> {
        match self {
            Self::V0(payload) => &payload.details,
            Self::V1(payload) => &payload.details,
        }
    }

    /// The address override the signer declared.
    pub fn address_override(&self) -> Option<&S::Address> {
        match self {
            Self::V0(payload) => payload.address_override.as_ref(),
            Self::V1(payload) => payload.address_override.as_ref(),
        }
    }

    /// The runtime commitment: the chain ID, runtime version and schema hash signed for.
    pub fn runtime_commitment(&self) -> &RuntimeCommitment {
        match self {
            Self::V0(payload) => &payload.runtime_commitment,
            Self::V1(payload) => &payload.runtime_commitment,
        }
    }

    /// The signing key (V0) or `None` (V1).
    pub fn signer(&self) -> Option<&C::PublicKey> {
        match self {
            Self::V0(payload) => Some(&payload.signer),
            Self::V1(_) => None,
        }
    }

    /// The multisig credential's address (V1) or `None` (V0).
    pub fn credential_address(&self) -> Option<&S::Address> {
        match self {
            Self::V0(_) => None,
            Self::V1(payload) => Some(&payload.credential_address),
        }
    }

    /// The length of the payload's borsh encoding (what hashing it costs), without encoding it
    /// into memory.
    ///
    /// # Errors
    /// If the call's `BorshSerialize` fails (consensus types must never fail to encode).
    pub fn encoded_len(&self) -> Result<usize, TransactionError> {
        self.as_ref().encoded_len()
    }

    /// `SHA-256(borsh(payload))`, hashed with the state hasher as it is encoded.
    ///
    /// # Errors
    /// As [`encoded_len`](Self::encoded_len).
    pub fn prehash(&self) -> Result<[u8; 32], TransactionError> {
        self.as_ref().prehash()
    }

    /// The signed bytes: `signing_bytes(SigningDomain::Transaction, chain_id, prehash)`, 51 bytes.
    ///
    /// # Errors
    /// As [`encoded_len`](Self::encoded_len).
    pub fn signing_bytes(&self, chain_id: u64) -> Result<SigningBytes, TransactionError> {
        self.as_ref().signing_bytes(chain_id)
    }
}

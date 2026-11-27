//! [`UnsignedTransaction`]: a transaction before it is signed.

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::SafeVec;
use selendra_primitives::signing::SigningBytes;

use super::{
    Multisig, RuntimeCommitment, SchemaHash, Transaction, TransactionCallable, TransactionError,
    TransactionSigningPayload, TransactionSigningPayloadV0, TransactionSigningPayloadV1,
    TxCryptoSpec, UniquenessData, Version0, Version1, value_traits,
};
use crate::{AccountAddress, ConsensusType, Credential, Spec, TxDetails};

/// A transaction before it is signed: what a client builds, then signs with one key
/// (`sign`, native only, V0) or turns into a multisig transaction for its signers
/// ([`to_multisig_tx`](Self::to_multisig_tx), V1).
///
/// `details.runtime_version` is the runtime version it is signed for: the signature commits
/// to that version's schema hash (and the chain ID).
///
/// borsh: `runtime_call`, `uniqueness`, `details`, `address_override`. JSON: an object with
/// exactly these fields (`address_override` `null` for none, never missing).
#[derive(BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, ConsensusType)]
#[serde(bound = "", deny_unknown_fields)]
pub struct UnsignedTransaction<R: TransactionCallable, S: Spec> {
    /// The call.
    pub runtime_call: R::Call,
    /// How the transaction is kept unique.
    pub uniqueness: UniquenessData,
    /// Fees, gas limit and the runtime version signed for.
    pub details: TxDetails<S>,
    /// The address to run as instead of the signer's default one
    /// ([`AuthorizationData::address_override`](super::AuthorizationData::address_override)).
    #[serde(deserialize_with = "super::required_option")]
    pub address_override: Option<S::Address>,
}

value_traits!(
    [R: TransactionCallable, S: Spec]
    UnsignedTransaction<R, S> {
        runtime_call,
        uniqueness,
        details,
        address_override,
    }
);

impl<R: TransactionCallable, S: Spec> UnsignedTransaction<R, S> {
    /// The transaction of `runtime_call`.
    pub const fn new(
        runtime_call: R::Call,
        uniqueness: UniquenessData,
        details: TxDetails<S>,
        address_override: Option<S::Address>,
    ) -> Self {
        Self {
            runtime_call,
            uniqueness,
            details,
            address_override,
        }
    }

    /// The commitment the signature carries on `chain_id`, the runtime version
    /// (`details.runtime_version`) having `schema_hash`.
    pub fn runtime_commitment(&self, chain_id: u64, schema_hash: &SchemaHash) -> RuntimeCommitment {
        RuntimeCommitment::new(chain_id, self.details.runtime_version, schema_hash)
    }

    /// The single-key signing payload for `signer` and `commitment`.
    pub fn signing_payload_v0<C: TxCryptoSpec>(
        &self,
        signer: &C::PublicKey,
        commitment: RuntimeCommitment,
    ) -> TransactionSigningPayload<R, S, C> {
        TransactionSigningPayload::V0(TransactionSigningPayloadV0 {
            runtime_call: self.runtime_call.clone(),
            uniqueness: self.uniqueness,
            details: self.details.clone(),
            signer: signer.clone(),
            address_override: self.address_override,
            runtime_commitment: commitment,
        })
    }

    /// The multisig signing payload for `multisig` and `commitment`.
    pub fn signing_payload_v1<C: TxCryptoSpec>(
        &self,
        multisig: &Multisig<C>,
        commitment: RuntimeCommitment,
    ) -> TransactionSigningPayload<R, S, C> {
        TransactionSigningPayload::V1(TransactionSigningPayloadV1 {
            runtime_call: self.runtime_call.clone(),
            uniqueness: self.uniqueness,
            details: self.details.clone(),
            credential_address: S::Address::default_for(&Credential::Multisig(
                multisig.credential_id(),
            )),
            address_override: self.address_override,
            runtime_commitment: commitment,
        })
    }

    /// The bytes `signer` signs on `chain_id`, the runtime version having `schema_hash`.
    ///
    /// # Errors
    /// If the payload does not encode.
    pub fn signing_bytes_v0<C: TxCryptoSpec>(
        &self,
        signer: &C::PublicKey,
        chain_id: u64,
        schema_hash: &SchemaHash,
    ) -> Result<SigningBytes, TransactionError> {
        self.signing_payload_v0::<C>(signer, self.runtime_commitment(chain_id, schema_hash))
            .signing_bytes(chain_id)
    }

    /// The bytes each of `multisig`'s signers signs on `chain_id`, the runtime version having
    /// `schema_hash`.
    ///
    /// # Errors
    /// If the payload does not encode.
    pub fn signing_bytes_v1<C: TxCryptoSpec>(
        &self,
        multisig: &Multisig<C>,
        chain_id: u64,
        schema_hash: &SchemaHash,
    ) -> Result<SigningBytes, TransactionError> {
        self.signing_payload_v1(multisig, self.runtime_commitment(chain_id, schema_hash))
            .signing_bytes(chain_id)
    }

    /// Signs the transaction with `key` on `chain_id`, for the runtime version
    /// (`details.runtime_version`) with `schema_hash`: a V0 transaction.
    ///
    /// # Errors
    /// If the payload does not encode.
    #[cfg(feature = "native")]
    pub fn sign<C: TxCryptoSpec>(
        self,
        key: &C::PrivateKey,
        chain_id: u64,
        schema_hash: &SchemaHash,
    ) -> Result<Transaction<R, S, C>, TransactionError> {
        let pub_key = selendra_interface::crypto::PrivateKey::pub_key(key);
        let bytes = self.signing_bytes_v0::<C>(&pub_key, chain_id, schema_hash)?;
        let signature = selendra_primitives::signing::sign_signing_bytes(key, &bytes);
        Ok(self.to_signed_tx(pub_key, signature))
    }

    /// The V0 transaction with `signature` by `pub_key` (not verified).
    pub fn to_signed_tx<C: TxCryptoSpec>(
        self,
        pub_key: C::PublicKey,
        signature: C::Signature,
    ) -> Transaction<R, S, C> {
        Transaction::V0(Version0 {
            signature,
            pub_key,
            runtime_call: self.runtime_call,
            uniqueness: self.uniqueness,
            details: self.details,
            address_override: self.address_override,
        })
    }

    /// The V1 transaction for `multisig`, with no signature yet: every key unused
    /// (`Version1::sign`, native only, and [`Version1::add_signature`] add them).
    pub fn to_multisig_tx<C: TxCryptoSpec>(self, multisig: Multisig<C>) -> Version1<R, S, C> {
        Version1 {
            signatures: SafeVec::new(),
            unused_pub_keys: multisig.keys_vec(),
            min_signers: multisig.min_signers(),
            runtime_call: self.runtime_call,
            uniqueness: self.uniqueness,
            details: self.details,
            address_override: self.address_override,
        }
    }
}

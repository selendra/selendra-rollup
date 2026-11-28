//! Native transactions: [`Transaction`], single-key ([`Version0`]) or multisig ([`Version1`]).

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::SafeVec;
use selendra_interface::crypto::CredentialId;
use selendra_primitives::signing::{SigningBytes, verify_signing_bytes};

use selendra_state::metered::StateGas;

use super::signing_payload::SigningPayloadRef;
use super::{
    MAX_SIGNERS, Multisig, MultisigError, PubKeyAndSignature, RuntimeCommitment, SchemaHash,
    TransactionCallable, TransactionError, TransactionSigningPayload, TransactionSigningPayloadV0,
    TransactionSigningPayloadV1, TxCryptoSpec, UniquenessData, UnsignedTransaction, value_traits,
};
use crate::{AccountAddress, ConsensusType, Credential, GasMeter, Spec, TxDetails, TxStateError};

/// The length of a [`RuntimeCommitment`]'s borsh encoding: its 32 bytes.
const RUNTIME_COMMITMENT_LEN: usize = 32;

/// A single-key transaction.
///
/// borsh: `signature`, `pub_key`, `runtime_call`, `uniqueness`, `details`, `address_override`
/// (an option). JSON: an object with exactly these fields (keys and signatures `0x` + lowercase
/// hex; `address_override` `null` for none, never missing).
#[derive(BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, ConsensusType)]
#[serde(bound = "", deny_unknown_fields)]
pub struct Version0<R: TransactionCallable, S: Spec, C: TxCryptoSpec> {
    /// The signature over the transaction's signed bytes.
    pub signature: C::Signature,
    /// The signing key (also in the signed payload).
    pub pub_key: C::PublicKey,
    /// The call.
    pub runtime_call: R::Call,
    /// How the transaction is kept unique.
    pub uniqueness: UniquenessData,
    /// Fees, gas limit and the runtime version signed for.
    pub details: TxDetails<S>,
    /// The address to run as instead of the key's default one
    /// ([`AuthorizationData::address_override`](super::AuthorizationData::address_override)).
    #[serde(deserialize_with = "super::required_option")]
    pub address_override: Option<S::Address>,
}

value_traits!(
    [R: TransactionCallable, S: Spec, C: TxCryptoSpec]
    Version0<R, S, C> {
        signature,
        pub_key,
        runtime_call,
        uniqueness,
        details,
        address_override,
    }
);

/// A multisig transaction: the signatures made, and the multisig's other keys (needed to
/// compute its credential).
///
/// borsh: `signatures` (each the signature, then the key), `unused_pub_keys`, `min_signers` (one
/// byte), `runtime_call`, `uniqueness`, `details`, `address_override`; each list is a `u32` LE
/// count (at most [`MAX_SIGNERS`]) and the items. JSON: an object with exactly these fields.
///
/// Decoding checks only each list's length: whether the keys and the threshold form a valid
/// multisig (at most [`MAX_SIGNERS`] keys in all, no key twice, `1 ≤ min_signers ≤ keys`) is
/// checked by [`multisig`](Self::multisig), and so by every method that needs the credential.
#[derive(BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, ConsensusType)]
#[serde(bound = "", deny_unknown_fields)]
pub struct Version1<R: TransactionCallable, S: Spec, C: TxCryptoSpec> {
    /// The signatures made, each with its key.
    #[borsh(bound(
        serialize = "PubKeyAndSignature<C>: BorshSerialize",
        deserialize = "PubKeyAndSignature<C>: BorshDeserialize"
    ))]
    pub signatures: SafeVec<PubKeyAndSignature<C>, MAX_SIGNERS>,
    /// The multisig's keys that did not sign.
    pub unused_pub_keys: SafeVec<C::PublicKey, MAX_SIGNERS>,
    /// The threshold: how many of the keys must sign.
    pub min_signers: u8,
    /// The call.
    pub runtime_call: R::Call,
    /// How the transaction is kept unique.
    pub uniqueness: UniquenessData,
    /// Fees, gas limit and the runtime version signed for.
    pub details: TxDetails<S>,
    /// The address to run as instead of the multisig's default one.
    #[serde(deserialize_with = "super::required_option")]
    pub address_override: Option<S::Address>,
}

value_traits!(
    [R: TransactionCallable, S: Spec, C: TxCryptoSpec]
    Version1<R, S, C> {
        signatures,
        unused_pub_keys,
        min_signers,
        runtime_call,
        uniqueness,
        details,
        address_override,
    }
);

/// A native transaction, signed with ed25519 (`C = Ed25519CryptoSpec`, the default) or
/// secp256k1 (`EvmCryptoSpec`; software keys only). The authenticator (Phase 5 S11) reads it
/// from its envelope, whose tag gives the scheme.
///
/// borsh: a tag (`0` = V0, `1` = V1), then the version's fields. JSON: `{"v0": …}` or
/// `{"v1": …}`. A consensus type. There is no legacy format (upstream's `legacy_v0`).
///
/// The signature covers the transaction's [`TransactionSigningPayload`] for a chain ID and a
/// runtime version's schema hash ([`signing_bytes`](Self::signing_bytes)), and is checked only
/// against [`SigningBytes`] ([`verify_signature`](Self::verify_signature)), so a signature over
/// a bare payload cannot be checked by mistake (P5-07):
///
/// ```compile_fail,E0308
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_modules_api::transaction::{Transaction, TransactionCallable};
///
/// struct Runtime;
/// impl TransactionCallable for Runtime {
///     type Call = u64;
/// }
///
/// fn check(tx: &Transaction<Runtime, TestSpec>, payload: &[u8]) {
///     let _ = tx.verify_signature(payload);
/// }
/// ```
///
/// ```
/// use selendra_modules_api::test_utils::TestSpec;
/// use selendra_modules_api::transaction::{Transaction, TransactionCallable};
///
/// struct Runtime;
/// impl TransactionCallable for Runtime {
///     type Call = u64;
/// }
///
/// fn check(tx: &Transaction<Runtime, TestSpec>, chain_id: u64, schema_hash: &[u8; 32]) {
///     let bytes = tx.signing_bytes(chain_id, schema_hash).unwrap();
///     let _ = tx.verify_signature(&bytes);
/// }
/// ```
#[derive(BorshSerialize, BorshDeserialize, serde::Serialize, serde::Deserialize, ConsensusType)]
#[serde(bound = "", rename_all = "snake_case")]
pub enum Transaction<
    R: TransactionCallable,
    S: Spec,
    C: TxCryptoSpec = selendra_primitives::crypto::Ed25519CryptoSpec,
> {
    /// A single-key transaction.
    V0(#[borsh(bound(serialize = "", deserialize = ""))] Version0<R, S, C>),
    /// A multisig transaction.
    V1(#[borsh(bound(serialize = "", deserialize = ""))] Version1<R, S, C>),
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> Clone for Transaction<R, S, C> {
    fn clone(&self) -> Self {
        match self {
            Self::V0(tx) => Self::V0(tx.clone()),
            Self::V1(tx) => Self::V1(tx.clone()),
        }
    }
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> PartialEq for Transaction<R, S, C> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::V0(a), Self::V0(b)) => a == b,
            (Self::V1(a), Self::V1(b)) => a == b,
            _ => false,
        }
    }
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> Eq for Transaction<R, S, C> {}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> core::fmt::Debug for Transaction<R, S, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::V0(tx) => f.debug_tuple("V0").field(tx).finish(),
            Self::V1(tx) => f.debug_tuple("V1").field(tx).finish(),
        }
    }
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> From<Version0<R, S, C>>
    for Transaction<R, S, C>
{
    fn from(tx: Version0<R, S, C>) -> Self {
        Self::V0(tx)
    }
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> From<Version1<R, S, C>>
    for Transaction<R, S, C>
{
    fn from(tx: Version1<R, S, C>) -> Self {
        Self::V1(tx)
    }
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> Version0<R, S, C> {
    /// The transaction without its signature.
    pub fn to_unsigned_transaction(&self) -> UnsignedTransaction<R, S> {
        UnsignedTransaction::new(
            self.runtime_call.clone(),
            self.uniqueness,
            self.details.clone(),
            self.address_override,
        )
    }

    /// The signing key's credential.
    pub fn credential(&self) -> Credential {
        C::credential(&self.pub_key)
    }

    /// The signing payload for `commitment`, borrowing the transaction's fields.
    pub(crate) fn signing_payload_ref(
        &self,
        commitment: RuntimeCommitment,
    ) -> SigningPayloadRef<'_, R, S, C> {
        SigningPayloadRef::V0 {
            runtime_call: &self.runtime_call,
            uniqueness: self.uniqueness,
            details: &self.details,
            signer: &self.pub_key,
            address_override: self.address_override.as_ref(),
            runtime_commitment: commitment,
        }
    }

    /// The length of the borsh encoding of the signing payload
    /// ([`signing_payload_ref`](Self::signing_payload_ref)), from `encoded_len`, the length of
    /// this transaction's own encoding (as a [`Transaction`], its tag included; the
    /// authenticator has it: the bytes it decoded). The payload holds the transaction's fields
    /// but the signature (the signer's key in another place), and the runtime commitment, so
    /// it is `encoded_len - len(signature) + 32`. Constant time: the call is not walked.
    ///
    /// `None` if `encoded_len` is shorter than the signature. If `encoded_len` is not the
    /// length of this transaction's canonical encoding, the payload does not encode to the
    /// result ([`TransactionError::NonCanonicalEncoding`] when it is hashed at that length).
    pub(crate) fn signing_payload_len(&self, encoded_len: usize) -> Option<usize> {
        let signature = borsh::object_length(&self.signature).ok()?;
        encoded_len
            .checked_sub(signature)?
            .checked_add(RUNTIME_COMMITMENT_LEN)
    }

    /// The signing payload for `commitment`.
    pub fn signing_payload(
        &self,
        commitment: RuntimeCommitment,
    ) -> TransactionSigningPayload<R, S, C> {
        TransactionSigningPayload::V0(TransactionSigningPayloadV0 {
            runtime_call: self.runtime_call.clone(),
            uniqueness: self.uniqueness,
            details: self.details.clone(),
            signer: self.pub_key.clone(),
            address_override: self.address_override,
            runtime_commitment: commitment,
        })
    }
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> Version1<R, S, C> {
    /// The multisig: the signers' keys and the unused keys, with the threshold.
    ///
    /// # Errors
    /// If they are not a valid multisig ([`Multisig::new`]): more than [`MAX_SIGNERS`] keys in
    /// all, a key listed twice (a signer's key among the unused keys included), or a threshold
    /// of 0 or above the number of keys.
    pub fn multisig(&self) -> Result<Multisig<C>, MultisigError> {
        let keys = self
            .signatures
            .iter()
            .map(|signature| signature.pub_key.clone())
            .chain(self.unused_pub_keys.iter().cloned())
            .collect();
        Multisig::new(self.min_signers, keys)
    }

    /// The multisig's credential id ([`Multisig::credential_id`]).
    ///
    /// # Errors
    /// As [`multisig`](Self::multisig).
    pub fn credential_id(&self) -> Result<CredentialId, MultisigError> {
        Ok(self.multisig()?.credential_id())
    }

    /// The multisig's credential.
    ///
    /// # Errors
    /// As [`multisig`](Self::multisig).
    pub fn credential(&self) -> Result<Credential, MultisigError> {
        Ok(Credential::Multisig(self.credential_id()?))
    }

    /// The transaction without its signatures and keys.
    pub fn to_unsigned_transaction(&self) -> UnsignedTransaction<R, S> {
        UnsignedTransaction::new(
            self.runtime_call.clone(),
            self.uniqueness,
            self.details.clone(),
            self.address_override,
        )
    }

    /// The signing payload for `commitment`. The same whichever keys signed.
    ///
    /// # Errors
    /// As [`multisig`](Self::multisig).
    pub fn signing_payload(
        &self,
        commitment: RuntimeCommitment,
    ) -> Result<TransactionSigningPayload<R, S, C>, MultisigError> {
        Ok(TransactionSigningPayload::V1(TransactionSigningPayloadV1 {
            runtime_call: self.runtime_call.clone(),
            uniqueness: self.uniqueness,
            details: self.details.clone(),
            credential_address: S::Address::default_for(&self.credential()?),
            address_override: self.address_override,
            runtime_commitment: commitment,
        }))
    }

    /// The signing payload for `commitment`, borrowing the transaction's fields;
    /// `credential_address` is the multisig credential's default address (the caller computed
    /// the credential).
    pub(crate) fn signing_payload_ref(
        &self,
        credential_address: S::Address,
        commitment: RuntimeCommitment,
    ) -> SigningPayloadRef<'_, R, S, C> {
        SigningPayloadRef::V1 {
            runtime_call: &self.runtime_call,
            uniqueness: self.uniqueness,
            details: &self.details,
            credential_address,
            address_override: self.address_override.as_ref(),
            runtime_commitment: commitment,
        }
    }

    /// The length of the borsh encoding of the signing payload for `credential_address`
    /// ([`signing_payload_ref`](Self::signing_payload_ref)), from `encoded_len`, the length of
    /// this transaction's own encoding (as a [`Transaction`], its tag included). The payload
    /// holds the transaction's fields but the signatures (with their keys), the unused keys and
    /// the threshold, and adds the credential address and the runtime commitment, so it is
    /// `encoded_len - len(signatures) - len(unused keys) - 1 + len(credential_address) + 32`.
    /// Bounded work: the lists' encodings (at most [`MAX_SIGNERS`] items each), never the
    /// call.
    ///
    /// `None` if `encoded_len` is shorter than those fields. If it is not the length of this
    /// transaction's canonical encoding, the payload does not encode to the result.
    pub(crate) fn signing_payload_len(
        &self,
        encoded_len: usize,
        credential_address: &S::Address,
    ) -> Option<usize> {
        let signatures = borsh::object_length(&self.signatures).ok()?;
        let unused = borsh::object_length(&self.unused_pub_keys).ok()?;
        let address = borsh::object_length(credential_address).ok()?;
        encoded_len
            .checked_sub(signatures)?
            .checked_sub(unused)?
            .checked_sub(1)?
            .checked_add(address)?
            .checked_add(RUNTIME_COMMITMENT_LEN)
    }

    /// Whether at least `min_signers` keys signed.
    pub fn is_fully_signed(&self) -> bool {
        self.signatures.len() >= usize::from(self.min_signers)
    }

    /// Adds `signature` by `pub_key`, moving the key from the unused keys to the signers.
    ///
    /// # Errors
    /// [`MultisigError::DuplicateSigner`] if the key already signed,
    /// [`MultisigError::OutsiderSigner`] if it is not one of the multisig's keys. Nothing
    /// changes then. The signature is not verified.
    pub fn add_signature(
        &mut self,
        signature: C::Signature,
        pub_key: C::PublicKey,
    ) -> Result<(), MultisigError> {
        if self
            .signatures
            .iter()
            .any(|signed| signed.pub_key == pub_key)
        {
            return Err(MultisigError::DuplicateSigner);
        }
        let index = self
            .unused_pub_keys
            .iter()
            .position(|key| *key == pub_key)
            .ok_or(MultisigError::OutsiderSigner)?;
        // There is room: the unused key moves to the signers, and a transaction built by
        // `to_multisig_tx` has at most `MAX_SIGNERS` keys in all.
        self.signatures
            .try_push(PubKeyAndSignature { signature, pub_key })
            .map_err(|_| MultisigError::TooManyKeys {
                keys: self.signatures.len() + self.unused_pub_keys.len(),
            })?;
        self.unused_pub_keys.remove(index);
        Ok(())
    }

    /// Signs the transaction with `key` for `chain_id` and the runtime version's
    /// `schema_hash`, and adds the signature ([`add_signature`](Self::add_signature)).
    ///
    /// # Errors
    /// If the keys are not a valid multisig ([`multisig`](Self::multisig)), the payload does
    /// not encode, or [`add_signature`](Self::add_signature) fails. Nothing changes then.
    #[cfg(feature = "native")]
    pub fn sign(
        &mut self,
        key: &C::PrivateKey,
        chain_id: u64,
        schema_hash: &SchemaHash,
    ) -> Result<(), TransactionError> {
        let signature = self.sign_without_adding(key, chain_id, schema_hash)?;
        Ok(self.add_signature(
            signature,
            selendra_interface::crypto::PrivateKey::pub_key(key),
        )?)
    }

    /// The signature `key` makes over the transaction for `chain_id` and `schema_hash`, without
    /// adding it.
    ///
    /// # Errors
    /// If the keys are not a valid multisig, or the payload does not encode.
    #[cfg(feature = "native")]
    pub fn sign_without_adding(
        &self,
        key: &C::PrivateKey,
        chain_id: u64,
        schema_hash: &SchemaHash,
    ) -> Result<C::Signature, TransactionError> {
        let commitment =
            RuntimeCommitment::new(chain_id, self.details.runtime_version, schema_hash);
        let credential_address = S::Address::default_for(&self.credential()?);
        let bytes = self
            .signing_payload_ref(credential_address, commitment)
            .signing_bytes(chain_id)?;
        Ok(selendra_primitives::signing::sign_signing_bytes(
            key, &bytes,
        ))
    }
}

impl<R: TransactionCallable, S: Spec, C: TxCryptoSpec> Transaction<R, S, C> {
    /// The call.
    pub fn runtime_call(&self) -> &R::Call {
        match self {
            Self::V0(tx) => &tx.runtime_call,
            Self::V1(tx) => &tx.runtime_call,
        }
    }

    /// The call, consuming the transaction.
    pub fn into_runtime_call(self) -> R::Call {
        match self {
            Self::V0(tx) => tx.runtime_call,
            Self::V1(tx) => tx.runtime_call,
        }
    }

    /// The uniqueness data.
    pub fn uniqueness(&self) -> UniquenessData {
        match self {
            Self::V0(tx) => tx.uniqueness,
            Self::V1(tx) => tx.uniqueness,
        }
    }

    /// The transaction details.
    pub fn details(&self) -> &TxDetails<S> {
        match self {
            Self::V0(tx) => &tx.details,
            Self::V1(tx) => &tx.details,
        }
    }

    /// The address override the signer declared.
    pub fn address_override(&self) -> Option<&S::Address> {
        match self {
            Self::V0(tx) => tx.address_override.as_ref(),
            Self::V1(tx) => tx.address_override.as_ref(),
        }
    }

    /// The signer's credential: the key's (V0) or the multisig's (V1).
    ///
    /// # Errors
    /// A V1 transaction whose keys are not a valid multisig.
    pub fn credential(&self) -> Result<Credential, MultisigError> {
        match self {
            Self::V0(tx) => Ok(tx.credential()),
            Self::V1(tx) => tx.credential(),
        }
    }

    /// The transaction without its signatures.
    pub fn to_unsigned_transaction(&self) -> UnsignedTransaction<R, S> {
        match self {
            Self::V0(tx) => tx.to_unsigned_transaction(),
            Self::V1(tx) => tx.to_unsigned_transaction(),
        }
    }

    /// The commitment the transaction's signature must carry on `chain_id`, if its runtime
    /// version (`details.runtime_version`) has `schema_hash`.
    pub fn runtime_commitment(&self, chain_id: u64, schema_hash: &SchemaHash) -> RuntimeCommitment {
        RuntimeCommitment::new(chain_id, self.details().runtime_version, schema_hash)
    }

    /// The signing payload on `chain_id`, the runtime version having `schema_hash`.
    ///
    /// # Errors
    /// A V1 transaction whose keys are not a valid multisig.
    pub fn signing_payload(
        &self,
        chain_id: u64,
        schema_hash: &SchemaHash,
    ) -> Result<TransactionSigningPayload<R, S, C>, MultisigError> {
        let commitment = self.runtime_commitment(chain_id, schema_hash);
        match self {
            Self::V0(tx) => Ok(tx.signing_payload(commitment)),
            Self::V1(tx) => tx.signing_payload(commitment),
        }
    }

    /// The bytes the transaction's signatures must cover on `chain_id`, the runtime version
    /// (`details.runtime_version`) having `schema_hash` (the runtime's version table gives it).
    /// The payload is encoded from the transaction's own fields (borrowed, not copied).
    ///
    /// # Errors
    /// A V1 transaction whose keys are not a valid multisig, or a payload that does not encode.
    pub fn signing_bytes(
        &self,
        chain_id: u64,
        schema_hash: &SchemaHash,
    ) -> Result<SigningBytes, TransactionError> {
        let commitment = self.runtime_commitment(chain_id, schema_hash);
        let payload = match self {
            Self::V0(tx) => tx.signing_payload_ref(commitment),
            Self::V1(tx) => {
                tx.signing_payload_ref(S::Address::default_for(&tx.credential()?), commitment)
            }
        };
        payload.signing_bytes(chain_id)
    }

    /// Checks the signatures against `bytes` ([`signing_bytes`](Self::signing_bytes)): the key's
    /// (V0), or a valid multisig's, every signature by one of its keys, at least the threshold
    /// of them, each key once (V1, [`Multisig::verify`]). Charges no gas: the authenticator
    /// charges before calling it.
    ///
    /// # Errors
    /// [`TransactionError::BadSignature`] or [`TransactionError::Multisig`].
    pub fn verify_signature(&self, bytes: &SigningBytes) -> Result<(), TransactionError> {
        match self {
            Self::V0(tx) => {
                verify_signing_bytes(&tx.signature, &tx.pub_key, bytes).map_err(|error| {
                    TransactionError::BadSignature {
                        error: error.to_string(),
                    }
                })
            }
            Self::V1(tx) => Ok(tx.multisig()?.verify(bytes, &tx.signatures)?),
        }
    }

    /// The number of keys the transaction carries (what decoding it decoded): 1 (V0), or its
    /// signers' and unused keys (V1).
    pub fn key_count(&self) -> usize {
        match self {
            Self::V0(_) => 1,
            Self::V1(tx) => tx.signatures.len() + tx.unused_pub_keys.len(),
        }
    }

    /// The number of signatures the transaction carries.
    pub fn signature_count(&self) -> usize {
        match self {
            Self::V0(_) => 1,
            Self::V1(tx) => tx.signatures.len(),
        }
    }

    /// Charges `meter` for decoding the transaction's public keys: the spec's
    /// `pubkey_decode` of the scheme per key ([`key_count`](Self::key_count): V0 one, V1 the
    /// signers and the unused keys, unused keys included: decoding the transaction decoded
    /// them all; P5-62).
    ///
    /// # Errors
    /// The charge was refused or overflows (the phase is then poisoned).
    pub fn charge_gas_for_key_decode<M: GasMeter<S>>(
        &self,
        meter: &mut M,
    ) -> Result<(), TxStateError<S>> {
        let per_key = C::SCHEME.cost(&S::GAS_SCHEDULE.pubkey_decode);
        let keys = u64::try_from(self.key_count()).unwrap_or(u64::MAX);
        meter
            .metered()
            .charge_linear(<S::Gas as StateGas>::ZERO, per_key, keys)
    }

    /// Charges `meter` for verifying the transaction's signatures over a message of
    /// `msg_len` bytes: the spec's `sig_verify + sig_per_byte·msg_len` of the scheme per
    /// signature, every signature charged before any is verified (so batch verification would
    /// cost the same). The authenticator calls it right before
    /// [`verify_signature`](Self::verify_signature), which charges nothing.
    ///
    /// # Errors
    /// A charge was refused or overflows (the phase is then poisoned; the earlier signatures'
    /// charges stay).
    pub fn charge_gas_for_signature<M: GasMeter<S>>(
        &self,
        msg_len: usize,
        meter: &mut M,
    ) -> Result<(), TxStateError<S>> {
        let schedule = &S::GAS_SCHEDULE;
        let verify = C::SCHEME.cost(&schedule.sig_verify);
        let per_byte = C::SCHEME.cost(&schedule.sig_per_byte);
        let units = u64::try_from(msg_len).unwrap_or(u64::MAX);
        for _ in 0..self.signature_count() {
            meter.metered().charge_linear(verify, per_byte, units)?;
        }
        Ok(())
    }
}

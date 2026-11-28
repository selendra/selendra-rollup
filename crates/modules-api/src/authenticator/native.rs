//! [`SelendraAuthenticator`]: the native authenticator (ed25519 and secp256k1 transactions).

use core::marker::PhantomData;

use selendra_interface::TxHash;
use selendra_interface::common::HexHash;
use selendra_interface::stf::{FullyBakedTx, RawTx};
use selendra_primitives::crypto::{Ed25519CryptoSpec, EvmCryptoSpec};
use selendra_state::metered::StateGas;

use super::{AuthenticatorInput, AuthenticatorKind, Envelope, EnvelopeError, RuntimeVersions};
use crate::capabilities::authentication::AuthenticatorState;
use crate::capabilities::{
    AuthenticationError, AuthenticationOutput, BatchFromUnregisteredSequencer, FatalError,
    TransactionAuthenticator, UnregisteredAuthenticationError, calculate_hash_metered,
};
use crate::transaction::{
    AuthorizationData, Multisig, Transaction, TransactionCallable, TransactionError, TxCryptoSpec,
};
use crate::{
    AccountAddress, Credential, MeteredBorshDeserialize, MeteredBorshDeserializeError,
    MeteredHasher, Spec, TxStateError,
};

/// The native authenticator of a runtime whose calls are `R::Call`
/// ([`TransactionCallable`]: every runtime), on the spec `S`, accepting the runtime versions of
/// `V`.
///
/// It reads the envelope ([`Envelope`]: tag `0` an ed25519 transaction, `1` a secp256k1 one;
/// the reserved tags `2`/`3` are `FatalError::UnsupportedAuthenticator`), then authenticates the
/// [`Transaction`] in it: the runtime version it names must be accepted at the accessor's rollup
/// height (`V::VERSIONS`), and its signatures must cover the signed bytes for the chain ID and
/// that version's schema hash. Each stage is charged first (the [module docs](super)).
///
/// - tx hash: `SHA-256(FullyBakedTx.data)`, so the envelope tag is covered (upstream hashed the
///   inner bytes only: the same bytes under another tag had the same hash, P5-38);
/// - non-malleable hash: `SHA-256(signed bytes)` for every version, so another encoding of the
///   same signed transaction (signatures listed in another order, a key or signature encoded
///   differently) cannot replay it (upstream used the raw hash for V0, P5-35);
/// - the authorization data's default address is the credential's
///   ([`AccountAddress::default_for`]: an EVM key's account is its `0x…` address, P5-08).
pub struct SelendraAuthenticator<S, R, V>(PhantomData<Marker<S, R, V>>);

/// The authenticator holds no value of its parameters.
type Marker<S, R, V> = fn() -> (S, R, V);

impl<S, R, V> core::fmt::Debug for SelendraAuthenticator<S, R, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SelendraAuthenticator")
    }
}

impl<S, R, V> Default for SelendraAuthenticator<S, R, V> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<S, R, V> Clone for SelendraAuthenticator<S, R, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S, R, V> Copy for SelendraAuthenticator<S, R, V> {}

/// Why the envelope stage failed: the transaction hash's charge, or the envelope.
pub(super) enum EnvelopeFailure {
    Auth(AuthenticationError),
    Envelope(EnvelopeError, TxHash),
}

fn fatal(error: FatalError, tx_hash: TxHash) -> AuthenticationError {
    AuthenticationError::FatalError(error, tx_hash)
}

fn signature_failed(error: impl ToString, tx_hash: TxHash) -> AuthenticationError {
    fatal(
        FatalError::SigVerificationFailed(error.to_string()),
        tx_hash,
    )
}

impl<S: Spec, R: TransactionCallable, V: RuntimeVersions> SelendraAuthenticator<S, R, V> {
    /// Stage 1 and the envelope: the transaction hash (charged), then the envelope read in
    /// place: the envelope borrows `tx`'s bytes, nothing is copied (P5-37). Both entry points
    /// go through it.
    pub(super) fn hash_and_parse<'a, A: AuthenticatorState<S>>(
        tx: &'a FullyBakedTx,
        state: &mut A,
    ) -> Result<(TxHash, Envelope<'a>), EnvelopeFailure> {
        let tx_hash = calculate_hash_metered(tx.data(), state)
            .map_err(|error| EnvelopeFailure::Auth(AuthenticationError::out_of_gas(&error)))?;
        let envelope = Envelope::parse(tx.data())
            .map_err(|error| EnvelopeFailure::Envelope(error, tx_hash))?;
        Ok((tx_hash, envelope))
    }

    fn envelope_error(error: EnvelopeError, tx_hash: TxHash) -> AuthenticationError {
        match error {
            EnvelopeError::Reserved { tag } => {
                fatal(FatalError::UnsupportedAuthenticator { tag }, tx_hash)
            }
            other => fatal(
                FatalError::DeserializationFailed(other.to_string()),
                tx_hash,
            ),
        }
    }

    fn authenticate_envelope<A: AuthenticatorState<S>>(
        tx_hash: TxHash,
        envelope: Envelope<'_>,
        chain_id: u64,
        state: &mut A,
    ) -> Result<AuthenticationOutput<S, R::Call>, AuthenticationError> {
        match envelope.kind() {
            AuthenticatorKind::Ed25519 => Self::authenticate_native::<Ed25519CryptoSpec, A>(
                tx_hash,
                envelope.raw_tx(),
                chain_id,
                state,
            ),
            AuthenticatorKind::Secp256k1 => Self::authenticate_native::<EvmCryptoSpec, A>(
                tx_hash,
                envelope.raw_tx(),
                chain_id,
                state,
            ),
            // `Envelope::parse` returns enabled authenticators only.
            kind @ (AuthenticatorKind::Eip712 | AuthenticatorKind::EthereumRlp) => Err(fatal(
                FatalError::UnsupportedAuthenticator { tag: kind.tag() },
                tx_hash,
            )),
        }
    }

    /// Stages 2 to 7 for a native transaction signed with `C` (the [module docs](super)).
    fn authenticate_native<C: TxCryptoSpec, A: AuthenticatorState<S>>(
        tx_hash: TxHash,
        raw_tx: &[u8],
        chain_id: u64,
        state: &mut A,
    ) -> Result<AuthenticationOutput<S, R::Call>, AuthenticationError> {
        let out_of_gas = |error: TxStateError<S>| AuthenticationError::out_of_gas(&error);

        // 2. The decode, per byte (`from_slice`: trailing bytes rejected).
        let tx = match Transaction::<R, S, C>::metered_from_slice(raw_tx, state) {
            Ok(tx) => tx,
            Err(MeteredBorshDeserializeError::Gas(error)) => return Err(out_of_gas(error)),
            Err(MeteredBorshDeserializeError::Decode(error)) => {
                return Err(fatal(
                    FatalError::DeserializationFailed(error.to_string()),
                    tx_hash,
                ));
            }
        };

        // 4. The keys the decode decoded, charged right after it (their number is known only
        // now), before anything can reject the transaction.
        tx.charge_gas_for_key_decode(state).map_err(out_of_gas)?;

        // 3. The runtime version, at the accessor's height.
        let height = state.rollup_height_to_access();
        let got = tx.details().runtime_version;
        let Some(window) = V::VERSIONS.resolve(height, got) else {
            return Err(fatal(
                FatalError::InvalidRuntimeVersion {
                    expected: V::VERSIONS.primary_at(height).spec_version,
                    got,
                },
                tx_hash,
            ));
        };
        let commitment = window.commitment(chain_id);

        // 5. The credential (V1: the multisig's hash, charged first) and the signing payload,
        // borrowing the transaction's fields: its encoding and prehash, charged first.
        let (credential, multisig) = match &tx {
            Transaction::V0(v0) => (C::credential(&v0.pub_key), None),
            Transaction::V1(v1) => {
                // The checks that read no key (constant time), the credential's charge (by its
                // preimage's length: the keys' lengths, nothing copied or compared), then the
                // multisig built (the keys copied, sorted and checked for duplicates, which the
                // charge pays for: the credential hashes the same keys).
                Multisig::<C>::check_shape(v1.min_signers, tx.key_count())
                    .map_err(|error| signature_failed(error, tx_hash))?;
                let keys = v1
                    .signatures
                    .iter()
                    .map(|signature| &signature.pub_key)
                    .chain(v1.unused_pub_keys.iter());
                let preimage_len = Multisig::<C>::credential_preimage_len(keys);
                let costs = &S::GAS_SCHEDULE.state;
                state
                    .metered()
                    .charge_linear(
                        costs.hash_update,
                        costs.hash_per_byte,
                        u64::try_from(preimage_len).unwrap_or(u64::MAX),
                    )
                    .map_err(out_of_gas)?;
                let multisig = v1
                    .multisig()
                    .map_err(|error| signature_failed(error, tx_hash))?;
                (
                    Credential::Multisig(multisig.credential_id()),
                    Some(multisig),
                )
            }
        };
        // The payload's length from the transaction's (the bytes stage 2 decoded and paid
        // for), not by walking the call: the encode-and-hash charge comes before any work
        // proportional to the call. The encoding then stops at that length.
        let (payload, len) = match &tx {
            Transaction::V0(v0) => (
                v0.signing_payload_ref(commitment),
                v0.signing_payload_len(raw_tx.len()),
            ),
            Transaction::V1(v1) => {
                let address = S::Address::default_for(&credential);
                let len = v1.signing_payload_len(raw_tx.len(), &address);
                (v1.signing_payload_ref(address, commitment), len)
            }
        };
        let encoding = |error: TransactionError| match error {
            TransactionError::NonCanonicalEncoding => fatal(
                FatalError::DeserializationFailed(error.to_string()),
                tx_hash,
            ),
            other => fatal(FatalError::Other(other.to_string()), tx_hash),
        };
        let len = len.ok_or_else(|| encoding(TransactionError::NonCanonicalEncoding))?;
        let units = u64::try_from(len).unwrap_or(u64::MAX);
        let schedule = &S::GAS_SCHEDULE;
        state
            .metered()
            .charge_linear(schedule.state.hash_update, schedule.encode_per_byte, units)
            .map_err(out_of_gas)?;
        state
            .metered()
            .charge_linear(
                <S::Gas as StateGas>::ZERO,
                schedule.state.hash_per_byte,
                units,
            )
            .map_err(out_of_gas)?;
        let bytes = payload
            .signing_bytes_of_len(chain_id, len)
            .map_err(encoding)?;

        // 6. The non-malleable hash: of the signed bytes, for every version.
        let non_malleable_hash = MeteredHasher::<S, A>::digest(bytes.as_bytes(), state)
            .map(HexHash::new)
            .map_err(out_of_gas)?;

        // 7. The signatures: all charged, then verified.
        tx.charge_gas_for_signature(bytes.len(), state)
            .map_err(out_of_gas)?;
        let verified = match (&tx, &multisig) {
            (Transaction::V1(v1), Some(multisig)) => multisig
                .verify(&bytes, &v1.signatures)
                .map_err(TransactionError::from),
            _ => tx.verify_signature(&bytes),
        };
        verified.map_err(|error| signature_failed(error, tx_hash))?;

        let auth_data = AuthorizationData::new(
            tx.uniqueness(),
            tx_hash,
            non_malleable_hash,
            credential,
            tx.address_override().copied(),
        );
        let details = tx.details().clone();
        Ok(AuthenticationOutput {
            tx: details.into(),
            auth_data,
            call: tx.into_runtime_call(),
        })
    }
}

impl<S: Spec, R: TransactionCallable, V: RuntimeVersions> TransactionAuthenticator<S>
    for SelendraAuthenticator<S, R, V>
{
    type Decodable = R::Call;
    type Input = AuthenticatorInput;

    fn authenticate<A: AuthenticatorState<S>>(
        tx: &FullyBakedTx,
        chain_id: u64,
        state: &mut A,
    ) -> Result<AuthenticationOutput<S, R::Call>, AuthenticationError> {
        let (tx_hash, envelope) =
            Self::hash_and_parse(tx, state).map_err(|failure| match failure {
                EnvelopeFailure::Auth(error) => error,
                EnvelopeFailure::Envelope(error, tx_hash) => Self::envelope_error(error, tx_hash),
            })?;
        Self::authenticate_envelope(tx_hash, envelope, chain_id, state)
    }

    fn authenticate_unregistered<A: AuthenticatorState<S>>(
        batch: &BatchFromUnregisteredSequencer,
        chain_id: u64,
        state: &mut A,
    ) -> Result<AuthenticationOutput<S, R::Call>, UnregisteredAuthenticationError> {
        let (tx_hash, envelope) =
            Self::hash_and_parse(&batch.tx, state).map_err(|failure| match failure {
                EnvelopeFailure::Auth(error) => error.into(),
                EnvelopeFailure::Envelope(..) => {
                    UnregisteredAuthenticationError::InvalidAuthenticationDiscriminant
                }
            })?;
        Ok(Self::authenticate_envelope(
            tx_hash, envelope, chain_id, state,
        )?)
    }

    #[cfg(feature = "native")]
    fn compute_tx_hash(tx: &FullyBakedTx) -> TxHash {
        crate::capabilities::calculate_hash(tx.data())
    }

    #[cfg(feature = "native")]
    fn decode_serialized_tx(tx: &FullyBakedTx) -> Result<R::Call, FatalError> {
        let envelope = Envelope::parse(tx.data()).map_err(|error| match error {
            EnvelopeError::Reserved { tag } => FatalError::UnsupportedAuthenticator { tag },
            other => FatalError::DeserializationFailed(other.to_string()),
        })?;
        let decode = |error: borsh::io::Error| FatalError::DeserializationFailed(error.to_string());
        match envelope.kind() {
            AuthenticatorKind::Ed25519 => {
                borsh::from_slice::<Transaction<R, S, Ed25519CryptoSpec>>(envelope.raw_tx())
                    .map(Transaction::into_runtime_call)
                    .map_err(decode)
            }
            AuthenticatorKind::Secp256k1 => {
                borsh::from_slice::<Transaction<R, S, EvmCryptoSpec>>(envelope.raw_tx())
                    .map(Transaction::into_runtime_call)
                    .map_err(decode)
            }
            kind @ (AuthenticatorKind::Eip712 | AuthenticatorKind::EthereumRlp) => {
                Err(FatalError::UnsupportedAuthenticator { tag: kind.tag() })
            }
        }
    }

    fn add_standard_auth(tx: RawTx) -> AuthenticatorInput {
        AuthenticatorInput::Ed25519(tx)
    }

    fn encode_authenticator_input(input: &AuthenticatorInput) -> FullyBakedTx {
        input.to_fully_baked_tx()
    }
}

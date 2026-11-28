//! [`TransactionAuthenticator`]: checking that the claimed sender of a transaction signed it, and
//! decoding it. The native authenticator is [`SelendraAuthenticator`](crate::authenticator).

use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::TxHash;
use selendra_interface::common::HexHash;
use selendra_interface::reexports::digest::Digest;
use selendra_interface::stf::{FullyBakedTx, RawTx};
use selendra_state::metered::{Metered, ReadsUser};
use selendra_state::{StateHasher, VersionReader};
use serde::{Deserialize, Serialize};

use crate::transaction::{AuthenticatedTransactionData, AuthorizationData};
use crate::{GasMeter, MeteredHasher, Spec, TxStateError};

/// The state an authenticator runs on: the pre-execution state of a transaction
/// ([`PreExecWorkingSet`](crate::PreExecWorkingSet)), or any metered accessor that reads
/// [`User`](selendra_state::User) state, charges a transaction meter ([`GasMeter`]) and knows
/// the rollup height ([`VersionReader`], which selects the runtime versions accepted).
///
/// Implemented for every such accessor.
pub trait AuthenticatorState<S: Spec>:
    GasMeter<S> + Metered<Rights: ReadsUser> + VersionReader
{
}

impl<S: Spec, T> AuthenticatorState<S> for T where
    T: GasMeter<S> + Metered<Rights: ReadsUser> + VersionReader
{
}

/// A batch from an unregistered sequencer: one transaction, a forced registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchFromUnregisteredSequencer {
    /// The transaction.
    pub tx: FullyBakedTx,
    /// The batch's id.
    pub id: [u8; 32],
}

/// What authentication returns: the transaction's details, what it establishes about the
/// sender ([`AuthorizationData`]: hashes, credential, default address) and the call.
///
/// Upstream returned a tuple whose first item held the raw hash next to the details; the hash is
/// in [`AuthorizationData::tx_hash`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationOutput<S: Spec, Call> {
    /// The transaction's details (fees, gas limit, runtime version).
    pub tx: AuthenticatedTransactionData<S>,
    /// Who signed, the hashes, the address override.
    pub auth_data: AuthorizationData<S>,
    /// The call to run.
    pub call: Call,
}

/// Why authentication failed in a way the sequencer should have caught before including the
/// transaction: [`AuthenticationError::FatalError`] (the sequencer is slashed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum FatalError {
    /// The envelope or the transaction does not decode (trailing bytes, an unknown envelope tag
    /// and an oversized transaction included).
    #[error("the transaction does not decode: {0}")]
    DeserializationFailed(String),
    /// A signature does not verify over the signed bytes (wrong chain ID, runtime version
    /// commitment, signer, domain or payload all end here), or a multisig is invalid.
    #[error("signature verification failed: {0}")]
    SigVerificationFailed(String),
    /// The runtime version the transaction was signed for is not accepted at this height:
    /// unknown, or outside its window. `expected` is the newest version accepted (a version in
    /// its grace period is accepted too).
    #[error("runtime version {got} is not accepted (the current version is {expected})")]
    InvalidRuntimeVersion {
        /// The newest version accepted at this height.
        expected: u32,
        /// The version the transaction was signed for.
        got: u32,
    },
    /// An envelope tag reserved for an authenticator not enabled yet (EIP-712 `2`, Ethereum
    /// RLP `3`: Phase 7).
    #[error("envelope tag {tag} is reserved for an authenticator that is not enabled")]
    UnsupportedAuthenticator {
        /// The envelope tag.
        tag: u8,
    },
    /// Any other fatal error.
    #[error("{0}")]
    Other(String),
}

/// Why authentication failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationError {
    /// A failure the sequencer should have caught before including the transaction: the
    /// sequencer is slashed. With the transaction's hash.
    #[error("fatal authentication error: {0} (transaction {1})")]
    FatalError(FatalError, TxHash),
    /// Authentication ran out of gas (or its gas overflowed): including the transaction may
    /// have been an honest mistake, so the sequencer pays for the checks but is not slashed.
    #[error("authentication ran out of gas: {0}")]
    OutOfGas(String),
}

impl AuthenticationError {
    /// A gas failure ([`AuthenticationError::OutOfGas`]).
    pub(crate) fn out_of_gas(error: &impl core::fmt::Display) -> Self {
        Self::OutOfGas(error.to_string())
    }
}

/// Why the authentication of an unregistered sequencer's transaction (a forced registration)
/// failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum UnregisteredAuthenticationError {
    /// As [`AuthenticationError::FatalError`].
    #[error("fatal authentication error: {0} (transaction {1})")]
    FatalError(FatalError, TxHash),
    /// As [`AuthenticationError::OutOfGas`].
    #[error("authentication ran out of gas: {0}")]
    OutOfGas(String),
    /// The envelope's tag is not one of an enabled authenticator, or the envelope does not
    /// decode.
    #[error("invalid authentication discriminant")]
    InvalidAuthenticationDiscriminant,
}

impl From<AuthenticationError> for UnregisteredAuthenticationError {
    fn from(error: AuthenticationError) -> Self {
        match error {
            AuthenticationError::FatalError(error, hash) => Self::FatalError(error, hash),
            AuthenticationError::OutOfGas(error) => Self::OutOfGas(error),
        }
    }
}

/// Authenticates transactions: checks that the claimed sender signed (typically, verifies the
/// signatures) and decodes the call. Authentication alone does not run a transaction: the
/// [`TransactionAuthorizer`](super::TransactionAuthorizer) decides that.
///
/// Every check is charged to the pre-execution state's meter before it runs; a gas failure is
/// [`AuthenticationError::OutOfGas`], anything else [`AuthenticationError::FatalError`].
///
/// The chain ID is an input (Phase 8 reads it from kernel state per network).
pub trait TransactionAuthenticator<S: Spec> {
    /// The call a transaction carries, which the runtime runs.
    type Decodable: Send;

    /// What the authenticator reads from a [`FullyBakedTx`]'s data: an envelope naming the
    /// authenticator, and the transaction.
    type Input: BorshDeserialize + BorshSerialize + Clone + Debug + Send + Sync + 'static;

    /// Authenticates `tx` on the chain `chain_id`, charging `state`.
    ///
    /// # Errors
    /// See [`AuthenticationError`].
    fn authenticate<A: AuthenticatorState<S>>(
        tx: &FullyBakedTx,
        chain_id: u64,
        state: &mut A,
    ) -> Result<AuthenticationOutput<S, Self::Decodable>, AuthenticationError>;

    /// Authenticates the transaction of an unregistered sequencer's batch (a forced
    /// registration). Nobody pays for a failed authentication here, so it must stay cheap; the
    /// blob storage bounds how many such batches there are, and a transaction that
    /// authenticates pays for its blob.
    ///
    /// # Errors
    /// See [`UnregisteredAuthenticationError`].
    fn authenticate_unregistered<A: AuthenticatorState<S>>(
        batch: &BatchFromUnregisteredSequencer,
        chain_id: u64,
        state: &mut A,
    ) -> Result<AuthenticationOutput<S, Self::Decodable>, UnregisteredAuthenticationError>;

    /// The hash [`authenticate`](Self::authenticate) gives `tx`, unmetered (node only).
    #[cfg(feature = "native")]
    fn compute_tx_hash(tx: &FullyBakedTx) -> TxHash;

    /// Decodes `tx`'s call without authenticating it or charging gas (node only: off-chain
    /// code).
    ///
    /// # Errors
    /// The envelope or the transaction does not decode.
    #[cfg(feature = "native")]
    fn decode_serialized_tx(tx: &FullyBakedTx) -> Result<Self::Decodable, FatalError>;

    /// `tx` in the envelope of the standard authenticator.
    fn add_standard_auth(tx: RawTx) -> Self::Input;

    /// The transaction carrying `input`.
    #[must_use]
    fn encode_authenticator_input(input: &Self::Input) -> FullyBakedTx;

    /// `tx` in the envelope of the standard authenticator, as a transaction.
    #[must_use]
    fn encode_with_standard_auth(tx: RawTx) -> FullyBakedTx {
        Self::encode_authenticator_input(&Self::add_standard_auth(tx))
    }
}

/// The hash of `data` (SHA-256, the state hasher), charging `meter` `hash_update +
/// hash_per_byte·len` first.
///
/// # Errors
/// The charge was refused (the phase is then poisoned).
pub fn calculate_hash_metered<S: Spec, M: GasMeter<S>>(
    data: &[u8],
    meter: &mut M,
) -> Result<TxHash, TxStateError<S>> {
    MeteredHasher::<S, M>::digest(data, meter).map(HexHash::new)
}

/// The hash of `data` (SHA-256, the state hasher), unmetered.
pub fn calculate_hash(data: &[u8]) -> TxHash {
    HexHash::new(StateHasher::digest(data).into())
}

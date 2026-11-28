//! Transactions: a transaction's details ([`TxDetails`]) and their authenticated form
//! ([`AuthenticatedTransactionData`]), the priority fee ([`PriorityFeeBips`]); native
//! transactions ([`Transaction`]: single-key [`Version0`] or multisig [`Version1`], signed with
//! ed25519 or secp256k1, [`TxCryptoSpec`]), how they are built ([`UnsignedTransaction`]) and what
//! they sign ([`TransactionSigningPayload`], with the [`RuntimeCommitment`] to the network and
//! runtime version); the runtime versions accepted at each height ([`VersionTable`]); K-of-N
//! multisigs ([`Multisig`]); what authentication establishes ([`UniquenessData`],
//! [`AuthorizationData`]); and what a transaction's fees pay ([`TransactionConsumption`]).
//!
//! # Signing
//! A native transaction's signatures cover
//! `signing_bytes(SigningDomain::Transaction, chain_id, SHA-256(borsh(payload)))`
//! (`selendra_primitives::signing`): the signing payload holds the call, uniqueness data and
//! details, the address override, the signing key (V0) or the multisig credential's address
//! (V1), and the runtime commitment. Signatures are only ever checked against
//! [`SigningBytes`](selendra_primitives::signing::SigningBytes), never against a bare
//! payload. Encodings and known-answer vectors are in `docs/serialization.md` ("Native
//! transactions").

mod auth_data;
mod data;
mod multisig;
mod rewards;
mod runtime_version;
mod scheme;
mod signing_payload;
mod types;
mod unsigned;

#[cfg(test)]
pub(crate) mod tests;

use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub use auth_data::{AuthorizationData, UniquenessData};
pub(crate) use data::required_option;
pub use data::{
    AuthenticatedTransactionData, PriorityFeeApplyOverflowError, PriorityFeeBips, TxDetails,
};
#[cfg(test)]
pub(crate) use multisig::count_multisig_builds;
pub use multisig::{MAX_SIGNERS, Multisig, MultisigError, PubKeyAndSignature};
pub use rewards::{ProverReward, RemainingFunds, SequencerReward, TransactionConsumption};
pub use runtime_version::{
    RuntimeCommitment, SchemaHash, VersionTable, VersionTableError, VersionWindow,
    check_version_table,
};
pub use scheme::{SignatureScheme, TxCryptoSpec};
pub use signing_payload::{
    TransactionSigningPayload, TransactionSigningPayloadV0, TransactionSigningPayloadV1,
};
pub use types::{Transaction, Version0, Version1};
pub use unsigned::UnsignedTransaction;

use crate::{ConsensusType, DispatchCall};

/// What a transaction calls: [`Call`](Self::Call), the runtime's call type. Implemented for
/// every runtime ([`DispatchCall::Decodable`]); tests implement it for other call types.
pub trait TransactionCallable {
    /// The call type. It is signed, so it is a consensus type.
    type Call: ConsensusType
        + BorshSerialize
        + BorshDeserialize
        + Serialize
        + DeserializeOwned
        + Debug
        + Clone
        + PartialEq
        + Eq
        + Send
        + Sync;
}

impl<D: DispatchCall> TransactionCallable for D {
    type Call = D::Decodable;
}

/// Why a native transaction cannot be signed or its signatures do not verify.
///
/// Upstream's `TransactionVerificationError` also had a gas variant: gas is charged by the
/// authenticator, before each check (Phase 5 S11).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransactionError {
    /// A V1 transaction's keys are not a valid multisig, or its signatures do not satisfy it.
    #[error("multisig: {0}")]
    Multisig(#[from] MultisigError),
    /// A V0 transaction's signature does not verify.
    #[error("invalid signature: {error}")]
    BadSignature {
        /// Why.
        error: String,
    },
    /// The signing payload does not encode (a call type whose `BorshSerialize` fails, which a
    /// consensus type must never do).
    #[error("the signing payload does not encode: {error}")]
    Encoding {
        /// Why.
        error: String,
    },
    /// The signing payload does not encode to the length the transaction's own encoding gives
    /// (the length the authenticator charges for before encoding the payload): a field, in
    /// practice the call, was decoded from bytes other than its own encoding (a call type whose
    /// decoding is not canonical).
    #[error(
        "the signing payload does not encode to the length the transaction's encoding gives: \
         the transaction's encoding is not canonical"
    )]
    NonCanonicalEncoding,
}

impl TransactionError {
    fn encoding(error: borsh::io::Error) -> Self {
        Self::Encoding {
            error: error.to_string(),
        }
    }
}

/// `Clone`, `PartialEq`, `Eq` and `Debug` for a struct generic over a runtime, field by field:
/// the std derives would require the runtime type itself to implement them.
macro_rules! value_traits {
    ([$($generics:tt)*] $name:ident <$($param:ident),*> { $($field:ident),* $(,)? }) => {
        impl<$($generics)*> Clone for $name<$($param),*> {
            fn clone(&self) -> Self {
                Self { $($field: self.$field.clone()),* }
            }
        }

        impl<$($generics)*> PartialEq for $name<$($param),*> {
            fn eq(&self, other: &Self) -> bool {
                true $(&& self.$field == other.$field)*
            }
        }

        impl<$($generics)*> Eq for $name<$($param),*> {}

        impl<$($generics)*> core::fmt::Debug for $name<$($param),*> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name))
                    $(.field(stringify!($field), &self.$field))*
                    .finish()
            }
        }
    };
}

pub(crate) use value_traits;

//! The module system's bounds on keys and signatures: what `selendra-interface`'s
//! [`PublicKey`](selendra_interface::crypto::PublicKey) and
//! [`Signature`](selendra_interface::crypto::Signature) must also be for transactions to carry
//! them (borsh, a JSON schema, a text form) and for them to be signed or stored (consensus
//! types).
//!
//! Unlike upstream, the bounds of [`SignatureExt`] and [`PublicKeyExt`] do not depend on
//! features: a key type is usable in a guest build exactly when it is in a node build (upstream
//! required `FromStr` with `native` only, so a type could satisfy the bound in one build and not
//! the other).

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use schemars::JsonSchema;
use selendra_interface::common::ConsensusType;

/// A signature the module system can carry: borsh-encoded in transactions, with a JSON schema
/// and a text form, and a consensus type.
pub trait SignatureExt:
    selendra_interface::crypto::Signature
    + BorshSerialize
    + BorshDeserialize
    + JsonSchema
    + FromStr<Err = anyhow::Error>
    + ConsensusType
{
}

impl<S> SignatureExt for S where
    S: selendra_interface::crypto::Signature
        + BorshSerialize
        + BorshDeserialize
        + JsonSchema
        + FromStr<Err = anyhow::Error>
        + ConsensusType
{
}

/// A public key the module system can carry: borsh-encoded in transactions, with a JSON schema
/// and a text form, and a consensus type.
pub trait PublicKeyExt:
    selendra_interface::crypto::PublicKey
    + BorshSerialize
    + BorshDeserialize
    + JsonSchema
    + FromStr<Err = anyhow::Error>
    + ConsensusType
{
}

impl<P> PublicKeyExt for P where
    P: selendra_interface::crypto::PublicKey
        + BorshSerialize
        + BorshDeserialize
        + JsonSchema
        + FromStr<Err = anyhow::Error>
        + ConsensusType
{
}

/// A private key of the module system (node-only: private keys never reach the zk guest),
/// whose public key and signature are [`PublicKeyExt`] and [`SignatureExt`].
///
/// Upstream also required `arbitrary::Arbitrary` under its `arbitrary` feature; private keys
/// have no such impl here (tests generate them).
#[cfg(feature = "native")]
pub trait PrivateKeyExt:
    selendra_interface::crypto::PrivateKey<PublicKey: PublicKeyExt, Signature: SignatureExt>
{
}

#[cfg(feature = "native")]
impl<P> PrivateKeyExt for P where
    P: selendra_interface::crypto::PrivateKey<PublicKey: PublicKeyExt, Signature: SignatureExt>
{
}

#[cfg(test)]
mod tests {
    use selendra_primitives::crypto::{
        Ed25519PublicKey, Ed25519Signature, EthereumPublicKey, EthereumSignature,
    };

    use super::*;

    #[test]
    fn selendra_keys_and_signatures_qualify() {
        fn public_key<P: PublicKeyExt>() {}
        fn signature<S: SignatureExt>() {}
        public_key::<Ed25519PublicKey>();
        public_key::<EthereumPublicKey>();
        signature::<Ed25519Signature>();
        signature::<EthereumSignature>();
    }
}

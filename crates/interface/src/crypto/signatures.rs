//! Asymmetric cryptography primitive definitions

use std::fmt::Debug;
use std::hash;

use derive_more::derive::Display;
use serde::{Deserialize, Serialize};

use super::CredentialId;

/// Representation of a signature verification error.
#[derive(Debug, Display)]
pub struct SigVerificationError {
    /// The error message.
    pub error: String,
}

/// A digital signature.
pub trait Signature:
    for<'a> TryFrom<&'a [u8], Error = anyhow::Error>
    + TryFrom<Vec<u8>>
    + AsRef<[u8]>
    + Eq
    + Clone
    + Debug
    + Send
    + Sync
    + Serialize
    + for<'a> Deserialize<'a>
{
    /// The public key associated with the signature.
    type PublicKey;

    /// Verifies the signature.
    fn verify(&self, pub_key: &Self::PublicKey, msg: &[u8]) -> Result<(), SigVerificationError>;
}

/// A public key for verifying digital signatures.
pub trait PublicKey:
    Eq
    + hash::Hash
    + Clone
    + Debug
    + Send
    + Sync
    + Serialize
    + PartialOrd
    + Ord
    + for<'a> Deserialize<'a>
    + TryFrom<Vec<u8>>
    + AsRef<[u8]>
{
    /// Returns hashed public key.
    fn credential_id(&self) -> CredentialId;
}

/// A private key for generating digital signatures.
#[cfg(feature = "native")]
pub trait PrivateKey:
    Debug
    + Send
    + Sync
    + Serialize
    + Clone
    + serde::de::DeserializeOwned
    + TryFrom<Vec<u8>>
    + AsRef<[u8]>
{
    /// The public key type associated with this signature scheme.
    type PublicKey: PublicKey;

    /// The signature associated with the key pair.
    type Signature: Signature<PublicKey = Self::PublicKey>;

    /// Generates a new key pair.
    fn generate() -> Self;

    /// Returns the public key derived from this private key.
    fn pub_key(&self) -> Self::PublicKey;

    /// Signs the provided message using the private key.
    fn sign(&self, msg: &[u8]) -> Self::Signature;
}

//! Ed25519 keys and signatures, backed by `ed25519-consensus`.
//!
//! `ed25519-consensus` implements the ZIP-215 validation rules, which are fully specified,
//! so every implementation (native, SP1, batch or single verification) accepts exactly the
//! same signatures. Other ed25519 libraries (e.g. `ed25519-dalek`) differ on edge cases,
//! which would let the prover and the nodes disagree. Do not mix libraries.

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_consensus::{Signature, VerificationKey};
use schemars::JsonSchema;
use selendra_interface::common::HexString;
use selendra_interface::crypto::{CredentialId, SigVerificationError};

/// Length of an ed25519 public key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;
/// Length of an ed25519 signature in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// An ed25519 public key. Decoding checks that the bytes are a valid curve point.
#[derive(PartialEq, Eq, Hash, Clone, Debug, PartialOrd, Ord)]
pub struct Ed25519PublicKey {
    pub_key: VerificationKey,
}

impl Ed25519PublicKey {
    /// Returns the bytes of the underlying public key.
    pub fn bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.pub_key.as_bytes()
    }

    /// Decodes a public key, checking that the bytes are a valid curve point.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Result<Self, ed25519_consensus::Error> {
        Ok(Self {
            pub_key: VerificationKey::try_from(bytes)?,
        })
    }
}

impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; PUBLIC_KEY_LENGTH] = value
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid public key size: {}", value.len()))?;
        Ok(Self::from_bytes(bytes)?)
    }
}

impl TryFrom<Vec<u8>> for Ed25519PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.pub_key.as_ref()
    }
}

impl selendra_interface::crypto::PublicKey for Ed25519PublicKey {
    fn credential_id(&self) -> CredentialId {
        // The pub key is already 32 bytes, so we don't hash it.
        CredentialId::from_bytes(*self.bytes())
    }
}

impl BorshSerialize for Ed25519PublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self.bytes())
    }
}

impl BorshDeserialize for Ed25519PublicKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
        reader.read_exact(&mut bytes)?;
        Self::from_bytes(bytes).map_err(std::io::Error::other)
    }
}

/// JSON: `0x`-prefixed hex (the prefix is optional when parsing). Binary formats: raw bytes.
impl serde::Serialize for Ed25519PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&HexString(*self.bytes()), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let HexString(bytes) =
            <HexString<[u8; PUBLIC_KEY_LENGTH]> as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for Ed25519PublicKey {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Ed25519PublicKey".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        HexString::<[u8; PUBLIC_KEY_LENGTH]>::json_schema(generator)
    }
}

impl FromStr for Ed25519PublicKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let HexString(bytes) = HexString::<[u8; PUBLIC_KEY_LENGTH]>::from_str(s)?;
        Ok(Self::from_bytes(bytes)?)
    }
}

/// An ed25519 signature.
///
/// Stored as its 64 raw bytes, which are exactly what [`AsRef`], borsh and serde expose and
/// what verification checks. (Upstream kept a parsed copy next to a byte copy and serialized
/// both, so a decoded signature could expose bytes different from the ones verified.)
#[derive(PartialEq, Eq, Hash, Clone, BorshSerialize, BorshDeserialize)]
pub struct Ed25519Signature([u8; SIGNATURE_LENGTH]);

impl Ed25519Signature {
    /// Wraps raw signature bytes. Any 64 bytes are a well-formed signature; validity is
    /// only decided by [`selendra_interface::crypto::Signature::verify`].
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw signature bytes.
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0
    }
}

impl core::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ed25519Signature({})", HexString(self.0))
    }
}

impl From<Signature> for Ed25519Signature {
    fn from(signature: Signature) -> Self {
        Self(signature.to_bytes())
    }
}

impl TryFrom<&[u8]> for Ed25519Signature {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; SIGNATURE_LENGTH] = value
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature size: {}", value.len()))?;
        Ok(Self(bytes))
    }
}

impl TryFrom<Vec<u8>> for Ed25519Signature {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl selendra_interface::crypto::Signature for Ed25519Signature {
    type PublicKey = Ed25519PublicKey;

    fn verify(&self, pub_key: &Self::PublicKey, msg: &[u8]) -> Result<(), SigVerificationError> {
        pub_key
            .pub_key
            .verify(&Signature::from(self.0), msg)
            .map_err(|e| SigVerificationError {
                error: e.to_string(),
            })
    }
}

/// JSON: `0x`-prefixed hex (the prefix is optional when parsing). Binary formats: raw bytes.
impl serde::Serialize for Ed25519Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&HexString(self.0), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <HexString<[u8; SIGNATURE_LENGTH]> as serde::Deserialize>::deserialize(deserializer)
            .map(|h| Self(h.0))
    }
}

impl JsonSchema for Ed25519Signature {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Ed25519Signature".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        HexString::<[u8; SIGNATURE_LENGTH]>::json_schema(generator)
    }
}

impl FromStr for Ed25519Signature {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HexString::<[u8; SIGNATURE_LENGTH]>::from_str(s).map(|h| Self(h.0))
    }
}

#[cfg(feature = "native")]
pub use private_key::Ed25519PrivateKey;

#[cfg(feature = "native")]
mod private_key {
    use ed25519_consensus::SigningKey;
    use rand_core::OsRng;
    use selendra_interface::common::HexString;

    use super::{Ed25519PublicKey, Ed25519Signature};

    /// An ed25519 private key. Only available with the `native` feature.
    ///
    /// JSON: `0x`-prefixed hex of the 32-byte secret. `Debug` never prints the secret.
    #[derive(Clone)]
    pub struct Ed25519PrivateKey {
        key: SigningKey,
    }

    impl Ed25519PrivateKey {
        /// Creates a private key from its 32 secret bytes.
        pub fn from_bytes(bytes: [u8; 32]) -> Self {
            Self {
                key: SigningKey::from(bytes),
            }
        }

        /// Returns the private key as a hex string (no `0x` prefix).
        pub fn as_hex(&self) -> String {
            hex::encode(self.key.as_bytes())
        }
    }

    impl core::fmt::Debug for Ed25519PrivateKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Ed25519PrivateKey")
                .field("public_key", &self.key.verification_key())
                .field("private_key", &"***REDACTED***")
                .finish()
        }
    }

    impl AsRef<[u8]> for Ed25519PrivateKey {
        fn as_ref(&self) -> &[u8] {
            self.key.as_bytes()
        }
    }

    impl TryFrom<Vec<u8>> for Ed25519PrivateKey {
        type Error = anyhow::Error;

        fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
            let bytes: [u8; 32] = value
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid private key size: {}", value.len()))?;
            Ok(Self::from_bytes(bytes))
        }
    }

    impl serde::Serialize for Ed25519PrivateKey {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serde::Serialize::serialize(&HexString(*self.key.as_bytes()), serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for Ed25519PrivateKey {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            <HexString<[u8; 32]> as serde::Deserialize>::deserialize(deserializer)
                .map(|h| Self::from_bytes(h.0))
        }
    }

    impl selendra_interface::crypto::PrivateKey for Ed25519PrivateKey {
        type PublicKey = Ed25519PublicKey;
        type Signature = Ed25519Signature;

        fn generate() -> Self {
            Self {
                key: SigningKey::new(OsRng),
            }
        }

        fn pub_key(&self) -> Self::PublicKey {
            Ed25519PublicKey {
                pub_key: self.key.verification_key(),
            }
        }

        fn sign(&self, msg: &[u8]) -> Self::Signature {
            self.key.sign(msg).into()
        }
    }
}

#[cfg(test)]
mod tests {
    use selendra_interface::crypto::{PrivateKey, PublicKey, Signature};

    use super::*;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// RFC 8032 section 7.1, TEST 1 (empty message).
    #[test]
    fn rfc8032_test_1() {
        let sk = Ed25519PrivateKey::from_bytes(h(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let pk = Ed25519PublicKey::from_bytes(h(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ))
        .unwrap();
        let sig = Ed25519Signature::from_bytes(h(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ));

        assert_eq!(sk.pub_key(), pk);
        assert_eq!(sk.sign(b""), sig);
        sig.verify(&pk, b"").unwrap();
        assert_eq!(pk.credential_id(), CredentialId::from_bytes(*pk.bytes()));
    }

    #[test]
    fn sign_and_verify() {
        let sk = Ed25519PrivateKey::generate();
        let pk = sk.pub_key();
        let sig = sk.sign(b"selendra");

        sig.verify(&pk, b"selendra").unwrap();
        assert!(sig.verify(&pk, b"other message").is_err());
        assert!(
            sig.verify(&Ed25519PrivateKey::generate().pub_key(), b"selendra")
                .is_err()
        );

        let mut tampered = sig.to_bytes();
        tampered[0] ^= 1;
        assert!(
            Ed25519Signature::from_bytes(tampered)
                .verify(&pk, b"selendra")
                .is_err()
        );
    }

    #[test]
    fn borsh_is_raw_bytes() {
        let sk = Ed25519PrivateKey::generate();
        let pk = sk.pub_key();
        let sig = sk.sign(b"msg");

        let pk_bytes = borsh::to_vec(&pk).unwrap();
        assert_eq!(pk_bytes, pk.bytes());
        assert_eq!(
            borsh::from_slice::<Ed25519PublicKey>(&pk_bytes).unwrap(),
            pk
        );

        let sig_bytes = borsh::to_vec(&sig).unwrap();
        assert_eq!(sig_bytes, sig.as_ref());
        assert_eq!(
            borsh::from_slice::<Ed25519Signature>(&sig_bytes).unwrap(),
            sig
        );

        assert!(borsh::from_slice::<Ed25519PublicKey>(&pk_bytes[..31]).is_err());
        assert!(borsh::from_slice::<Ed25519Signature>(&sig_bytes[..63]).is_err());
    }

    #[test]
    fn invalid_public_key_is_rejected_everywhere() {
        // Not every 32-byte string is a curve point; find one that isn't.
        let bad = (0u8..=255)
            .map(|i| [i; PUBLIC_KEY_LENGTH])
            .find(|b| VerificationKey::try_from(*b).is_err())
            .expect("some constant byte string is not a valid point");

        assert!(Ed25519PublicKey::from_bytes(bad).is_err());
        assert!(Ed25519PublicKey::try_from(bad.as_slice()).is_err());
        assert!(borsh::from_slice::<Ed25519PublicKey>(&bad).is_err());
        assert!(
            serde_json::from_str::<Ed25519PublicKey>(&format!("\"{}\"", HexString(bad))).is_err()
        );
        assert!(Ed25519PublicKey::from_str(&hex::encode(bad)).is_err());
    }

    #[test]
    fn json_is_hex_and_roundtrips() {
        let sk = Ed25519PrivateKey::generate();
        let pk = sk.pub_key();
        let sig = sk.sign(b"msg");

        let pk_json = serde_json::to_string(&pk).unwrap();
        assert_eq!(pk_json, format!("\"0x{}\"", hex::encode(pk.bytes())));
        assert_eq!(
            serde_json::from_str::<Ed25519PublicKey>(&pk_json).unwrap(),
            pk
        );
        assert_eq!(
            Ed25519PublicKey::from_str(&hex::encode(pk.bytes())).unwrap(),
            pk
        );

        let sig_json = serde_json::to_string(&sig).unwrap();
        assert_eq!(
            serde_json::from_str::<Ed25519Signature>(&sig_json).unwrap(),
            sig
        );

        let sk_json = serde_json::to_string(&sk).unwrap();
        let sk2: Ed25519PrivateKey = serde_json::from_str(&sk_json).unwrap();
        assert_eq!(sk2.as_hex(), sk.as_hex());
    }

    #[test]
    fn binary_serde_roundtrips() {
        let sk = Ed25519PrivateKey::generate();
        let pk = sk.pub_key();
        let sig = sk.sign(b"msg");

        let bytes = postcard::to_allocvec(&(&pk, &sig, &sk)).unwrap();
        let (pk2, sig2, sk2): (Ed25519PublicKey, Ed25519Signature, Ed25519PrivateKey) =
            postcard::from_bytes(&bytes).unwrap();
        assert_eq!((pk2, sig2, sk2.as_hex()), (pk, sig, sk.as_hex()));
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let sk = Ed25519PrivateKey::generate();
        let debug = format!("{sk:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&sk.as_hex()));
    }
}

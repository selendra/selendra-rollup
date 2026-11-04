//! secp256k1 keys and ECDSA signatures over `keccak256(message)`, as used by Ethereum
//! wallets. Backed by `k256`.
//!
//! Every key and signature has exactly one accepted encoding: public keys are stored
//! SEC1-compressed (33 bytes), and signatures must be low-S (EIP-2), so a valid signature
//! cannot be turned into a second valid one by negating `s`.

use std::str::FromStr;

use alloy_primitives::keccak256;
use borsh::{BorshDeserialize, BorshSerialize};
use k256::ecdsa::VerifyingKey;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use schemars::JsonSchema;
use selendra_interface::common::HexString;
use selendra_interface::crypto::{CredentialId, SigVerificationError};

use crate::EthereumAddress;

/// Length of a compressed SEC1 secp256k1 public key.
pub const PUBLIC_KEY_LENGTH: usize = 33;
/// Length of an ECDSA signature (`r || s`).
pub const SIGNATURE_LENGTH: usize = 64;

/// A secp256k1 public key, stored in compressed SEC1 form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthereumPublicKey {
    // Always the compressed encoding of a valid, non-identity point.
    bytes: [u8; PUBLIC_KEY_LENGTH],
}

impl EthereumPublicKey {
    /// Parses a SEC1 public key (33-byte compressed or 65-byte uncompressed) and
    /// normalizes it to the compressed form.
    ///
    /// Only the standard tags are accepted: `0x02`/`0x03` (33 bytes) and `0x04` (65 bytes).
    /// `k256` also accepts SEC1 "compact" (`0x05`) and "hybrid" (`0x06`/`0x07`) points, which
    /// would give the same key additional encodings; those are rejected.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, k256::elliptic_curve::Error> {
        match (bytes.len(), bytes.first()) {
            (33, Some(0x02 | 0x03)) | (65, Some(0x04)) => {}
            _ => return Err(k256::elliptic_curve::Error),
        }
        Ok(Self::from(&k256::PublicKey::from_sec1_bytes(bytes)?))
    }

    /// Returns the compressed SEC1 bytes.
    pub fn bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.bytes
    }

    fn verifying_key(&self) -> VerifyingKey {
        // The bytes were produced from a valid point, so this cannot fail.
        VerifyingKey::from_sec1_bytes(&self.bytes).expect("stored key is a valid point")
    }

    /// The Ethereum address of this key: the last 20 bytes of `keccak256` of the
    /// uncompressed point (without the `0x04` tag).
    pub fn ethereum_address(&self) -> EthereumAddress {
        let uncompressed = self.verifying_key().to_sec1_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        EthereumAddress::new(addr)
    }
}

impl From<&k256::PublicKey> for EthereumPublicKey {
    fn from(key: &k256::PublicKey) -> Self {
        let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
        bytes.copy_from_slice(VerifyingKey::from(key).to_sec1_point(true).as_bytes());
        Self { bytes }
    }
}

impl core::fmt::Debug for EthereumPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EthereumPublicKey({})", HexString(self.bytes))
    }
}

impl TryFrom<&[u8]> for EthereumPublicKey {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_sec1_bytes(value).map_err(|e| anyhow::anyhow!("Invalid public key: {e}"))
    }
}

impl TryFrom<Vec<u8>> for EthereumPublicKey {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl AsRef<[u8]> for EthereumPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl selendra_interface::crypto::PublicKey for EthereumPublicKey {
    /// The credential of a secp256k1 key is its Ethereum address, left-padded to 32 bytes.
    fn credential_id(&self) -> CredentialId {
        self.ethereum_address().as_credential_id()
    }
}

/// Borsh: exactly the 33 compressed bytes; anything else is rejected.
impl BorshSerialize for EthereumPublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.bytes)
    }
}

impl BorshDeserialize for EthereumPublicKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
        reader.read_exact(&mut bytes)?;
        let key = Self::from_sec1_bytes(&bytes).map_err(std::io::Error::other)?;
        // Only the compressed form is canonical. Checked, not assumed: the fuzzer found that
        // k256 accepts other 33-byte encodings (compact `0x05`) of the same key.
        if key.bytes != bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "non-canonical secp256k1 public key encoding",
            ));
        }
        Ok(key)
    }
}

/// JSON: `0x`-prefixed lowercase hex of the compressed key. Binary serde: a length-prefixed
/// byte sequence. Borsh: the 33 raw bytes.
impl serde::Serialize for EthereumPublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&HexString(self.bytes), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for EthereumPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let HexString(bytes) =
            <HexString<[u8; PUBLIC_KEY_LENGTH]> as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_sec1_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for EthereumPublicKey {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "EthereumPublicKey".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        HexString::<[u8; PUBLIC_KEY_LENGTH]>::json_schema(generator)
    }
}

impl FromStr for EthereumPublicKey {
    type Err = anyhow::Error;

    /// Accepts `0x`-prefixed lowercase hex of a compressed or uncompressed SEC1 key; an
    /// uncompressed key is normalized to its compressed form.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let HexString(bytes) = HexString::<Vec<u8>>::from_str(s)?;
        Self::try_from(bytes.as_slice())
    }
}

/// An ECDSA secp256k1 signature (`r || s`) over `keccak256(message)`.
///
/// Construction rejects malformed scalars and high-S signatures, so every value of this
/// type is the unique canonical form of its signature.
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize)]
pub struct EthereumSignature([u8; SIGNATURE_LENGTH]);

impl EthereumSignature {
    /// Validates and wraps raw signature bytes: `r` and `s` must be valid non-zero
    /// scalars and `s` must be in the lower half of the curve order (EIP-2).
    pub fn from_bytes(bytes: [u8; SIGNATURE_LENGTH]) -> anyhow::Result<Self> {
        let sig = k256::ecdsa::Signature::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("Invalid signature: {e}"))?;
        if sig.normalize_s() != sig {
            anyhow::bail!("Invalid signature: high-S (EIP-2)");
        }
        Ok(Self(bytes))
    }

    /// Returns the raw signature bytes.
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0
    }
}

impl core::fmt::Debug for EthereumSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EthereumSignature({})", HexString(self.0))
    }
}

impl BorshDeserialize for EthereumSignature {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; SIGNATURE_LENGTH];
        reader.read_exact(&mut bytes)?;
        Self::from_bytes(bytes).map_err(std::io::Error::other)
    }
}

impl TryFrom<&[u8]> for EthereumSignature {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; SIGNATURE_LENGTH] = value
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature size: {}", value.len()))?;
        Self::from_bytes(bytes)
    }
}

impl TryFrom<Vec<u8>> for EthereumSignature {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl AsRef<[u8]> for EthereumSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl selendra_interface::crypto::Signature for EthereumSignature {
    type PublicKey = EthereumPublicKey;

    fn verify(&self, pub_key: &Self::PublicKey, msg: &[u8]) -> Result<(), SigVerificationError> {
        let to_err = |e: k256::ecdsa::Error| SigVerificationError {
            error: e.to_string(),
        };
        // Bytes were validated at construction; parsing again only rebuilds the scalars.
        let sig = k256::ecdsa::Signature::from_slice(&self.0).map_err(to_err)?;
        pub_key
            .verifying_key()
            .verify_prehash(keccak256(msg).as_slice(), &sig)
            .map_err(to_err)
    }
}

/// JSON: `0x`-prefixed lowercase hex. Binary serde: a length-prefixed byte sequence.
/// Borsh: the 64 raw bytes.
impl serde::Serialize for EthereumSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&HexString(self.0), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for EthereumSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let HexString(bytes) =
            <HexString<[u8; SIGNATURE_LENGTH]> as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for EthereumSignature {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "EthereumSignature".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        HexString::<[u8; SIGNATURE_LENGTH]>::json_schema(generator)
    }
}

impl FromStr for EthereumSignature {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let HexString(bytes) = HexString::<[u8; SIGNATURE_LENGTH]>::from_str(s)?;
        Self::from_bytes(bytes)
    }
}

#[cfg(feature = "native")]
pub use private_key::EthereumPrivateKey;

#[cfg(feature = "native")]
mod private_key {
    use alloy_primitives::keccak256;
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::elliptic_curve::Generate;
    use selendra_interface::common::HexString;

    use super::{EthereumPublicKey, EthereumSignature};

    /// A secp256k1 private key. Only available with the `native` feature.
    ///
    /// JSON: `0x`-prefixed hex of the 32-byte secret. `Debug` never prints the secret.
    #[derive(Clone)]
    pub struct EthereumPrivateKey {
        key: SigningKey,
        // Derived from `key`; kept only because `PrivateKey` requires `AsRef<[u8]>`.
        bytes: [u8; 32],
    }

    impl EthereumPrivateKey {
        /// Creates a private key from its 32 secret bytes (must be a valid non-zero scalar).
        pub fn from_bytes(bytes: [u8; 32]) -> anyhow::Result<Self> {
            let key = SigningKey::from_bytes(&bytes.into())
                .map_err(|e| anyhow::anyhow!("Invalid private key: {e}"))?;
            Ok(Self { key, bytes })
        }

        /// Returns the secret as `0x` + lowercase hex: the same string as its JSON form.
        pub fn as_hex(&self) -> String {
            HexString(self.bytes).to_string()
        }
    }

    impl core::fmt::Debug for EthereumPrivateKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("EthereumPrivateKey")
                .field(
                    "public_key",
                    &selendra_interface::crypto::PrivateKey::pub_key(self),
                )
                .field("private_key", &"***REDACTED***")
                .finish()
        }
    }

    impl AsRef<[u8]> for EthereumPrivateKey {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl TryFrom<Vec<u8>> for EthereumPrivateKey {
        type Error = anyhow::Error;

        fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
            let bytes: [u8; 32] = value
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid private key size: {}", value.len()))?;
            Self::from_bytes(bytes)
        }
    }

    impl serde::Serialize for EthereumPrivateKey {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serde::Serialize::serialize(&HexString(self.bytes), serializer)
        }
    }

    impl<'de> serde::Deserialize<'de> for EthereumPrivateKey {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let HexString(bytes) =
                <HexString<[u8; 32]> as serde::Deserialize>::deserialize(deserializer)?;
            Self::from_bytes(bytes).map_err(serde::de::Error::custom)
        }
    }

    impl selendra_interface::crypto::PrivateKey for EthereumPrivateKey {
        type PublicKey = EthereumPublicKey;
        type Signature = EthereumSignature;

        fn generate() -> Self {
            let key = SigningKey::generate();
            let bytes = key.to_bytes().into();
            Self { key, bytes }
        }

        fn pub_key(&self) -> Self::PublicKey {
            EthereumPublicKey::from(&k256::PublicKey::from(self.key.verifying_key()))
        }

        fn sign(&self, msg: &[u8]) -> Self::Signature {
            // RFC 6979 deterministic nonce; k256 always returns low-S signatures.
            let sig: k256::ecdsa::Signature = self
                .key
                .sign_prehash(keccak256(msg).as_slice())
                .expect("a 32-byte prehash is always signable");
            EthereumSignature::from_bytes(sig.to_bytes().into())
                .expect("k256 produces valid low-S signatures")
        }
    }
}

#[cfg(test)]
mod tests {
    use selendra_interface::crypto::{PrivateKey, PublicKey, Signature};

    use super::*;

    /// secp256k1 group order n, big-endian.
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    /// `n - s` as big-endian bytes.
    fn negate_s(s: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut d = N[i] as i16 - s[i] as i16 - borrow;
            borrow = (d < 0) as i16;
            if d < 0 {
                d += 256;
            }
            out[i] = d as u8;
        }
        out
    }

    fn key(byte_hex: &str) -> EthereumPrivateKey {
        let b: [u8; 32] = hex::decode(byte_hex).unwrap().try_into().unwrap();
        EthereumPrivateKey::from_bytes(b).unwrap()
    }

    /// Well-known Ethereum vectors (private key -> address).
    #[test]
    fn ethereum_address_vectors() {
        let one = key("0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(
            one.pub_key().ethereum_address().to_string(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
        let web3 = key("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
        assert_eq!(
            web3.pub_key().ethereum_address().to_string(),
            "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
        );
        assert_eq!(
            one.pub_key().credential_id(),
            one.pub_key().ethereum_address().as_credential_id()
        );
    }

    #[test]
    fn sign_and_verify() {
        let sk = EthereumPrivateKey::generate();
        let pk = sk.pub_key();
        let sig = sk.sign(b"selendra");

        sig.verify(&pk, b"selendra").unwrap();
        assert!(sig.verify(&pk, b"other").is_err());
        assert!(
            sig.verify(&EthereumPrivateKey::generate().pub_key(), b"selendra")
                .is_err()
        );
    }

    #[test]
    fn rejects_high_s() {
        let sk = EthereumPrivateKey::generate();
        let sig = sk.sign(b"msg").to_bytes();

        let mut high = sig;
        high[32..].copy_from_slice(&negate_s(&sig[32..]));

        // The flipped signature is mathematically valid ECDSA for the same message...
        let raw = k256::ecdsa::Signature::from_slice(&high).unwrap();
        assert_ne!(raw.normalize_s(), raw, "flipped s must be high");
        // k256 verification already rejects it. We additionally reject at decode time,
        // so a high-S signature can never be stored, and so a patched k256 (SP1) that
        // behaved differently could not change which signatures are valid.
        let vk = VerifyingKey::from_sec1_bytes(sk.pub_key().bytes()).unwrap();
        assert!(
            vk.verify_prehash(keccak256(b"msg").as_slice(), &raw)
                .is_err()
        );
        // ...but is not accepted by any of our entry points.
        assert!(EthereumSignature::from_bytes(high).is_err());
        assert!(EthereumSignature::try_from(high.as_slice()).is_err());
        assert!(borsh::from_slice::<EthereumSignature>(&high).is_err());
        assert!(
            serde_json::from_str::<EthereumSignature>(&format!("\"{}\"", HexString(high))).is_err()
        );
    }

    #[test]
    fn rejects_malformed_signatures() {
        // Start from a valid signature and break one scalar at a time, so each rejection comes
        // from that scalar's range check alone.
        let good: [u8; 64] = EthereumPrivateKey::generate()
            .sign(b"m")
            .as_ref()
            .try_into()
            .unwrap();
        assert!(EthereumSignature::from_bytes(good).is_ok());

        // The secp256k1 group order n.
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        for bad_scalar in [[0u8; 32].as_slice(), &n, &[0xff; 32]] {
            let mut bad_r = good;
            bad_r[..32].copy_from_slice(bad_scalar);
            assert!(EthereumSignature::from_bytes(bad_r).is_err());

            let mut bad_s = good;
            bad_s[32..].copy_from_slice(bad_scalar);
            assert!(EthereumSignature::from_bytes(bad_s).is_err());
        }
    }

    #[test]
    fn public_key_is_normalized_to_compressed() {
        let sk = EthereumPrivateKey::generate();
        let pk = sk.pub_key();
        let uncompressed = VerifyingKey::from_sec1_bytes(pk.bytes())
            .unwrap()
            .to_sec1_point(false);

        let from_uncompressed = EthereumPublicKey::try_from(uncompressed.as_bytes()).unwrap();
        assert_eq!(from_uncompressed, pk);
        assert_eq!(from_uncompressed.as_ref(), pk.bytes());
        assert_eq!(borsh::to_vec(&from_uncompressed).unwrap(), pk.bytes());
        // Borsh only accepts the 33-byte compressed form.
        assert!(borsh::from_slice::<EthereumPublicKey>(uncompressed.as_bytes()).is_err());
        assert!(EthereumPublicKey::from_sec1_bytes(&[0; 33]).is_err());

        // Found by fuzzing: SEC1 "compact" (0x05 || x) is the same key under another tag.
        let mut compact = *pk.bytes();
        compact[0] = 0x05;
        assert!(EthereumPublicKey::from_sec1_bytes(&compact).is_err());
        assert!(borsh::from_slice::<EthereumPublicKey>(&compact).is_err());
        // Hybrid (0x06/0x07 || x || y) likewise.
        let mut hybrid = uncompressed.as_bytes().to_vec();
        for tag in [0x06, 0x07] {
            hybrid[0] = tag;
            assert!(EthereumPublicKey::from_sec1_bytes(&hybrid).is_err());
        }
    }

    #[test]
    fn encodings_roundtrip() {
        let sk = EthereumPrivateKey::generate();
        let pk = sk.pub_key();
        let sig = sk.sign(b"msg");

        assert_eq!(
            borsh::from_slice::<EthereumPublicKey>(&borsh::to_vec(&pk).unwrap()).unwrap(),
            pk
        );
        assert_eq!(borsh::to_vec(&sig).unwrap(), sig.as_ref());
        assert_eq!(
            borsh::from_slice::<EthereumSignature>(sig.as_ref()).unwrap(),
            sig
        );

        assert_eq!(sk.as_hex(), format!("0x{}", hex::encode(sk.as_ref())));
        assert_eq!(
            serde_json::to_string(&sk).unwrap(),
            format!("\"{}\"", sk.as_hex())
        );

        let json = serde_json::to_string(&(&pk, &sig, &sk)).unwrap();
        let (pk2, sig2, sk2): (EthereumPublicKey, EthereumSignature, EthereumPrivateKey) =
            serde_json::from_str(&json).unwrap();
        assert_eq!((pk2, sig2, sk2.as_hex()), (pk, sig, sk.as_hex()));

        let bin = postcard::to_allocvec(&(&pk, &sig, &sk)).unwrap();
        let (pk3, sig3, sk3): (EthereumPublicKey, EthereumSignature, EthereumPrivateKey) =
            postcard::from_bytes(&bin).unwrap();
        assert_eq!((pk3, sig3, sk3.as_hex()), (pk, sig, sk.as_hex()));

        assert_eq!(
            format!("0x{}", hex::encode(pk.bytes()))
                .parse::<EthereumPublicKey>()
                .unwrap(),
            pk
        );
        assert!(
            hex::encode(pk.bytes())
                .parse::<EthereumPublicKey>()
                .is_err()
        );
    }

    #[test]
    fn private_key_validation_and_redaction() {
        assert!(EthereumPrivateKey::from_bytes([0; 32]).is_err());
        assert!(EthereumPrivateKey::from_bytes(N).is_err());
        let sk = EthereumPrivateKey::generate();
        let debug = format!("{sk:?}");
        assert!(debug.contains("REDACTED") && !debug.contains(&hex::encode(sk.as_ref())));
    }
}

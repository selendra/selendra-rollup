//! Ed25519 keys and signatures, backed by `ed25519-consensus`.
//!
//! `ed25519-consensus` implements the ZIP-215 validation rules, which are fully specified,
//! so batch and single verification accept exactly the same signatures. Other ed25519
//! libraries (e.g. `ed25519-dalek`) differ on edge cases, which would let the prover and the
//! nodes disagree. Do not mix libraries.
//!
//! One exception remains in the library: the SP1-patched `curve25519-dalek-ng` rejects point
//! encodings with `y >= p` that the native crate (and ZIP-215) accept. Keys and signatures
//! are therefore checked for canonical encodings when they are constructed, so the native
//! and guest builds accept the same set.

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek_ng::edwards::CompressedEdwardsY;
use ed25519_consensus::{Signature, VerificationKey};
use schemars::JsonSchema;
use selendra_interface::common::HexString;
use selendra_interface::crypto::{CredentialId, SigVerificationError};

/// Length of an ed25519 public key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;
/// Length of an ed25519 signature in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// The field modulus `p = 2^255 - 19`, little-endian.
const FIELD_MODULUS: [u8; 32] = {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

/// `y = p - 1`, little-endian. `y = 1` and `y = p - 1` are the only `y` values with `x = 0`.
const Y_MINUS_ONE: [u8; 32] = {
    let mut y = FIELD_MODULUS;
    y[0] = 0xec;
    y
};

/// `y = 1`, little-endian.
const Y_ONE: [u8; 32] = {
    let mut y = [0; 32];
    y[0] = 1;
    y
};

/// The prime group order `l = 2^252 + 27742317777372353535851937790883648493`, little-endian.
const GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// `a < b` for little-endian 256-bit integers.
fn less_than_le(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().rev().cmp(b.iter().rev()).is_lt()
}

/// Whether a compressed Edwards point encoding is canonical, using byte compares only: the
/// masked `y` is below `p`, and the sign bit is not set when `x = 0` (`y = 1` or `y = p - 1`).
/// Does not check that the bytes decode to a point.
fn is_canonical_y(bytes: &[u8; 32]) -> bool {
    let mut y = *bytes;
    let sign_bit = y[31] & 0x80 != 0;
    y[31] &= 0x7f;
    less_than_le(&y, &FIELD_MODULUS) && !(sign_bit && (y == Y_ONE || y == Y_MINUS_ONE))
}

/// Why a 32-byte string is not an accepted ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidEd25519PublicKey {
    /// The bytes do not decode to a curve point.
    #[error("not a valid ed25519 curve point")]
    NotAPoint,
    /// The point is valid but these bytes are not its canonical encoding (`y >= p`, or the
    /// sign bit set on `x = 0`).
    #[error("non-canonical ed25519 public key encoding")]
    NonCanonical,
    /// The point has small order. Under ZIP-215 (cofactored) verification anyone can
    /// produce a valid signature for such a key, for any message.
    #[error("small-order ed25519 public key")]
    SmallOrder,
}

/// An ed25519 public key.
///
/// Decoding accepts only the canonical encoding of a curve point that is not of small order,
/// so every key has exactly one byte string (and one address), and nobody can sign for a key
/// without its private key. `ed25519-consensus` alone accepts both (ZIP-215 is a rule for
/// *signatures*; it does not make key bytes unique).
///
/// ⚠️ Mixed-order keys (`A + T`, `T` a nonzero torsion point) are accepted: they are not of
/// small order, and under ZIP-215 (cofactored) verification the holder of `A`'s private key
/// can sign for each of them. So "one point, one encoding" holds, but one private key gives
/// up to 8 valid keys (and addresses/credentials). Anything that needs "one private key, one
/// identity" (e.g. one registration per sequencer) must add a prime-order check (`[l]A = 0`)
/// or not rely on it.
#[derive(PartialEq, Eq, Hash, Clone, Debug, PartialOrd, Ord)]
pub struct Ed25519PublicKey {
    pub_key: VerificationKey,
}

impl Ed25519PublicKey {
    /// Returns the bytes of the underlying public key.
    pub fn bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.pub_key.as_bytes()
    }

    /// Decodes a public key: a canonically encoded curve point that is not of small order.
    ///
    /// Canonicality is checked on the bytes before decompressing: natively dalek-ng decodes
    /// `y >= p` (reduced mod p) while the SP1 guest's patched decompress rejects it, so
    /// checking after decompression would give `NonCanonical` natively and `NotAPoint` in the
    /// guest. With the byte check first both builds return the same error for every input.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Result<Self, InvalidEd25519PublicKey> {
        if !is_canonical_y(&bytes) {
            return Err(InvalidEd25519PublicKey::NonCanonical);
        }
        let point = CompressedEdwardsY(bytes)
            .decompress()
            .ok_or(InvalidEd25519PublicKey::NotAPoint)?;
        // Unreachable after `is_canonical_y`; kept as a cheap safety check.
        if point.compress().to_bytes() != bytes {
            return Err(InvalidEd25519PublicKey::NonCanonical);
        }
        if point.is_small_order() {
            return Err(InvalidEd25519PublicKey::SmallOrder);
        }
        let pub_key =
            VerificationKey::try_from(bytes).map_err(|_| InvalidEd25519PublicKey::NotAPoint)?;
        Ok(Self { pub_key })
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

/// JSON: `0x`-prefixed lowercase hex. Binary serde: a length-prefixed byte sequence.
/// Borsh: the raw bytes.
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

/// Why 64 bytes are not an accepted ed25519 signature encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidEd25519Signature {
    /// `R` is not the canonical encoding of its `y` coordinate: `y >= p`, or the sign bit set
    /// on a point with `x = 0` (`y = 1` or `y = p - 1`).
    #[error("non-canonical ed25519 signature R encoding")]
    NonCanonicalR,
    /// `s` is not reduced (`s >= l`). Such a signature never verifies.
    #[error("non-canonical ed25519 signature s (s >= l)")]
    NonCanonicalS,
}

/// Checks that `R` and `s` are canonically encoded, with byte comparisons only (no curve
/// operations). Whether `R` is a curve point at all is left to verification.
///
/// Required for consensus, not only for unique encodings: `ed25519-consensus` decompresses
/// `R` with `curve25519-dalek-ng`, which natively accepts `y >= p` (ZIP-215 allows it) but in
/// the SP1 guest (patched dalek-ng) rejects it. A key holder could then sign with a
/// non-canonical `R` that the nodes accept and the prover rejects. Rejecting it here makes
/// both builds accept exactly the same signatures. The `x = 0` sign-bit encodings decode to
/// the same point in both builds; they are rejected only so each `R` has one encoding.
/// Honest signers never produce any of these.
fn check_canonical(bytes: &[u8; SIGNATURE_LENGTH]) -> Result<(), InvalidEd25519Signature> {
    let mut r = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&bytes[32..]);

    if !is_canonical_y(&r) {
        return Err(InvalidEd25519Signature::NonCanonicalR);
    }
    if !less_than_le(&s, &GROUP_ORDER) {
        return Err(InvalidEd25519Signature::NonCanonicalS);
    }
    Ok(())
}

/// An ed25519 signature (`R || s`).
///
/// Stored as its 64 raw bytes, which are exactly what [`AsRef`], borsh and serde expose and
/// what verification checks. (Upstream kept a parsed copy next to a byte copy and serialized
/// both, so a decoded signature could expose bytes different from the ones verified.)
///
/// Construction rejects non-canonical `R` and `s` encodings (see [`InvalidEd25519Signature`]),
/// so every value of this type is the unique encoding of its signature, and native nodes and
/// the zk guest accept the same set.
#[derive(PartialEq, Eq, Hash, Clone, BorshSerialize)]
pub struct Ed25519Signature([u8; SIGNATURE_LENGTH]);

impl Ed25519Signature {
    /// Validates and wraps raw signature bytes: `R` and `s` must be canonically encoded.
    /// Whether the signature is valid for a key and message is only decided by
    /// [`selendra_interface::crypto::Signature::verify`].
    pub fn from_bytes(bytes: [u8; SIGNATURE_LENGTH]) -> Result<Self, InvalidEd25519Signature> {
        check_canonical(&bytes)?;
        Ok(Self(bytes))
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

impl BorshDeserialize for Ed25519Signature {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; SIGNATURE_LENGTH];
        reader.read_exact(&mut bytes)?;
        Self::from_bytes(bytes).map_err(std::io::Error::other)
    }
}

impl TryFrom<&[u8]> for Ed25519Signature {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; SIGNATURE_LENGTH] = value
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature size: {}", value.len()))?;
        Ok(Self::from_bytes(bytes)?)
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
        // Every constructor already checks this; it is a few byte comparisons, and it keeps
        // the native/guest agreement independent of how `self` was built.
        check_canonical(&self.0).map_err(|e| SigVerificationError {
            error: e.to_string(),
        })?;
        pub_key
            .pub_key
            .verify(&Signature::from(self.0), msg)
            .map_err(|e| SigVerificationError {
                error: e.to_string(),
            })
    }
}

/// JSON: `0x`-prefixed lowercase hex. Binary serde: a length-prefixed byte sequence.
/// Borsh: the raw bytes.
impl serde::Serialize for Ed25519Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&HexString(self.0), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let HexString(bytes) =
            <HexString<[u8; SIGNATURE_LENGTH]> as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_bytes(bytes).map_err(serde::de::Error::custom)
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
        let HexString(bytes) = HexString::<[u8; SIGNATURE_LENGTH]>::from_str(s)?;
        Ok(Self::from_bytes(bytes)?)
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

        /// Returns the secret as `0x` + lowercase hex: the same string as its JSON form.
        pub fn as_hex(&self) -> String {
            HexString(self.key.as_bytes()).to_string()
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
            // `R` comes from point compression and `s` is reduced, so this is canonical.
            Ed25519Signature::from_bytes(self.key.sign(msg).to_bytes())
                .expect("ed25519 signing produces canonical signatures")
        }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek_ng::edwards::CompressedEdwardsY;
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
        ))
        .unwrap();

        assert_eq!(sk.pub_key(), pk);
        assert_eq!(sk.sign(b""), sig);
        sig.verify(&pk, b"").unwrap();
        assert_eq!(pk.credential_id(), CredentialId::from_bytes(*pk.bytes()));
    }

    /// RFC 8032 section 7.1, TEST 2 and TEST 3: pass the canonicality checks and verify.
    #[test]
    fn rfc8032_tests_2_and_3() {
        for (sk, pk, msg, sig) in [
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ] {
            let sk = Ed25519PrivateKey::from_bytes(h(sk));
            let pk = Ed25519PublicKey::from_bytes(h(pk)).unwrap();
            let msg = hex::decode(msg).unwrap();
            let sig = Ed25519Signature::from_bytes(h(sig)).unwrap();

            assert_eq!(sk.pub_key(), pk);
            assert_eq!(sk.sign(&msg), sig);
            sig.verify(&pk, &msg).unwrap();
        }
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
                .unwrap()
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
        assert!(Ed25519PublicKey::from_str(&HexString(bad).to_string()).is_err());
    }

    fn assert_rejected_everywhere(bytes: [u8; PUBLIC_KEY_LENGTH], why: InvalidEd25519PublicKey) {
        assert_eq!(
            Ed25519PublicKey::from_bytes(bytes),
            Err(why),
            "{}",
            hex::encode(bytes)
        );
        assert!(Ed25519PublicKey::try_from(bytes.as_slice()).is_err());
        assert!(borsh::from_slice::<Ed25519PublicKey>(&bytes).is_err());
        let s = HexString(bytes).to_string();
        assert!(serde_json::from_str::<Ed25519PublicKey>(&format!("\"{s}\"")).is_err());
        assert!(Ed25519PublicKey::from_str(&s).is_err());
    }

    /// Canonical encodings of the 8 small-order points. With a small-order key, the signature
    /// `R = identity, s = 0` verifies for every message under ZIP-215, so anyone could sign.
    const SMALL_ORDER: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ];

    #[test]
    fn small_order_public_keys_are_rejected() {
        for hex_point in SMALL_ORDER {
            let bytes: [u8; 32] = hex::decode(hex_point).unwrap().try_into().unwrap();
            let point = CompressedEdwardsY(bytes).decompress().unwrap();
            assert!(point.is_small_order() && point.compress().to_bytes() == bytes);

            // ed25519-consensus alone accepts the key and the forged signature.
            let vk = VerificationKey::try_from(bytes).unwrap();
            let mut forged = [0u8; SIGNATURE_LENGTH];
            forged[0] = 1;
            assert!(
                vk.verify(&ed25519_consensus::Signature::from(forged), b"any message")
                    .is_ok()
            );

            assert_rejected_everywhere(bytes, InvalidEd25519PublicKey::SmallOrder);
        }
    }

    #[test]
    fn non_canonical_public_keys_are_rejected() {
        // y = p + d for d < 19 (y >= p), with either sign bit; plus the sign bit set on the
        // two x = 0 points (y = 1 and y = -1). All of these that decode are non-canonical.
        let mut encodings = Vec::new();
        for d in 0u8..19 {
            let mut y = [0xffu8; 32];
            y[0] = 0xed + d;
            y[31] = 0x7f;
            encodings.push(y);
            y[31] = 0xff;
            encodings.push(y);
        }
        for hex_point in [SMALL_ORDER[0], SMALL_ORDER[1]] {
            let mut bytes: [u8; 32] = hex::decode(hex_point).unwrap().try_into().unwrap();
            bytes[31] |= 0x80;
            encodings.push(bytes);
        }

        // Every one is `NonCanonical`, whether or not it decodes: the byte check runs before
        // decompression, so native and the SP1 guest (whose patched decompress rejects
        // `y >= p`) return the same variant.
        let mut decodable = 0;
        for bytes in encodings {
            assert_rejected_everywhere(bytes, InvalidEd25519PublicKey::NonCanonical);
            if let Some(point) = CompressedEdwardsY(bytes).decompress() {
                decodable += 1;
                assert_ne!(point.compress().to_bytes(), bytes);
                assert!(VerificationKey::try_from(bytes).is_ok());
            }
        }
        // Natively 12 values of d decode, each with 2 sign bits, plus the 2 sign-bit variants.
        assert_eq!(decodable, 26);
    }

    #[test]
    fn non_canonical_key_that_decodes_natively_is_non_canonical() {
        // y = p + d with y = d on the curve: native dalek-ng reduces and decodes it, the
        // guest's patched decompress does not. Both must report `NonCanonical`.
        let d = (2u8..19)
            .find(|&d| {
                let mut y = [0u8; 32];
                y[0] = d;
                CompressedEdwardsY(y).decompress().is_some()
            })
            .unwrap();
        let mut bytes = FIELD_MODULUS;
        bytes[0] += d;
        assert!(CompressedEdwardsY(bytes).decompress().is_some());
        assert!(!is_canonical_y(&bytes));
        assert_rejected_everywhere(bytes, InvalidEd25519PublicKey::NonCanonical);

        // An off-curve canonical y is still `NotAPoint`.
        let mut not_a_point = None;
        for b in 2u8..=u8::MAX {
            let mut y = [0u8; 32];
            y[0] = b;
            if CompressedEdwardsY(y).decompress().is_none() {
                not_a_point = Some(y);
                break;
            }
        }
        assert_rejected_everywhere(not_a_point.unwrap(), InvalidEd25519PublicKey::NotAPoint);
    }

    #[test]
    fn modulus_and_order_constants() {
        use curve25519_dalek_ng::scalar::Scalar;

        assert_eq!(
            GROUP_ORDER,
            curve25519_dalek_ng::constants::BASEPOINT_ORDER.to_bytes()
        );
        let mut l_minus_one = GROUP_ORDER;
        l_minus_one[0] -= 1;
        assert!(Scalar::from_canonical_bytes(l_minus_one).is_some());
        assert!(Scalar::from_canonical_bytes(GROUP_ORDER).is_none());

        // p - 1 is the canonical encoding of the field element -1; p is not canonical.
        let minus_one = curve25519_dalek_ng::edwards::CompressedEdwardsY(Y_MINUS_ONE)
            .decompress()
            .unwrap();
        assert_eq!(minus_one.compress().to_bytes(), Y_MINUS_ONE);
        assert!(less_than_le(&Y_MINUS_ONE, &FIELD_MODULUS));
        assert!(!less_than_le(&FIELD_MODULUS, &FIELD_MODULUS));
    }

    /// A signature by `a` (secret scalar) over `msg` with an arbitrary `R` encoding whose
    /// point has small order: `s = k * a`, `k = SHA-512(R_bytes || A || msg)`. Under ZIP-215
    /// (`[8][s]B = [8]R + [8][k]A`) it verifies for any small-order `R`, whatever `R_bytes` is.
    fn sign_with_r(a: u64, r_bytes: [u8; 32], msg: &[u8]) -> (VerificationKey, [u8; 64]) {
        use curve25519_dalek_ng::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek_ng::scalar::Scalar;
        use sha2::{Digest, Sha512};

        let a = Scalar::from(a);
        let a_bytes = (&a * &ED25519_BASEPOINT_TABLE).compress().to_bytes();
        let hash: [u8; 64] = Sha512::new()
            .chain_update(r_bytes)
            .chain_update(a_bytes)
            .chain_update(msg)
            .finalize()
            .into();
        let s = Scalar::from_bytes_mod_order_wide(&hash) * a;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(s.as_bytes());
        (VerificationKey::try_from(a_bytes).unwrap(), sig)
    }

    fn assert_signature_rejected_everywhere(
        bytes: [u8; SIGNATURE_LENGTH],
        why: InvalidEd25519Signature,
    ) {
        assert_eq!(
            Ed25519Signature::from_bytes(bytes),
            Err(why),
            "{}",
            hex::encode(bytes)
        );
        assert!(Ed25519Signature::try_from(bytes.as_slice()).is_err());
        assert!(Ed25519Signature::try_from(bytes.to_vec()).is_err());
        assert!(borsh::from_slice::<Ed25519Signature>(&bytes).is_err());
        let s = HexString(bytes).to_string();
        assert!(serde_json::from_str::<Ed25519Signature>(&format!("\"{s}\"")).is_err());
        assert!(Ed25519Signature::from_str(&s).is_err());
        assert!(
            postcard::from_bytes::<Ed25519Signature>(
                &postcard::to_allocvec(&HexString(bytes)).unwrap()
            )
            .is_err()
        );
    }

    fn le(mut y: [u8; 32], sign_bit: bool) -> [u8; 32] {
        if sign_bit {
            y[31] |= 0x80;
        }
        y
    }

    /// `R` encodings with `y >= p`, which the native (unpatched) dalek-ng decodes and the SP1
    /// guest's patched dalek-ng rejects; plus the sign bit on the two `x = 0` points.
    fn non_canonical_r() -> Vec<[u8; 32]> {
        let mut p_plus_one = FIELD_MODULUS;
        p_plus_one[0] += 1;
        let mut all_ones = [0xff; 32];
        all_ones[31] = 0x7f; // 2^255 - 1 = p + 18
        let mut encodings = Vec::new();
        for sign_bit in [false, true] {
            encodings.push(le(FIELD_MODULUS, sign_bit)); // y = p (= 0 mod p)
            encodings.push(le(p_plus_one, sign_bit)); // y = p + 1 (= 1 mod p)
            encodings.push(le(all_ones, sign_bit));
        }
        encodings.push(le(Y_ONE, true));
        encodings.push(le(Y_MINUS_ONE, true));
        encodings
    }

    #[test]
    fn non_canonical_signature_r_is_rejected() {
        let valid = Ed25519PrivateKey::generate().sign(b"msg").to_bytes();
        for r in non_canonical_r() {
            let mut sig = valid;
            sig[..32].copy_from_slice(&r);
            assert_signature_rejected_everywhere(sig, InvalidEd25519Signature::NonCanonicalR);
        }

        // Canonical encodings next to the boundary are accepted (whether they verify is
        // up to `verify`): y = p - 1 and y = 1 without the sign bit, y = 0 with it.
        for r in [Y_MINUS_ONE, Y_ONE, le([0; 32], true)] {
            let mut sig = valid;
            sig[..32].copy_from_slice(&r);
            Ed25519Signature::from_bytes(sig).unwrap();
        }
    }

    /// The consensus bug this check closes: raw `ed25519-consensus` natively accepts these
    /// signatures (ZIP-215 allows a non-canonical `R`), while in the SP1 guest the `y >= p`
    /// ones fail to decompress. Our type rejects all of them in every build.
    #[test]
    fn crafted_non_canonical_r_signatures_are_rejected() {
        let msg = b"transfer everything";
        let mut natively_valid = 0;
        for r in non_canonical_r() {
            let Some(point) = CompressedEdwardsY(r).decompress() else {
                continue;
            };
            if !point.is_small_order() {
                continue;
            }
            assert_ne!(point.compress().to_bytes(), r);

            let (vk, sig) = sign_with_r(0x05e1_ed7a, r, msg);
            vk.verify(&ed25519_consensus::Signature::from(sig), msg)
                .expect("raw ed25519-consensus accepts the non-canonical R");
            natively_valid += 1;

            let pk = Ed25519PublicKey::from_bytes(*vk.as_bytes()).unwrap();
            assert_signature_rejected_everywhere(sig, InvalidEd25519Signature::NonCanonicalR);
            // Even if the bytes reach `verify` some other way, it rejects them.
            assert!(Ed25519Signature(sig).verify(&pk, msg).is_err());
        }
        // y = p and y = p + 1 (both sign bits), and the two x = 0 sign-bit encodings.
        assert_eq!(natively_valid, 6);

        // The same construction with the canonical R is an ordinary valid signature.
        let (vk, sig) = sign_with_r(0x05e1_ed7a, Y_ONE, msg);
        let pk = Ed25519PublicKey::from_bytes(*vk.as_bytes()).unwrap();
        Ed25519Signature::from_bytes(sig)
            .unwrap()
            .verify(&pk, msg)
            .unwrap();
    }

    #[test]
    fn non_canonical_signature_s_is_rejected() {
        let sk = Ed25519PrivateKey::generate();
        let pk = sk.pub_key();
        let valid = sk.sign(b"msg").to_bytes();

        let mut l_minus_one = GROUP_ORDER;
        l_minus_one[0] -= 1;
        let mut l_plus_one = GROUP_ORDER;
        l_plus_one[0] += 1;
        let mut high_bit = [0u8; 32];
        high_bit[31] = 0x80;

        // s + l is the same scalar mod l; ed25519-consensus already rejects it at verify.
        let s = curve25519_dalek_ng::scalar::Scalar::from_canonical_bytes(
            valid[32..].try_into().unwrap(),
        )
        .unwrap();
        let mut s_plus_l = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(s.as_bytes()[i]) + u16::from(GROUP_ORDER[i]) + carry;
            s_plus_l[i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);

        for s in [GROUP_ORDER, l_plus_one, high_bit, [0xff; 32], s_plus_l] {
            let mut sig = valid;
            sig[32..].copy_from_slice(&s);
            assert!(
                pk.pub_key
                    .verify(&ed25519_consensus::Signature::from(sig), b"msg")
                    .is_err()
            );
            assert_signature_rejected_everywhere(sig, InvalidEd25519Signature::NonCanonicalS);
        }
        for s in [l_minus_one, [0; 32]] {
            let mut sig = valid;
            sig[32..].copy_from_slice(&s);
            Ed25519Signature::from_bytes(sig).unwrap();
        }
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
            Ed25519PublicKey::from_str(&format!("0x{}", hex::encode(pk.bytes()))).unwrap(),
            pk
        );
        assert!(Ed25519PublicKey::from_str(&hex::encode(pk.bytes())).is_err());

        let sig_json = serde_json::to_string(&sig).unwrap();
        assert_eq!(
            serde_json::from_str::<Ed25519Signature>(&sig_json).unwrap(),
            sig
        );

        let sk_json = serde_json::to_string(&sk).unwrap();
        assert_eq!(sk_json, format!("\"{}\"", sk.as_hex()));
        assert_eq!(sk.as_hex(), format!("0x{}", hex::encode(sk.as_ref())));
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
        assert!(!debug.contains(&hex::encode(sk.as_ref())));
    }
}

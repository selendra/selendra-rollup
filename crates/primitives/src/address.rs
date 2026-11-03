//! Native Selendra addresses: 28 bytes, shown as bech32m with the `sel` prefix.

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::BasicAddress;
use selendra_interface::crypto::CredentialId;

use crate::bech32::{self, Bech32ParseError};

/// The bech32m human-readable prefix of every native address (`sel1…`).
///
/// Part of the chain's identity: changing it after genesis changes how every address is
/// written, so it is a compile-time constant rather than configuration.
pub const ADDRESS_PREFIX: &str = "sel";

/// A native Selendra address.
///
/// Borsh and binary serde encode the 28 raw bytes; JSON, `Display` and `FromStr` use
/// canonical bech32m (`sel1…`).
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    arbitrary::Arbitrary,
)]
pub struct Address([u8; Address::LENGTH]);

impl Address {
    /// The length of an address in bytes.
    pub const LENGTH: usize = 28;

    /// Creates a new address containing the given bytes.
    pub const fn new(addr: [u8; Self::LENGTH]) -> Self {
        Self(addr)
    }

    /// Exposes the inner bytes of the address.
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// The address of a credential is its first 28 bytes. For an ed25519 key the credential
/// id is the public key itself, so this is the public key truncated to 28 bytes.
impl From<CredentialId> for Address {
    fn from(credential_id: CredentialId) -> Self {
        let mut addr = [0u8; Self::LENGTH];
        addr.copy_from_slice(&credential_id.0.0[..Self::LENGTH]);
        Self(addr)
    }
}

impl From<[u8; Address::LENGTH]> for Address {
    fn from(addr: [u8; Address::LENGTH]) -> Self {
        Self(addr)
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = anyhow::Error;

    fn try_from(addr: &[u8]) -> Result<Self, Self::Error> {
        let addr: [u8; Self::LENGTH] = addr.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Address must be {} bytes long, got {}",
                Self::LENGTH,
                addr.len()
            )
        })?;
        Ok(Self(addr))
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&bech32::encode(ADDRESS_PREFIX, &self.0))
    }
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl FromStr for Address {
    type Err = Bech32ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bech32::decode(ADDRESS_PREFIX, s).map(Self)
    }
}

impl serde::Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            serde::Serialize::serialize(&self.0, serializer)
        }
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = <String as serde::Deserialize>::deserialize(deserializer)?;
            s.parse().map_err(serde::de::Error::custom)
        } else {
            <[u8; Self::LENGTH] as serde::Deserialize>::deserialize(deserializer).map(Self)
        }
    }
}

impl schemars::JsonSchema for Address {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Address".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        // 28 bytes = 45 data symbols, plus a 6-symbol checksum.
        schemars::json_schema!({
            "type": "string",
            "pattern": format!("^{ADDRESS_PREFIX}1[02-9ac-hj-np-z]{{51}}$"),
            "description": "A native Selendra address: bech32m with the `sel` prefix",
        })
    }
}

impl BasicAddress for Address {}

#[cfg(test)]
mod tests {
    use selendra_interface::crypto::{PrivateKey, PublicKey};

    use super::*;
    use crate::crypto::{Ed25519PrivateKey, Ed25519PublicKey};

    // Vectors from an independent BIP-350 reference encoder; the same encoder reproduces
    // upstream's `sov1…` vectors for these inputs.
    const ADDR_11: &str = "sel1pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skyy6cwf";
    const ADDR_1_TO_28: &str = "sel1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8gzuxv";

    #[test]
    fn test_vectors() {
        assert_eq!(Address::new([11; 28]).to_string(), ADDR_11);
        let one_to_28: [u8; 28] = core::array::from_fn(|i| i as u8 + 1);
        assert_eq!(Address::new(one_to_28).to_string(), ADDR_1_TO_28);
        assert_eq!(ADDR_11.parse::<Address>().unwrap(), Address::new([11; 28]));
        assert_eq!(
            ADDR_1_TO_28.parse::<Address>().unwrap(),
            Address::new(one_to_28)
        );
    }

    #[test]
    fn address_from_public_key() {
        let pk: Ed25519PublicKey =
            "022e229198d957bf0c0a504e7d7bcec99a1d62cccc7861ed2452676ad0323ad8"
                .parse()
                .unwrap();
        let addr = Address::from(pk.credential_id());
        assert_eq!(addr.as_bytes()[..], pk.bytes()[..28]);
        assert_eq!(
            addr.to_string(),
            "sel1qghz9yvcm9tm7rq22p88677wexdp6ckve3uxrmfy2fnk5vu0s50"
        );
    }

    /// The devnet genesis account in TODO.md ("Genesis allocation (testing)"), derived from
    /// the public half of the gitignored `keys/team-test-ed25519.key`.
    #[test]
    fn team_test_genesis_address() {
        let pk: Ed25519PublicKey =
            "4c3505f649e7354cf5904725232a1fb91b7b78ddb0be0e6e34c43ca2ff871e84"
                .parse()
                .unwrap();
        assert_eq!(
            Address::from(pk.credential_id()).to_string(),
            "sel1fs6stajfuu65eavsgujjx2slhydhk7xakzlqum35cs72ydqpl45"
        );
    }

    #[test]
    fn rejects_other_prefixes() {
        // The same bytes, valid bech32m, but`sov` prefix.
        for s in [
            "sov1pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skqm7ehv",
            "sov1qghz9yvcm9tm7rq22p88677wexdp6ckve3uxrmfy2fnk5grt3d2",
        ] {
            assert!(matches!(
                s.parse::<Address>(),
                Err(Bech32ParseError::WrongHrp { found, .. }) if found == "sov"
            ));
        }
    }

    #[test]
    fn rejects_plain_bech32() {
        let bech32_not_m = "sel1pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9sk3c25tt";
        assert!(matches!(
            bech32_not_m.parse::<Address>(),
            Err(Bech32ParseError::Bech32(_))
        ));
    }

    #[test]
    fn rejects_wrong_length() {
        let twenty_nine_bytes = "sel1pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skzcgnvlvj";
        assert!(matches!(
            twenty_nine_bytes.parse::<Address>(),
            Err(Bech32ParseError::WrongLength {
                expected: 28,
                found: 29
            })
        ));
    }

    #[test]
    fn rejects_non_canonical_encodings() {
        // Both decode to [11; 28] but are not its canonical string. Upstream accepted them.
        let extra_symbol = "sel1pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skq9pc28z";
        let nonzero_padding = "sel1pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9shejwdnm";
        for s in [extra_symbol, nonzero_padding] {
            assert!(
                matches!(s.parse::<Address>(), Err(Bech32ParseError::NonCanonical)),
                "{s}"
            );
        }
    }

    #[test]
    fn case_handling() {
        let upper = ADDR_11.to_ascii_uppercase();
        let addr: Address = upper.parse().unwrap();
        assert_eq!(addr.to_string(), ADDR_11);

        let mixed = format!("SEL{}", &ADDR_11[3..]);
        assert!(mixed.parse::<Address>().is_err());
    }

    #[test]
    fn encodings_roundtrip() {
        let addr = Address::from(Ed25519PrivateKey::generate().pub_key().credential_id());

        assert_eq!(borsh::to_vec(&addr).unwrap(), addr.as_bytes());
        assert_eq!(borsh::from_slice::<Address>(addr.as_bytes()).unwrap(), addr);

        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(json, format!("\"{addr}\""));
        assert_eq!(serde_json::from_str::<Address>(&json).unwrap(), addr);

        let bin = postcard::to_allocvec(&addr).unwrap();
        assert_eq!(postcard::from_bytes::<Address>(&bin).unwrap(), addr);

        assert_eq!(Address::try_from(addr.as_ref()).unwrap(), addr);
        assert!(Address::try_from(&addr.as_bytes()[..27]).is_err());
    }

    #[test]
    fn string_shape_matches_schema() {
        let s = Address::new([0xff; 28]).to_string();
        assert!(s.starts_with("sel1"));
        assert_eq!(s.len(), 4 + 51);
        assert!(
            s[4..]
                .chars()
                .all(|c| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(c))
        );
    }
}

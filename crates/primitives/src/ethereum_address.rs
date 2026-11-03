// Adapted from Sovereign SDK `crates/module-system/sov-address/src/evm/address.rs` at c7046e2
// (Sovereign Permissionless Commercial License, Copyright Sovereign Labs, Inc.).
// Changes: see docs/provenance.md.

//! 20-byte Ethereum addresses (`0x…`).

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::BasicAddress;
use selendra_interface::crypto::CredentialId;

use crate::multi_address::Not28Bytes;

/// A 20-byte Ethereum address. Displayed with the EIP-55 checksum.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    arbitrary::Arbitrary,
)]
pub struct EthereumAddress([u8; EthereumAddress::LENGTH]);

impl EthereumAddress {
    /// The length of an Ethereum address in bytes.
    pub const LENGTH: usize = 20;

    /// Creates an address from its 20 bytes.
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Exposes the inner bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// The credential of this address: the 20 bytes left-padded with zeros to 32.
    ///
    /// There is deliberately no conversion back from a [`CredentialId`]: a credential
    /// does not record which kind of key produced it. Use the key's own address instead.
    pub fn as_credential_id(&self) -> CredentialId {
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(&self.0);
        CredentialId::from_bytes(padded)
    }
}

impl From<[u8; EthereumAddress::LENGTH]> for EthereumAddress {
    fn from(bytes: [u8; EthereumAddress::LENGTH]) -> Self {
        Self(bytes)
    }
}

impl From<EthereumAddress> for [u8; EthereumAddress::LENGTH] {
    fn from(addr: EthereumAddress) -> Self {
        addr.0
    }
}

impl From<alloy_primitives::Address> for EthereumAddress {
    fn from(addr: alloy_primitives::Address) -> Self {
        Self(addr.into_array())
    }
}

impl From<EthereumAddress> for alloy_primitives::Address {
    fn from(addr: EthereumAddress) -> Self {
        Self::new(addr.0)
    }
}

impl TryFrom<&[u8]> for EthereumAddress {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; Self::LENGTH] = value.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Ethereum address must be {} bytes, got {}",
                Self::LENGTH,
                value.len()
            )
        })?;
        Ok(Self(bytes))
    }
}

impl AsRef<[u8]> for EthereumAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Display for EthereumAddress {
    /// EIP-55 checksummed, e.g. `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&alloy_primitives::Address::from(*self).to_checksum(None))
    }
}

impl core::fmt::Debug for EthereumAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl FromStr for EthereumAddress {
    type Err = anyhow::Error;

    /// Requires the `0x` prefix and 40 hex digits. All-lowercase and all-uppercase carry
    /// no checksum and are accepted; mixed case must be a valid EIP-55 checksum.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s
            .strip_prefix("0x")
            .ok_or_else(|| anyhow::anyhow!("Ethereum address must start with 0x"))?;
        if hex.len() != 2 * Self::LENGTH || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!("Ethereum address must be 40 hex digits");
        }
        let has_lower = hex.bytes().any(|b| b.is_ascii_lowercase());
        let has_upper = hex.bytes().any(|b| b.is_ascii_uppercase());
        if has_lower && has_upper {
            return alloy_primitives::Address::parse_checksummed(s, None)
                .map(Self::from)
                .map_err(|_| anyhow::anyhow!("Invalid EIP-55 checksum"));
        }
        let mut bytes = [0u8; Self::LENGTH];
        hex::decode_to_slice(hex, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl serde::Serialize for EthereumAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            serde::Serialize::serialize(&self.0, serializer)
        }
    }
}

impl<'de> serde::Deserialize<'de> for EthereumAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = <String as serde::Deserialize>::deserialize(deserializer)?;
            s.parse().map_err(serde::de::Error::custom)
        } else {
            <[u8; Self::LENGTH] as serde::Deserialize>::deserialize(deserializer).map(Self)
        }
    }
}

impl schemars::JsonSchema for EthereumAddress {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "EthereumAddress".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^0x[a-fA-F0-9]{40}$",
            "description": "20 bytes in hexadecimal format, with `0x` prefix (EIP-55 checksum if mixed case).",
        })
    }
}

impl BasicAddress for EthereumAddress {}
impl Not28Bytes for EthereumAddress {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors from EIP-55.
    const EIP55: [&str; 4] = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];

    #[test]
    fn eip55_roundtrip() {
        for s in EIP55 {
            let addr: EthereumAddress = s.parse().unwrap();
            assert_eq!(addr.to_string(), s);
            // Single-case forms carry no checksum and are accepted.
            let lower = format!("0x{}", s[2..].to_ascii_lowercase());
            let upper = format!("0x{}", s[2..].to_ascii_uppercase());
            assert_eq!(lower.parse::<EthereumAddress>().unwrap(), addr);
            assert_eq!(upper.parse::<EthereumAddress>().unwrap(), addr);
        }
    }

    #[test]
    fn rejects_bad_checksum_and_shape() {
        // Flip the case of one letter in a checksummed address.
        let bad = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD";
        assert!(bad.parse::<EthereumAddress>().is_err());
        assert!(
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
                .parse::<EthereumAddress>()
                .is_err()
        );
        assert!(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeA"
                .parse::<EthereumAddress>()
                .is_err()
        );
        assert!(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeg"
                .parse::<EthereumAddress>()
                .is_err()
        );
    }

    #[test]
    fn credential_is_left_padded() {
        let addr: EthereumAddress = EIP55[0].parse().unwrap();
        let cred = addr.as_credential_id();
        assert_eq!(cred.0.0[..12], [0u8; 12]);
        assert_eq!(&cred.0.0[12..], addr.as_bytes());
    }

    #[test]
    fn encodings_roundtrip() {
        let addr: EthereumAddress = EIP55[1].parse().unwrap();
        assert_eq!(borsh::to_vec(&addr).unwrap(), addr.as_bytes());
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(json, format!("\"{}\"", EIP55[1]));
        assert_eq!(
            serde_json::from_str::<EthereumAddress>(&json).unwrap(),
            addr
        );
        let bin = postcard::to_allocvec(&addr).unwrap();
        assert_eq!(postcard::from_bytes::<EthereumAddress>(&bin).unwrap(), addr);
    }
}

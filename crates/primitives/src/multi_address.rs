// Adapted from Sovereign SDK `crates/module-system/sov-address/src/lib.rs` at c7046e2
// (Sovereign Permissionless Commercial License, Copyright Sovereign Labs, Inc.).
// Changes: see docs/provenance.md.

//! [`MultiAddress`]: one account address type covering native `sel1…` accounts and
//! VM-native accounts such as Ethereum's `0x…`.

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::BasicAddress;
use selendra_interface::crypto::PublicKey;

use crate::address::{ADDRESS_PREFIX, Address};
use crate::crypto::{Ed25519PublicKey, EthereumPublicKey};
use crate::ethereum_address::EthereumAddress;

/// Selendra's account address: a native `sel1…` address or an Ethereum `0x…` address.
pub type MultiAddressEvm = MultiAddress<EthereumAddress>;

/// An account address: either a native [`Address`] or a VM-specific address.
///
/// Encodings:
/// - borsh: tag byte (`0` = `Standard`, `1` = `Vm`) followed by the address bytes;
/// - JSON / `Display` / `FromStr`: the plain address string; `sel1…` is `Standard`,
///   anything else is parsed as the VM address;
/// - raw bytes ([`AsRef`], [`TryFrom<&[u8]>`]): 28 bytes is `Standard`, otherwise `Vm`.
///   [`Not28Bytes`] guarantees this is unambiguous.
///
/// There is deliberately no `From<CredentialId>`: a credential does not say which kind of
/// key produced it, so converting one would silently pick a variant (upstream picked
/// `Standard`, giving Ethereum keys a meaningless `sel1…` account). Get the address from the
/// key instead: `MultiAddressEvm::from(&public_key)`.
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
#[borsh(use_discriminant = false)]
pub enum MultiAddress<VmAddress> {
    /// A native address (`sel1…`).
    Standard(Address),
    /// A VM-specific address (for [`MultiAddressEvm`]: Ethereum `0x…`).
    Vm(VmAddress),
}

/// Marker for VM address types whose byte length is never 28, so raw bytes can be
/// assigned to the right [`MultiAddress`] variant by length.
pub trait Not28Bytes {}

/// Conversion from a VM address into an account address.
pub trait FromVmAddress<VmAddress> {
    /// Wraps a VM address.
    fn from_vm_address(value: VmAddress) -> Self;
}

impl<VmAddress> FromVmAddress<VmAddress> for MultiAddress<VmAddress> {
    fn from_vm_address(value: VmAddress) -> Self {
        Self::Vm(value)
    }
}

impl<VmAddress> FromVmAddress<VmAddress> for VmAddress {
    fn from_vm_address(value: VmAddress) -> Self {
        value
    }
}

impl<VmAddress> From<Address> for MultiAddress<VmAddress> {
    fn from(value: Address) -> Self {
        Self::Standard(value)
    }
}

impl From<EthereumAddress> for MultiAddressEvm {
    fn from(value: EthereumAddress) -> Self {
        Self::Vm(value)
    }
}

/// An ed25519 key owns the native account of its credential (`sel1…`).
impl From<&Ed25519PublicKey> for MultiAddressEvm {
    fn from(key: &Ed25519PublicKey) -> Self {
        Self::Standard(Address::from(key.credential_id()))
    }
}

/// A secp256k1 key owns its Ethereum account (`0x…`), the same account MetaMask shows.
impl From<&EthereumPublicKey> for MultiAddressEvm {
    fn from(key: &EthereumPublicKey) -> Self {
        Self::Vm(key.ethereum_address())
    }
}

impl<VmAddress: AsRef<[u8]>> AsRef<[u8]> for MultiAddress<VmAddress> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Standard(addr) => addr.as_ref(),
            Self::Vm(addr) => addr.as_ref(),
        }
    }
}

impl<VmAddress: Not28Bytes + for<'a> TryFrom<&'a [u8], Error = anyhow::Error>> TryFrom<&[u8]>
    for MultiAddress<VmAddress>
{
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == Address::LENGTH {
            Address::try_from(bytes).map(Self::Standard)
        } else {
            VmAddress::try_from(bytes).map(Self::Vm)
        }
    }
}

impl<VmAddress: core::fmt::Display> core::fmt::Display for MultiAddress<VmAddress> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Standard(addr) => core::fmt::Display::fmt(addr, f),
            Self::Vm(addr) => core::fmt::Display::fmt(addr, f),
        }
    }
}

impl<VmAddress: core::fmt::Display> core::fmt::Debug for MultiAddress<VmAddress> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

/// `true` if `s` starts with `sel1` (any case; bech32 allows all-uppercase).
fn has_native_prefix(s: &str) -> bool {
    let n = ADDRESS_PREFIX.len() + 1;
    s.len() >= n
        && s.is_char_boundary(n)
        && s[..n].eq_ignore_ascii_case(&format!("{ADDRESS_PREFIX}1"))
}

impl<VmAddress: FromStr<Err: Into<anyhow::Error>>> FromStr for MultiAddress<VmAddress> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if has_native_prefix(s) {
            Ok(Self::Standard(s.parse()?))
        } else {
            VmAddress::from_str(s).map(Self::Vm).map_err(Into::into)
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
enum BinaryRepr<VmAddress> {
    Standard(Address),
    Vm(VmAddress),
}

impl<VmAddress: serde::Serialize + core::fmt::Display + Copy> serde::Serialize
    for MultiAddress<VmAddress>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            match *self {
                Self::Standard(a) => BinaryRepr::<VmAddress>::Standard(a),
                Self::Vm(a) => BinaryRepr::Vm(a),
            }
            .serialize(serializer)
        }
    }
}

impl<'de, VmAddress> serde::Deserialize<'de> for MultiAddress<VmAddress>
where
    VmAddress: serde::Deserialize<'de> + FromStr<Err: Into<anyhow::Error>>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = <String as serde::Deserialize>::deserialize(deserializer)?;
            s.parse().map_err(serde::de::Error::custom)
        } else {
            Ok(match BinaryRepr::deserialize(deserializer)? {
                BinaryRepr::Standard(a) => Self::Standard(a),
                BinaryRepr::Vm(a) => Self::Vm(a),
            })
        }
    }
}

/// JSON is a plain string, so the schema is "a native address or a VM address"
/// (upstream derived the schema of an `{"Standard": …}` object, which never matched).
impl<VmAddress: schemars::JsonSchema> schemars::JsonSchema for MultiAddress<VmAddress> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("MultiAddress_{}", VmAddress::schema_name()).into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "anyOf": [
                generator.subschema_for::<Address>(),
                generator.subschema_for::<VmAddress>(),
            ],
            "description": "A native `sel1…` address or a VM address",
        })
    }
}

impl<VmAddress> BasicAddress for MultiAddress<VmAddress> where
    VmAddress: BasicAddress + Not28Bytes + FromStr<Err: Into<anyhow::Error>>
{
}

#[cfg(test)]
mod tests {
    use selendra_interface::crypto::PrivateKey;

    use super::*;
    use crate::crypto::{Ed25519PrivateKey, EthereumPrivateKey};

    const SEL: &str = "sel1pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skyy6cwf"; // [11; 28]
    const ETH: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"; // private key 1

    fn sel() -> MultiAddressEvm {
        MultiAddressEvm::Standard(Address::new([11; 28]))
    }
    fn eth() -> MultiAddressEvm {
        MultiAddressEvm::Vm(ETH.parse().unwrap())
    }

    #[test]
    fn parses_by_prefix() {
        assert_eq!(SEL.parse::<MultiAddressEvm>().unwrap(), sel());
        assert_eq!(
            SEL.to_ascii_uppercase().parse::<MultiAddressEvm>().unwrap(),
            sel()
        );
        assert_eq!(ETH.parse::<MultiAddressEvm>().unwrap(), eth());
        assert_eq!(sel().to_string(), SEL);
        assert_eq!(eth().to_string(), ETH);

        // A broken sel1 string must fail as a native address, not fall through to 0x parsing.
        let err = "sel1qqqq"
            .parse::<MultiAddressEvm>()
            .unwrap_err()
            .to_string();
        assert!(!err.contains("0x"), "{err}");
        for bad in [
            "sov1pv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skqm7ehv",
            "7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
            "",
            "sel",
            "é",
        ] {
            assert!(bad.parse::<MultiAddressEvm>().is_err(), "{bad}");
        }
    }

    #[test]
    fn raw_bytes_pick_variant_by_length() {
        assert_eq!(MultiAddressEvm::try_from(&[11u8; 28][..]).unwrap(), sel());
        let eth_bytes = *eth_addr().as_bytes();
        assert_eq!(MultiAddressEvm::try_from(&eth_bytes[..]).unwrap(), eth());
        assert_eq!(sel().as_ref(), &[11u8; 28]);
        assert_eq!(eth().as_ref(), &eth_bytes);
        for len in [0, 19, 21, 27, 29, 32] {
            assert!(
                MultiAddressEvm::try_from(&vec![1u8; len][..]).is_err(),
                "{len}"
            );
        }
    }

    fn eth_addr() -> EthereumAddress {
        ETH.parse().unwrap()
    }

    #[test]
    fn borsh_is_tagged() {
        let s = borsh::to_vec(&sel()).unwrap();
        assert_eq!(s[0], 0);
        assert_eq!(&s[1..], &[11u8; 28]);
        let e = borsh::to_vec(&eth()).unwrap();
        assert_eq!(e[0], 1);
        assert_eq!(&e[1..], eth_addr().as_bytes());
        assert_eq!(borsh::from_slice::<MultiAddressEvm>(&s).unwrap(), sel());
        assert_eq!(borsh::from_slice::<MultiAddressEvm>(&e).unwrap(), eth());
        assert!(borsh::from_slice::<MultiAddressEvm>(&[2u8; 21]).is_err());

        // A field after the address still decodes correctly (variable-length enum).
        let pair = (eth(), 90_000_000_000u64);
        let bytes = borsh::to_vec(&pair).unwrap();
        assert_eq!(
            borsh::from_slice::<(MultiAddressEvm, u64)>(&bytes).unwrap(),
            pair
        );
    }

    #[test]
    fn serde_roundtrips() {
        for addr in [sel(), eth()] {
            let json = serde_json::to_string(&addr).unwrap();
            assert_eq!(json, format!("\"{addr}\""));
            assert_eq!(
                serde_json::from_str::<MultiAddressEvm>(&json).unwrap(),
                addr
            );
            let bin = postcard::to_allocvec(&addr).unwrap();
            assert_eq!(postcard::from_bytes::<MultiAddressEvm>(&bin).unwrap(), addr);
        }
    }

    #[test]
    fn keys_own_the_right_account() {
        let ed = Ed25519PrivateKey::generate().pub_key();
        assert_eq!(
            MultiAddressEvm::from(&ed),
            MultiAddressEvm::Standard(Address::from(ed.credential_id()))
        );

        // Private key 1: the secp256k1 key owns 0x7E5F…, not a sel1 address.
        let mut one = [0u8; 32];
        one[31] = 1;
        let secp = EthereumPrivateKey::from_bytes(one).unwrap().pub_key();
        assert_eq!(MultiAddressEvm::from(&secp), eth());
    }

    /// The devnet genesis accounts in TODO.md ("Genesis allocation (testing)"), derived from
    /// the public halves of the gitignored `keys/team-test-*.key` files.
    #[test]
    fn team_test_genesis_accounts() {
        let secp: EthereumPublicKey =
            "0324718b830d04cba00c6eb7456c9f2da9afaf27342e5cd615b7a228d9adad585c"
                .parse()
                .unwrap();
        assert_eq!(
            MultiAddressEvm::from(&secp).to_string(),
            "0x02f9647E14d07ac4c76295ed34eBa30a47b626A3"
        );

        let ed: Ed25519PublicKey =
            "4c3505f649e7354cf5904725232a1fb91b7b78ddb0be0e6e34c43ca2ff871e84"
                .parse()
                .unwrap();
        assert_eq!(
            MultiAddressEvm::from(&ed).to_string(),
            "sel1fs6stajfuu65eavsgujjx2slhydhk7xakzlqum35cs72ydqpl45"
        );
    }

    #[test]
    fn json_schema_is_a_string_union() {
        let schema = serde_json::to_value(schemars::schema_for!(MultiAddressEvm)).unwrap();
        let any_of = schema["anyOf"].as_array().unwrap();
        assert_eq!(any_of.len(), 2);
        let text = schema.to_string();
        assert!(text.contains("^sel1") && text.contains("^0x"));
    }
}

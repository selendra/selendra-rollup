use std::fmt;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::BasicAddress;
use selendra_interface::common::{HexHash, hex_string_serde};

/// The DA address of the sequencer in tests.
pub const MOCK_SEQUENCER_DA_ADDRESS: [u8; 32] = [0; 32];

/// An address on the mock DA layer: 32 bytes.
///
/// borsh: the 32 bytes. `Display`, `FromStr` and JSON: `0x` + 64 lowercase hex digits, and
/// nothing else (no missing prefix, no uppercase). Binary serde formats: a sequence of 32 bytes.
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
    arbitrary::Arbitrary,
)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
#[serde(transparent)]
pub struct MockAddress {
    #[serde(with = "hex_string_serde")]
    addr: [u8; 32],
}

selendra_interface::impl_consensus_type!(MockAddress);

impl MockAddress {
    /// The address with the given bytes.
    pub const fn new(addr: [u8; 32]) -> Self {
        Self { addr }
    }

    /// The address's bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.addr
    }
}

impl schemars::JsonSchema for MockAddress {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "MockAddress".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^0x[a-f0-9]{64}$",
            "description": "A mock DA address: 32 bytes as `0x` + lowercase hex.",
        })
    }
}

impl FromStr for MockAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HexHash::from_str(s).map(|hash| Self::new(hash.0))
    }
}

impl<'a> TryFrom<&'a [u8]> for MockAddress {
    type Error = anyhow::Error;

    fn try_from(addr: &'a [u8]) -> Result<Self, Self::Error> {
        let addr = addr
            .try_into()
            .map_err(|_| anyhow::anyhow!("a mock address is 32 bytes, got {}", addr.len()))?;
        Ok(Self { addr })
    }
}

impl AsRef<[u8]> for MockAddress {
    fn as_ref(&self) -> &[u8] {
        &self.addr
    }
}

impl From<[u8; 32]> for MockAddress {
    fn from(addr: [u8; 32]) -> Self {
        Self { addr }
    }
}

impl fmt::Display for MockAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&HexHash::new(self.addr), f)
    }
}

impl fmt::Debug for MockAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MockAddress({self})")
    }
}

impl BasicAddress for MockAddress {}

#[cfg(test)]
mod tests {
    use proptest::prelude::any;

    use super::*;

    #[test]
    fn encodings_known_answer() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0x01;
        let addr = MockAddress::new(bytes);
        let hex = "0xab00000000000000000000000000000000000000000000000000000000000001";

        assert_eq!(borsh::to_vec(&addr).unwrap(), bytes);
        assert_eq!(addr.to_string(), hex);
        assert_eq!(format!("{addr:?}"), format!("MockAddress({hex})"));
        assert_eq!(serde_json::to_string(&addr).unwrap(), format!("\"{hex}\""));
        assert_eq!(MockAddress::from_str(hex).unwrap(), addr);
        assert_eq!(
            serde_json::from_str::<MockAddress>(&format!("\"{hex}\"")).unwrap(),
            addr
        );
        assert_eq!(borsh::from_slice::<MockAddress>(&bytes).unwrap(), addr);
        // postcard: a length-prefixed byte sequence.
        let postcard = postcard::to_allocvec(&addr).unwrap();
        assert_eq!(postcard[0], 32);
        assert_eq!(postcard[1..], bytes);
        assert_eq!(
            postcard::from_bytes::<MockAddress>(&postcard).unwrap(),
            addr
        );
    }

    /// Upstream accepted the hex without `0x` and in any case (several strings per address),
    /// and its JSON had no prefix.
    #[test]
    fn only_canonical_strings_are_accepted() {
        let addr = MockAddress::new([0xab; 32]);
        let canonical = addr.to_string();
        let no_prefix = canonical.trim_start_matches("0x").to_owned();
        let upper = format!("0x{}", no_prefix.to_ascii_uppercase());
        for bad in [no_prefix.as_str(), upper.as_str(), "0x", "0xab", "", "0X"] {
            assert!(MockAddress::from_str(bad).is_err(), "{bad}");
            assert!(serde_json::from_str::<MockAddress>(&format!("\"{bad}\"")).is_err());
        }
        // 33 bytes, and 31.
        assert!(MockAddress::from_str(&format!("{canonical}ab")).is_err());
        assert!(MockAddress::from_str(&canonical[..64]).is_err());
        // The JSON byte-array form is not accepted.
        assert!(serde_json::from_str::<MockAddress>(&format!("{:?}", [0xabu8; 32])).is_err());
    }

    #[test]
    fn borsh_rejects_wrong_lengths() {
        assert!(borsh::from_slice::<MockAddress>(&[1; 31]).is_err());
        assert!(borsh::from_slice::<MockAddress>(&[1; 33]).is_err());
    }

    #[test]
    fn try_from_slice_needs_32_bytes() {
        let addr = MockAddress::new([100; 32]);
        assert_eq!(MockAddress::try_from(addr.as_ref()).unwrap(), addr);
        assert!(MockAddress::try_from(&[100u8; 31][..]).is_err());
        assert!(MockAddress::try_from(&[100u8; 33][..]).is_err());
    }

    #[test]
    fn json_schema_matches_the_strings() {
        let schema = schemars::schema_for!(MockAddress);
        assert_eq!(schema.get("pattern").unwrap(), "^0x[a-f0-9]{64}$");
        assert_eq!(schema.get("type").unwrap(), "string");
    }

    #[test_strategy::proptest]
    fn round_trips(#[strategy(any::<[u8; 32]>())] bytes: [u8; 32]) {
        let addr = MockAddress::new(bytes);
        let borsh_bytes = borsh::to_vec(&addr).unwrap();
        assert_eq!(
            borsh::from_slice::<MockAddress>(&borsh_bytes).unwrap(),
            addr
        );
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(serde_json::from_str::<MockAddress>(&json).unwrap(), addr);
        let postcard = postcard::to_allocvec(&addr).unwrap();
        assert_eq!(
            postcard::from_bytes::<MockAddress>(&postcard).unwrap(),
            addr
        );
        assert_eq!(addr.to_string().parse::<MockAddress>().unwrap(), addr);
        assert_eq!(*addr.as_bytes(), bytes);
    }
}

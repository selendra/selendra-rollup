//! Cryptographic primitive traits used throughout Selendra. Concrete key types live in
//! `selendra-primitives`.
mod signatures;
pub use signatures::*;

use crate::common::HexHash;

/// Type that represents an identifier for an authorizer of the transaction.
/// The credential is a [`HexHash`].
/// For example, this can be a padded EVM address or a hash of a rollup public key.
#[derive(
    borsh::BorshDeserialize,
    borsh::BorshSerialize,
    serde::Serialize,
    serde::Deserialize,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    derive_more::Display,
    derive_more::FromStr,
    derive_more::From,
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
pub struct CredentialId(pub HexHash);

impl CredentialId {
    /// Make new `CredentialId`
    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(HexHash::new(value))
    }
}

impl schemars::JsonSchema for CredentialId {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "CredentialId".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        HexHash::json_schema(generator)
    }
}

impl From<[u8; 32]> for CredentialId {
    fn from(value: [u8; 32]) -> Self {
        Self(HexHash::new(value))
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    fn check_str_and_back(credential_id: CredentialId) {
        let s = credential_id.to_string();
        let credential_id_recovered = CredentialId::from_str(&s).unwrap();
        assert_eq!(credential_id, credential_id_recovered);
    }

    #[test]
    fn test_hash_str_and_back_simple() {
        for i in [0u8, 1, 0x7f, 0xff] {
            let credential_id = CredentialId(HexHash::new([i; 32]));
            check_str_and_back(credential_id);
        }
    }

    #[test]
    fn test_only_canonical_string_is_accepted() {
        let credential_id = CredentialId(HexHash::new([10u8; 32]));
        let s = credential_id.to_string();
        assert!(CredentialId::from_str(&s.replace("0x", "")).is_err());
        assert!(CredentialId::from_str(&s.to_ascii_uppercase().replace("0X", "0x")).is_err());
        assert_eq!(CredentialId::from_str(&s).unwrap(), credential_id);
    }

    #[test_strategy::proptest]
    fn test_arbitrary_hash_str_and_back(credential_id: CredentialId) {
        check_str_and_back(credential_id);
    }
}

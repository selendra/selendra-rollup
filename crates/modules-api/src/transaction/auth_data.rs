//! What authentication establishes about a transaction: how it is kept unique
//! ([`UniquenessData`]) and who sent it ([`AuthorizationData`]).

use selendra_interface::TxHash;
use selendra_interface::crypto::CredentialId;

use crate::{AccountAddress, ConsensusType, Credential, Spec};

/// How a transaction is kept from being included twice.
///
/// borsh: a tag (`0` = `Nonce`, `1` = `Generation`, `2` = `Window`), then the `u64` LE. JSON:
/// `{"nonce": n}`, `{"generation": n}` or `{"window": n}` (`n` a number). A consensus type.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    schemars::JsonSchema,
    ConsensusType,
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
#[serde(rename_all = "snake_case")]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum UniquenessData {
    /// Nonce-based: an account's transactions have unique, consecutive nonces.
    Nonce(u64) = 0,
    /// Generation-based: the last generations are remembered; a transaction older than them
    /// is invalid, and one within them or newer must have a hash unique within its generation.
    Generation(u64) = 1,
    /// Window-based: an account's transactions have unique, not necessarily consecutive
    /// nonces; nonces within the window below the highest seen are still accepted.
    Window(u64) = 2,
}

/// What the authenticator establishes about a transaction: its uniqueness data, its hashes, the
/// credential that signed it, and the address it runs as. Never serialized.
///
/// The credential id and the default address are derived from the typed [`Credential`] when the
/// value is built ([`AuthorizationData::new`]), on every path: an EVM key's default address is
/// its `0x…` account (`Vm`) whichever authenticator built it (upstream computed
/// `default_address` as `credential_id.into()` in the native authenticator, a `sel1…` address
/// for an EVM key, and let each authenticator set it; P5-08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationData<S: Spec> {
    uniqueness: UniquenessData,
    tx_hash: TxHash,
    non_malleable_hash: TxHash,
    credential: Credential,
    credential_id: CredentialId,
    default_address: S::Address,
    address_override: Option<S::Address>,
}

impl<S: Spec> AuthorizationData<S> {
    /// The authorization of a transaction with `uniqueness`, hashed as `tx_hash` on the wire
    /// and `non_malleable_hash` for replay protection, signed by `credential`, which declared
    /// `address_override`.
    pub fn new(
        uniqueness: UniquenessData,
        tx_hash: TxHash,
        non_malleable_hash: TxHash,
        credential: Credential,
        address_override: Option<S::Address>,
    ) -> Self {
        Self {
            uniqueness,
            tx_hash,
            non_malleable_hash,
            credential_id: credential.credential_id(),
            default_address: S::Address::default_for(&credential),
            credential,
            address_override,
        }
    }

    /// How the transaction is kept unique.
    pub const fn uniqueness(&self) -> UniquenessData {
        self.uniqueness
    }

    /// The hash of the transaction as received (its envelope's bytes).
    pub const fn tx_hash(&self) -> &TxHash {
        &self.tx_hash
    }

    /// The hash used for replay protection: the hash of the signed bytes, so it does not change
    /// when the same signed transaction is encoded differently (a different set or order of
    /// multisig signatures, another encoding of a key).
    pub const fn non_malleable_hash(&self) -> &TxHash {
        &self.non_malleable_hash
    }

    /// The credential that signed the transaction.
    pub const fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The credential's id ([`Credential::credential_id`]).
    pub const fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }

    /// The credential's default address ([`AccountAddress::default_for`]): the sender when
    /// there is no [`address_override`](Self::address_override).
    pub const fn default_address(&self) -> &S::Address {
        &self.default_address
    }

    /// The address the signer asked the transaction to run as, instead of the default one.
    ///
    /// - `None`: the credential's default address. Allowed unless an explicit `false` entry
    ///   exists for `(default_address, credential_id)` (allowed unless revoked).
    /// - `Some(x)`: requires an explicit `(x, credential_id)` entry in the accounts module; the
    ///   transaction is skipped otherwise.
    ///
    /// `Some(default_address)` is not the same as `None`: `None` uses the implicit "allowed
    /// unless revoked" rule, `Some(_)` needs an explicit entry, so passing the default address
    /// as `Some` skips the transaction unless that exact pair was registered. Pass `None` for
    /// the default address.
    pub const fn address_override(&self) -> Option<&S::Address> {
        self.address_override.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use selendra_interface::common::HexHash;
    use selendra_primitives::crypto::{Ed25519PublicKey, EthereumPublicKey};
    use selendra_primitives::{Address, EthereumAddress, MultiAddressEvm};

    use super::*;
    use crate::test_utils::TestSpec;

    #[test]
    fn uniqueness_encodings() {
        let cases = [
            (UniquenessData::Nonce(0x0102), 0u8, r#"{"nonce":258}"#),
            (UniquenessData::Generation(7), 1, r#"{"generation":7}"#),
            (
                UniquenessData::Window(u64::MAX),
                2,
                r#"{"window":18446744073709551615}"#,
            ),
        ];
        for (value, tag, json) in cases {
            let bytes = borsh::to_vec(&value).unwrap();
            assert_eq!(bytes[0], tag);
            assert_eq!(bytes.len(), 9);
            let (UniquenessData::Nonce(n)
            | UniquenessData::Generation(n)
            | UniquenessData::Window(n)) = value;
            assert_eq!(bytes[1..], n.to_le_bytes());
            assert_eq!(borsh::from_slice::<UniquenessData>(&bytes).unwrap(), value);
            assert_eq!(serde_json::to_string(&value).unwrap(), json);
            assert_eq!(serde_json::from_str::<UniquenessData>(json).unwrap(), value);
            let binary = postcard::to_allocvec(&value).unwrap();
            assert_eq!(
                postcard::from_bytes::<UniquenessData>(&binary).unwrap(),
                value
            );
        }
        for rejected in [&[3u8, 0, 0, 0, 0, 0, 0, 0, 0][..], &[0, 0], &[0; 10]] {
            assert!(borsh::from_slice::<UniquenessData>(rejected).is_err());
        }
        for rejected in [
            r#"{"Nonce":1}"#,
            r#"{"nonce":"1"}"#,
            r#"{"nonce":-1}"#,
            r#"7"#,
        ] {
            assert!(serde_json::from_str::<UniquenessData>(rejected).is_err());
        }
    }

    /// P5-08 (regression, the authorization side): the default address follows the key kind
    /// (upstream: `credential_id.into()`, a `Standard` address for an EVM key).
    #[test]
    fn default_address_follows_the_credential() {
        let secp: EthereumPublicKey =
            "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap();
        let eth: EthereumAddress = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
            .parse()
            .unwrap();
        let data = AuthorizationData::<TestSpec>::new(
            UniquenessData::Nonce(1),
            HexHash::new([1; 32]),
            HexHash::new([2; 32]),
            Credential::Secp256k1(secp),
            None,
        );
        assert_eq!(data.default_address(), &MultiAddressEvm::Vm(eth));
        assert_eq!(
            data.credential_id(),
            &selendra_interface::crypto::PublicKey::credential_id(&secp)
        );
        assert_eq!(data.credential(), &Credential::Secp256k1(secp));
        assert_eq!(data.uniqueness(), UniquenessData::Nonce(1));
        assert_eq!(data.tx_hash(), &HexHash::new([1; 32]));
        assert_eq!(data.non_malleable_hash(), &HexHash::new([2; 32]));
        assert_eq!(data.address_override(), None);

        let ed: Ed25519PublicKey =
            "0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                .parse()
                .unwrap();
        let other = MultiAddressEvm::Standard(Address::new([9; 28]));
        let data = AuthorizationData::<TestSpec>::new(
            UniquenessData::Window(3),
            HexHash::new([1; 32]),
            HexHash::new([1; 32]),
            Credential::Ed25519(ed.clone()),
            Some(other),
        );
        assert_eq!(
            data.default_address(),
            &MultiAddressEvm::Standard(Address::from_hash_prefix(ed.bytes()))
        );
        assert_eq!(data.address_override(), Some(&other));
    }
}

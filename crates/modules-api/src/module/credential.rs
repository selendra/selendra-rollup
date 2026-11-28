//! How an account is derived from the key that signs: [`Credential`] and [`AccountAddress`].

use selendra_interface::BasicAddress;
use selendra_interface::crypto::{CredentialId, PublicKey};
use selendra_primitives::crypto::{Ed25519PublicKey, EthereumPublicKey};
use selendra_primitives::{Address, MultiAddressEvm};

/// What authenticated a transaction, with its kind: an ed25519 key, a secp256k1 key, or a
/// multisig credential.
///
/// The kind matters: the same 32 bytes of [`CredentialId`] can come from different kinds of
/// key, and each kind owns a different account ([`AccountAddress::default_for`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Credential {
    /// An ed25519 public key (native `sel1…` accounts).
    Ed25519(Ed25519PublicKey),
    /// A secp256k1 public key (Ethereum `0x…` accounts).
    Secp256k1(EthereumPublicKey),
    /// A multisig credential: the hash identifying the key set and threshold.
    Multisig(CredentialId),
}

impl Credential {
    /// The credential id: the ed25519 key's bytes, the secp256k1 key's padded Ethereum address,
    /// or the multisig hash.
    pub fn credential_id(&self) -> CredentialId {
        match self {
            Self::Ed25519(key) => key.credential_id(),
            Self::Secp256k1(key) => key.ethereum_address().as_credential_id(),
            Self::Multisig(id) => *id,
        }
    }
}

/// An account address type that knows which account each kind of credential owns.
///
/// This replaces upstream's `Spec::Address: From<CredentialId>` (P5-08): a credential id does
/// not say which kind of key produced it, so the conversion picked one rule for every key, and
/// a secp256k1 key's account became a `sel1…` address nobody funds instead of its `0x…`
/// address.
pub trait AccountAddress: BasicAddress {
    /// The account `credential` owns when nothing else (e.g. the accounts module) says
    /// otherwise.
    fn default_for(credential: &Credential) -> Self;

    /// `credential`'s default account and its id together:
    /// `(Self::default_for(credential), credential.credential_id())`, so an implementation can
    /// derive both from one piece of work. The authorization data is built with it
    /// ([`AuthorizationData::new`](crate::transaction::AuthorizationData::new)).
    ///
    /// The default computes the two separately. An override must return exactly these two
    /// values.
    fn default_and_credential_id(credential: &Credential) -> (Self, CredentialId) {
        (Self::default_for(credential), credential.credential_id())
    }
}

/// - ed25519 key → `Standard` (the first 28 bytes of the key);
/// - secp256k1 key → `Vm` (its Ethereum address, the account MetaMask shows);
/// - multisig → `Standard` (the first 28 bytes of the credential hash).
///
/// A secp256k1 key's id is its Ethereum address too (zero-padded), so
/// [`default_and_credential_id`](AccountAddress::default_and_credential_id) derives that address
/// once for both ([`EthereumPublicKey::ethereum_address`]: one decompression and one keccak256 of
/// 64 bytes), not twice.
impl AccountAddress for MultiAddressEvm {
    fn default_for(credential: &Credential) -> Self {
        match credential {
            Credential::Ed25519(key) => Self::from(key),
            Credential::Secp256k1(key) => Self::Vm(key.ethereum_address()),
            Credential::Multisig(id) => Self::Standard(Address::from_hash_prefix(id.as_bytes())),
        }
    }

    fn default_and_credential_id(credential: &Credential) -> (Self, CredentialId) {
        match credential {
            Credential::Secp256k1(key) => {
                let address = key.ethereum_address();
                (Self::Vm(address), address.as_credential_id())
            }
            other => (Self::default_for(other), other.credential_id()),
        }
    }
}

#[cfg(test)]
mod tests {
    use selendra_primitives::EthereumAddress;
    use selendra_primitives::crypto::count_ethereum_address_derivations;

    use super::*;
    use crate::Spec;
    use crate::test_utils::TestSpec;

    /// The secp256k1 public key of private key 1 (the generator point), and its Ethereum
    /// address (a well-known vector).
    const SECP256K1_KEY_OF_1: &str =
        "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const ADDRESS_OF_1: &str = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
    /// RFC 8032 test 1's public key.
    const ED25519_KEY: &str = "0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    // Regressions of upstream's `Spec::Address: From<CredentialId>` bug

    /// P5-08 (regression, the `Spec` side): an EVM key's account is its `0x…` address
    /// (`Vm`). Upstream's `S::Address::from(credential_id)` made it `Standard` (the first 28
    /// bytes of the zero-padded Ethereum address).
    #[test]
    fn account_address_is_key_aware() {
        type A = <TestSpec as Spec>::Address;

        let secp: EthereumPublicKey = SECP256K1_KEY_OF_1.parse().unwrap();
        let eth: EthereumAddress = ADDRESS_OF_1.parse().unwrap();
        assert_eq!(
            A::default_for(&Credential::Secp256k1(secp)),
            MultiAddressEvm::Vm(eth)
        );
        // Shown with its EIP-55 checksum.
        assert_eq!(
            A::default_for(&Credential::Secp256k1(secp)).to_string(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );

        let ed: Ed25519PublicKey = ED25519_KEY.parse().unwrap();
        let mut first_28 = [0u8; 28];
        first_28.copy_from_slice(&ed.bytes()[..28]);
        assert_eq!(
            A::default_for(&Credential::Ed25519(ed)),
            MultiAddressEvm::Standard(Address::new(first_28))
        );

        let id = CredentialId::from_bytes(std::array::from_fn(|i| u8::try_from(i).unwrap()));
        let first_28: [u8; 28] = std::array::from_fn(|i| u8::try_from(i).unwrap());
        assert_eq!(
            A::default_for(&Credential::Multisig(id)),
            MultiAddressEvm::Standard(Address::new(first_28))
        );
    }

    /// `default_and_credential_id` gives `default_for` and `credential_id` for every kind of
    /// credential, and derives a secp256k1 key's Ethereum address once for the two (the default
    /// implementation, computing them separately, derives it twice). Every derivation is
    /// counted, whichever function runs it (`selendra-primitives` counts in
    /// `EthereumPublicKey::ethereum_address`, which `EthereumPublicKey::credential_id` and
    /// `MultiAddressEvm::from` run too).
    #[test]
    fn default_and_credential_id_derive_once() {
        type A = <TestSpec as Spec>::Address;

        let secp: EthereumPublicKey = SECP256K1_KEY_OF_1.parse().unwrap();
        let ed: Ed25519PublicKey = ED25519_KEY.parse().unwrap();
        for (credential, derivations) in [
            (Credential::Secp256k1(secp), 1),
            (Credential::Ed25519(ed), 0),
            (Credential::Multisig(CredentialId::from_bytes([7; 32])), 0),
        ] {
            let (count, (address, id)) =
                count_ethereum_address_derivations(|| A::default_and_credential_id(&credential));
            assert_eq!(count, derivations, "{credential:?}");
            assert_eq!(address, A::default_for(&credential));
            assert_eq!(id, credential.credential_id());
        }
        // Each separately (what the default implementation does): one derivation each.
        let (count, _) = count_ethereum_address_derivations(|| {
            (
                A::default_for(&Credential::Secp256k1(secp)),
                Credential::Secp256k1(secp).credential_id(),
            )
        });
        assert_eq!(count, 2);
        // `selendra-primitives`' own conversions are counted too.
        let (count, _) = count_ethereum_address_derivations(|| {
            (
                MultiAddressEvm::from(&secp),
                PublicKey::credential_id(&secp),
            )
        });
        assert_eq!(count, 2);
    }

    #[test]
    fn credential_ids() {
        let secp: EthereumPublicKey = SECP256K1_KEY_OF_1.parse().unwrap();
        assert_eq!(
            Credential::Secp256k1(secp).credential_id(),
            secp.credential_id()
        );
        let ed: Ed25519PublicKey = ED25519_KEY.parse().unwrap();
        assert_eq!(
            Credential::Ed25519(ed.clone()).credential_id().as_bytes(),
            ed.bytes()
        );
        let id = CredentialId::from_bytes([9; 32]);
        assert_eq!(Credential::Multisig(id).credential_id(), id);
    }
}

//! The signature schemes native transactions are signed with ([`SignatureScheme`]) and the
//! crypto specs implementing them ([`TxCryptoSpec`]).

use selendra_primitives::crypto::{Ed25519CryptoSpec, EvmCryptoSpec};

use crate::{Credential, CryptoSpecExt, SchemeCosts};

/// A signature scheme of native transactions. The byte values are part of the protocol (the
/// multisig credential hashes them): never reuse one. They are their own number space: the
/// authenticator's envelope tags (Phase 5 S11) are allocated separately, and several envelope
/// formats may carry one scheme (the native secp256k1 envelope and the reserved EIP-712 and
/// Ethereum RLP ones are all secp256k1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SignatureScheme {
    /// ed25519 (native `sel1…` accounts).
    Ed25519 = 0,
    /// ECDSA over secp256k1 with keccak256 (Ethereum-style keys; software keys only: wallets
    /// sign through EIP-712, Phase 7).
    Secp256k1 = 1,
}

impl SignatureScheme {
    /// The scheme's byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The scheme's entry of a per-scheme cost table.
    pub const fn cost<G: Copy>(self, costs: &SchemeCosts<G>) -> G {
        match self {
            Self::Ed25519 => costs.ed25519,
            Self::Secp256k1 => costs.secp256k1,
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for selendra_primitives::crypto::Ed25519CryptoSpec {}
    impl Sealed for selendra_primitives::crypto::EvmCryptoSpec {}
}

/// A crypto spec native transactions are signed with: [`Ed25519CryptoSpec`] or
/// [`EvmCryptoSpec`], nothing else (sealed).
///
/// It names the [`SignatureScheme`] and says which [`Credential`] a key is. Sealed because the
/// credential decides the signer's account ([`AccountAddress::default_for`](crate::AccountAddress)):
/// a spec from another crate could present its keys as another kind of credential.
pub trait TxCryptoSpec: CryptoSpecExt + Eq + sealed::Sealed {
    /// The scheme.
    const SCHEME: SignatureScheme;

    /// The credential `key` is.
    fn credential(key: &Self::PublicKey) -> Credential;
}

impl TxCryptoSpec for Ed25519CryptoSpec {
    const SCHEME: SignatureScheme = SignatureScheme::Ed25519;

    fn credential(key: &Self::PublicKey) -> Credential {
        Credential::Ed25519(key.clone())
    }
}

impl TxCryptoSpec for EvmCryptoSpec {
    const SCHEME: SignatureScheme = SignatureScheme::Secp256k1;

    fn credential(key: &Self::PublicKey) -> Credential {
        Credential::Secp256k1(*key)
    }
}

#[cfg(test)]
mod tests {
    use selendra_primitives::crypto::{Ed25519PublicKey, EthereumPublicKey};

    use super::*;

    #[test]
    fn scheme_bytes_are_pinned() {
        assert_eq!(SignatureScheme::Ed25519.as_u8(), 0);
        assert_eq!(SignatureScheme::Secp256k1.as_u8(), 1);
        assert_eq!(Ed25519CryptoSpec::SCHEME, SignatureScheme::Ed25519);
        assert_eq!(EvmCryptoSpec::SCHEME, SignatureScheme::Secp256k1);
        let costs = SchemeCosts {
            ed25519: 3u64,
            secp256k1: 5,
        };
        assert_eq!(SignatureScheme::Ed25519.cost(&costs), 3);
        assert_eq!(SignatureScheme::Secp256k1.cost(&costs), 5);
    }

    #[test]
    fn credentials_keep_the_key_kind() {
        let ed: Ed25519PublicKey =
            "0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                .parse()
                .unwrap();
        assert_eq!(
            Ed25519CryptoSpec::credential(&ed),
            Credential::Ed25519(ed.clone())
        );
        let secp: EthereumPublicKey =
            "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap();
        assert_eq!(
            EvmCryptoSpec::credential(&secp),
            Credential::Secp256k1(secp)
        );
    }
}

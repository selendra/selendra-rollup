//! Concrete cryptography for Selendra. A single implementation is shared by native
//! execution and every zkVM, so they can never disagree on which signatures are valid.

pub mod ed25519;

use selendra_interface::zk::CryptoSpec;

#[cfg(feature = "native")]
pub use self::ed25519::Ed25519PrivateKey;
pub use self::ed25519::{Ed25519PublicKey, Ed25519Signature};

/// The [`CryptoSpec`] for native `sel1…` accounts: ed25519 signatures and SHA-256.
///
/// `sha2` and `ed25519-consensus` are pinned to the exact versions SP1's guest patches
/// accelerate; the patches are applied when building the guest, so this one type works
/// natively and inside the zkVM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519CryptoSpec;

impl CryptoSpec for Ed25519CryptoSpec {
    #[cfg(feature = "native")]
    type PrivateKey = Ed25519PrivateKey;
    type PublicKey = Ed25519PublicKey;
    type Hasher = sha2::Sha256;
    type Signature = Ed25519Signature;
}

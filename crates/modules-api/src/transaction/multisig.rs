//! K-of-N multisig credentials ([`Multisig`]) and the signatures a multisig transaction carries
//! ([`PubKeyAndSignature`]).

use selendra_interface::common::SafeVec;
use selendra_interface::crypto::CredentialId;
use selendra_interface::reexports::digest::Digest;
use selendra_primitives::signing::{SigningBytes, verify_signing_bytes};
use selendra_state::StateHasher;

use super::TxCryptoSpec;
use crate::ConsensusType;

/// The most keys a multisig has, signers and the others together.
pub const MAX_SIGNERS: usize = 21;

/// A signature and the key that made it.
///
/// borsh: the signature, then the key. JSON: `{"signature": …, "pub_key": …}` (each `0x` +
/// lowercase hex), no unknown fields. A consensus type.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
    ConsensusType,
)]
#[serde(bound = "", deny_unknown_fields)]
pub struct PubKeyAndSignature<C: TxCryptoSpec> {
    /// The signature.
    pub signature: C::Signature,
    /// The key.
    pub pub_key: C::PublicKey,
}

/// Why keys and a threshold are not a valid multisig, or signatures do not satisfy one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MultisigError {
    /// The threshold is 0: anyone could act for the multisig, with no signature at all.
    #[error("a multisig needs a threshold of at least 1")]
    ZeroThreshold,
    /// The threshold is above the number of keys: no set of signatures meets it.
    #[error("the threshold {min_signers} is above the number of keys ({keys})")]
    ThresholdAboveKeys {
        /// The threshold.
        min_signers: u8,
        /// The number of keys.
        keys: usize,
    },
    /// More than [`MAX_SIGNERS`] keys.
    #[error("{keys} keys, more than the {MAX_SIGNERS} a multisig may have")]
    TooManyKeys {
        /// The number of keys.
        keys: usize,
    },
    /// A key is listed twice.
    #[error("a key is listed twice")]
    DuplicateKey,
    /// A signature is by a key that is not one of the multisig's.
    #[error("a signature is by a key that is not one of the multisig's")]
    OutsiderSigner,
    /// Two signatures are by the same key.
    #[error("a key signed twice")]
    DuplicateSigner,
    /// Fewer signatures than the threshold.
    #[error("{got} signatures, {required} required")]
    NotEnoughSignatures {
        /// The threshold.
        required: u8,
        /// The number of signatures.
        got: usize,
    },
    /// A signature does not verify.
    #[error("invalid signature: {error}")]
    BadSignature {
        /// Why.
        error: String,
    },
}

/// A K-of-N multisig: at least `min_signers` of its keys must sign.
///
/// Built only by [`Multisig::new`], which enforces `1 ≤ min_signers ≤ keys ≤ MAX_SIGNERS` and
/// distinct keys, and keeps the keys sorted by their encoding. Upstream accepted a threshold of
/// 0 (no signature needed), a threshold above the number of keys, up to 42 keys and duplicate
/// keys, and its `verify_signature` checked signers against the signatures themselves rather
/// than the multisig's keys (P5-34).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multisig<C: TxCryptoSpec> {
    min_signers: u8,
    keys: SafeVec<C::PublicKey, MAX_SIGNERS>,
}

impl<C: TxCryptoSpec> Multisig<C> {
    /// The domain tag of [`credential_id`](Self::credential_id).
    pub const DOMAIN: &'static [u8] = b"SELENDRA/multisig/v1";

    /// The multisig of `keys` (in any order) with threshold `min_signers`.
    ///
    /// # Errors
    /// If `min_signers` is 0 or above the number of keys, there are more than [`MAX_SIGNERS`]
    /// keys, or a key is listed twice.
    pub fn new(min_signers: u8, mut keys: Vec<C::PublicKey>) -> Result<Self, MultisigError> {
        #[cfg(test)]
        MULTISIG_BUILDS.with(|count| count.set(count.get() + 1));
        Self::check_shape(min_signers, keys.len())?;
        // A key's bytes are its borsh encoding (both schemes encode keys as their raw bytes),
        // and each key has one encoding.
        keys.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
        if keys
            .windows(2)
            .any(|pair| pair[0].as_ref() == pair[1].as_ref())
        {
            return Err(MultisigError::DuplicateKey);
        }
        let count = keys.len();
        let keys =
            SafeVec::try_from(keys).map_err(|_| MultisigError::TooManyKeys { keys: count })?;
        Ok(Self { min_signers, keys })
    }

    /// The checks of [`new`](Self::new) that read no key, in its order: at most
    /// [`MAX_SIGNERS`] keys, then a threshold of at least 1 and at most `keys`. Constant time:
    /// the authenticator runs them before charging for the multisig's credential, and the
    /// duplicate-key check (which sorts the keys) after.
    ///
    /// # Errors
    /// [`MultisigError::TooManyKeys`], [`MultisigError::ZeroThreshold`] or
    /// [`MultisigError::ThresholdAboveKeys`].
    pub(crate) fn check_shape(min_signers: u8, keys: usize) -> Result<(), MultisigError> {
        if keys > MAX_SIGNERS {
            return Err(MultisigError::TooManyKeys { keys });
        }
        if min_signers == 0 {
            return Err(MultisigError::ZeroThreshold);
        }
        if usize::from(min_signers) > keys {
            return Err(MultisigError::ThresholdAboveKeys { min_signers, keys });
        }
        Ok(())
    }

    /// The length of the credential's preimage ([`credential_id`](Self::credential_id)) for
    /// `keys`: the domain tag, the scheme and threshold bytes, the keys' `u32` count and their
    /// bytes. Reads only the keys' lengths (no copy, no comparison): what the authenticator
    /// charges for the credential before validating the keys.
    pub(crate) fn credential_preimage_len<'k>(
        keys: impl IntoIterator<Item = &'k C::PublicKey>,
    ) -> usize {
        let keys: usize = keys.into_iter().map(|key| key.as_ref().len()).sum();
        Self::DOMAIN.len() + 2 + 4 + keys
    }

    /// The threshold.
    pub const fn min_signers(&self) -> u8 {
        self.min_signers
    }

    /// The keys, sorted by their encoding.
    pub fn keys(&self) -> &[C::PublicKey] {
        &self.keys
    }

    /// The keys, sorted, as a transaction's list.
    pub(crate) fn keys_vec(&self) -> SafeVec<C::PublicKey, MAX_SIGNERS> {
        self.keys.clone()
    }

    /// Whether `key` is one of the multisig's keys.
    pub fn contains(&self, key: &C::PublicKey) -> bool {
        self.position(key).is_some()
    }

    fn position(&self, key: &C::PublicKey) -> Option<usize> {
        self.keys
            .binary_search_by(|probe| probe.as_ref().cmp(key.as_ref()))
            .ok()
    }

    /// The multisig's credential: `SHA-256("SELENDRA/multisig/v1" ‖ scheme ‖ min_signers ‖
    /// borsh(sorted keys))` (`scheme` and `min_signers` one byte each; `borsh(sorted keys)` the
    /// `u32` LE count, then each key's bytes, sorted), hashed with the state hasher.
    ///
    /// The same keys and threshold give the same credential whichever keys sign and in
    /// whatever order they are listed; another scheme or threshold gives another one (upstream:
    /// `H(min_signers ‖ borsh(keys sorted by Ord))`, with no domain tag or scheme).
    pub fn credential_id(&self) -> CredentialId {
        let mut hasher = StateHasher::new();
        hasher.update(Self::DOMAIN);
        hasher.update([C::SCHEME.as_u8(), self.min_signers]);
        // `keys.len() <= MAX_SIGNERS`, so it fits.
        hasher.update(
            u32::try_from(self.keys.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for key in &self.keys {
            hasher.update(key.as_ref());
        }
        CredentialId::from_bytes(hasher.finalize().into())
    }

    /// Checks that `signatures` satisfy the multisig over `bytes`: each is by one of its keys,
    /// no key signs twice, there are at least [`min_signers`](Self::min_signers), and every one
    /// verifies (an invalid signature fails the whole set, so they can be batch-verified).
    ///
    /// The structural checks come before any signature is verified.
    ///
    /// # Errors
    /// The first rule broken.
    pub fn verify(
        &self,
        bytes: &SigningBytes,
        signatures: &[PubKeyAndSignature<C>],
    ) -> Result<(), MultisigError> {
        let mut signed = [false; MAX_SIGNERS];
        for PubKeyAndSignature { pub_key, .. } in signatures {
            let position = self
                .position(pub_key)
                .ok_or(MultisigError::OutsiderSigner)?;
            if std::mem::replace(&mut signed[position], true) {
                return Err(MultisigError::DuplicateSigner);
            }
        }
        if signatures.len() < usize::from(self.min_signers) {
            return Err(MultisigError::NotEnoughSignatures {
                required: self.min_signers,
                got: signatures.len(),
            });
        }
        for PubKeyAndSignature { signature, pub_key } in signatures {
            verify_signing_bytes(signature, pub_key, bytes).map_err(|error| {
                MultisigError::BadSignature {
                    error: error.to_string(),
                }
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    /// How many multisigs this thread built or tried to build ([`Multisig::new`] calls: the
    /// keys copied, then sorted and checked for duplicates).
    static MULTISIG_BUILDS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// The multisigs `f` builds or tries to build ([`Multisig::new`] calls, which every build goes
/// through, `Version1::multisig` included), and its result: the authenticator must build one
/// only after charging for its credential.
#[cfg(test)]
pub(crate) fn count_multisig_builds<T>(f: impl FnOnce() -> T) -> (u64, T) {
    let before = MULTISIG_BUILDS.with(core::cell::Cell::get);
    let result = f();
    (MULTISIG_BUILDS.with(core::cell::Cell::get) - before, result)
}

#[cfg(test)]
pub(super) mod tests;

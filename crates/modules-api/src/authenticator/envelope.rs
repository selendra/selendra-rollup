//! The envelope of a transaction: which authenticator reads it ([`AuthenticatorKind`]), and the
//! transaction's bytes ([`AuthenticatorInput`], read in place by [`Envelope::parse`]).

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::Bytes;
use selendra_interface::stf::{FullyBakedTx, MAX_RAW_TX_SIZE, RawTx, TxTooLarge};

use crate::ConsensusType;
use crate::transaction::{Transaction, TransactionCallable, TxCryptoSpec};
use crate::{Spec, transaction::SignatureScheme};

/// The authenticators an envelope can name: its tag, the first byte of a
/// [`FullyBakedTx`]'s data. The values are part of the protocol: never reuse one. They are
/// their own number space, separate from the [`SignatureScheme`] bytes (the multisig
/// credential's): several envelopes carry secp256k1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AuthenticatorKind {
    /// A native transaction signed with ed25519 (`Transaction<R, S, Ed25519CryptoSpec>`).
    Ed25519 = 0,
    /// A native transaction signed with secp256k1 (`Transaction<R, S, EvmCryptoSpec>`;
    /// software keys only).
    Secp256k1 = 1,
    /// Reserved: an EIP-712 typed-data transaction (Phase 7).
    Eip712 = 2,
    /// Reserved: an Ethereum RLP transaction (Phase 7).
    EthereumRlp = 3,
}

impl AuthenticatorKind {
    /// The envelope tag.
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// The authenticator of envelope tag `tag`, if one is allocated.
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Ed25519),
            1 => Some(Self::Secp256k1),
            2 => Some(Self::Eip712),
            3 => Some(Self::EthereumRlp),
            _ => None,
        }
    }

    /// Whether the authenticator is enabled: the native ones. The reserved tags are rejected
    /// (`FatalError::UnsupportedAuthenticator`) until Phase 7.
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Ed25519 | Self::Secp256k1)
    }

    /// The signature scheme of a native authenticator's transactions (`None` for the reserved
    /// ones).
    pub const fn native_scheme(self) -> Option<SignatureScheme> {
        match self {
            Self::Ed25519 => Some(SignatureScheme::Ed25519),
            Self::Secp256k1 => Some(SignatureScheme::Secp256k1),
            Self::Eip712 | Self::EthereumRlp => None,
        }
    }
}

/// What a [`FullyBakedTx`]'s data holds for the native authenticator: the envelope tag
/// ([`AuthenticatorKind`]), then the transaction ([`RawTx`]: a `u32` LE length, at most
/// `MAX_RAW_TX_SIZE`, and the bytes). Nothing may follow.
///
/// borsh: exactly that (tag `0` = `Ed25519`, `1` = `Secp256k1`; `2` and `3` are reserved and do
/// not decode). A consensus type. The authenticator never decodes it into a value (that would
/// copy the transaction before any gas is charged, P5-37): it reads it in place with
/// [`Envelope::parse`], which accepts exactly the bytes this type's decoder accepts.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, ConsensusType)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum AuthenticatorInput {
    /// A native ed25519 transaction.
    Ed25519(RawTx) = 0,
    /// A native secp256k1 transaction.
    Secp256k1(RawTx) = 1,
}

/// What `#[derive(BorshDeserialize)]` generates (the tag, then the variant's `RawTx`; another
/// tag is `InvalidData`, "Unexpected variant tag"), written out so this crate's tests can count
/// the decodes: the authenticator never runs it (P5-37).
impl BorshDeserialize for AuthenticatorInput {
    fn deserialize_reader<Rd: borsh::io::Read>(reader: &mut Rd) -> borsh::io::Result<Self> {
        #[cfg(test)]
        super::tests::ENVELOPE_DECODES.with(|count| count.set(count.get() + 1));
        match u8::deserialize_reader(reader)? {
            0 => RawTx::deserialize_reader(reader).map(Self::Ed25519),
            1 => RawTx::deserialize_reader(reader).map(Self::Secp256k1),
            tag => Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                format!("Unexpected variant tag: {tag:?}"),
            )),
        }
    }
}

/// A transaction does not fit in an envelope (its encoding is larger than `MAX_RAW_TX_SIZE`),
/// or does not encode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeTransactionError {
    /// The transaction is too large.
    #[error(transparent)]
    TooLarge(#[from] TxTooLarge),
    /// Its `BorshSerialize` failed (a consensus type never does).
    #[error("the transaction does not encode: {0}")]
    Encoding(String),
}

impl AuthenticatorInput {
    /// The envelope of a native transaction: its scheme's tag, then its borsh encoding.
    ///
    /// # Errors
    /// See [`EncodeTransactionError`].
    pub fn from_transaction<R: TransactionCallable, S: Spec, C: TxCryptoSpec>(
        tx: &Transaction<R, S, C>,
    ) -> Result<Self, EncodeTransactionError> {
        let bytes = borsh::to_vec(tx)
            .map_err(|error| EncodeTransactionError::Encoding(error.to_string()))?;
        let raw = RawTx::new(bytes)?;
        Ok(match C::SCHEME {
            SignatureScheme::Ed25519 => Self::Ed25519(raw),
            SignatureScheme::Secp256k1 => Self::Secp256k1(raw),
        })
    }

    /// The authenticator named.
    pub const fn kind(&self) -> AuthenticatorKind {
        match self {
            Self::Ed25519(_) => AuthenticatorKind::Ed25519,
            Self::Secp256k1(_) => AuthenticatorKind::Secp256k1,
        }
    }

    /// The transaction.
    pub const fn raw_tx(&self) -> &RawTx {
        match self {
            Self::Ed25519(raw) | Self::Secp256k1(raw) => raw,
        }
    }

    /// The envelope's bytes: the tag, the `u32` LE length, the transaction (its borsh
    /// encoding).
    pub fn to_bytes(&self) -> Vec<u8> {
        let raw = self.raw_tx().as_bytes();
        let mut bytes = Vec::with_capacity(ENVELOPE_HEADER_LEN + raw.len());
        bytes.push(self.kind().tag());
        // At most `MAX_RAW_TX_SIZE` bytes, which fits a `u32`.
        bytes.extend(u32::try_from(raw.len()).unwrap_or(u32::MAX).to_le_bytes());
        bytes.extend_from_slice(raw);
        bytes
    }

    /// The transaction carrying the envelope (no sequencing data). Infallible: a `RawTx` behind
    /// the 5-byte header always fits a `FullyBakedTx` (`selendra-interface` asserts
    /// `MAX_RAW_TX_SIZE + 5 <= MAX_FULLY_BAKED_TX_SIZE` at compile time).
    pub fn to_fully_baked_tx(&self) -> FullyBakedTx {
        match FullyBakedTx::new(Bytes::from(self.to_bytes())) {
            Ok(tx) => tx,
            Err(_) => unreachable!("MAX_RAW_TX_SIZE + 5 <= MAX_FULLY_BAKED_TX_SIZE"),
        }
    }
}

/// The length of an envelope's header: the tag and the transaction's `u32` LE length.
pub const ENVELOPE_HEADER_LEN: usize = 5;

/// Why bytes are not an envelope an enabled authenticator reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// No bytes.
    #[error("empty envelope")]
    Empty,
    /// A tag no authenticator has.
    #[error("unknown envelope tag {tag}")]
    UnknownTag {
        /// The tag.
        tag: u8,
    },
    /// A tag reserved for an authenticator that is not enabled (EIP-712, Ethereum RLP).
    #[error("envelope tag {tag} is reserved for an authenticator that is not enabled")]
    Reserved {
        /// The tag.
        tag: u8,
    },
    /// The bytes end inside the length.
    #[error("the envelope ends inside the transaction's length")]
    Truncated,
    /// The declared length is above `MAX_RAW_TX_SIZE`.
    #[error("the envelope declares {len} bytes, more than the maximum of {MAX_RAW_TX_SIZE}")]
    TooLarge {
        /// The declared length.
        len: u32,
    },
    /// The declared length is not the number of bytes that follow.
    #[error("the envelope declares {declared} bytes, but {actual} follow")]
    LengthMismatch {
        /// The declared length.
        declared: u32,
        /// The bytes after the header.
        actual: usize,
    },
}

/// An envelope read in place: the authenticator and the transaction's bytes, borrowed from the
/// [`FullyBakedTx`]'s data (no copy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope<'a> {
    kind: AuthenticatorKind,
    raw_tx: &'a [u8],
}

impl<'a> Envelope<'a> {
    /// Reads the envelope of `data` in place: the tag must be an enabled authenticator's, the
    /// length at most `MAX_RAW_TX_SIZE` and exactly the number of bytes that follow. These are
    /// [`AuthenticatorInput`]'s decoding rules: exactly the same bytes are accepted.
    ///
    /// Reads 5 bytes and copies none: the transaction's bytes are a subslice of `data`.
    ///
    /// # Errors
    /// See [`EnvelopeError`].
    pub fn parse(data: &'a [u8]) -> Result<Self, EnvelopeError> {
        let (&tag, rest) = data.split_first().ok_or(EnvelopeError::Empty)?;
        let kind = AuthenticatorKind::from_tag(tag).ok_or(EnvelopeError::UnknownTag { tag })?;
        if !kind.is_enabled() {
            return Err(EnvelopeError::Reserved { tag });
        }
        let (len, raw_tx) = rest
            .split_first_chunk::<4>()
            .ok_or(EnvelopeError::Truncated)?;
        let len = u32::from_le_bytes(*len);
        if usize::try_from(len).map_or(true, |len| len > MAX_RAW_TX_SIZE) {
            return Err(EnvelopeError::TooLarge { len });
        }
        if usize::try_from(len) != Ok(raw_tx.len()) {
            return Err(EnvelopeError::LengthMismatch {
                declared: len,
                actual: raw_tx.len(),
            });
        }
        Ok(Self { kind, raw_tx })
    }

    /// The authenticator named (an enabled one).
    pub const fn kind(&self) -> AuthenticatorKind {
        self.kind
    }

    /// The transaction's bytes.
    pub const fn raw_tx(&self) -> &'a [u8] {
        self.raw_tx
    }
}

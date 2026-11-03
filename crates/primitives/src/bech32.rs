//! Strict bech32m encoding for fixed-size identifiers (addresses, later token ids).

use bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError};
use bech32::{Bech32m, Hrp};

/// Largest payload (bytes) accepted by [`encode`]/[`decode`]: with a prefix of up to 10
/// characters, 40 bytes (64 data symbols + separator + 6 checksum) stays under the
/// 90-character bech32m limit.
pub const MAX_PAYLOAD: usize = 40;

/// Why a bech32m string was rejected.
#[derive(Debug, thiserror::Error)]
pub enum Bech32ParseError {
    /// Not valid bech32m: bad characters, mixed case, bad checksum, or plain bech32.
    #[error("Bech32 error: {0}")]
    Bech32(#[from] CheckedHrpstringError),
    /// Valid bech32m, but for a different prefix (e.g. `sov1…` instead of `sel1…`).
    #[error("Wrong prefix: expected `{expected}`, got `{found}`")]
    WrongHrp {
        /// The required prefix.
        expected: &'static str,
        /// The prefix found in the string.
        found: String,
    },
    /// The payload has the wrong number of bytes.
    #[error("Wrong length: expected {expected} bytes, got {found}")]
    WrongLength {
        /// The required number of bytes.
        expected: usize,
        /// The number of bytes decoded.
        found: usize,
    },
    /// The string decodes to a valid payload but is not its canonical encoding
    /// (extra padding symbol or non-zero padding bits).
    #[error("Non-canonical bech32m encoding")]
    NonCanonical,
}

/// Encodes `bytes` as lowercase bech32m with the given prefix.
///
/// # Panics
///
/// If `hrp` is not a valid bech32 prefix. Prefixes are constants covered by tests; the
/// payload size is bounded at compile time so the 90-character bech32m limit always holds.
pub fn encode<const N: usize>(hrp: &'static str, bytes: &[u8; N]) -> String {
    const { assert!(N <= MAX_PAYLOAD, "payload too long for bech32m") };
    let hrp = Hrp::parse(hrp).expect("bech32 prefixes are valid constants");
    bech32::encode::<Bech32m>(hrp, bytes).expect("fixed-size payloads fit in bech32m")
}

/// Decodes a bech32m string with prefix `hrp` into exactly `N` bytes.
///
/// Only the canonical encoding is accepted, so every `N`-byte value has exactly one
/// valid string (uppercase input is allowed and treated as its lowercase form).
pub fn decode<const N: usize>(hrp: &'static str, s: &str) -> Result<[u8; N], Bech32ParseError> {
    let checked = CheckedHrpstring::new::<Bech32m>(s)?;

    let found = checked.hrp().to_lowercase();
    if found != hrp {
        return Err(Bech32ParseError::WrongHrp {
            expected: hrp,
            found,
        });
    }

    let bytes: Vec<u8> = checked.byte_iter().collect();
    let bytes: [u8; N] = bytes
        .try_into()
        .map_err(|b: Vec<u8>| Bech32ParseError::WrongLength {
            expected: N,
            found: b.len(),
        })?;

    if encode(hrp, &bytes) != s.to_ascii_lowercase() {
        return Err(Bech32ParseError::NonCanonical);
    }
    Ok(bytes)
}

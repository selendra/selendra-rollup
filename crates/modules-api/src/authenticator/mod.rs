//! The native authenticator ([`SelendraAuthenticator`]): reads a transaction's envelope
//! ([`Envelope`], [`AuthenticatorInput`]), then authenticates the native transaction in it
//! (ed25519 or secp256k1, single-key or multisig) against the chain ID and the runtime versions
//! accepted ([`RuntimeVersions`]), charging every stage first.
//!
//! # Stages
//! Each stage is charged to the pre-execution meter before its work (the spec's `GasSchedule`
//! costs; `n` is a length in bytes). In the order they run, numbered as in the Phase 5 plan
//! (D17):
//! - (1) the transaction hash, `SHA-256(FullyBakedTx.data)` (it covers the envelope tag):
//!   `hash_per_byte·n`, then `hash_update`. Then the envelope is read in place (5 bytes, no
//!   copy: [`Envelope::parse`]);
//! - (2) the transaction's borsh decode: `decode_per_byte·n`, then `borsh::from_slice` (trailing
//!   bytes rejected);
//! - (4) the public keys stage 2 decoded: `pubkey_decode[scheme]` per key (V0: one; V1: the
//!   signers and the unused keys). The keys are decoded (curve decompression) inside stage 2,
//!   and their number is known only after it, so this is charged right after the work it pays
//!   for, before anything else can reject the transaction: a decode that fails, or a refused
//!   charge, leaves at most 42 key decodes unpaid (the `SafeVec` caps of a V1 transaction;
//!   P5-62). A V0 secp256k1 key's credential id and default address, derived together when
//!   the authorization data is built (both are its Ethereum address: one decompression and one
//!   keccak256 of 64 bytes per transaction), are priced in its `pubkey_decode`;
//! - (3) the runtime version: looked up in the version table at the accessor's rollup height
//!   (uncharged: a search of a small constant table);
//! - (5) the signing payload: for V1 first the multisig's credential, `hash_update +
//!   hash_per_byte·n` over its preimage (`n` from the keys' lengths), the threshold and the
//!   number of keys checked before it (constant time) and the keys after it (copied, sorted,
//!   no duplicate): an invalid multisig is `SigVerificationFailed`, having paid stages 1, 2 and
//!   4, and for a duplicate key the credential's charge too. Then the payload's encoding and
//!   prehash, `encode_per_byte·n + hash_update`, then `hash_per_byte·n`, with `n` the payload's
//!   length computed from the transaction's, the bytes stage 2 paid to decode (V0: minus the
//!   signature; V1: minus the signatures with their keys, the unused keys and the threshold,
//!   plus the credential address; both plus the 32-byte runtime commitment), so the call is
//!   not walked: both are charged before any work proportional to the call. The encoding
//!   stops at the first write past `n` bytes (at most `n` are encoded and hashed): a payload
//!   that does not encode to exactly `n` (a call decoded from bytes other than its own
//!   encoding) is `DeserializationFailed`. The payload borrows the transaction's fields: the
//!   call is never copied;
//! - (6) the non-malleable hash, `SHA-256(signed bytes)`: `hash_per_byte·51`, then `hash_update`;
//! - (7) the signatures: `sig_verify[scheme] + sig_per_byte[scheme]·51` each, all charged before
//!   any is verified.
//!
//! A gas failure is `AuthenticationError::OutOfGas` (and poisons the pre-execution phase);
//! anything else is `AuthenticationError::FatalError`. Encodings and the stages are in
//! `docs/serialization.md` ("Authenticator").

mod envelope;
mod native;

#[cfg(test)]
mod tests;

pub use envelope::{
    AuthenticatorInput, AuthenticatorKind, ENVELOPE_HEADER_LEN, EncodeTransactionError, Envelope,
    EnvelopeError,
};
pub use native::SelendraAuthenticator;

use crate::transaction::VersionTable;

/// The runtime versions a runtime accepts: its version table, a constant (so an invalid table
/// is a compile error, `VersionTable::new_or_panic`).
///
/// Phase 8's runtime implements it; tests and tools implement it on marker types.
pub trait RuntimeVersions {
    /// The version table.
    const VERSIONS: VersionTable<'static>;
}

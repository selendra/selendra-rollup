//! A mock DA layer for tests and local chains: the types of [`MockDaSpec`] (hashes, addresses,
//! block headers, blobs) and [`MockDaVerifier`].
//!
//! The verifier proves nothing: it accepts every claimed set of blobs. So a rollup on the mock
//! DA layer trusts whoever produces its blocks. Never use it on a network with value.
//!
//! The DA services (in-memory, sqlite, RPC) are not here yet (Phase 9).
//!
//! Encodings (`docs/serialization.md`, "Mock adapters"): [`MockHash`] and [`MockAddress`] are
//! 32 raw bytes in borsh, and `0x` + 64 lowercase hex digits in text and JSON.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod address;
mod types;
mod verifier;

// `selendra-interface/native` adds `BlobReaderTrait::advance`, which this crate implements only
// with its own `native` feature. Cargo cannot make the first imply the second (the dependency
// points the other way), so say what to do instead of failing with a missing trait item.
#[cfg(not(feature = "native"))]
selendra_interface::__if_native! {
    compile_error!(
        "`selendra-interface/native` is enabled but `selendra-mock-da/native` is not: enable both"
    );
}

pub use address::{MOCK_SEQUENCER_DA_ADDRESS, MockAddress};
#[cfg(feature = "native")]
pub use types::MockBlock;
pub use types::{MockBlob, MockBlockHeader, MockHash};
pub use verifier::{MockDaSpec, MockDaVerifier};

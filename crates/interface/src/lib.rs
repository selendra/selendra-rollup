//! Core traits and types every Selendra component is generic over. They let the same
//! state transition function run on different DA layers (Avail, mock) and be proven with
//! different zkVMs (SP1, mock), while sharing one full node implementation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod address;
pub mod common;
pub mod crypto;
pub mod da;
#[cfg(feature = "native")]
pub mod node;
pub mod stf;
pub mod zk;

pub use address::{BasicAddress, MaybeArbitrary};
pub use bytes::{Buf, BufMut, Bytes, BytesMut};

/// A rollup transaction hash.
pub type TxHash = common::HexHash;

/// Useful third-party crate re-exports.
pub mod reexports {
    pub use {anyhow, digest, schemars};
}

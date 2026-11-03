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

/// Expands its input only when this crate's `native` feature is enabled. Lets dependent crates
/// detect `selendra-interface/native` (a crate cannot otherwise see another crate's features).
#[cfg(feature = "native")]
#[doc(hidden)]
#[macro_export]
macro_rules! __if_native {
    ($($item:tt)*) => { $($item)* };
}

/// Expands its input only when this crate's `native` feature is enabled. Lets dependent crates
/// detect `selendra-interface/native` (a crate cannot otherwise see another crate's features).
#[cfg(not(feature = "native"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __if_native {
    ($($item:tt)*) => {};
}

/// Useful third-party crate re-exports.
pub mod reexports {
    pub use {anyhow, digest, schemars};
}

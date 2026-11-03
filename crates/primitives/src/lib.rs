//! Selendra primitives: key types, signature schemes and account addresses
//! (native `sel1…` and Ethereum `0x…`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod address;
pub mod bech32;
pub mod crypto;
pub mod ethereum_address;
pub mod multi_address;

pub use address::{ADDRESS_PREFIX, Address};
pub use ethereum_address::EthereumAddress;
pub use multi_address::{FromVmAddress, MultiAddress, MultiAddressEvm, Not28Bytes};

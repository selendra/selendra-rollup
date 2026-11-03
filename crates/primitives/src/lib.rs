//! Selendra primitives: key types, signature schemes and account addresses
//! (native `sel1…` and Ethereum `0x…`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod address;
pub mod bech32;
pub mod crypto;
pub mod ethereum_address;
pub mod multi_address;
pub mod signing;

// `selendra-interface/native` adds `CryptoSpec::PrivateKey`, which this crate implements only with
// its own `native` feature. Cargo cannot make the first imply the second (the dependency points
// the other way), so say what to do instead of failing with a missing trait item.
#[cfg(not(feature = "native"))]
selendra_interface::__if_native! {
    compile_error!(
        "`selendra-interface/native` is enabled but `selendra-primitives/native` is not: enable both"
    );
}

pub use address::{ADDRESS_PREFIX, Address};
pub use ethereum_address::EthereumAddress;
pub use multi_address::{FromVmAddress, MultiAddress, MultiAddressEvm, Not28Bytes};

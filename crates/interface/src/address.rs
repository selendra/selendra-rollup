use borsh::{BorshDeserialize, BorshSerialize};
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// A marker trait for general addresses.
pub trait BasicAddress:
    Ord
    + core::fmt::Debug
    + core::fmt::Display
    + Send
    + Unpin
    + Sync
    + Clone
    + Copy
    + core::hash::Hash
    + AsRef<[u8]>
    + for<'a> TryFrom<&'a [u8], Error = anyhow::Error>
    + core::str::FromStr<
        Err: core::fmt::Debug
                 + core::fmt::Display
                 + Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    > + Serialize
    + DeserializeOwned
    + BorshDeserialize
    + BorshSerialize
    + MaybeArbitrary
    + JsonSchema
    + 'static
{
}

/// Implement the `arbitrary::Arbitrary` trait when the `arbitrary` feature is enabled.
#[cfg(feature = "arbitrary")]
pub trait MaybeArbitrary: for<'a> arbitrary::Arbitrary<'a> {}
#[cfg(feature = "arbitrary")]
impl<T: for<'a> arbitrary::Arbitrary<'a>> MaybeArbitrary for T {}

/// Implement the `arbitrary::Arbitrary` trait when the `arbitrary` feature is enabled.
#[cfg(not(feature = "arbitrary"))]
pub trait MaybeArbitrary {}
#[cfg(not(feature = "arbitrary"))]
impl<T> MaybeArbitrary for T {}

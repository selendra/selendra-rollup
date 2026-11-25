//! [`CallMessage`]: what a module's calls are.

use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::ConsensusType;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// What a module's call message ([`Module::CallMessage`](crate::Module::CallMessage)) is:
/// implemented for every type with these bounds.
///
/// A call message is signed and decoded in the zk guest, so it is a consensus type
/// ([`ConsensusType`]): no `usize`, `isize`, floats or hash collections at any depth (upstream
/// had no such bound; e.g. its EVM module's call message held a `usize`, which the 32-bit guest
/// fails to decode above `u32::MAX`, P5-44). Its JSON form (serde) is for clients and is never
/// decoded in the state transition.
///
/// A call message whose fields are not all consensus types is not a `CallMessage` (E0277; the
/// derived `ConsensusType` impl is bounded by the field types, so `Transfer<usize>` is not one):
///
/// ```compile_fail,E0277
/// use selendra_modules_api::*;
///
/// #[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
/// #[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema, ConsensusType)]
/// struct Transfer<T> {
///     amount: T,
/// }
///
/// fn call_message<C: CallMessage>() {}
/// call_message::<Transfer<usize>>();
/// ```
///
/// ```
/// use selendra_modules_api::*;
///
/// #[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
/// #[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema, ConsensusType)]
/// struct Transfer<T> {
///     amount: T,
/// }
///
/// fn call_message<C: CallMessage>() {}
/// call_message::<Transfer<u64>>();
/// ```
///
/// Upstream also required `UniversalWallet` (later, TODO "Later" item).
pub trait CallMessage:
    ConsensusType
    + BorshSerialize
    + BorshDeserialize
    + Serialize
    + DeserializeOwned
    + schemars::JsonSchema
    + Debug
    + Clone
    + PartialEq
    + Eq
    + Send
    + Sync
    + 'static
{
}

impl<T> CallMessage for T where
    T: ConsensusType
        + BorshSerialize
        + BorshDeserialize
        + Serialize
        + DeserializeOwned
        + schemars::JsonSchema
        + Debug
        + Clone
        + PartialEq
        + Eq
        + Send
        + Sync
        + 'static
{
}

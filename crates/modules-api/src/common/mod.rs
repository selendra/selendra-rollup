//! Types shared by modules: token amounts, 32-byte ids, errors, the module system's key and
//! signature bounds, and the sequencer kinds.

mod amount;
mod crypto;
mod error;
mod hash32_id;
mod module_id;
mod module_utils;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub use amount::{Amount, MAX_U128_DECIMAL_PLACES, ParseAmountError};
#[cfg(feature = "native")]
pub use crypto::PrivateKeyExt;
pub use crypto::{PublicKeyExt, SignatureExt};
pub use error::{
    CoreModuleError, ErrorContext, ErrorDetail, ErrorDetailError, ModuleError, to_json_object,
};
#[doc(hidden)]
pub use hash32_id::{__encode, __is_valid_prefix, __json_schema, __parse};
pub use hash32_id::{InvalidIdLength, MAX_HASH32_ID_PREFIX_LEN};
pub use module_id::ModuleId;
pub use module_utils::NotInstantiable;

/// The kind of sequencer that published a blob.
///
/// borsh: one tag byte, `0` = `Preferred`, `1` = `NonPreferred`. JSON: `"Preferred"` /
/// `"NonPreferred"`.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Copy,
    Clone,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
pub enum SequencerType {
    /// The preferred sequencer, whose batches are not deferred.
    Preferred,
    /// Any other sequencer: registered normally, or through an emergency registration.
    NonPreferred,
}

selendra_interface::impl_consensus_type!(SequencerType);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequencer_type_tags_are_pinned() {
        assert_eq!(borsh::to_vec(&SequencerType::Preferred).unwrap(), [0]);
        assert_eq!(borsh::to_vec(&SequencerType::NonPreferred).unwrap(), [1]);
        assert!(borsh::from_slice::<SequencerType>(&[2]).is_err());
        assert!(borsh::from_slice::<SequencerType>(&[0, 0]).is_err());
        assert_eq!(
            serde_json::to_string(&SequencerType::NonPreferred).unwrap(),
            "\"NonPreferred\""
        );
    }
}

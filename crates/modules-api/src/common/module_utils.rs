//! [`NotInstantiable`]: the call message (or event type) of a module that takes no calls (emits
//! no events).

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator};

use crate::ConsensusType;

/// A type with no values: the call message of a module that takes no calls, or the event type
/// of a module that emits none.
///
/// borsh decoding always fails (every byte string is rejected); there is nothing to encode.
/// Its JSON schema is `null` (an enum with no variants confuses schema tools).
#[derive(
    serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone, Copy, ConsensusType,
)]
pub enum NotInstantiable {}

impl borsh::BorshDeserialize for NotInstantiable {
    fn deserialize_reader<R: borsh::io::Read>(_reader: &mut R) -> borsh::io::Result<Self> {
        Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "NotInstantiable has no values",
        ))
    }
}

impl borsh::BorshSerialize for NotInstantiable {
    fn serialize<W: borsh::io::Write>(&self, _writer: &mut W) -> borsh::io::Result<()> {
        match *self {}
    }
}

impl JsonSchema for NotInstantiable {
    fn schema_name() -> Cow<'static, str> {
        "NotInstantiable".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({ "type": "null" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_decodes() {
        for bytes in [&[][..], &[0], &[1, 2, 3]] {
            assert!(borsh::from_slice::<NotInstantiable>(bytes).is_err());
            assert!(postcard::from_bytes::<NotInstantiable>(bytes).is_err());
        }
        assert!(serde_json::from_str::<NotInstantiable>("null").is_err());
        assert!(serde_json::from_str::<NotInstantiable>("\"A\"").is_err());
        let schema = serde_json::to_value(schemars::schema_for!(NotInstantiable)).unwrap();
        assert_eq!(schema["type"], "null");
    }
}

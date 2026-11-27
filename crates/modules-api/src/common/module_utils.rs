//! [`NotInstantiable`]: the call message (or event type) of a module that takes no calls (emits
//! no events).

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator};

use crate::ConsensusType;

/// A type with no values: the call message of a module that takes no calls, or the event type
/// of a module that emits none.
///
/// borsh decoding always fails (every byte string is rejected); there is nothing to encode.
/// Its JSON schema is `false`, which no value matches, inlined where used (so the schema of a
/// runtime's call type admits no call to a module without calls); as a root schema,
/// `{"not": {}}`. (An enum with no variants confuses schema tools; the schema was `null`,
/// which `null` matched, though no JSON decodes.)
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
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "NotInstantiable".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        Schema::from(false)
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
        assert_eq!(schema["not"], serde_json::json!({}));
        assert_eq!(schema.get("type"), None);
    }

    /// The schema admits no value, like decoding: inlined as `false` where used (it was
    /// `{"type": "null"}`, which `null` matched, though `null` never decodes).
    #[test]
    fn schema_admits_nothing() {
        let mut generator = SchemaGenerator::default();
        let schema = generator.subschema_for::<NotInstantiable>();
        assert_eq!(schema, Schema::from(false));
        assert_eq!(generator.definitions().len(), 0);
    }
}

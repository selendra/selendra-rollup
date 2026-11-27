//! What the runtime derives' code calls (through `__private`; not public API): the JSON (serde)
//! decoding and the JSON schema of a runtime's call and event types, keyed by module name, the
//! borsh error of an unknown module tag, and the strict serde decoding of a runtime's genesis
//! configuration. The generated code supplies the per-module parts ([`MessageEnum`],
//! [`GenesisConfigFields`]); the rest is written once, here.

use std::fmt;
use std::marker::PhantomData;

use schemars::{Schema, SchemaGenerator};
use serde::Deserialize;
use serde::de::{
    self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, Unexpected, Visitor,
};

/// A runtime's call or event type: one variant per module, each holding that module's message
/// (implemented by the runtime derives).
pub trait MessageEnum: Sized {
    /// The type's name (serde's enum name).
    const TYPE_NAME: &'static str;

    /// The `(DISCRIMINANT, NAME)` of each module, in the order of the runtime's fields.
    const MODULES: &'static [(u8, &'static str)];

    /// The modules' names, in the same order (serde's variant names).
    const NAMES: &'static [&'static str];

    /// Decodes the message of the module with `discriminant` (one of [`MODULES`](Self::MODULES))
    /// from `variant`.
    ///
    /// # Errors
    /// The message does not decode, or no module has `discriminant`.
    fn deserialize_variant<'de, A: de::VariantAccess<'de>>(
        discriminant: u8,
        variant: A,
    ) -> Result<Self, A::Error>;

    /// The schema of each module's message, with the module's name, in field order.
    fn variant_schemas(generator: &mut SchemaGenerator) -> Vec<(&'static str, Schema)>;
}

/// Decodes `M` externally tagged by module name (`{"bank": …}`); in binary serde formats, by
/// the module's discriminant (the variant index `M`'s `Serialize` writes).
///
/// # Errors
/// Not an object with exactly one key, a key that is not a module's name, or a message that
/// does not decode.
pub fn deserialize_message<'de, M: MessageEnum, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<M, D::Error> {
    deserializer.deserialize_enum(M::TYPE_NAME, M::NAMES, MessageVisitor::<M>(PhantomData))
}

struct MessageVisitor<M>(PhantomData<fn() -> M>);

impl<'de, M: MessageEnum> Visitor<'de> for MessageVisitor<M> {
    type Value = M;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a message of one of the modules of {}, keyed by the module's name",
            M::TYPE_NAME
        )
    }

    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<M, A::Error> {
        let (discriminant, variant) = data.variant_seed(ModuleTag::<M>(PhantomData))?;
        M::deserialize_variant(discriminant, variant)
    }
}

/// The variant tag: a module's name (JSON), or its discriminant (binary formats). Decodes to
/// the discriminant.
struct ModuleTag<M>(PhantomData<fn() -> M>);

impl<'de, M: MessageEnum> DeserializeSeed<'de> for ModuleTag<M> {
    type Value = u8;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<u8, D::Error> {
        deserializer.deserialize_identifier(self)
    }
}

impl<M: MessageEnum> Visitor<'_> for ModuleTag<M> {
    type Value = u8;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the name of one of the modules of {}", M::TYPE_NAME)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<u8, E> {
        M::MODULES
            .iter()
            .find(|&&(_, name)| name == value)
            .map(|&(discriminant, _)| discriminant)
            .ok_or_else(|| E::unknown_variant(value, M::NAMES))
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<u8, E> {
        match std::str::from_utf8(value) {
            Ok(value) => self.visit_str(value),
            Err(_) => Err(E::invalid_value(Unexpected::Bytes(value), &self)),
        }
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<u8, E> {
        M::MODULES
            .iter()
            .find(|&&(discriminant, _)| u64::from(discriminant) == value)
            .map(|&(discriminant, _)| discriminant)
            .ok_or_else(|| E::invalid_value(Unexpected::Unsigned(value), &self))
    }
}

/// The error of [`MessageEnum::deserialize_variant`] for a discriminant no module has (which
/// [`deserialize_message`] never passes).
pub fn no_module_with<E: de::Error>(discriminant: u8) -> E {
    E::custom(format_args!(
        "no module of the runtime has the discriminant {discriminant}"
    ))
}

/// The borsh error of a call or event whose tag is no module's discriminant.
pub fn unknown_module_tag(tag: u8) -> borsh::io::Error {
    borsh::io::Error::new(
        borsh::io::ErrorKind::InvalidData,
        format!("no module of the runtime has the discriminant {tag}"),
    )
}

/// The schema of `M`: one of an object per module, with exactly one property, the module's
/// name, holding its message. Inlined where used (the type is generic over the spec, and the
/// name would not tell the instances apart).
pub fn messages_schema<M: MessageEnum>(generator: &mut SchemaGenerator) -> Schema {
    let variants: Vec<serde_json::Value> = M::variant_schemas(generator)
        .into_iter()
        .map(|(name, schema)| {
            serde_json::json!({
                "type": "object",
                "properties": { name: schema },
                "required": [name],
                "additionalProperties": false,
            })
        })
        .collect();
    schemars::json_schema!({ "oneOf": variants })
}

/// A runtime's genesis configuration (`{Runtime}GenesisConfig`): a struct with one field per
/// module (implemented by the `Genesis` derive), decoded by [`deserialize_genesis_config`]. The
/// fields are numbered in order: `index` is always less than `FIELDS.len()`.
pub trait GenesisConfigFields<'de>: Sized {
    /// The type's name (serde's struct name).
    const TYPE_NAME: &'static str;

    /// The fields' names (each module's field in the runtime, without `r#`), in order.
    const FIELDS: &'static [&'static str];

    /// One slot per field, filled while decoding: `(Option<C0>, Option<C1>, …)`.
    type Slots;

    /// Every slot empty.
    fn empty_slots() -> Self::Slots;

    /// Decodes the value of the field `index` from `map` into its slot ([`fill_slot`]).
    ///
    /// # Errors
    /// The slot is already filled (a duplicate field), or the value does not decode.
    fn next_value<A: MapAccess<'de>>(
        slots: &mut Self::Slots,
        index: usize,
        map: &mut A,
    ) -> Result<(), A::Error>;

    /// Decodes the field `index` from the next element of `seq` into its slot
    /// ([`fill_element`]): `false` if `seq` has no more elements.
    ///
    /// # Errors
    /// The element does not decode.
    fn next_element<A: SeqAccess<'de>>(
        slots: &mut Self::Slots,
        index: usize,
        seq: &mut A,
    ) -> Result<bool, A::Error>;

    /// The configuration from the filled slots ([`take_slot`] each).
    ///
    /// # Errors
    /// A slot is empty (a missing field: the first, in order).
    fn from_slots<E: de::Error>(slots: Self::Slots) -> Result<Self, E>;
}

/// Decodes `C` strictly: in human-readable formats (JSON), an object with exactly `C`'s fields,
/// each once (an unknown, duplicate or missing field is an error, also for a field whose type
/// is an `Option`, which serde's derive reads as `None` when missing); in binary formats, the
/// fields in order.
///
/// # Errors
/// Not an object (in a human-readable format), an unknown, duplicate or missing field, or a
/// value that does not decode.
pub fn deserialize_genesis_config<'de, C: GenesisConfigFields<'de>, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<C, D::Error> {
    let human_readable = deserializer.is_human_readable();
    deserializer.deserialize_struct(
        C::TYPE_NAME,
        C::FIELDS,
        ConfigVisitor::<C> {
            human_readable,
            config: PhantomData,
        },
    )
}

struct ConfigVisitor<C> {
    human_readable: bool,
    config: PhantomData<fn() -> C>,
}

impl<'de, C: GenesisConfigFields<'de>> Visitor<'de> for ConfigVisitor<C> {
    type Value = C;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the genesis configuration {}: an object with the fields ",
            C::TYPE_NAME
        )?;
        for (i, field) in C::FIELDS.iter().enumerate() {
            let separator = if i == 0 { "" } else { ", " };
            write!(f, "{separator}`{field}`")?;
        }
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<C, A::Error> {
        let mut slots = C::empty_slots();
        while let Some(index) = map.next_key_seed(FieldIndex::<C>(PhantomData))? {
            C::next_value(&mut slots, index, &mut map)?;
        }
        C::from_slots(slots)
    }

    /// Binary formats only (in JSON, an array is not a genesis configuration).
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<C, A::Error> {
        if self.human_readable {
            return Err(de::Error::invalid_type(Unexpected::Seq, &self));
        }
        let mut slots = C::empty_slots();
        for index in 0..C::FIELDS.len() {
            if !C::next_element(&mut slots, index, &mut seq)? {
                return Err(de::Error::invalid_length(index, &self));
            }
        }
        C::from_slots(slots)
    }
}

/// A field's key: one of the names in `FIELDS` (never its index). Decodes to its index.
struct FieldIndex<C>(PhantomData<fn() -> C>);

impl<'de, C: GenesisConfigFields<'de>> DeserializeSeed<'de> for FieldIndex<C> {
    type Value = usize;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<usize, D::Error> {
        deserializer.deserialize_identifier(self)
    }
}

impl<'de, C: GenesisConfigFields<'de>> Visitor<'de> for FieldIndex<C> {
    type Value = usize;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a field of the genesis configuration {}", C::TYPE_NAME)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<usize, E> {
        C::FIELDS
            .iter()
            .position(|&field| field == value)
            .ok_or_else(|| E::unknown_field(value, C::FIELDS))
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<usize, E> {
        match std::str::from_utf8(value) {
            Ok(value) => self.visit_str(value),
            Err(_) => Err(E::invalid_value(Unexpected::Bytes(value), &self)),
        }
    }
}

/// Decodes the next value of `map` into `slot`, the slot of the field `field`.
///
/// # Errors
/// `slot` is already filled (a duplicate field), or the value does not decode.
pub fn fill_slot<'de, T: Deserialize<'de>, A: MapAccess<'de>>(
    slot: &mut Option<T>,
    field: &'static str,
    map: &mut A,
) -> Result<(), A::Error> {
    if slot.is_some() {
        return Err(de::Error::duplicate_field(field));
    }
    *slot = Some(map.next_value()?);
    Ok(())
}

/// Decodes the next element of `seq` into `slot`: `false` if there is none.
///
/// # Errors
/// The element does not decode.
pub fn fill_element<'de, T: Deserialize<'de>, A: SeqAccess<'de>>(
    slot: &mut Option<T>,
    seq: &mut A,
) -> Result<bool, A::Error> {
    *slot = seq.next_element()?;
    Ok(slot.is_some())
}

/// The value of the field `field`.
///
/// # Errors
/// `slot` is empty: the field is missing.
pub fn take_slot<T, E: de::Error>(slot: Option<T>, field: &'static str) -> Result<T, E> {
    slot.ok_or_else(|| E::missing_field(field))
}

/// The error of [`GenesisConfigFields::next_value`] and
/// [`next_element`](GenesisConfigFields::next_element) for an index with no field (which
/// [`deserialize_genesis_config`] never passes).
pub fn no_field_at<E: de::Error>(index: usize) -> E {
    E::custom(format_args!(
        "the genesis configuration has no field {index}"
    ))
}

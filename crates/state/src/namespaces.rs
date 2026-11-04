//! Defines namespaces that are used to partition the state of the rollup.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::Serialize;

/// The namespaces used in the rollup. Related to the db's namespaces.
///
/// borsh: one tag byte (`0` user, `1` kernel, `2` accessory). JSON: the snake_case variant name
/// as a string only (serde's derived enum decoding also accepts `{"user":null}`).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Namespace {
    /// The user namespace. Used by the User modules and is synchronized with the visible height.
    User,
    /// The kernel namespace. Used by the Kernel modules and is synchronized with the true height.
    Kernel,
    /// The accessory namespace. Values in this namespace are writeable but not readable inside
    /// the state transition function. They are used to provide auxiliary data via API.
    Accessory,
}

/// Namespaces which can be merkle proven.
///
/// Encoded like [`Namespace`]: borsh tag `0` user, `1` kernel; JSON a string only.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvableNamespace {
    /// The user namespace.
    User,
    /// The kernel namespace.
    Kernel,
}

/// Implements `Deserialize` for a fieldless enum: human-readable formats (JSON) accept only the
/// variant name as a string, so each value has one JSON encoding; binary formats keep serde's
/// derived encoding (the variant index), which the derived `Serialize` writes.
macro_rules! string_only_enum_deserialize {
    ($ty:ident { $($variant:ident => $name:literal),+ $(,)? }) => {
        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(rename_all = "snake_case")]
                enum Repr {
                    $($variant),+
                }

                const VARIANTS: &[&str] = &[$($name),+];
                if deserializer.is_human_readable() {
                    let name = <String as serde::Deserialize>::deserialize(deserializer)?;
                    match name.as_str() {
                        $($name => Ok(Self::$variant),)+
                        other => Err(serde::de::Error::unknown_variant(other, VARIANTS)),
                    }
                } else {
                    Ok(match <Repr as serde::Deserialize>::deserialize(deserializer)? {
                        $(Repr::$variant => Self::$variant,)+
                    })
                }
            }
        }
    };
}

string_only_enum_deserialize!(Namespace {
    User => "user",
    Kernel => "kernel",
    Accessory => "accessory",
});

string_only_enum_deserialize!(ProvableNamespace {
    User => "user",
    Kernel => "kernel",
});

/// Converts a type into a runtime namespace.
pub trait CompileTimeNamespace: core::fmt::Debug + Send + Sync + 'static {
    /// The runtime namespace variant associated with the type.
    const NAMESPACE: Namespace;
}

/// Converts a type into a Provable Namespace at compile time.
pub trait ProvableCompileTimeNamespace: CompileTimeNamespace {
    /// The runtime namespace variant associated with the type.
    const PROVABLE_NAMESPACE: ProvableNamespace;
}

/// A type-level representation of the user namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct User;

impl CompileTimeNamespace for User {
    const NAMESPACE: Namespace = Namespace::User;
}

impl ProvableCompileTimeNamespace for User {
    const PROVABLE_NAMESPACE: ProvableNamespace = ProvableNamespace::User;
}

/// A type-level representation of the kernel namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Kernel;

impl CompileTimeNamespace for Kernel {
    const NAMESPACE: Namespace = Namespace::Kernel;
}

impl ProvableCompileTimeNamespace for Kernel {
    const PROVABLE_NAMESPACE: ProvableNamespace = ProvableNamespace::Kernel;
}

/// A type-level representation of the accessory namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Accessory;

impl CompileTimeNamespace for Accessory {
    const NAMESPACE: Namespace = Namespace::Accessory;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borsh_tags_are_pinned() {
        assert_eq!(borsh::to_vec(&Namespace::User).unwrap(), [0]);
        assert_eq!(borsh::to_vec(&Namespace::Kernel).unwrap(), [1]);
        assert_eq!(borsh::to_vec(&Namespace::Accessory).unwrap(), [2]);
        assert_eq!(borsh::to_vec(&ProvableNamespace::User).unwrap(), [0]);
        assert_eq!(borsh::to_vec(&ProvableNamespace::Kernel).unwrap(), [1]);
        assert!(borsh::from_slice::<Namespace>(&[3]).is_err());
        assert!(borsh::from_slice::<ProvableNamespace>(&[2]).is_err());
        assert!(borsh::from_slice::<Namespace>(&[0, 0]).is_err());
    }

    #[test]
    fn json_is_the_variant_name_only() {
        for (ns, json) in [
            (Namespace::User, r#""user""#),
            (Namespace::Kernel, r#""kernel""#),
            (Namespace::Accessory, r#""accessory""#),
        ] {
            assert_eq!(serde_json::to_string(&ns).unwrap(), json);
            assert_eq!(serde_json::from_str::<Namespace>(json).unwrap(), ns);
        }
        assert_eq!(
            serde_json::from_str::<ProvableNamespace>(r#""kernel""#).unwrap(),
            ProvableNamespace::Kernel
        );
        // Serde's derived enum decoding would also accept these.
        assert!(serde_json::from_str::<Namespace>(r#"{"user":null}"#).is_err());
        assert!(serde_json::from_str::<ProvableNamespace>(r#"{"user":null}"#).is_err());
        assert!(serde_json::from_str::<Namespace>(r#""User""#).is_err());
        assert!(serde_json::from_str::<ProvableNamespace>(r#""accessory""#).is_err());
    }

    #[test]
    fn binary_serde_roundtrip() {
        for ns in [Namespace::User, Namespace::Kernel, Namespace::Accessory] {
            let bytes = postcard::to_allocvec(&ns).unwrap();
            assert_eq!(postcard::from_bytes::<Namespace>(&bytes).unwrap(), ns);
        }
        for ns in [ProvableNamespace::User, ProvableNamespace::Kernel] {
            let bytes = postcard::to_allocvec(&ns).unwrap();
            assert_eq!(
                postcard::from_bytes::<ProvableNamespace>(&bytes).unwrap(),
                ns
            );
        }
    }

    #[test]
    fn markers_map_to_their_namespace() {
        assert_eq!(User::NAMESPACE, Namespace::User);
        assert_eq!(Kernel::NAMESPACE, Namespace::Kernel);
        assert_eq!(Accessory::NAMESPACE, Namespace::Accessory);
        assert_eq!(User::PROVABLE_NAMESPACE, ProvableNamespace::User);
        assert_eq!(Kernel::PROVABLE_NAMESPACE, ProvableNamespace::Kernel);
    }
}

//! The derives' errors, with their exact messages, on `proc_macro2` input (`parse_quote!`).
//! What the derives generate is tested where it compiles against the real traits:
//! `selendra-modules-api`'s integration tests (`tests/derives/`) and doctests.
//!
//! The `ModuleInfo` cases include upstream's trybuild cases (`tests/integration/trybuild/
//! module_info/`): `field_missing_attribute`, `no_generics`, `not_supported_type`,
//! `derive_on_enum_not_supported`, `missing_address` (here `#[id]`) and
//! `second_addr_not_supported`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, parse_quote};

use crate::attrs::MAX_MODULE_NAME_LEN;
use crate::module_event::MAX_EVENT_NAME_LEN;
use crate::{consensus_type, module_event, module_info};

fn module_info_error(input: DeriveInput) -> String {
    match module_info::derive(&input) {
        Ok(tokens) => panic!("expected an error, got {tokens}"),
        Err(error) => error.to_string(),
    }
}

fn module_event_error(input: DeriveInput) -> String {
    match module_event::derive(&input) {
        Ok(tokens) => panic!("expected an error, got {tokens}"),
        Err(error) => error.to_string(),
    }
}

/// A module struct with `fields` besides a valid `#[module_info]` and an `#[id]` field.
fn module(fields: TokenStream) -> DeriveInput {
    parse_quote! {
        #[module_info(discriminant = 224, name = "test")]
        struct TestModule<S: Spec> {
            #[id]
            id: ModuleId,
            #fields
        }
    }
}

/// A module struct with the struct attributes `module_info` (none, one or several) and an
/// `#[id]` field.
fn module_with(module_info: TokenStream) -> DeriveInput {
    parse_quote! {
        #module_info
        struct TestModule<S: Spec> {
            #[id]
            id: ModuleId,
        }
    }
}

// -------------------------------------------------------------------------------------------
// `ModuleInfo`: the struct

#[test]
fn valid_module_is_accepted() {
    let input = module(quote! {
        /// A doc comment and other derives' attributes are left alone.
        #[allow(dead_code)]
        #[state(item = 0)]
        value: StateValue<u64>,
        #[state(item = 1, codec = CustomCodec::new)]
        map: StateMap<u8, u8, CustomCodec>,
        #[module]
        bank: Bank<S>,
        #[phantom]
        spec: PhantomData<S>,
    });
    assert!(module_info::derive(&input).is_ok());
}

/// Upstream trybuild `derive_on_enum_not_supported`.
#[test]
fn enum_is_rejected() {
    let input = parse_quote! {
        #[module_info(discriminant = 224, name = "test")]
        enum TestModule<S: Spec> {
            #[state]
            TestState1(StateMap<String, String>),
            #[state]
            TestState2(S),
        }
    };
    assert_eq!(
        module_info_error(input),
        "`ModuleInfo` can only be derived for a struct with named fields"
    );
}

#[test]
fn tuple_struct_and_union_are_rejected() {
    let tuple = parse_quote! {
        #[module_info(discriminant = 224, name = "test")]
        struct TestModule<S: Spec>(#[id] ModuleId, #[phantom] PhantomData<S>);
    };
    let union = parse_quote! {
        #[module_info(discriminant = 224, name = "test")]
        union TestModule<S: Spec> {
            id: ModuleId,
            spec: PhantomData<S>,
        }
    };
    for input in [tuple, union] {
        assert_eq!(
            module_info_error(input),
            "`ModuleInfo` can only be derived for a struct with named fields"
        );
    }
}

/// Upstream trybuild `no_generics`.
#[test]
fn non_generic_struct_is_rejected() {
    let input = parse_quote! {
        struct TestStruct {}
    };
    assert_eq!(
        module_info_error(input),
        "a module is generic over its spec: `struct Module<S: Spec>` (the first generic \
         parameter)"
    );
}

#[test]
fn first_generic_parameter_must_be_a_type() {
    let lifetime = parse_quote! {
        #[module_info(discriminant = 224, name = "test")]
        struct TestModule<'a, S: Spec> {
            #[id]
            id: ModuleId,
            #[phantom]
            spec: PhantomData<&'a S>,
        }
    };
    assert_eq!(
        module_info_error(lifetime),
        "the first generic parameter of a module must be its spec type (`S: Spec`), not a \
         lifetime"
    );
    let constant = parse_quote! {
        #[module_info(discriminant = 224, name = "test")]
        struct TestModule<const N: u8, S: Spec> {
            #[id]
            id: ModuleId,
            #[phantom]
            spec: PhantomData<S>,
        }
    };
    assert_eq!(
        module_info_error(constant),
        "the first generic parameter of a module must be its spec type (`S: Spec`), not a const \
         parameter"
    );
}

/// Later generic parameters are the module's business.
#[test]
fn more_generic_parameters_are_accepted() {
    let input = parse_quote! {
        #[module_info(discriminant = 224, name = "test")]
        struct TestModule<S: Spec, T: Clone, const N: usize> where T: Default {
            #[id]
            id: ModuleId,
            #[phantom]
            spec: PhantomData<(S, T, [u8; N])>,
        }
    };
    assert!(module_info::derive(&input).is_ok());
}

// -------------------------------------------------------------------------------------------
// `ModuleInfo`: `#[module_info(…)]`

#[test]
fn missing_module_info_is_rejected() {
    let input = module_with(quote!());
    assert_eq!(
        module_info_error(input),
        "missing `#[module_info(discriminant = N, name = \"…\")]`"
    );
}

#[test]
fn duplicate_module_info_is_rejected() {
    let input = module_with(quote! {
        #[module_info(discriminant = 224, name = "test")]
        #[module_info(discriminant = 225, name = "other")]
    });
    assert_eq!(
        module_info_error(input),
        "duplicate `#[module_info]` attribute"
    );
}

#[test]
fn module_info_without_arguments_is_rejected() {
    for attr in [quote!(#[module_info]), quote!(#[module_info = "test"])] {
        assert_eq!(
            module_info_error(module_with(attr)),
            "expected `#[module_info(discriminant = N, name = \"…\")]`"
        );
    }
}

#[test]
fn missing_discriminant_or_name_is_rejected() {
    assert_eq!(
        module_info_error(module_with(quote!(#[module_info(name = "test")]))),
        "`#[module_info]` is missing `discriminant = N`"
    );
    assert_eq!(
        module_info_error(module_with(quote!(#[module_info(discriminant = 224)]))),
        "`#[module_info]` is missing `name = \"…\"`"
    );
    assert_eq!(
        module_info_error(module_with(quote!(#[module_info()]))),
        "`#[module_info]` is missing `discriminant = N`"
    );
}

#[test]
fn duplicate_discriminant_or_name_is_rejected() {
    assert_eq!(
        module_info_error(module_with(quote! {
            #[module_info(discriminant = 224, discriminant = 225, name = "test")]
        })),
        "duplicate `discriminant` in `#[module_info]`"
    );
    assert_eq!(
        module_info_error(module_with(quote! {
            #[module_info(discriminant = 224, name = "test", name = "other")]
        })),
        "duplicate `name` in `#[module_info]`"
    );
}

#[test]
fn discriminant_zero_is_rejected() {
    let input = module_with(quote!(#[module_info(discriminant = 0, name = "test")]));
    assert_eq!(
        module_info_error(input),
        "discriminant 0 is reserved: use 1..=255"
    );
}

#[test]
fn discriminant_must_be_a_u8_literal() {
    for discriminant in [
        quote!(256),
        quote!(-1),
        quote!(BANK),
        quote!(1 + 2),
        quote!("1"),
        quote!(1u16),
    ] {
        let input = module_with(quote! {
            #[module_info(discriminant = #discriminant, name = "test")]
        });
        assert_eq!(
            module_info_error(input),
            "the discriminant must be an integer literal in 1..=255",
            "{discriminant}"
        );
    }
    for discriminant in [quote!(1), quote!(255), quote!(0x80), quote!(7u8)] {
        let input = module_with(quote! {
            #[module_info(discriminant = #discriminant, name = "test")]
        });
        assert!(module_info::derive(&input).is_ok(), "{discriminant}");
    }
}

#[test]
fn invalid_name_is_rejected() {
    let too_long = "a".repeat(MAX_MODULE_NAME_LEN + 1);
    for name in [
        "",
        "Bank",
        "bank-v2",
        "1bank",
        "_bank",
        "bank v2",
        "bänk",
        too_long.as_str(),
    ] {
        let input = module_with(quote!(#[module_info(discriminant = 224, name = #name)]));
        assert_eq!(
            module_info_error(input),
            format!(
                "invalid module name {name:?}: expected `^[a-z][a-z0-9_]{{0,31}}$` (a lowercase \
                 letter, then at most 31 lowercase letters, digits or `_`)"
            )
        );
    }
    let longest = "a".repeat(MAX_MODULE_NAME_LEN);
    for name in ["b", "bank", "bank_v2", "b_", "a0", longest.as_str()] {
        let input = module_with(quote!(#[module_info(discriminant = 224, name = #name)]));
        assert!(module_info::derive(&input).is_ok(), "{name}");
    }
}

#[test]
fn name_must_be_a_string_literal() {
    let input = module_with(quote!(#[module_info(discriminant = 224, name = bank)]));
    assert_eq!(
        module_info_error(input),
        "the name must be a string literal"
    );
}

// -------------------------------------------------------------------------------------------
// `ModuleInfo`: fields

/// Upstream trybuild `field_missing_attribute`.
#[test]
fn field_without_attribute_is_rejected() {
    let input = module(quote! {
        test_state1: StateMap<u32, u32>,
        #[state(item = 0)]
        test_state2: StateMap<Vec<u8>, u64>,
    });
    assert_eq!(
        module_info_error(input),
        "field `test_state1` needs one of `#[id]`, `#[state(item = N)]`, `#[module]` or \
         `#[phantom]`"
    );
    // Foreign attributes do not count.
    let input = module(quote! {
        /// Documented.
        #[allow(dead_code)]
        #[serde(skip)]
        test_state1: StateMap<u32, u32>,
    });
    assert_eq!(
        module_info_error(input),
        "field `test_state1` needs one of `#[id]`, `#[state(item = N)]`, `#[module]` or \
         `#[phantom]`"
    );
}

#[test]
fn field_with_two_attributes_is_rejected() {
    let input = module(quote! {
        #[state(item = 0)]
        #[module]
        bank: Bank<S>,
    });
    assert_eq!(
        module_info_error(input),
        "field `bank` has more than one of `#[id]`, `#[state]`, `#[module]` and `#[phantom]`"
    );
}

/// Upstream trybuild `missing_address`.
#[test]
fn missing_id_is_rejected() {
    let input = parse_quote! {
        #[module_info(discriminant = 224, name = "test")]
        struct TestModule<S: Spec> {
            #[state(item = 0)]
            test_state1: StateMap<u32, u32>,
            #[phantom]
            spec: PhantomData<S>,
        }
    };
    assert_eq!(
        module_info_error(input),
        "a module needs an `#[id]` field (its `ModuleId`)"
    );
    let unit = parse_quote! {
        #[module_info(discriminant = 224, name = "test")]
        struct TestModule<S: Spec>;
    };
    assert_eq!(
        module_info_error(unit),
        "a module needs an `#[id]` field (its `ModuleId`)"
    );
}

/// Upstream trybuild `second_addr_not_supported`.
#[test]
fn duplicate_id_is_rejected() {
    let input = module(quote! {
        #[id]
        id_2: ModuleId,
    });
    assert_eq!(
        module_info_error(input),
        "only one field can be `#[id]` (`id` already is)"
    );
}

#[test]
fn arguments_to_flag_attributes_are_rejected() {
    for (attr, name) in [
        (quote!(#[id(x)]), "id"),
        (quote!(#[module = 1]), "module"),
        (quote!(#[phantom()]), "phantom"),
    ] {
        let input = parse_quote! {
            #[module_info(discriminant = 224, name = "test")]
            struct TestModule<S: Spec> {
                #attr
                field: PhantomData<S>,
            }
        };
        assert_eq!(
            module_info_error(input),
            format!("`#[{name}]` takes no arguments")
        );
    }
}

#[test]
fn state_without_item_is_rejected() {
    for attr in [
        quote!(#[state]),
        quote!(#[state()]),
        quote!(#[state = 0]),
        quote!(#[state(codec = CustomCodec::new)]),
    ] {
        let input = module(quote! {
            #attr
            value: StateValue<u64>,
        });
        assert_eq!(
            module_info_error(input),
            "`#[state]` needs an item id: `#[state(item = N)]`, N in 0..=255",
            "{attr}"
        );
    }
}

#[test]
fn item_id_must_be_a_u8_literal() {
    for item in [
        quote!(256),
        quote!(-1),
        quote!(ITEM),
        quote!("0"),
        quote!(0u32),
    ] {
        let input = module(quote! {
            #[state(item = #item)]
            value: StateValue<u64>,
        });
        assert_eq!(
            module_info_error(input),
            "the item id must be an integer literal in 0..=255",
            "{item}"
        );
    }
}

#[test]
fn duplicate_state_keys_are_rejected() {
    let input = module(quote! {
        #[state(item = 0, item = 1)]
        value: StateValue<u64>,
    });
    assert_eq!(module_info_error(input), "duplicate `item` in `#[state]`");
    let input = module(quote! {
        #[state(item = 0, codec = A::new, codec = B::new)]
        value: StateValue<u64>,
    });
    assert_eq!(module_info_error(input), "duplicate `codec` in `#[state]`");
}

#[test]
fn duplicate_item_id_is_rejected() {
    let input = module(quote! {
        #[state(item = 3)]
        first: StateValue<u64>,
        #[state(item = 4)]
        second: StateValue<u64>,
        #[state(item = 3)]
        third: StateValue<u64>,
    });
    assert_eq!(
        module_info_error(input),
        "item id 3 is already used by field `first`"
    );
}

/// Upstream trybuild `not_supported_type`.
#[test]
fn non_path_state_type_is_rejected() {
    for ty in [quote!([usize; 22]), quote!((u8, u8)), quote!(&'static u8)] {
        let input = module(quote! {
            #[state(item = 0)]
            test_state1: #ty,
        });
        assert_eq!(
            module_info_error(input),
            "a `#[state]` field must be a state container type (e.g. `StateValue<V>`, \
             `StateMap<K, V>`, `StateVec<V>`)",
            "{ty}"
        );
    }
    let input = module(quote! {
        #[state(item = 0)]
        parenthesized: (StateValue<u8>),
        #[state(item = 1)]
        aliased: crate::state::Balances<S>,
    });
    assert!(module_info::derive(&input).is_ok());
}

// -------------------------------------------------------------------------------------------
// `ModuleEvent`

#[test]
fn module_event_on_struct_or_union_is_rejected() {
    let structure = parse_quote! {
        struct Transfer { amount: u128 }
    };
    let union = parse_quote! {
        union Transfer { amount: u128 }
    };
    for input in [structure, union] {
        assert_eq!(
            module_event_error(input),
            "`ModuleEvent` can only be derived for an enum (each variant is an event)"
        );
    }
}

/// A derived event key `"{NAME}/{event}"` must fit `MAX_EVENT_KEY_LEN` with any module name:
/// 223 bytes pass, 224 are a compile error (otherwise the call emitting it would be reverted).
#[test]
fn event_name_longer_than_the_bound_is_rejected() {
    assert_eq!(MAX_MODULE_NAME_LEN + 1 + MAX_EVENT_NAME_LEN, 256);
    let longest = format_ident!("E{}", "v".repeat(MAX_EVENT_NAME_LEN - 1));
    let input = parse_quote! {
        enum Event {
            Short,
            #longest { amount: u128 },
        }
    };
    assert!(module_event::derive(&input).is_ok());

    let name = format!("E{}", "v".repeat(MAX_EVENT_NAME_LEN));
    let too_long = format_ident!("{name}");
    let input = parse_quote! {
        enum Event {
            Short,
            #too_long(u128),
        }
    };
    assert_eq!(
        module_event_error(input),
        format!(
            "the event name `{name}` is 224 bytes, more than 223: its key \
             `\"{{module name}}/{name}\"` could exceed MAX_EVENT_KEY_LEN (256 bytes; module \
             names are at most 32)"
        )
    );
}

#[test]
fn module_event_accepts_every_variant_kind() {
    let input = parse_quote! {
        enum Event<S: Spec> {
            Named { to: S::Address },
            Unnamed(u128, u8),
            Unit,
            r#type,
        }
    };
    assert!(module_event::derive(&input).is_ok());
    let empty = parse_quote! {
        enum NoEvents {}
    };
    assert!(module_event::derive(&empty).is_ok());
}

// -------------------------------------------------------------------------------------------
// `ConsensusType`

#[test]
fn consensus_type_on_union_is_rejected() {
    let input = parse_quote! {
        union Bits { a: u32, b: f32 }
    };
    match consensus_type::derive(&input) {
        Ok(tokens) => panic!("expected an error, got {tokens}"),
        Err(error) => assert_eq!(
            error.to_string(),
            "`ConsensusType` cannot be derived for a union"
        ),
    }
}

#[test]
fn consensus_type_accepts_structs_and_enums() {
    let inputs: [DeriveInput; 5] = [
        parse_quote!(
            struct Unit;
        ),
        parse_quote!(
            struct Tuple(u8, Vec<u8>);
        ),
        parse_quote!(
            struct Named<T>
            where
                T: Clone,
            {
                value: T,
                next: Option<Box<Self>>,
            }
        ),
        parse_quote!(
            enum Empty {}
        ),
        parse_quote!(
            enum Tree<T> {
                Leaf(T),
                Node(Vec<Tree<T>>),
            }
        ),
    ];
    for input in inputs {
        assert!(consensus_type::derive(&input).is_ok());
    }
}

/// A recursive field is checked next to the impl, not bounded (the trait solver would loop),
/// and the parameters it mentions are bounded by their own identifiers (a raw one included).
#[test]
fn consensus_type_bounds_the_parameters_of_recursive_fields() {
    let input = parse_quote! {
        struct Pairs<r#type> {
            items: Vec<(Self, r#type)>,
        }
    };
    let tokens = match consensus_type::derive(&input) {
        Ok(tokens) => tokens.to_string(),
        Err(error) => panic!("{error}"),
    };
    assert!(
        tokens.contains("r#type : :: selendra_modules_api :: __private :: ConsensusType"),
        "{tokens}"
    );
    assert!(!tokens.contains("Vec < (Self , r#type) > :"), "{tokens}");
    assert!(
        tokens.contains("Vec < (Pairs < r#type > , r#type) > > ()"),
        "{tokens}"
    );
}

// -------------------------------------------------------------------------------------------
// Regressions of upstream's module macro bugs

/// P5-28: upstream numbered state fields by position and refused more than 128 (another check
/// said 255): item ids are explicit and cover the whole byte, so a module can have 256 state
/// items, ids 0 to 255.
#[test]
fn item_ids_cover_full_u8() {
    let fields = (0..=u8::MAX).map(|item| {
        let field = format_ident!("item_{item}");
        quote! {
            #[state(item = #item)]
            #field: StateValue<u64>,
        }
    });
    let input = module(quote!(#(#fields)*));
    assert!(module_info::derive(&input).is_ok());
}

/// P5-29: upstream built identifiers from field names with `Ident::new`, which panics on a raw
/// identifier (`r#type`); the derive builds no identifier from a field name, and names fields
/// without the `r#`.
#[test]
fn raw_identifier_field_is_supported() {
    let input = module(quote! {
        #[state(item = 0)]
        r#type: StateValue<u64>,
        #[module]
        r#mod: Bank<S>,
    });
    let tokens = match module_info::derive(&input) {
        Ok(tokens) => tokens.to_string(),
        Err(error) => panic!("{error}"),
    };
    assert!(
        tokens.contains("StateItem :: new (0 , \"type\")"),
        "{tokens}"
    );
    let input = module(quote! {
        r#type: StateValue<u64>,
    });
    assert_eq!(
        module_info_error(input),
        "field `type` needs one of `#[id]`, `#[state(item = N)]`, `#[module]` or `#[phantom]`"
    );
}

/// P5-30: upstream accepted `#[kernel_module]` on a field and then hit `unreachable!`, and
/// kept a dead `#[gas]` path: unknown attributes and keys are errors spanned at the input,
/// never a panic.
#[test]
fn unknown_attribute_is_spanned_error() {
    for attr in [quote!(#[kernel_module]), quote!(#[gas])] {
        let input = module(quote! {
            #attr
            kernel: Kernel<S>,
        });
        assert_eq!(
            module_info_error(input),
            "field `kernel` needs one of `#[id]`, `#[state(item = N)]`, `#[module]` or \
             `#[phantom]`"
        );
    }
    let input = module(quote! {
        #[state(item = 0, kernel)]
        value: StateValue<u64>,
    });
    assert_eq!(
        module_info_error(input),
        "unknown key `kernel` in `#[state]`: expected `item` or `codec`"
    );
    let input = module(quote! {
        #[state(item = 0, codec_builder = "CustomCodec::new")]
        value: StateValue<u64>,
    });
    assert_eq!(
        module_info_error(input),
        "unknown key `codec_builder` in `#[state]`: expected `item` or `codec`"
    );
    let input = module_with(quote! {
        #[module_info(discriminant = 224, name = "test", sequencer_safety = "f")]
    });
    assert_eq!(
        module_info_error(input),
        "unknown key `sequencer_safety` in `#[module_info]`: expected `discriminant` or `name`"
    );
}

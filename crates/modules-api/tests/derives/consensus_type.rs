//! `#[derive(ConsensusType)]`: structs and enums of consensus types are consensus types,
//! through aliases, nested user types, generic parameters (bounded by the field types) and
//! recursion; derived types are stored with the borsh codec. (Rejections: the `compile_fail`
//! doctests of the derive.)

// The types below are checked by the type system only: their fields are never read.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_modules_api::test_utils::TestSpec;
use selendra_modules_api::*;
use selendra_state::{BorshCodec, Prefix, StateValue};

use crate::working_set;

fn consensus<T: ConsensusType + ?Sized>() {}

type Balance = u128;

/// An alias, collections, arrays.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, ConsensusType)]
pub struct Account {
    balance: Balance,
    tags: BTreeMap<u8, String>,
    owners: BTreeSet<[u8; 32]>,
    note: Option<String>,
}

#[derive(ConsensusType)]
pub struct Wrapper<T>(T);

#[derive(ConsensusType)]
pub struct Unit;

/// Nested user types, every variant kind.
#[derive(ConsensusType)]
pub enum Shape<T> {
    Account(Account),
    Nested { inner: Wrapper<Account>, value: T },
    Tuple(Balance, Vec<Wrapper<T>>),
    Nothing,
}

#[derive(ConsensusType)]
pub enum Empty {}

/// A `PhantomData` field bounds nothing: `Marker<T>` is a consensus type for every `T`.
#[derive(ConsensusType)]
pub struct Marker<T> {
    marker: PhantomData<T>,
}

/// Recursive through its own name, through `Self`, and generic.
#[derive(ConsensusType)]
pub struct List {
    value: u64,
    next: Option<Box<List>>,
}

#[derive(ConsensusType)]
pub struct SelfList {
    value: u64,
    next: Option<Box<Self>>,
}

#[derive(ConsensusType)]
pub enum Tree<T> {
    Leaf(T),
    Node(Vec<Tree<T>>),
}

/// The only field holding `T` is recursive: `T` is still bounded.
#[derive(ConsensusType)]
pub struct Pairs<T> {
    items: Vec<(Pairs<T>, T)>,
}

/// A spec's associated types, the module system's types.
#[derive(ConsensusType)]
pub struct Payment<S: Spec> {
    to: S::Address,
    amount: Amount,
    gas: S::Gas,
    module: ModuleId,
}

/// Bounds and `where` clauses of the type are kept; lifetimes and const parameters.
#[derive(ConsensusType)]
pub struct Bounded<'a, T: Clone, U, const N: usize>
where
    U: Default,
{
    value: T,
    other: U,
    bytes: [u8; N],
    lifetime: PhantomData<&'a ()>,
}

#[test]
fn derived_types_are_consensus_types() {
    consensus::<Account>();
    consensus::<Wrapper<u64>>();
    consensus::<Wrapper<Account>>();
    consensus::<Wrapper<Wrapper<Option<Account>>>>();
    consensus::<Unit>();
    consensus::<Shape<String>>();
    consensus::<Empty>();
    consensus::<Marker<f64>>();
    consensus::<Marker<usize>>();
    consensus::<List>();
    consensus::<SelfList>();
    consensus::<Tree<u32>>();
    consensus::<Pairs<u64>>();
    consensus::<Payment<TestSpec>>();
    consensus::<Bounded<'static, u8, u16, 4>>();
}

/// Generic code: the derived impl holds exactly when the field types are consensus types.
#[test]
fn generic_parameters_are_bounded_by_the_field_types() {
    fn wrapped<T: ConsensusType>() {
        consensus::<Wrapper<T>>();
        consensus::<Shape<T>>();
        consensus::<Tree<T>>();
        consensus::<Pairs<T>>();
    }
    fn any_marker<T>() {
        consensus::<Marker<T>>();
    }
    fn payment<S: Spec>() {
        consensus::<Payment<S>>();
    }
    wrapped::<u8>();
    any_marker::<f32>();
    payment::<TestSpec>();
}

/// The borsh codec stores consensus types only: a derived type is one.
#[test]
fn derived_type_is_a_state_value() {
    let mut item = StateValue::<Account>::with_codec(Prefix::new(252, 0), BorshCodec);
    let account = Account {
        balance: 7,
        tags: BTreeMap::from([(1, "one".to_owned())]),
        owners: BTreeSet::from([[2; 32]]),
        note: None,
    };
    let mut state = working_set::<TestSpec>(1_000_000);
    item.set(&account, &mut state).unwrap();
    assert_eq!(item.get(&mut state).unwrap(), Some(account));
}

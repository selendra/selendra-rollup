//! Container tests against the in-memory accessor.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use proptest::prelude::any;
use selendra_interface::common::HexString;

use super::*;
use crate::test_state::{InMemoryState, UnwrapInfallible};
use crate::{
    Accessory, BorshCodec, InfallibleStateReaderAndWriter, Kernel, Prefix, SlotKey, SlotValue,
    StateReader, StateWriter, User,
};

fn keys(map: &BTreeMap<SlotKey, SlotValue>) -> Vec<Vec<u8>> {
    map.keys().map(|k| k.as_ref().to_vec()).collect()
}

// ---------------------------------------------------------------------------------------------
// Key layout (pinned: changing any of these changes the state root of every chain).

#[test]
fn state_value_key_is_the_prefix() {
    let mut state = InMemoryState::default();
    let mut value = StateValue::<u32>::with_codec(Prefix::new(1, 2), BorshCodec);
    value.set(&7, &mut state).unwrap_infallible();
    assert_eq!(keys(&state.user), [vec![1, 2]]);
    assert_eq!(state.user.values().next().unwrap().value(), [7, 0, 0, 0]);
    assert_eq!(value.slot_key().as_ref(), [1, 2]);
}

#[test]
fn state_map_key_is_prefix_then_borsh_key() {
    let mut state = InMemoryState::default();
    let mut map = StateMap::<u64, u32>::with_codec(Prefix::new(1, 2), BorshCodec);
    map.set(&5, &9, &mut state).unwrap_infallible();
    assert_eq!(keys(&state.user), [vec![1, 2, 5, 0, 0, 0, 0, 0, 0, 0]]);
    assert_eq!(state.user.values().next().unwrap().value(), [9, 0, 0, 0]);

    let mut map = StateMap::<String, u8>::with_codec(Prefix::new(3, 4), BorshCodec);
    map.set(&"ab".to_string(), &1, &mut state)
        .unwrap_infallible();
    assert!(
        state
            .user
            .contains_key(&SlotKey::try_from_bytes(&[3, 4, 2, 0, 0, 0, b'a', b'b']).unwrap())
    );
}

#[test]
fn state_vec_key_layout() {
    let mut state = InMemoryState::default();
    let mut vec = StateVec::<u32>::with_codec(Prefix::new(1, 2), BorshCodec);
    vec.push(&10, &mut state).unwrap_infallible();
    vec.push(&11, &mut state).unwrap_infallible();
    assert_eq!(
        keys(&state.user),
        [
            vec![1, 2],
            vec![1, 2, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![1, 2, 1, 0, 0, 0, 0, 0, 0, 0],
        ]
    );
    let get = |key: &[u8]| state.user[&SlotKey::try_from_bytes(key).unwrap()].clone();
    assert_eq!(get(&[1, 2]).value(), 2u64.to_le_bytes());
    assert_eq!(get(&[1, 2, 1, 0, 0, 0, 0, 0, 0, 0]).value(), [11, 0, 0, 0]);
}

/// Upstream stored elements under item `item + 128`, which panicked for `item >= 128` and
/// collided with item `item + 128` of the same module.
#[test]
fn state_vec_works_with_any_item_and_does_not_touch_other_items() {
    let mut state = InMemoryState::default();
    let mut vec = StateVec::<u32>::with_codec(Prefix::new(1, 255), BorshCodec);
    let mut low = StateVec::<u32>::with_codec(Prefix::new(1, 0), BorshCodec);
    let mut high = StateValue::<u32>::with_codec(Prefix::new(1, 128), BorshCodec);
    vec.push(&1, &mut state).unwrap_infallible();
    low.push(&2, &mut state).unwrap_infallible();
    high.set(&3, &mut state).unwrap_infallible();
    assert_eq!(vec.collect_infallible::<Vec<_>, _>(&mut state), [1]);
    assert_eq!(low.collect_infallible::<Vec<_>, _>(&mut state), [2]);
    assert_eq!(high.get(&mut state).unwrap_infallible(), Some(3));
    assert!(
        state
            .user
            .keys()
            .all(|k| matches!(k.prefix().item(), 0 | 128 | 255))
    );
}

// ---------------------------------------------------------------------------------------------
// StateValue

#[test]
fn state_value_get_set_remove_delete() {
    let mut state = InMemoryState::default();
    let mut value = StateValue::<u64>::with_codec(Prefix::new(0, 1), BorshCodec);

    assert_eq!(value.get(&mut state).unwrap_infallible(), None);
    assert!(matches!(
        value.get_or_err(&mut state).unwrap_infallible(),
        Err(StateValueError::MissingValue(p, _)) if p == Prefix::new(0, 1)
    ));
    assert_eq!(value.remove(&mut state).unwrap_infallible(), None);
    assert!(value.remove_or_err(&mut state).unwrap_infallible().is_err());

    value.set(&5, &mut state).unwrap_infallible();
    assert_eq!(value.get(&mut state).unwrap_infallible(), Some(5));
    assert_eq!(value.get_or_err(&mut state).unwrap_infallible().unwrap(), 5);
    assert_eq!(value.remove(&mut state).unwrap_infallible(), Some(5));
    assert!(state.user.is_empty());

    value.set(&6, &mut state).unwrap_infallible();
    assert_eq!(
        value.remove_or_err(&mut state).unwrap_infallible().unwrap(),
        6
    );
    value.set(&7, &mut state).unwrap_infallible();
    value.delete(&mut state).unwrap_infallible();
    assert_eq!(value.get(&mut state).unwrap_infallible(), None);
    assert!(state.user.is_empty());

    assert_eq!(
        value.decode_unwrap(&SlotValue::from(8u64.to_le_bytes().to_vec())),
        8
    );
    assert_eq!(value.prefix(), &Prefix::new(0, 1));
    assert_eq!(value.codec(), &BorshCodec);
}

#[test]
fn state_value_set_encode_like() {
    let mut state = InMemoryState::default();
    let mut value = StateValue::<Vec<u8>>::with_codec(Prefix::new(0, 1), BorshCodec);
    // A slice is stored exactly like the `Vec` it stands for.
    value.set(&[1u8, 2, 3][..], &mut state).unwrap_infallible();
    assert_eq!(
        value.get(&mut state).unwrap_infallible(),
        Some(vec![1, 2, 3])
    );
}

#[test]
fn state_value_borrow() {
    let mut state = InMemoryState::default();
    let mut value = StateValue::<String>::with_codec(Prefix::new(0, 1), BorshCodec);
    assert!(value.borrow(&mut state).unwrap_infallible().is_none());
    value.set(&"hi".to_string(), &mut state).unwrap_infallible();
    let borrowed = value.borrow(&mut state).unwrap_infallible();
    assert_eq!(format!("{borrowed:?}"), "Some(\"hi\")");
    let borrowed = borrowed.unwrap();
    assert_eq!(&*borrowed, "hi");
    assert_eq!(borrowed.to_string(), "hi");

    let missing = StateValue::<String>::with_codec(Prefix::new(0, 2), BorshCodec);
    let b = missing.borrow(&mut state).unwrap_infallible();
    assert_eq!(&*b.unwrap_or("default".into()), "default");
    let b = missing.borrow(&mut state).unwrap_infallible();
    assert_eq!(b.ok_or("absent").unwrap_err(), "absent");
    let b = missing.borrow(&mut state).unwrap_infallible();
    assert_eq!(b.ok_or_else(|| 3).unwrap_err(), 3);
}

#[test]
fn state_value_borrow_mut_save_discard_delete() {
    let mut state = InMemoryState::default();
    let mut value = StateValue::<u64>::with_codec(Prefix::new(0, 1), BorshCodec);
    value.set(&1, &mut state).unwrap_infallible();

    // save writes the change back
    let mut b = value.borrow_mut(&mut state).unwrap_infallible().unwrap();
    *b += 10;
    assert_eq!(*b, 11);
    b.save(&mut state).unwrap_infallible();
    assert_eq!(value.get(&mut state).unwrap_infallible(), Some(11));

    // discard leaves state unchanged
    let mut b = value.borrow_mut(&mut state).unwrap_infallible().unwrap();
    *b = 100;
    b.discard();
    assert_eq!(value.get(&mut state).unwrap_infallible(), Some(11));

    // dropping a borrow that was only read is fine
    {
        let b = value
            .borrow_mut(&mut state)
            .unwrap_infallible()
            .expect("set");
        assert_eq!(*b, 11);
    }
    assert_eq!(value.get(&mut state).unwrap_infallible(), Some(11));

    // delete removes the value
    let b = value.borrow_mut(&mut state).unwrap_infallible();
    assert_eq!(format!("{b:?}"), "Some(11)");
    b.unwrap().delete(&mut state).unwrap_infallible();
    assert_eq!(value.get(&mut state).unwrap_infallible(), None);

    // an absent value can be created through `unwrap_or` + save
    let mut b = value
        .borrow_mut(&mut state)
        .unwrap_infallible()
        .unwrap_or(5);
    *b *= 2;
    b.save(&mut state).unwrap_infallible();
    assert_eq!(value.get(&mut state).unwrap_infallible(), Some(10));

    // an Option can be saved too (Some writes it)
    let mut b = value.borrow_mut(&mut state).unwrap_infallible();
    assert!(b.is_some());
    *b = Some(3);
    b.unwrap().save(&mut state).unwrap_infallible();
    assert_eq!(value.get(&mut state).unwrap_infallible(), Some(3));

    let missing = StateValue::<u64>::with_codec(Prefix::new(0, 9), BorshCodec);
    let mut missing2 = missing.clone();
    assert!(
        missing2
            .borrow_mut(&mut state)
            .unwrap_infallible()
            .ok_or("absent")
            .is_err()
    );
    assert!(
        missing2
            .borrow_mut(&mut state)
            .unwrap_infallible()
            .ok_or_else(|| "absent")
            .is_err()
    );
}

/// Binding a `BorrowedMut`, modifying it and dropping it loses the write; `#[must_use]` doesn't
/// catch this (the borrow is bound), so debug builds panic. Release builds discard the change.
#[test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "a `BorrowedMut` was modified and then dropped")
)]
fn borrowed_mut_dropped_after_a_change() {
    let mut state = InMemoryState::default();
    let mut map = StateMap::<u64, u64>::with_codec(Prefix::new(0, 1), BorshCodec);
    map.set(&1, &1, &mut state).unwrap_infallible();
    let credit = |map: &mut StateMap<u64, u64>, state: &mut InMemoryState, early: bool| {
        let mut balance = map.borrow_mut(&1, state).unwrap_infallible().unwrap_or(0);
        *balance += 10;
        if early {
            return; // forgot to save: the credit is lost
        }
        balance.save(state).unwrap_infallible();
    };
    credit(&mut map, &mut state, false);
    assert_eq!(map.get(&1, &mut state).unwrap_infallible(), Some(11));
    credit(&mut map, &mut state, true);
    assert_eq!(map.get(&1, &mut state).unwrap_infallible(), Some(11));
}

/// The guard follows the value through `unwrap`/`ok_or`, and is checked when an `ok_or` on a
/// value the caller set to `None` drops the borrow.
#[test]
fn borrowed_mut_guard_moves_through_unwrap() {
    let mut state = InMemoryState::default();
    let mut value = StateValue::<u64>::with_codec(Prefix::new(0, 2), BorshCodec);
    // untouched borrow of a missing value: `ok_or` returns the error without a panic
    assert!(
        value
            .borrow_mut(&mut state)
            .unwrap_infallible()
            .ok_or("absent")
            .is_err()
    );
    // modified as an Option, then unwrapped and saved
    let mut b = value.borrow_mut(&mut state).unwrap_infallible();
    *b = Some(4);
    b.ok_or("absent")
        .unwrap()
        .save(&mut state)
        .unwrap_infallible();
    assert_eq!(value.get(&mut state).unwrap_infallible(), Some(4));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut b = value.borrow_mut(&mut state).unwrap_infallible();
        *b = None;
        let _ = b.ok_or("absent");
    }));
    assert_eq!(result.is_err(), cfg!(debug_assertions));
}

/// A value whose decoder is stricter than its encoder can be written but never read back (every
/// read would panic). Debug builds catch it at the write.
#[derive(Debug, borsh::BorshSerialize)]
struct BoundedBytes(Vec<u8>);

impl borsh::BorshDeserialize for BoundedBytes {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes = Vec::<u8>::deserialize_reader(reader)?;
        if bytes.len() > 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "too long",
            ));
        }
        Ok(Self(bytes))
    }
}

#[test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "does not decode from its own encoding")
)]
fn storing_a_value_that_does_not_round_trip_is_caught_in_debug() {
    let mut state = InMemoryState::default();
    let mut value = StateValue::<BoundedBytes>::with_codec(Prefix::new(0, 3), BorshCodec);
    value
        .set(&BoundedBytes(vec![1, 2, 3, 4]), &mut state)
        .unwrap_infallible();
    value
        .set(&BoundedBytes(vec![0; 5]), &mut state)
        .unwrap_infallible();
    // release builds only: the write succeeds, and every read of the key would panic
    assert_eq!(state.user.len(), 1);
}

/// A container only reads bytes its own codec wrote; two containers sharing a prefix (a bug) is
/// the one way to break that, and decoding then panics (documented on `get_decoded`).
#[test]
#[should_panic(expected = "Failed to decode u64 value 0x0100000068")]
fn decode_failure_panics() {
    let mut state = InMemoryState::default();
    let mut string = StateValue::<String>::with_codec(Prefix::new(0, 1), BorshCodec);
    let number = StateValue::<u64>::with_codec(Prefix::new(0, 1), BorshCodec);
    string.set(&"h".to_string(), &mut state).unwrap_infallible();
    let _ = number.get(&mut state);
}

// ---------------------------------------------------------------------------------------------
// StateMap

#[test]
fn state_map_operations() {
    let mut state = InMemoryState::default();
    let mut map = StateMap::<u64, String>::with_codec(Prefix::new(2, 0), BorshCodec);

    assert_eq!(map.get(&1, &mut state).unwrap_infallible(), None);
    match map.get_or_err(&1, &mut state).unwrap_infallible() {
        Err(StateMapError::MissingValue(prefix, key, _)) => {
            assert_eq!(prefix, Prefix::new(2, 0));
            assert_eq!(key, map.slot_key(&1u64));
        }
        Ok(v) => panic!("unexpected {v}"),
    }

    map.set(&1, &"one".to_string(), &mut state)
        .unwrap_infallible();
    map.set(&2, &"two".to_string(), &mut state)
        .unwrap_infallible();
    assert_eq!(
        map.get(&1, &mut state).unwrap_infallible().as_deref(),
        Some("one")
    );
    assert_eq!(
        map.get_or_err(&2, &mut state).unwrap_infallible().unwrap(),
        "two"
    );

    map.set_if_absent(&1, &"uno".to_string(), &mut state)
        .unwrap_infallible();
    map.set_if_absent(&3, &"three".to_string(), &mut state)
        .unwrap_infallible();
    assert_eq!(
        map.get(&1, &mut state).unwrap_infallible().as_deref(),
        Some("one")
    );
    assert_eq!(
        map.get(&3, &mut state).unwrap_infallible().as_deref(),
        Some("three")
    );

    assert_eq!(
        map.remove(&1, &mut state).unwrap_infallible().as_deref(),
        Some("one")
    );
    assert_eq!(map.remove(&1, &mut state).unwrap_infallible(), None);
    assert_eq!(
        map.remove_or_err(&2, &mut state)
            .unwrap_infallible()
            .unwrap(),
        "two"
    );
    assert!(
        map.remove_or_err(&2, &mut state)
            .unwrap_infallible()
            .is_err()
    );
    map.delete(&3, &mut state).unwrap_infallible();
    map.delete(&4, &mut state).unwrap_infallible();
    assert!(state.user.is_empty());
}

#[test]
fn state_map_borrow_and_borrow_mut() {
    let mut state = InMemoryState::default();
    let mut map = StateMap::<u64, u64>::with_codec(Prefix::new(2, 0), BorshCodec);
    map.set(&1, &10, &mut state).unwrap_infallible();
    assert_eq!(*map.borrow(&1, &mut state).unwrap_infallible().unwrap(), 10);
    assert!(map.borrow(&2, &mut state).unwrap_infallible().is_none());

    let mut b = map.borrow_mut(&1, &mut state).unwrap_infallible().unwrap();
    *b += 1;
    b.save(&mut state).unwrap_infallible();
    assert_eq!(map.get(&1, &mut state).unwrap_infallible(), Some(11));

    let mut b = map.borrow_mut(&1, &mut state).unwrap_infallible().unwrap();
    *b += 1;
    b.discard();
    assert_eq!(map.get(&1, &mut state).unwrap_infallible(), Some(11));

    let b = map
        .borrow_mut(&2, &mut state)
        .unwrap_infallible()
        .unwrap_or(0);
    b.save(&mut state).unwrap_infallible();
    assert_eq!(map.get(&2, &mut state).unwrap_infallible(), Some(0));

    map.borrow_mut(&1, &mut state)
        .unwrap_infallible()
        .unwrap()
        .delete(&mut state)
        .unwrap_infallible();
    assert_eq!(map.get(&1, &mut state).unwrap_infallible(), None);
}

#[test]
fn state_map_encode_like_keys() {
    let mut state = InMemoryState::default();
    let mut map = StateMap::<HexString, u64>::with_codec(Prefix::new(2, 1), BorshCodec);
    map.set(&HexString(vec![1, 2]), &5, &mut state)
        .unwrap_infallible();
    // A byte slice is encoded like a `HexString`.
    let key: [u8; 2] = [1, 2];
    assert_eq!(
        map.get(key.as_slice(), &mut state).unwrap_infallible(),
        Some(5)
    );
    assert_eq!(
        map.slot_key(key.as_slice()),
        map.slot_key(&HexString(vec![1, 2]))
    );

    let mut map = StateMap::<u64, Vec<u32>>::with_codec(Prefix::new(2, 2), BorshCodec);
    map.set(&0, &[1u32, 2][..], &mut state).unwrap_infallible();
    assert_eq!(
        map.get(&0, &mut state).unwrap_infallible(),
        Some(vec![1, 2])
    );
}

// ---------------------------------------------------------------------------------------------
// Namespaces

#[test]
fn namespaces_are_isolated() {
    let mut state = InMemoryState::default();
    let prefix = Prefix::new(5, 5);
    let mut user = StateValue::<u32>::with_codec(prefix, BorshCodec);
    let mut kernel = KernelStateValue::<u32>::with_codec(prefix, BorshCodec);
    let mut accessory = AccessoryStateValue::<u32>::with_codec(prefix, BorshCodec);

    user.set(&1, &mut state).unwrap_infallible();
    kernel.set(&2, &mut state).unwrap_infallible();
    accessory.set(&3, &mut state).unwrap_infallible();
    assert_eq!(user.get(&mut state).unwrap_infallible(), Some(1));
    assert_eq!(kernel.get(&mut state).unwrap_infallible(), Some(2));
    assert_eq!(accessory.get(&mut state).unwrap_infallible(), Some(3));

    let mut user_map = StateMap::<u8, u8>::with_codec(prefix, BorshCodec);
    let mut kernel_map = KernelStateMap::<u8, u8>::with_codec(prefix, BorshCodec);
    let mut accessory_map = AccessoryStateMap::<u8, u8>::with_codec(prefix, BorshCodec);
    user_map.set(&0, &10, &mut state).unwrap_infallible();
    kernel_map.set(&0, &20, &mut state).unwrap_infallible();
    accessory_map.set(&0, &30, &mut state).unwrap_infallible();

    let mut user_vec = StateVec::<u8>::with_codec(Prefix::new(6, 6), BorshCodec);
    let mut kernel_vec = KernelStateVec::<u8>::with_codec(Prefix::new(6, 6), BorshCodec);
    let mut accessory_vec = AccessoryStateVec::<u8>::with_codec(Prefix::new(6, 6), BorshCodec);
    user_vec.push(&1, &mut state).unwrap_infallible();
    kernel_vec
        .set_all(vec![2, 2], &mut state)
        .unwrap_infallible();
    accessory_vec
        .set_all(vec![3, 3, 3], &mut state)
        .unwrap_infallible();

    user.delete(&mut state).unwrap_infallible();
    user_map.delete(&0, &mut state).unwrap_infallible();
    user_vec.clear(&mut state).unwrap_infallible();
    assert!(state.user.is_empty());
    assert_eq!(kernel.get(&mut state).unwrap_infallible(), Some(2));
    assert_eq!(accessory.get(&mut state).unwrap_infallible(), Some(3));
    assert_eq!(kernel_map.get(&0, &mut state).unwrap_infallible(), Some(20));
    assert_eq!(
        accessory_map.get(&0, &mut state).unwrap_infallible(),
        Some(30)
    );
    assert_eq!(
        kernel_vec.collect_infallible::<Vec<_>, _>(&mut state),
        [2, 2]
    );
    assert_eq!(
        accessory_vec.collect_infallible::<Vec<_>, _>(&mut state),
        [3, 3, 3]
    );
    assert_eq!(state.kernel.len(), 1 + 1 + 3);
    assert_eq!(state.accessory.len(), 1 + 1 + 4);
}

/// Helper traits work through the blanket impls, and the namespaces of one accessor are separate
/// key spaces at runtime. (That a reader for one namespace can't be used for another, and that a
/// write-only accessor can't read, is checked by the `compile_fail` doctests in `accessors.rs`.)
#[test]
fn accessory_and_infallible_helper_traits() {
    fn bump<A: crate::AccessoryStateReaderAndWriter>(
        value: &mut AccessoryStateValue<u8>,
        a: &mut A,
    ) {
        let Ok(current) = value.get(a);
        let Ok(()) = value.set(&current.unwrap_or(0).wrapping_add(1), a);
    }
    fn read_kernel<A: InfallibleStateReaderAndWriter<Kernel>>(
        value: &KernelStateValue<u8>,
        a: &mut A,
    ) -> Option<u8> {
        let Ok(v) = value.get(a);
        v
    }
    let mut state = InMemoryState::default();
    let mut value = AccessoryStateValue::<u8>::with_codec(Prefix::new(1, 1), BorshCodec);
    bump(&mut value, &mut state);
    bump(&mut value, &mut state);
    assert_eq!(value.get(&mut state).unwrap_infallible(), Some(2));
    let kernel = KernelStateValue::<u8>::with_codec(Prefix::new(1, 1), BorshCodec);
    assert_eq!(read_kernel(&kernel, &mut state), None);
    assert_eq!(
        StateReader::<Accessory>::get(&mut state, &value.slot_key()).unwrap_infallible(),
        Some(SlotValue::from(vec![2]))
    );
    assert_eq!(
        StateReader::<User>::get(&mut state, &value.slot_key()).unwrap_infallible(),
        None
    );
}

/// An accessor that can write the accessory namespace but not read it, like the Phase 5
/// transaction accessor.
#[derive(Default)]
struct WriteOnlyAccessory {
    inner: InMemoryState,
}

impl StateWriter<Accessory> for WriteOnlyAccessory {
    type Error = std::convert::Infallible;

    fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Self::Error> {
        StateWriter::<Accessory>::set(&mut self.inner, key, value)
    }

    fn delete(&mut self, key: &SlotKey) -> Result<(), Self::Error> {
        StateWriter::<Accessory>::delete(&mut self.inner, key)
    }
}

/// Writing accessory state needs only a `StateWriter<Accessory>` (pins the method bounds: a
/// refactor requiring a reader too would break the Phase 5 write-only transaction accessor).
#[test]
fn accessory_writes_need_only_a_writer() {
    let mut state = WriteOnlyAccessory::default();
    let mut value = AccessoryStateValue::<u8>::with_codec(Prefix::new(1, 1), BorshCodec);
    let mut map = AccessoryStateMap::<u8, u8>::with_codec(Prefix::new(1, 2), BorshCodec);
    value.set(&7, &mut state).unwrap_infallible();
    map.set(&1, &2, &mut state).unwrap_infallible();
    map.set(&3, &4, &mut state).unwrap_infallible();
    assert_eq!(state.inner.accessory.len(), 3);
    value.delete(&mut state).unwrap_infallible();
    map.delete(&1, &mut state).unwrap_infallible();
    assert_eq!(keys(&state.inner.accessory), [vec![1, 2, 3]]);
    assert!(state.inner.user.is_empty() && state.inner.kernel.is_empty());
}

// ---------------------------------------------------------------------------------------------
// StateVec (upstream tests)

#[test]
fn double_ended_iterator_from_back() {
    let mut state = InMemoryState::default();
    let mut state_vec = StateVec::<u32>::with_codec(Prefix::new(0, 0), BorshCodec);

    state_vec.push(&0, &mut state).unwrap_infallible();
    state_vec.push(&1, &mut state).unwrap_infallible();

    let mut iter = state_vec.iter(&mut state).unwrap_infallible();
    assert_eq!(iter.next_back(), Some(Ok(1)));
    assert_eq!(iter.next_back(), Some(Ok(0)));
    // Everything was consumed by next_back
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next_back(), None);
}

#[test]
fn double_ended_iterator_meet_in_the_middle() {
    let mut state = InMemoryState::default();
    let mut state_vec = StateVec::<u32>::with_codec(Prefix::new(1, 1), BorshCodec);

    state_vec.push(&0, &mut state).unwrap_infallible();
    state_vec.push(&1, &mut state).unwrap_infallible();
    state_vec.push(&2, &mut state).unwrap_infallible();

    let mut iter = state_vec.iter(&mut state).unwrap_infallible();
    assert_eq!(iter.next(), Some(Ok(0)));
    assert_eq!(iter.next_back(), Some(Ok(2)));
    assert_eq!(iter.next(), Some(Ok(1)));
    // Everything was consumed
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next_back(), None);
}

#[test]
fn test_state_vec() {
    let mut state = InMemoryState::default();
    let mut state_vec = StateVec::<u32>::with_codec(Prefix::new(2, 2), BorshCodec);

    for test_case_action in test_cases() {
        check_test_case_action(&mut state_vec, test_case_action, &mut state);
    }
}

#[test]
fn test_kernel_and_accessory_state_vec() {
    let mut state = InMemoryState::default();
    let mut kernel_vec = KernelStateVec::<u32>::with_codec(Prefix::new(2, 2), BorshCodec);
    let mut accessory_vec = AccessoryStateVec::<u32>::with_codec(Prefix::new(2, 2), BorshCodec);
    for test_case_action in test_cases() {
        check_test_case_action(&mut kernel_vec, test_case_action, &mut state);
    }
    for test_case_action in test_cases() {
        check_test_case_action(&mut accessory_vec, test_case_action, &mut state);
    }
    assert!(state.user.is_empty());
}

enum TestCaseAction<T> {
    Push(T),
    Pop(T),
    Remove(u64, T),
    Last(T),
    Set(u64, T),
    SetAll(Vec<T>),
    CheckLen(u64),
    CheckContents(Vec<T>),
    CheckContentsReverse(Vec<T>),
    CheckGet(u64, Option<T>),
    Clear,
}

fn test_cases() -> Vec<TestCaseAction<u32>> {
    vec![
        TestCaseAction::Push(1),
        TestCaseAction::Push(2),
        TestCaseAction::CheckContents(vec![1, 2]),
        TestCaseAction::CheckLen(2),
        TestCaseAction::Pop(2),
        TestCaseAction::Set(0, 10),
        TestCaseAction::CheckContents(vec![10]),
        TestCaseAction::Push(8),
        TestCaseAction::CheckContents(vec![10, 8]),
        TestCaseAction::SetAll(vec![10]),
        TestCaseAction::CheckContents(vec![10]),
        TestCaseAction::CheckGet(1, None),
        TestCaseAction::Set(0, u32::MAX),
        TestCaseAction::Push(8),
        TestCaseAction::Push(0),
        TestCaseAction::CheckContents(vec![u32::MAX, 8, 0]),
        TestCaseAction::SetAll(vec![11, 12]),
        TestCaseAction::CheckContents(vec![11, 12]),
        TestCaseAction::SetAll(vec![]),
        TestCaseAction::CheckLen(0),
        TestCaseAction::Push(42),
        TestCaseAction::Push(1337),
        TestCaseAction::Clear,
        TestCaseAction::CheckContents(vec![]),
        TestCaseAction::CheckGet(0, None),
        TestCaseAction::SetAll(vec![1, 2, 3]),
        TestCaseAction::CheckContents(vec![1, 2, 3]),
        TestCaseAction::CheckContentsReverse(vec![3, 2, 1]),
        TestCaseAction::Last(3),
        TestCaseAction::Remove(0, 1),
        TestCaseAction::CheckContents(vec![2, 3]),
    ]
}

fn check_test_case_action<N, T, W>(
    state_vec: &mut NamespacedStateVec<N, T>,
    action: TestCaseAction<T>,
    state: &mut W,
) where
    BorshCodec: StateItemCodec<T>,
    T: Eq + Debug,
    W: InfallibleStateReaderAndWriter<N>,
    N: CompileTimeNamespace,
{
    match action {
        TestCaseAction::CheckContents(expected) => {
            let contents: Vec<T> = state_vec.collect_infallible(state);
            assert_eq!(expected, contents);
        }
        TestCaseAction::CheckLen(expected) => {
            let actual = state_vec.len(state).unwrap_infallible();
            assert_eq!(actual, expected);
        }
        TestCaseAction::Pop(expected) => {
            let actual = state_vec.pop(state).unwrap_infallible();
            assert_eq!(actual, Some(expected));
        }
        TestCaseAction::Push(value) => {
            state_vec.push(&value, state).unwrap_infallible();
        }
        TestCaseAction::Set(index, value) => {
            state_vec
                .set(index, &value, state)
                .unwrap_infallible()
                .unwrap();
        }
        TestCaseAction::SetAll(values) => {
            state_vec.set_all(values, state).unwrap_infallible();
        }
        TestCaseAction::CheckGet(index, expected) => {
            let actual = state_vec.get(index, state).unwrap_infallible();
            assert_eq!(actual, expected);
        }
        TestCaseAction::Clear => {
            state_vec.clear(state).unwrap_infallible();
        }
        TestCaseAction::Last(expected) => {
            let actual = state_vec.last(state).unwrap_infallible();
            assert_eq!(actual, Some(expected));
        }
        TestCaseAction::CheckContentsReverse(expected) => {
            let contents: Vec<T> = state_vec
                .iter(state)
                .unwrap_infallible()
                .rev()
                .map(UnwrapInfallible::unwrap_infallible)
                .collect();
            assert_eq!(expected, contents);
        }
        TestCaseAction::Remove(index, expected) => {
            let actual = state_vec.remove(index, state).unwrap_infallible();
            assert_eq!(actual, Some(expected));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// StateVec (new tests)

#[test]
fn state_vec_bounds_and_errors() {
    let mut state = InMemoryState::default();
    let mut vec = StateVec::<u32>::with_codec(Prefix::new(3, 3), BorshCodec);
    assert_eq!(vec.pop(&mut state).unwrap_infallible(), None);
    assert_eq!(vec.last(&mut state).unwrap_infallible(), None);
    assert_eq!(vec.remove(0, &mut state).unwrap_infallible(), None);
    assert!(matches!(
        vec.set(0, &1, &mut state).unwrap_infallible(),
        Err(StateVecError::IndexOutOfBounds(0))
    ));
    assert!(matches!(
        vec.get_or_err(0, &mut state).unwrap_infallible(),
        Err(StateVecError::IndexOutOfBounds(0))
    ));
    vec.push(&5, &mut state).unwrap_infallible();
    assert_eq!(
        vec.get_or_err(0, &mut state).unwrap_infallible().unwrap(),
        5
    );
    assert_eq!(vec.remove(1, &mut state).unwrap_infallible(), None);
    assert_eq!(vec.remove(u64::MAX, &mut state).unwrap_infallible(), None);
    assert_eq!(vec.get(u64::MAX, &mut state).unwrap_infallible(), None);
    assert_eq!(vec.len(&mut state).unwrap_infallible(), 1);

    // A missing element below `len` (only possible if state is corrupt) is reported, not
    // panicked on, and ends iteration.
    state.user.remove(&SlotKey::from_parts(
        &Prefix::new(3, 3),
        &0u64.to_le_bytes(),
    ));
    assert!(matches!(
        vec.get_or_err(0, &mut state).unwrap_infallible(),
        Err(StateVecError::MissingValue(_, 0, _))
    ));
    let mut iter = vec.iter(&mut state).unwrap_infallible();
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next_back(), None);
}

#[test]
fn state_vec_iter_size_hint() {
    let mut state = InMemoryState::default();
    let mut vec = StateVec::<u32>::with_codec(Prefix::new(3, 3), BorshCodec);
    vec.set_all(vec![1, 2, 3], &mut state).unwrap_infallible();
    let mut iter = vec.iter(&mut state).unwrap_infallible();
    assert_eq!(iter.size_hint(), (0, Some(3)));
    iter.next();
    iter.next_back();
    assert_eq!(iter.size_hint(), (0, Some(1)));
    iter.next();
    assert_eq!(iter.size_hint(), (0, Some(0)));
}

/// A reader that fails after a number of reads, like an accessor running out of gas.
struct FailingReader {
    inner: InMemoryState,
    reads_left: u32,
}

#[derive(Debug, thiserror::Error, PartialEq)]
#[error("out of gas")]
struct OutOfGas;

impl StateReader<User> for FailingReader {
    type Error = OutOfGas;

    fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error> {
        self.reads_left = self.reads_left.checked_sub(1).ok_or(OutOfGas)?;
        Ok(StateReader::<User>::get(&mut self.inner, key).unwrap_infallible())
    }
}

#[test]
fn state_vec_iter_ends_after_an_error() {
    let mut inner = InMemoryState::default();
    let mut vec = StateVec::<u32>::with_codec(Prefix::new(3, 3), BorshCodec);
    vec.set_all(vec![1, 2, 3], &mut inner).unwrap_infallible();
    // One read for the length, one for the first element, then out of gas.
    let mut state = FailingReader {
        inner,
        reads_left: 2,
    };
    let mut iter = vec.iter(&mut state).unwrap();
    assert_eq!(iter.next(), Some(Ok(1)));
    assert_eq!(iter.next(), Some(Err(OutOfGas)));
    // Upstream retried the same index forever (an endless stream of errors).
    assert_eq!(iter.next(), None);
    assert_eq!(iter.next_back(), None);
    assert_eq!(iter.size_hint(), (0, Some(0)));

    let mut state = FailingReader {
        inner: state.inner,
        reads_left: 0,
    };
    assert_eq!(vec.len(&mut state), Err(OutOfGas));
    assert!(vec.iter(&mut state).is_err());
}

/// An accessor whose writes fail after a number of writes (out of gas); reads never fail.
struct FailingWriter {
    inner: InMemoryState,
    writes_left: u32,
}

impl StateReader<User> for FailingWriter {
    type Error = OutOfGas;

    fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error> {
        Ok(StateReader::<User>::get(&mut self.inner, key).unwrap_infallible())
    }
}

impl StateWriter<User> for FailingWriter {
    type Error = OutOfGas;

    fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), Self::Error> {
        self.writes_left = self.writes_left.checked_sub(1).ok_or(OutOfGas)?;
        StateWriter::<User>::set(&mut self.inner, key, value).unwrap_infallible();
        Ok(())
    }

    fn delete(&mut self, key: &SlotKey) -> Result<(), Self::Error> {
        self.writes_left = self.writes_left.checked_sub(1).ok_or(OutOfGas)?;
        StateWriter::<User>::delete(&mut self.inner, key).unwrap_infallible();
        Ok(())
    }
}

/// A vec operation that runs out of gas partway may leave elements past `len` and partly
/// updated contents, but every element in `0..len` stays present and nothing past `len` can be
/// read. Upstream (and this port before the fix) could leave holes inside `0..len` (`pop`,
/// `clear`, `set_all`) and `get` returned elements past `len` (`push`, `set_all`).
#[test]
fn state_vec_keeps_its_invariant_when_a_write_fails() {
    type Op = fn(&mut StateVec<u32>, &mut FailingWriter) -> Result<(), OutOfGas>;
    let ops: [(&str, Op); 9] = [
        ("push", |v, s| v.push(&9, s)),
        ("pop", |v, s| v.pop(s).map(drop)),
        ("remove(0)", |v, s| v.remove(0, s).map(drop)),
        ("remove(2)", |v, s| v.remove(2, s).map(drop)),
        ("clear", |v, s| v.clear(s)),
        ("set_all(shorter)", |v, s| v.set_all(vec![7, 8], s)),
        ("set_all(longer)", |v, s| {
            v.set_all(vec![5, 6, 7, 8, 9, 10], s)
        }),
        ("set_all(empty)", |v, s| v.set_all(Vec::<u32>::new(), s)),
        ("set(1)", |v, s| v.set(1, &9, s).map(drop)),
    ];
    let prefix = Prefix::new(4, 4);
    for (name, op) in ops {
        for writes in 0..12 {
            let mut vec = StateVec::<u32>::with_codec(prefix, BorshCodec);
            let mut inner = InMemoryState::default();
            vec.set_all(vec![1, 2, 3, 4], &mut inner)
                .unwrap_infallible();
            let mut state = FailingWriter {
                inner,
                writes_left: writes,
            };
            let failed = op(&mut vec, &mut state).is_err();

            let mut state = state.inner;
            let len = vec.len(&mut state).unwrap_infallible();
            for i in 0..len {
                assert!(
                    vec.get_or_err(i, &mut state).unwrap_infallible().is_ok(),
                    "{name} with {writes} writes (failed: {failed}): hole at {i} (len {len})"
                );
            }
            for i in len..len + 8 {
                assert_eq!(
                    vec.get(i, &mut state).unwrap_infallible(),
                    None,
                    "{name} with {writes} writes: element {i} readable past len {len}"
                );
            }
            let all: Vec<u32> = vec.collect_infallible(&mut state);
            assert_eq!(all.len() as u64, len, "{name} with {writes} writes");
            if !failed {
                assert_vec_storage(&state, prefix, all.len());
            }
            // The vector stays usable: popping everything empties it.
            for _ in 0..len {
                assert!(vec.pop(&mut state).unwrap_infallible().is_some());
            }
            assert_eq!(vec.len(&mut state).unwrap_infallible(), 0);
        }
    }
}

/// `get` checks the length: an element left past `len` (e.g. by a `push` whose length write
/// failed) is not returned.
#[test]
fn state_vec_get_ignores_elements_past_len() {
    let prefix = Prefix::new(4, 5);
    let mut vec = StateVec::<u32>::with_codec(prefix, BorshCodec);
    let mut state = FailingWriter {
        inner: InMemoryState::default(),
        writes_left: 1,
    };
    assert_eq!(vec.push(&1, &mut state), Err(OutOfGas));
    let mut state = state.inner;
    assert_eq!(
        state.user.len(),
        1,
        "the element was written, the length not"
    );
    assert_eq!(vec.len(&mut state).unwrap_infallible(), 0);
    assert_eq!(vec.get(0, &mut state).unwrap_infallible(), None);
    assert_eq!(vec.last(&mut state).unwrap_infallible(), None);
    assert!(vec.iter(&mut state).unwrap_infallible().next().is_none());
    // A later push overwrites the leftover.
    vec.push(&2, &mut state).unwrap_infallible();
    assert_eq!(vec.collect_infallible::<Vec<_>, _>(&mut state), [2]);
    assert_vec_storage(&state, prefix, 1);
}

// ---------------------------------------------------------------------------------------------
// Model tests

/// Asserts that the user namespace holds exactly the vector's length key (unless absent) and the
/// element keys `0..len` under `prefix`: no stale elements.
fn assert_vec_storage(state: &InMemoryState, prefix: Prefix, len: usize) {
    let stored: BTreeSet<SlotKey> = state
        .user
        .keys()
        .filter(|k| k.len() > Prefix::LENGTH)
        .cloned()
        .collect();
    let expected: BTreeSet<SlotKey> = (0..len as u64)
        .map(|i| SlotKey::from_parts(&prefix, &i.to_le_bytes()))
        .collect();
    assert_eq!(stored, expected);
    assert!(state.user.keys().all(|k| k.prefix() == prefix));
}

#[derive(Debug, Clone, test_strategy::Arbitrary)]
enum VecOp {
    Push(u32),
    Pop,
    Set(#[strategy(0u64..10)] u64, u32),
    Remove(#[strategy(0u64..10)] u64),
    Get(#[strategy(0u64..10)] u64),
    GetOrErr(#[strategy(0u64..10)] u64),
    Last,
    Clear,
    SetAll(#[strategy(proptest::collection::vec(any::<u32>(), 0..8))] Vec<u32>),
}

#[test_strategy::proptest]
fn state_vec_matches_std_vec(
    #[strategy(proptest::collection::vec(any::<VecOp>(), 0..64))] ops: Vec<VecOp>,
) {
    let prefix = Prefix::new(7, 200);
    let mut state = InMemoryState::default();
    let mut vec = StateVec::<u32>::with_codec(prefix, BorshCodec);
    let mut model: Vec<u32> = Vec::new();

    for op in ops {
        match op {
            VecOp::Push(v) => {
                vec.push(&v, &mut state).unwrap_infallible();
                model.push(v);
            }
            VecOp::Pop => assert_eq!(vec.pop(&mut state).unwrap_infallible(), model.pop()),
            VecOp::Set(i, v) => {
                let result = vec.set(i, &v, &mut state).unwrap_infallible();
                match model.get_mut(i as usize) {
                    Some(slot) => {
                        assert!(result.is_ok());
                        *slot = v;
                    }
                    None => {
                        assert!(
                            matches!(result, Err(StateVecError::IndexOutOfBounds(j)) if j == i)
                        );
                    }
                }
            }
            VecOp::Remove(i) => {
                let expected = ((i as usize) < model.len()).then(|| model.remove(i as usize));
                assert_eq!(vec.remove(i, &mut state).unwrap_infallible(), expected);
            }
            VecOp::Get(i) => assert_eq!(
                vec.get(i, &mut state).unwrap_infallible(),
                model.get(i as usize).copied()
            ),
            VecOp::GetOrErr(i) => match vec.get_or_err(i, &mut state).unwrap_infallible() {
                Ok(v) => assert_eq!(Some(&v), model.get(i as usize)),
                Err(e) => {
                    assert!(matches!(e, StateVecError::IndexOutOfBounds(j) if j == i));
                    assert!(i as usize >= model.len());
                }
            },
            VecOp::Last => assert_eq!(
                vec.last(&mut state).unwrap_infallible(),
                model.last().copied()
            ),
            VecOp::Clear => {
                vec.clear(&mut state).unwrap_infallible();
                model.clear();
                assert!(state.user.is_empty());
            }
            VecOp::SetAll(values) => {
                vec.set_all(values.clone(), &mut state).unwrap_infallible();
                model = values;
            }
        }
        assert_eq!(vec.len(&mut state).unwrap_infallible(), model.len() as u64);
        assert_eq!(vec.collect_infallible::<Vec<_>, _>(&mut state), model);
        let reversed: Vec<u32> = vec
            .iter(&mut state)
            .unwrap_infallible()
            .rev()
            .map(UnwrapInfallible::unwrap_infallible)
            .collect();
        assert_eq!(reversed, model.iter().rev().copied().collect::<Vec<_>>());
        assert_vec_storage(&state, prefix, model.len());
    }
}

#[derive(Debug, Clone, test_strategy::Arbitrary)]
enum MapOp {
    Set(#[strategy(0u8..8)] u8, u32),
    SetIfAbsent(#[strategy(0u8..8)] u8, u32),
    Get(#[strategy(0u8..8)] u8),
    GetOrErr(#[strategy(0u8..8)] u8),
    Remove(#[strategy(0u8..8)] u8),
    RemoveOrErr(#[strategy(0u8..8)] u8),
    Delete(#[strategy(0u8..8)] u8),
    BorrowMutAdd(#[strategy(0u8..8)] u8, u32),
}

#[test_strategy::proptest]
fn state_map_matches_btree_map(
    #[strategy(proptest::collection::vec(any::<MapOp>(), 0..64))] ops: Vec<MapOp>,
) {
    let prefix = Prefix::new(9, 9);
    let mut state = InMemoryState::default();
    let mut map = StateMap::<u8, u32>::with_codec(prefix, BorshCodec);
    let mut model: BTreeMap<u8, u32> = BTreeMap::new();

    for op in ops {
        match op {
            MapOp::Set(k, v) => {
                map.set(&k, &v, &mut state).unwrap_infallible();
                model.insert(k, v);
            }
            MapOp::SetIfAbsent(k, v) => {
                map.set_if_absent(&k, &v, &mut state).unwrap_infallible();
                model.entry(k).or_insert(v);
            }
            MapOp::Get(k) => assert_eq!(
                map.get(&k, &mut state).unwrap_infallible(),
                model.get(&k).copied()
            ),
            MapOp::GetOrErr(k) => assert_eq!(
                map.get_or_err(&k, &mut state).unwrap_infallible().ok(),
                model.get(&k).copied()
            ),
            MapOp::Remove(k) => assert_eq!(
                map.remove(&k, &mut state).unwrap_infallible(),
                model.remove(&k)
            ),
            MapOp::RemoveOrErr(k) => assert_eq!(
                map.remove_or_err(&k, &mut state).unwrap_infallible().ok(),
                model.remove(&k)
            ),
            MapOp::Delete(k) => {
                map.delete(&k, &mut state).unwrap_infallible();
                model.remove(&k);
            }
            MapOp::BorrowMutAdd(k, v) => {
                let mut b = map
                    .borrow_mut(&k, &mut state)
                    .unwrap_infallible()
                    .unwrap_or(0);
                *b = b.wrapping_add(v);
                b.save(&mut state).unwrap_infallible();
                let entry = model.entry(k).or_insert(0);
                *entry = entry.wrapping_add(v);
            }
        }
        let stored: BTreeMap<u8, u32> = state
            .user
            .iter()
            .map(|(k, v)| {
                assert_eq!(k.prefix(), prefix);
                (
                    borsh::from_slice(k.without_prefix()).unwrap(),
                    borsh::from_slice(v.value()).unwrap(),
                )
            })
            .collect();
        assert_eq!(stored, model);
    }
}

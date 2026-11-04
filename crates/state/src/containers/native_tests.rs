//! Tests of the native container APIs (raw bytes, prefix iteration, storage proofs) and of
//! `verify_proof` and `arbitrary_state_map`.

use super::*;
use crate::test_state::{InMemoryState, UnwrapInfallible};
use crate::test_storage::{NamespaceState, ProvenTestAccessor, TestStorage};
use crate::{
    BorshCodec, Kernel, Prefix, SlotKey, SlotValue, StateCheckpoint, StateReader, StateWriter,
    Storage, User,
};

fn le(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------------------------
// Raw APIs

#[test]
fn state_value_raw_roundtrip_and_typed_compatibility() {
    let mut state = InMemoryState::default();
    let mut value = StateValue::<u32>::with_codec(Prefix::new(7, 7), BorshCodec);
    assert_eq!(value.get_raw(&mut state).unwrap_infallible(), None);

    value.set_raw(&le(5), &mut state).unwrap_infallible();
    assert_eq!(value.get(&mut state).unwrap_infallible(), Some(5));
    value.set(&6, &mut state).unwrap_infallible();
    assert_eq!(value.get_raw(&mut state).unwrap_infallible(), Some(le(6)));
    assert_eq!(
        value.remove_raw(&mut state).unwrap_infallible(),
        Some(le(6))
    );
    assert_eq!(value.get_raw(&mut state).unwrap_infallible(), None);
    assert!(state.user.is_empty());

    // Raw bytes are stored as they are, even if they are not a `u32`.
    value.set_raw(&[1, 2, 3], &mut state).unwrap_infallible();
    assert_eq!(
        value.get_raw(&mut state).unwrap_infallible(),
        Some(vec![1, 2, 3])
    );
}

#[test]
fn state_map_raw_roundtrip_and_typed_compatibility() {
    let mut state = InMemoryState::default();
    let mut map = StateMap::<u64, u32>::with_codec(Prefix::new(10, 10), BorshCodec);
    assert_eq!(map.get_raw(&7, &mut state).unwrap_infallible(), None);
    map.set_raw(&7, &le(3), &mut state).unwrap_infallible();
    assert_eq!(map.get(&7, &mut state).unwrap_infallible(), Some(3));
    map.set(&8, &4, &mut state).unwrap_infallible();
    assert_eq!(map.get_raw(&8, &mut state).unwrap_infallible(), Some(le(4)));
    assert_eq!(
        map.remove_raw(&7, &mut state).unwrap_infallible(),
        Some(le(3))
    );
    assert_eq!(map.remove_raw(&7, &mut state).unwrap_infallible(), None);
    assert_eq!(map.get(&7, &mut state).unwrap_infallible(), None);

    map.set_raw(&9, &[0xaa], &mut state).unwrap_infallible();
    let entries = map
        .iter_raw_from_keys([9u64, 8, 1], &mut state)
        .unwrap_infallible();
    assert_eq!(
        entries,
        [(9, Some(vec![0xaa])), (8, Some(le(4))), (1, None)]
    );
}

#[test]
fn accessory_map_iter_raw_from_keys_through_the_checkpoint() {
    let mut checkpoint = StateCheckpoint::new(TestStorage::default());
    let mut map = AccessoryStateMap::<u64, u32>::with_codec(Prefix::new(14, 14), BorshCodec);
    let mut accessory = checkpoint.accessory_state();
    map.set(&1, &10, &mut accessory).unwrap_infallible();
    map.set_raw(&2, &[0xaa, 0xbb], &mut accessory)
        .unwrap_infallible();
    let entries = map
        .iter_raw_from_keys(vec![1u64, 2, 3], &mut accessory)
        .unwrap_infallible();
    assert_eq!(
        entries,
        [(1, Some(le(10))), (2, Some(vec![0xaa, 0xbb])), (3, None)]
    );
}

#[test]
fn state_vec_raw_roundtrip_and_typed_compatibility() {
    let mut state = InMemoryState::default();
    let prefix = Prefix::new(5, 5);
    let mut vec = StateVec::<u32>::with_codec(prefix, BorshCodec);
    vec.push_raw(&le(1), &mut state).unwrap_infallible();
    vec.push(&2, &mut state).unwrap_infallible();
    vec.push_raw(&[9], &mut state).unwrap_infallible();
    assert_eq!(vec.len(&mut state).unwrap_infallible(), 3);
    // Same layout as typed pushes: length at the prefix, elements at prefix ‖ u64 LE.
    assert_eq!(
        state.user[&SlotKey::singleton(&prefix)].value(),
        3u64.to_le_bytes()
    );
    assert_eq!(
        state.user[&SlotKey::from_parts(&prefix, &2u64.to_le_bytes())].value(),
        [9]
    );

    assert_eq!(vec.get_raw(0, &mut state).unwrap_infallible(), Some(le(1)));
    assert_eq!(vec.get_raw(1, &mut state).unwrap_infallible(), Some(le(2)));
    assert_eq!(vec.get_raw(3, &mut state).unwrap_infallible(), None);
    assert_eq!(vec.pop_raw(&mut state).unwrap_infallible(), Some(vec![9]));
    assert_eq!(vec.collect_infallible::<Vec<_>, _>(&mut state), [1, 2]);

    assert!(
        vec.set_raw(1, &le(7), &mut state)
            .unwrap_infallible()
            .is_ok()
    );
    assert!(matches!(
        vec.set_raw(2, &le(7), &mut state).unwrap_infallible(),
        Err(StateVecError::IndexOutOfBounds(2))
    ));
    assert_eq!(vec.get(1, &mut state).unwrap_infallible(), Some(7));

    let raw: Vec<Vec<u8>> = vec
        .iter_raw(&mut state)
        .unwrap_infallible()
        .map(UnwrapInfallible::unwrap_infallible)
        .collect();
    assert_eq!(raw, [le(1), le(7)]);
    let mut iter = vec.iter_raw(&mut state).unwrap_infallible();
    assert_eq!(iter.size_hint(), (0, Some(2)));
    assert_eq!(
        iter.next_back().map(UnwrapInfallible::unwrap_infallible),
        Some(le(7))
    );
    assert_eq!(
        iter.next().map(UnwrapInfallible::unwrap_infallible),
        Some(le(1))
    );
    assert!(iter.next().is_none() && iter.next_back().is_none());

    assert_eq!(vec.pop_raw(&mut state).unwrap_infallible(), Some(le(7)));
    assert_eq!(vec.pop_raw(&mut state).unwrap_infallible(), Some(le(1)));
    assert_eq!(vec.pop_raw(&mut state).unwrap_infallible(), None);
    assert_eq!(state.user.len(), 1, "only the zero length is left");
}

/// A raw iterator ends after an error or at `len` (an element left past `len` is not read).
#[test]
fn state_vec_iter_raw_respects_len() {
    let mut state = InMemoryState::default();
    let prefix = Prefix::new(5, 6);
    let mut vec = StateVec::<u32>::with_codec(prefix, BorshCodec);
    vec.set_all(vec![1, 2], &mut state).unwrap_infallible();
    // A leftover past `len`, as a failed operation could leave.
    StateWriter::<User>::set(
        &mut state,
        &SlotKey::from_parts(&prefix, &2u64.to_le_bytes()),
        SlotValue::from(le(3)),
    )
    .unwrap_infallible();
    assert_eq!(vec.iter_raw(&mut state).unwrap_infallible().count(), 2);
    assert_eq!(vec.get_raw(2, &mut state).unwrap_infallible(), None);
}

/// The raw push/pop keep the vec's write-order invariant: after any failed write, every element
/// in `0..len` is present (upstream's `pop_raw` deleted the element before shrinking `len`).
#[test]
fn state_vec_raw_ops_keep_the_invariant_when_a_write_fails() {
    struct FailingWriter {
        inner: InMemoryState,
        writes_left: u32,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("out of gas")]
    struct OutOfGas;

    impl StateReader<User> for FailingWriter {
        type Error = OutOfGas;

        fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, OutOfGas> {
            Ok(StateReader::<User>::get(&mut self.inner, key).unwrap_infallible())
        }
    }

    impl StateWriter<User> for FailingWriter {
        type Error = OutOfGas;

        fn set(&mut self, key: &SlotKey, value: SlotValue) -> Result<(), OutOfGas> {
            self.writes_left = self.writes_left.checked_sub(1).ok_or(OutOfGas)?;
            StateWriter::<User>::set(&mut self.inner, key, value).unwrap_infallible();
            Ok(())
        }

        fn delete(&mut self, key: &SlotKey) -> Result<(), OutOfGas> {
            self.writes_left = self.writes_left.checked_sub(1).ok_or(OutOfGas)?;
            StateWriter::<User>::delete(&mut self.inner, key).unwrap_infallible();
            Ok(())
        }
    }

    type Op = fn(&mut StateVec<u32>, &mut FailingWriter) -> Result<(), OutOfGas>;
    let ops: [(&str, Op); 3] = [
        ("push_raw", |v, s| v.push_raw(&le(9), s)),
        ("pop_raw", |v, s| v.pop_raw(s).map(drop)),
        ("set_raw", |v, s| v.set_raw(0, &le(9), s).map(drop)),
    ];
    for (name, op) in ops {
        for writes in 0..3 {
            let mut vec = StateVec::<u32>::with_codec(Prefix::new(4, 4), BorshCodec);
            let mut inner = InMemoryState::default();
            vec.set_all(vec![1, 2, 3], &mut inner).unwrap_infallible();
            let mut state = FailingWriter {
                inner,
                writes_left: writes,
            };
            let _ = op(&mut vec, &mut state);
            let mut state = state.inner;
            let len = vec.len(&mut state).unwrap_infallible();
            for i in 0..len {
                assert!(
                    vec.get_or_err(i, &mut state).unwrap_infallible().is_ok(),
                    "{name} with {writes} writes: hole at {i} (len {len})"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Prefix iteration over committed storage

#[test]
fn state_map_iter_raw_user_and_kernel() {
    let user_map = StateMap::<u64, u32>::with_codec(Prefix::new(12, 12), BorshCodec);
    let kernel_map = KernelStateMap::<u64, u32>::with_codec(Prefix::new(12, 12), BorshCodec);
    let other = StateMap::<u64, u32>::with_codec(Prefix::new(12, 13), BorshCodec);
    let storage = TestStorage::default().commit_with(|state| {
        let (mut user_map, mut kernel_map, mut other) =
            (user_map.clone(), kernel_map.clone(), other.clone());
        user_map.set(&2, &20, state).unwrap_infallible();
        user_map.set(&1, &10, state).unwrap_infallible();
        kernel_map.set(&3, &30, state).unwrap_infallible();
        other.set(&4, &40, state).unwrap_infallible();
    });

    // Uncommitted writes are not seen.
    let mut checkpoint = StateCheckpoint::new(storage.clone());
    user_map
        .clone()
        .set(&5, &50, &mut checkpoint)
        .unwrap_infallible();

    let user: Vec<_> = user_map
        .iter_raw(checkpoint.storage())
        .unwrap()
        .unwrap()
        .map(Result::unwrap)
        .collect();
    // Ascending order of the encoded keys (u64 LE: 1 < 2).
    assert_eq!(user, [(1, le(10)), (2, le(20))]);
    let kernel: Vec<_> = kernel_map
        .iter_raw(&storage)
        .unwrap()
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(kernel, [(3, le(30))]);
}

/// A key that does not decode, or is not the canonical encoding of its decoded key, is an
/// `Err` item; iteration continues.
#[test]
fn state_map_iter_raw_rejects_non_canonical_keys() {
    let prefix = Prefix::new(12, 14);
    let map = StateMap::<LaxBool, u32>::with_codec(prefix, BorshCodec);
    let storage = TestStorage::default().commit_with(|state| {
        for key in [&[1][..], &[2], &[1, 0], &[0]] {
            StateWriter::<User>::set(
                state,
                &SlotKey::from_parts(&prefix, key),
                SlotValue::from(le(1)),
            )
            .unwrap_infallible();
        }
    });
    let entries: Vec<_> = map.iter_raw(&storage).unwrap().unwrap().collect();
    let summary: Vec<_> = entries
        .iter()
        .map(|e| e.as_ref().map(|(k, _)| k.0).map_err(|e| e.to_string()))
        .collect();
    assert_eq!(summary.len(), 4);
    assert_eq!(summary[0], Ok(false));
    assert_eq!(summary[1], Ok(true));
    assert!(
        summary[2]
            .as_ref()
            .unwrap_err()
            .contains("Failed to decode")
    );
    assert!(
        summary[3]
            .as_ref()
            .unwrap_err()
            .contains("not the canonical encoding")
    );
}

/// A bool that decodes any non-zero byte as `true` (borsh's `bool` rejects them): one key with
/// several accepted encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize)]
struct LaxBool(bool);

impl borsh::BorshDeserialize for LaxBool {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Self(u8::deserialize_reader(reader)? != 0))
    }
}

impl std::fmt::Display for LaxBool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for LaxBool {
    type Err = std::str::ParseBoolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

// ---------------------------------------------------------------------------------------------
// Storage proofs

struct Fixture {
    storage: TestStorage,
    value: StateValue<u32>,
    other_value: StateValue<u32>,
    map: StateMap<u64, u32>,
    other_map: StateMap<u64, u32>,
    kernel_map: KernelStateMap<u64, u32>,
}

fn fixture() -> Fixture {
    let value = StateValue::<u32>::with_codec(Prefix::new(20, 0), BorshCodec);
    let other_value = StateValue::<u32>::with_codec(Prefix::new(20, 1), BorshCodec);
    let map = StateMap::<u64, u32>::with_codec(Prefix::new(21, 0), BorshCodec);
    let other_map = StateMap::<u64, u32>::with_codec(Prefix::new(21, 1), BorshCodec);
    let kernel_map = KernelStateMap::<u64, u32>::with_codec(Prefix::new(21, 0), BorshCodec);
    let storage = TestStorage::default().commit_with(|state| {
        value.clone().set(&1, state).unwrap_infallible();
        other_value.clone().set(&2, state).unwrap_infallible();
        map.clone().set(&7, &70, state).unwrap_infallible();
        other_map.clone().set(&7, &71, state).unwrap_infallible();
        kernel_map.clone().set(&7, &72, state).unwrap_infallible();
    });
    Fixture {
        storage,
        value,
        other_value,
        map,
        other_map,
        kernel_map,
    }
}

#[test]
fn proofs_of_values_and_map_entries_verify() {
    let f = fixture();
    let root = f.storage.root();
    let mut api = ProvenTestAccessor(f.storage.clone());

    let proof = f.value.get_with_proof(&mut api).unwrap();
    assert_eq!(
        f.value.verify_proof::<TestStorage>(root, proof).unwrap(),
        Some(1)
    );

    let proof = f.map.get_with_proof(&7, &mut api).unwrap();
    assert_eq!(
        f.map.verify_proof::<TestStorage>(root, proof).unwrap(),
        (7, Some(70))
    );
    // Absence is proven too.
    let proof = f.map.get_with_proof(&8, &mut api).unwrap();
    assert_eq!(
        f.map.verify_proof::<TestStorage>(root, proof).unwrap(),
        (8, None)
    );
    let proof = f.kernel_map.get_with_proof(&7, &mut api).unwrap();
    assert_eq!(
        f.kernel_map
            .verify_proof::<TestStorage>(root, proof)
            .unwrap(),
        (7, Some(72))
    );

    // The proof survives its wire encodings.
    let proof = f.map.get_with_proof(&7, &mut api).unwrap();
    let proof: crate::StorageProof<NamespaceState> =
        borsh::from_slice(&borsh::to_vec(&proof).unwrap()).unwrap();
    let proof: crate::StorageProof<NamespaceState> =
        serde_json::from_str(&serde_json::to_string(&proof).unwrap()).unwrap();
    assert!(f.map.verify_proof::<TestStorage>(root, proof).is_ok());
}

fn verify_err<T: std::fmt::Debug>(result: anyhow::Result<T>, expected: &str) {
    let err = result.unwrap_err().to_string();
    assert!(err.contains(expected), "{err}");
}

#[test]
fn proofs_from_another_namespace_are_rejected() {
    let f = fixture();
    let root = f.storage.root();
    let mut api = ProvenTestAccessor(f.storage.clone());
    // Same prefix and key, kernel namespace.
    let kernel_proof = f.kernel_map.get_with_proof(&7, &mut api).unwrap();
    verify_err(
        f.map
            .verify_proof::<TestStorage>(root, kernel_proof.clone()),
        "different namespace",
    );
    // Relabeling the namespace makes it fail to open against the user root.
    let mut relabeled = kernel_proof;
    relabeled.namespace = crate::ProvableNamespace::User;
    verify_err(
        f.map.verify_proof::<TestStorage>(root, relabeled),
        "does not match the User root",
    );
}

/// Upstream's map `verify_proof` decoded the key without checking the prefix, so another
/// container's entry was accepted as an entry of this map.
#[test]
fn proofs_from_another_container_are_rejected() {
    let f = fixture();
    let root = f.storage.root();
    let mut api = ProvenTestAccessor(f.storage.clone());
    let proof = f.other_map.get_with_proof(&7, &mut api).unwrap();
    verify_err(
        f.map.verify_proof::<TestStorage>(root, proof.clone()),
        "another container",
    );
    assert_eq!(
        f.other_map
            .verify_proof::<TestStorage>(root, proof)
            .unwrap(),
        (7, Some(71))
    );

    // A value's proof is not a map entry (here the key would not even decode), nor another
    // value.
    let proof = f.value.get_with_proof(&mut api).unwrap();
    verify_err(
        f.map.verify_proof::<TestStorage>(root, proof.clone()),
        "another container",
    );
    verify_err(
        f.other_value.verify_proof::<TestStorage>(root, proof),
        "different key",
    );
}

#[test]
fn proofs_of_another_key_or_value_are_rejected() {
    let f = fixture();
    let root = f.storage.root();
    let mut api = ProvenTestAccessor(f.storage.clone());
    // A tampered key or value no longer opens.
    let mut proof = f.map.get_with_proof(&7, &mut api).unwrap();
    proof.value = Some(SlotValue::from(le(99)));
    verify_err(
        f.map.verify_proof::<TestStorage>(root, proof),
        "does not match the proof",
    );
    let mut proof = f.map.get_with_proof(&7, &mut api).unwrap();
    proof.key = f.map.slot_key(&8);
    verify_err(
        f.map.verify_proof::<TestStorage>(root, proof),
        "does not match the proof",
    );
    // Against another root.
    let proof = f.map.get_with_proof(&7, &mut api).unwrap();
    verify_err(
        f.map
            .verify_proof::<TestStorage>(TestStorage::PRE_GENESIS_ROOT, proof),
        "does not match the User root",
    );
}

/// The proven key must be the canonical encoding of the returned key, or the result would not
/// mean "`map[key]` is `value`".
#[test]
fn proofs_of_non_canonical_keys_are_rejected() {
    let prefix = Prefix::new(22, 0);
    let map = StateMap::<LaxBool, u32>::with_codec(prefix, BorshCodec);
    let storage = TestStorage::default().commit_with(|state| {
        map.clone()
            .set(&LaxBool(true), &1, state)
            .unwrap_infallible();
        StateWriter::<User>::set(
            state,
            &SlotKey::from_parts(&prefix, &[2]),
            SlotValue::from(le(2)),
        )
        .unwrap_infallible();
    });
    let root = storage.root();
    let mut api = ProvenTestAccessor(storage);

    let proof = map.get_with_proof(&LaxBool(true), &mut api).unwrap();
    assert_eq!(
        map.verify_proof::<TestStorage>(root, proof).unwrap(),
        (LaxBool(true), Some(1))
    );
    let proof =
        <ProvenTestAccessor as crate::ProvenStateAccessor<User>>::get_global_latest_with_proof(
            &mut api,
            SlotKey::from_parts(&prefix, &[2]),
        )
        .unwrap();
    verify_err(
        map.verify_proof::<TestStorage>(root, proof),
        "not the canonical encoding",
    );
}

#[test]
fn proofs_with_undecodable_values_are_rejected() {
    let value = StateValue::<u32>::with_codec(Prefix::new(23, 0), BorshCodec);
    let storage = TestStorage::default().commit_with(|state| {
        value.clone().set_raw(&[1, 2, 3], state).unwrap_infallible();
    });
    let root = storage.root();
    let proof = value
        .get_with_proof(&mut ProvenTestAccessor(storage))
        .unwrap();
    verify_err(
        value.verify_proof::<TestStorage>(root, proof),
        "Failed to decode value",
    );
}

#[test]
fn kernel_reads_through_the_proven_accessor() {
    let f = fixture();
    let mut api = ProvenTestAccessor(f.storage);
    assert_eq!(f.kernel_map.get(&7, &mut api).unwrap_infallible(), Some(72));
    assert_eq!(
        StateReader::<Kernel>::get(&mut api, &f.map.slot_key(&9)),
        Ok(None)
    );
}

// ---------------------------------------------------------------------------------------------
// arbitrary_state_map

#[test]
fn arbitrary_state_map_writes_its_entries() {
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let mut u = arbitrary::Unstructured::new(&data);
    let mut state = InMemoryState::default();
    let map = StateMap::<u16, String>::arbitrary_state_map(&mut u, &mut state).unwrap();
    assert!(!state.user.is_empty());
    let keys: Vec<SlotKey> = state.user.keys().cloned().collect();
    for key in keys {
        assert_eq!(key.prefix(), *map.prefix());
        let k: u16 = borsh::from_slice(key.without_prefix()).unwrap();
        assert!(map.get(&k, &mut state).unwrap_infallible().is_some());
    }

    // Write-only accessory state works too.
    let mut checkpoint = StateCheckpoint::new(TestStorage::default());
    let mut u = arbitrary::Unstructured::new(&data);
    AccessoryStateMap::<u8, u64>::arbitrary_state_map(&mut u, &mut checkpoint).unwrap();
    let (_, accessory, _) = checkpoint.freeze();
    assert!(!accessory.freeze().is_empty());
}

#[test_strategy::proptest]
fn arbitrary_state_map_never_panics(data: Vec<u8>) {
    let mut u = arbitrary::Unstructured::new(&data);
    let mut state = InMemoryState::default();
    let _ = KernelStateMap::<String, (u8, Vec<u8>, Option<u64>)>::arbitrary_state_map(
        &mut u, &mut state,
    );
}

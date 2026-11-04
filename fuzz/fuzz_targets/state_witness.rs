//! Decoders of prover- and client-supplied storage data from `selendra-state`: `ArrayWitness`
//! (borsh and JSON), witness hints (`Witness::try_get_hint`), `NodeLeaf` and `StorageProof`.
#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use selendra_state::{
    ArrayWitness, NodeLeaf, SlotKey, SlotValue, StorageProof, VAL_HASH_AND_SIZE_LEN, Witness,
    val_hash_and_size,
};

/// borsh: decoding must not panic, and anything accepted must be its own canonical encoding.
fn borsh_canonical<T: borsh::BorshDeserialize + borsh::BorshSerialize>(data: &[u8]) -> Option<T> {
    let value = borsh::from_slice::<T>(data).ok()?;
    assert_eq!(
        borsh::to_vec(&value).unwrap(),
        data,
        "non-canonical borsh accepted"
    );
    Some(value)
}

/// JSON: anything accepted must serialize back to the same JSON value (whitespace aside).
fn json_canonical<T: serde::de::DeserializeOwned + serde::Serialize>(s: &str) -> Option<T> {
    let value = serde_json::from_str::<T>(s).ok()?;
    let input: serde_json::Value = serde_json::from_str(s).unwrap();
    assert_eq!(
        serde_json::to_value(&value).unwrap(),
        input,
        "non-canonical JSON accepted"
    );
    Some(value)
}

/// Decodes `hint` as a `T` through a witness: never panics, and a hint accepted as a `T` is the
/// canonical encoding of the decoded value.
fn hint_canonical<T: borsh::BorshDeserialize + borsh::BorshSerialize>(hint: &[u8]) {
    let witness = ArrayWitness::from_hints(vec![hint.to_vec()]);
    if let Ok(value) = witness.try_get_hint::<T>() {
        assert_eq!(
            borsh::to_vec(&value).unwrap(),
            hint,
            "non-canonical hint accepted"
        );
    }
    assert!(
        witness.is_empty(),
        "a hint is consumed even when it does not decode"
    );
    assert!(witness.try_get_hint::<T>().is_err());
}

fuzz_target!(|data: &[u8]| {
    if let Some(witness) = borsh_canonical::<ArrayWitness>(data) {
        let hints: Vec<Vec<u8>> = borsh::from_slice(data).unwrap();
        assert_eq!(witness.len(), hints.len());
        for hint in &hints {
            // The hint types storages read from witnesses.
            hint_canonical::<Option<SlotValue>>(hint);
            hint_canonical::<Option<NodeLeaf>>(hint);
            hint_canonical::<BTreeMap<SlotKey, SlotValue>>(hint);
            hint_canonical::<StorageProof<Vec<u8>>>(hint);
        }
        assert_eq!(witness.ensure_consumed().is_ok(), hints.is_empty());
    }
    // The fuzz input as a single hint.
    hint_canonical::<Option<SlotValue>>(data);
    hint_canonical::<Option<NodeLeaf>>(data);

    if let Some(leaf) = borsh_canonical::<NodeLeaf>(data) {
        let combined = leaf.combine_val_hash_and_size();
        assert_eq!(combined.len(), VAL_HASH_AND_SIZE_LEN);
        assert_eq!(combined, val_hash_and_size(leaf.val_hash, leaf.size));
        assert_eq!(combined[..32], leaf.val_hash);
        assert_eq!(combined[32..], leaf.size.to_le_bytes());
    }
    if let Some(proof) = borsh_canonical::<StorageProof<Vec<u8>>>(data) {
        assert!(proof.key.len() >= 2);
    }

    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(witness) = json_canonical::<ArrayWitness>(s) {
        let bytes = borsh::to_vec(&witness).unwrap();
        let decoded: ArrayWitness = borsh::from_slice(&bytes).unwrap();
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            serde_json::to_value(&witness).unwrap()
        );
    }
    json_canonical::<StorageProof<Vec<u8>>>(s);
});

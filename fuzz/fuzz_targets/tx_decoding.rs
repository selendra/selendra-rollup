//! Transaction, event and proof-data decoders from `selendra-interface`, and the size-checked
//! transaction constructors (whatever they accept, the decoders accept back).
#![no_main]

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use selendra_interface::Bytes;
use selendra_interface::common::{HexString, RollupHeight, SlotNumber, VisibleSlotNumber};
use selendra_interface::crypto::CredentialId;
use selendra_interface::stf::{
    FullyBakedTx, MAX_FULLY_BAKED_TX_SIZE, MAX_RAW_TX_SIZE, RawTx, StoredEvent,
};
use selendra_interface::zk::aggregated_proof::CodeCommitmentHash;

fn borsh_canonical<T: borsh::BorshDeserialize + borsh::BorshSerialize>(data: &[u8]) {
    if let Ok(value) = borsh::from_slice::<T>(data) {
        assert_eq!(
            borsh::to_vec(&value).unwrap(),
            data,
            "non-canonical borsh accepted"
        );
    }
}

/// String form: anything accepted must print back as exactly the input.
fn str_canonical<T: FromStr + std::fmt::Display>(s: &str) {
    if let Ok(value) = T::from_str(s) {
        assert_eq!(value.to_string(), s, "non-canonical string accepted");
    }
}

/// JSON: anything accepted must serialize back to the same JSON value (whitespace aside).
fn json_canonical<T: serde::de::DeserializeOwned + serde::Serialize>(s: &str) {
    if let Ok(value) = serde_json::from_str::<T>(s) {
        let input: serde_json::Value = serde_json::from_str(s).unwrap();
        assert_eq!(
            serde_json::to_value(&value).unwrap(),
            input,
            "non-canonical JSON accepted"
        );
    }
}

/// A decoded transaction can be rebuilt with the constructors, and anything the constructors
/// build decodes back (the round-trip precondition of stored types).
fn constructors_roundtrip(data: &[u8]) {
    if let Ok(tx) = borsh::from_slice::<FullyBakedTx>(data) {
        let rebuilt = FullyBakedTx::new(tx.data().clone())
            .and_then(|t| t.with_sequencing_data(tx.sequencing_data().cloned()))
            .expect("a decoded transaction is constructible");
        assert_eq!(rebuilt, tx);
        assert_eq!(tx.len(), data.len());
    }
    if let Ok(raw) = borsh::from_slice::<RawTx>(data) {
        assert_eq!(RawTx::new(raw.as_bytes().to_vec()).unwrap(), raw);
    }

    match RawTx::new(data.to_vec()) {
        Ok(raw) => {
            let bytes = borsh::to_vec(&raw).unwrap();
            assert_eq!(borsh::from_slice::<RawTx>(&bytes).unwrap(), raw);
            let json = serde_json::to_string(&raw).unwrap();
            assert_eq!(serde_json::from_str::<RawTx>(&json).unwrap(), raw);
        }
        Err(_) => assert!(data.len() > MAX_RAW_TX_SIZE),
    }

    // The first byte picks where the data ends and the sequencing data starts.
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let (tx_data, seq) = rest.split_at(usize::from(split).min(rest.len()));
    let seq = (split % 2 == 0).then(|| Bytes::copy_from_slice(seq));
    match FullyBakedTx::new(Bytes::copy_from_slice(tx_data))
        .and_then(|t| t.with_sequencing_data(seq))
    {
        Ok(tx) => {
            let bytes = borsh::to_vec(&tx).unwrap();
            assert_eq!(bytes.len(), tx.len());
            assert_eq!(borsh::from_slice::<FullyBakedTx>(&bytes).unwrap(), tx);
            let json = serde_json::to_string(&tx).unwrap();
            assert_eq!(serde_json::from_str::<FullyBakedTx>(&json).unwrap(), tx);
        }
        Err(_) => assert!(rest.len() > MAX_FULLY_BAKED_TX_SIZE),
    }
}

fuzz_target!(|data: &[u8]| {
    constructors_roundtrip(data);
    borsh_canonical::<FullyBakedTx>(data);
    borsh_canonical::<RawTx>(data);
    borsh_canonical::<StoredEvent>(data);
    borsh_canonical::<CodeCommitmentHash>(data);
    borsh_canonical::<CredentialId>(data);

    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    json_canonical::<FullyBakedTx>(s);
    json_canonical::<RawTx>(s);
    json_canonical::<HexString>(s);
    json_canonical::<CredentialId>(s);
    json_canonical::<SlotNumber>(s);
    str_canonical::<HexString>(s);
    str_canonical::<HexString<[u8; 32]>>(s);
    str_canonical::<CredentialId>(s);
    str_canonical::<SlotNumber>(s);
    str_canonical::<VisibleSlotNumber>(s);
    str_canonical::<RollupHeight>(s);
});

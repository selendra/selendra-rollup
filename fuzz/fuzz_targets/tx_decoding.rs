//! Transaction, event and proof-data decoders from `selendra-interface`.
#![no_main]

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use selendra_interface::common::{HexString, RollupHeight, SlotNumber, VisibleSlotNumber};
use selendra_interface::crypto::CredentialId;
use selendra_interface::stf::{FullyBakedTx, RawTx, StoredEvent};
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

fuzz_target!(|data: &[u8]| {
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

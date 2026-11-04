//! State key and value decoders from `selendra-state`: `SlotKey`, `SlotValue`, `Prefix`,
//! `Namespace`, `ProvableNamespace`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use selendra_state::{Namespace, Prefix, ProvableNamespace, SlotKey, SlotValue};

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

fuzz_target!(|data: &[u8]| {
    if let Some(key) = borsh_canonical::<SlotKey>(data) {
        assert!(key.len() >= 2);
        assert_eq!(key.prefix().to_bytes(), key.as_ref()[..2]);
        assert_eq!(key.without_prefix(), &key.as_ref()[2..]);
    }
    borsh_canonical::<SlotValue>(data);
    borsh_canonical::<Prefix>(data);
    borsh_canonical::<Namespace>(data);
    borsh_canonical::<ProvableNamespace>(data);

    // Raw key bytes: accepted iff at least the 2 prefix bytes, kept verbatim.
    match SlotKey::try_from_bytes(data) {
        Ok(key) => assert_eq!(key.as_ref(), data),
        Err(_) => assert!(data.len() < 2),
    }
    if let Ok(key) = SlotKey::try_from_bytes(data) {
        let _ = key.truncate_to(usize::from(data[0]));
    }

    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(key) = json_canonical::<SlotKey>(s) {
        // JSON is the `Display` form in quotes.
        assert_eq!(serde_json::to_string(&key).unwrap(), format!("\"{key}\""));
    }
    json_canonical::<SlotValue>(s);
    if let Some(prefix) = json_canonical::<Prefix>(s) {
        assert_eq!(
            serde_json::to_string(&prefix).unwrap(),
            format!("\"{prefix}\"")
        );
    }
    json_canonical::<Namespace>(s);
    json_canonical::<ProvableNamespace>(s);
});

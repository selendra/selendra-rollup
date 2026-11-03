//! Key and signature decoders, and signature verification on arbitrary input.
#![no_main]

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use selendra_interface::common::HexString;
use selendra_interface::crypto::Signature;
use selendra_primitives::crypto::{
    Ed25519PublicKey, Ed25519Signature, EthereumPublicKey, EthereumSignature,
};

fn borsh_canonical<T: borsh::BorshDeserialize + borsh::BorshSerialize>(data: &[u8]) -> Option<T> {
    let value = borsh::from_slice::<T>(data).ok()?;
    assert_eq!(
        borsh::to_vec(&value).unwrap(),
        data,
        "non-canonical borsh accepted"
    );
    Some(value)
}

/// String form (`0x` + lowercase hex of the bytes): anything accepted must be exactly that.
fn str_canonical<T: FromStr + AsRef<[u8]>>(s: &str) {
    if let Ok(value) = T::from_str(s) {
        assert_eq!(
            HexString(value.as_ref()).to_string(),
            s,
            "non-canonical string accepted"
        );
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
    borsh_canonical::<Ed25519PublicKey>(data);
    borsh_canonical::<Ed25519Signature>(data);
    borsh_canonical::<EthereumPublicKey>(data);
    borsh_canonical::<EthereumSignature>(data);
    let _ = EthereumPublicKey::try_from(data);
    let _ = EthereumSignature::try_from(data);
    let _ = Ed25519PublicKey::try_from(data);

    // Verification of arbitrary (key, signature, message) must return, never panic.
    if data.len() >= 32 + 64 {
        let (pk, rest) = data.split_at(32);
        let (sig, msg) = rest.split_at(64);
        if let (Ok(pk), Ok(sig)) = (
            Ed25519PublicKey::try_from(pk),
            Ed25519Signature::try_from(sig),
        ) {
            let _ = sig.verify(&pk, msg);
        }
    }
    if data.len() >= 33 + 64 {
        let (pk, rest) = data.split_at(33);
        let (sig, msg) = rest.split_at(64);
        if let (Ok(pk), Ok(sig)) = (
            EthereumPublicKey::try_from(pk),
            EthereumSignature::try_from(sig),
        ) {
            let _ = sig.verify(&pk, msg);
        }
    }

    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    str_canonical::<Ed25519PublicKey>(s);
    str_canonical::<Ed25519Signature>(s);
    str_canonical::<EthereumSignature>(s);
    // Also accepts an uncompressed key, which is normalized to compressed (documented).
    if let Ok(pk) = EthereumPublicKey::from_str(s) {
        assert_eq!(
            EthereumPublicKey::from_str(&HexString(pk.as_ref()).to_string()).unwrap(),
            pk
        );
    }
    json_canonical::<Ed25519PublicKey>(s);
    json_canonical::<Ed25519Signature>(s);
    json_canonical::<EthereumPublicKey>(s);
    json_canonical::<EthereumSignature>(s);
});

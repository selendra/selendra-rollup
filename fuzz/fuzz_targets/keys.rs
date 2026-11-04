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

/// p = 2^255 - 19 and the group order l, little-endian, written out independently of the
/// code under test.
const P: [u8; 32] = {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn less_than(a: &[u8], b: &[u8; 32]) -> bool {
    a.iter().rev().cmp(b.iter().rev()).is_lt()
}

/// An accepted ed25519 signature has a canonical `R` (`y < p`, no sign bit on `x = 0`) and
/// `s < l`; anything else would let native and the SP1 guest disagree (see `ed25519.rs`).
fn ed25519_signature_canonical(data: &[u8]) {
    let Ok(sig) = Ed25519Signature::try_from(data) else {
        return;
    };
    let bytes = sig.to_bytes();
    let mut y = [0u8; 32];
    y.copy_from_slice(&bytes[..32]);
    let sign_bit = y[31] & 0x80 != 0;
    y[31] &= 0x7f;
    let mut minus_one = P;
    minus_one[0] -= 1;
    let mut one = [0u8; 32];
    one[0] = 1;
    assert!(less_than(&y, &P), "ed25519 R with y >= p accepted");
    assert!(
        !(sign_bit && (y == one || y == minus_one)),
        "ed25519 R with sign bit on x = 0 accepted"
    );
    assert!(less_than(&bytes[32..], &L), "ed25519 s >= l accepted");
}

fuzz_target!(|data: &[u8]| {
    borsh_canonical::<Ed25519PublicKey>(data);
    borsh_canonical::<Ed25519Signature>(data);
    ed25519_signature_canonical(data);
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

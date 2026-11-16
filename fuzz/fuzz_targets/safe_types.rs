//! Bounded containers and strings from `selendra-interface` (`SafeVec`, `SizedSafeString`,
//! `HexString<SafeVec<u8, N>>`): decoders (no panics, canonical, never over the cap, the capped
//! `HexString` ones agreeing with the uncapped one within the cap) and operations (never over
//! the cap, a failed operation changes nothing).
#![no_main]

use std::ops::Bound;
use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use selendra_interface::common::safe_vec::ExtendFromWithinError;
use selendra_interface::common::{HexString, SafeVec, SizedSafeString};

fn borsh_canonical<T: borsh::BorshDeserialize + borsh::BorshSerialize>(data: &[u8]) -> Option<T> {
    let value = borsh::from_slice::<T>(data).ok()?;
    assert_eq!(
        borsh::to_vec(&value).unwrap(),
        data,
        "non-canonical borsh accepted"
    );
    Some(value)
}

/// String form: anything accepted must print back as exactly the input.
fn str_canonical<T: FromStr + std::fmt::Display>(s: &str) -> Option<T> {
    let value = T::from_str(s).ok()?;
    assert_eq!(value.to_string(), s, "non-canonical string accepted");
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

fn printable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

const N: usize = 8;

fn bound(kind: u8, n: usize) -> Bound<usize> {
    match kind % 3 {
        0 => Bound::Included(n),
        1 => Bound::Excluded(n),
        _ => Bound::Unbounded,
    }
}

/// Runs the operations encoded in `data` (4 bytes each) on a `SafeVec<u8, N>` and on a model
/// `Vec<u8>` that spells out the expected semantics.
fn vec_ops(data: &[u8]) {
    let mut v = SafeVec::<u8, N>::new();
    let mut model: Vec<u8> = Vec::new();
    for chunk in data.chunks_exact(4) {
        let [op, a, b, kinds] = [chunk[0], chunk[1], chunk[2], chunk[3]];
        let (i, j) = (usize::from(a % 12), usize::from(b % 12));
        let fits = |model: &Vec<u8>, extra: usize| model.len() + extra <= N;
        let items: Vec<u8> = (0..j % 6).map(|k| a.wrapping_add(k as u8)).collect();
        match op % 13 {
            0 => {
                assert_eq!(v.try_push(a).is_ok(), fits(&model, 1));
                if fits(&model, 1) {
                    model.push(a);
                }
            }
            1 => {
                let ok = i <= model.len() && fits(&model, 1);
                assert_eq!(v.try_insert(i, b).is_ok(), ok);
                if ok {
                    model.insert(i, b);
                }
            }
            2 => {
                let ok = fits(&model, items.len());
                assert_eq!(v.try_extend_from_slice(&items).is_ok(), ok);
                if ok {
                    model.extend_from_slice(&items);
                }
            }
            3 => {
                let (start, end) = (bound(kinds, i), bound(kinds / 3, j));
                let len = model.len();
                let s = match start {
                    Bound::Included(n) => n,
                    Bound::Excluded(n) => n + 1,
                    Bound::Unbounded => 0,
                };
                let e = match end {
                    Bound::Included(n) => n + 1,
                    Bound::Excluded(n) => n,
                    Bound::Unbounded => len,
                };
                let result = v.try_extend_from_within((start, end));
                if s > e || e > len {
                    assert_eq!(result, Err(ExtendFromWithinError::InvalidRange { len }));
                } else if !fits(&model, e - s) {
                    assert!(matches!(result, Err(ExtendFromWithinError::Capacity(_))));
                } else {
                    assert_eq!(result, Ok(()));
                    model.extend_from_within(s..e);
                }
            }
            4 => {
                let ok = fits(&model, items.len());
                let mut other = items.clone();
                assert_eq!(v.try_append(&mut other).is_ok(), ok);
                assert_eq!(other.is_empty(), ok || items.is_empty());
                if ok {
                    model.extend_from_slice(&items);
                }
            }
            5 => {
                let ok = fits(&model, items.len());
                // Without a size hint: the overflow is found while pushing.
                assert_eq!(
                    v.try_extend(items.iter().copied().filter(|_| true)).is_ok(),
                    ok
                );
                if ok {
                    model.extend_from_slice(&items);
                }
            }
            6 => {
                v.truncate(i);
                model.truncate(i);
            }
            7 => assert_eq!(v.pop(), model.pop()),
            8 => {
                v.clear();
                model.clear();
            }
            9 => {
                if i < model.len() {
                    assert_eq!(v.remove(i), model.remove(i));
                }
            }
            10 => {
                v.dedup();
                model.dedup();
            }
            11 => {
                v.retain(|x| *x != a);
                model.retain(|x| *x != a);
            }
            _ => {
                if i <= j && j <= model.len() {
                    assert!(v.drain(i..j).eq(model.drain(i..j)));
                }
            }
        }
        assert!(v.len() <= N);
        assert!(v.capacity() <= N);
        assert_eq!(&v[..], &model[..]);
    }
    let bytes = borsh::to_vec(&v).unwrap();
    assert_eq!(borsh::from_slice::<SafeVec<u8, N>>(&bytes).unwrap(), v);
}

fn string_ops(data: &[u8]) {
    let mut s = SizedSafeString::<N>::new();
    let mut model = String::new();
    for &byte in data {
        let c = char::from(byte);
        let ok = model.len() < N && (0x20..=0x7e).contains(&byte);
        assert_eq!(s.try_push(c).is_ok(), ok);
        if ok {
            model.push(c);
        }
        assert_eq!(s.as_str(), model);
    }
}

fuzz_target!(|data: &[u8]| {
    vec_ops(data);
    string_ops(data);

    if let Some(v) = borsh_canonical::<SafeVec<u8, 16>>(data) {
        assert!(v.len() <= 16);
    }
    if let Some(v) = borsh_canonical::<SafeVec<u32, 4>>(data) {
        assert!(v.len() <= 4);
    }
    if let Some(v) = borsh_canonical::<SafeVec<SafeVec<u8, 3>, 3>>(data) {
        assert!(v.len() <= 3 && v.iter().all(|inner| inner.len() <= 3));
    }
    if let Some(s) = borsh_canonical::<SizedSafeString<16>>(data) {
        assert!(s.len() <= 16 && printable(s.as_str()));
    }
    if let Some(h) = borsh_canonical::<HexString<SafeVec<u8, 8>>>(data) {
        assert!(h.0.len() <= 8);
    }
    // Zero-sized elements are rejected by every decoder (no division by zero).
    assert!(borsh::from_slice::<SafeVec<(), 4>>(data).is_err());
    assert!(postcard::from_bytes::<SafeVec<(), 4>>(data).is_err());
    if let Ok(v) = postcard::from_bytes::<SafeVec<u8, 16>>(data) {
        assert!(v.len() <= 16);
    }
    if let Ok(s) = postcard::from_bytes::<SizedSafeString<16>>(data) {
        assert!(s.len() <= 16 && printable(s.as_str()));
    }
    // The capped `HexString` decoders (cap checked before decoding) accept exactly what the
    // uncapped one accepts within the cap.
    let uncapped = postcard::from_bytes::<HexString>(data).ok().map(|h| h.0);
    let capped = postcard::from_bytes::<HexString<SafeVec<u8, 8>>>(data).ok();
    assert_eq!(
        capped.map(|h| h.0.as_ref().to_vec()),
        uncapped.clone().filter(|v| v.len() <= 8)
    );
    let fixed = postcard::from_bytes::<HexString<[u8; 4]>>(data).ok();
    assert_eq!(
        fixed.map(|h| h.0.to_vec()),
        uncapped.filter(|v| v.len() == 4)
    );

    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(v) = json_canonical::<SafeVec<u8, 16>>(s) {
        assert!(v.len() <= 16);
    }
    if let Some(v) = json_canonical::<SafeVec<SafeVec<u8, 3>, 3>>(s) {
        assert!(v.len() <= 3 && v.iter().all(|inner| inner.len() <= 3));
    }
    if let Some(s) = json_canonical::<SizedSafeString<16>>(s) {
        assert!(s.len() <= 16 && printable(s.as_str()));
    }
    if let Some(h) = json_canonical::<HexString<SafeVec<u8, 8>>>(s) {
        assert!(h.0.len() <= 8);
    }
    assert!(serde_json::from_str::<SafeVec<(), 4>>(s).is_err());
    let uncapped = serde_json::from_str::<HexString>(s).ok().map(|h| h.0);
    let capped = serde_json::from_str::<HexString<SafeVec<u8, 8>>>(s).ok();
    assert_eq!(
        capped.map(|h| h.0.as_ref().to_vec()),
        uncapped.filter(|v| v.len() <= 8)
    );
    let uncapped = HexString::<Vec<u8>>::from_str(s).ok().map(|h| h.0);
    let capped = str_canonical::<HexString<SafeVec<u8, 8>>>(s);
    assert_eq!(
        capped.map(|h| h.0.as_ref().to_vec()),
        uncapped.clone().filter(|v| v.len() <= 8)
    );
    let fixed = HexString::<[u8; 4]>::from_str(s).ok();
    assert_eq!(
        fixed.map(|h| h.0.to_vec()),
        uncapped.filter(|v| v.len() == 4)
    );
    if let Some(parsed) = str_canonical::<SizedSafeString<16>>(s) {
        assert!(parsed.len() <= 16 && printable(parsed.as_str()));
    }
});

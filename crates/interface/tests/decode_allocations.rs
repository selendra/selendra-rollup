//! The capped types' decoders reject input over the cap before allocating for it
//! (docs/serialization.md, "Bounded containers and strings").
//!
//! One test in its own binary: the counting allocator is global, so nothing else may run while
//! it measures.

use std::alloc::System;
use std::str::FromStr;

use selendra_interface::common::{HexString, SafeString, SafeVec};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// The size of the inputs over the cap (or the length they claim).
const BIG: usize = 1 << 20;

/// What a rejected decode may allocate (error messages): far below [`BIG`].
const SMALL: usize = 16 * 1024;

/// A decode that must fail, with its error as a string.
type Decode<'a> = Box<dyn Fn() -> Result<(), String> + 'a>;

/// Runs `decode`, which must fail, and returns the bytes it allocated.
fn allocated_by_failed(decode: Decode<'_>) -> usize {
    let region = Region::new(GLOBAL);
    let result = decode();
    let bytes = region.change().bytes_allocated;
    assert!(result.is_err(), "decoding should fail");
    bytes
}

fn err<T, E: std::fmt::Display>(result: Result<T, E>) -> Result<(), String> {
    result.map(drop).map_err(|e| e.to_string())
}

/// Regression (S1 review): `SizedSafeString`'s serde decoder copied the whole string before
/// checking its length, and `HexString<SafeVec<u8, N>>`'s hex-decoded the whole string (or, in
/// a binary format, preallocated up to 1 MiB for the claimed length) before checking the cap.
#[test]
fn over_cap_input_is_rejected_before_allocating() {
    type CappedHex = HexString<SafeVec<u8, 8>>;
    let long_string = "a".repeat(BIG);
    let long_json_string = serde_json::to_string(&long_string).unwrap();
    let long_postcard_string = postcard::to_allocvec(&long_string).unwrap();
    let long_borsh_string = borsh::to_vec(&long_string).unwrap();
    let long_hex = format!("0x{}", "ab".repeat(BIG / 2));
    let long_json_hex = serde_json::to_string(&long_hex).unwrap();
    // postcard: `BIG` bytes. postcard reports the claimed length as the size hint only when
    // the input holds that many bytes.
    let big_bytes = postcard::to_allocvec(&vec![0u8; BIG]).unwrap();

    // The counter works: decoding into the uncapped types allocates for the input, and
    // serde's `Vec<u8>` preallocates for the claimed length.
    let region = Region::new(GLOBAL);
    drop(serde_json::from_str::<String>(&long_json_string).unwrap());
    assert!(region.change().bytes_allocated >= BIG);
    let region = Region::new(GLOBAL);
    drop(postcard::from_bytes::<Vec<u8>>(&big_bytes).unwrap());
    assert!(region.change().bytes_allocated >= BIG);

    let cases: [(&str, Decode<'_>); 8] = [
        (
            "SafeString from JSON",
            Box::new(|| err(serde_json::from_str::<SafeString>(&long_json_string))),
        ),
        (
            "SafeString from postcard",
            Box::new(|| err(postcard::from_bytes::<SafeString>(&long_postcard_string))),
        ),
        (
            "SafeString from borsh",
            Box::new(|| err(borsh::from_slice::<SafeString>(&long_borsh_string))),
        ),
        (
            "HexString<SafeVec<u8, 8>> from JSON",
            Box::new(|| err(serde_json::from_str::<CappedHex>(&long_json_hex))),
        ),
        (
            "HexString<SafeVec<u8, 8>> from str",
            Box::new(|| err(CappedHex::from_str(&long_hex))),
        ),
        (
            "HexString<SafeVec<u8, 8>> from postcard",
            Box::new(|| err(postcard::from_bytes::<CappedHex>(&big_bytes))),
        ),
        (
            "HexString<[u8; 32]> from postcard",
            Box::new(|| err(postcard::from_bytes::<HexString<[u8; 32]>>(&big_bytes))),
        ),
        (
            "SafeVec<u8, 8> from postcard",
            Box::new(|| err(postcard::from_bytes::<SafeVec<u8, 8>>(&big_bytes))),
        ),
    ];
    let over: Vec<String> = cases
        .into_iter()
        .map(|(name, decode)| (name, allocated_by_failed(decode)))
        .filter(|&(_, bytes)| bytes >= SMALL)
        .map(|(name, bytes)| format!("{name}: {bytes} bytes allocated"))
        .collect();
    assert!(over.is_empty(), "{over:#?}");
}

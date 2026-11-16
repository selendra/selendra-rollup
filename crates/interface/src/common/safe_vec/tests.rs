use std::ops::Bound;

use proptest::prelude::*;
use serde::de::{DeserializeSeed, SeqAccess};

use super::*;

macro_rules! safe_vec {
    ($elem:expr; $n:expr) => {
        vec![$elem; $n].try_into().unwrap()
    };
    ($($x:expr),+ $(,)?) => {
        vec![$($x),+].try_into().unwrap()
    };
}

#[test]
fn test_try_insert_doesnt_panic() {
    let mut v = SafeVec::<_, 1000>::new();
    assert_eq!(v.len(), 0);
    for i in 0..1000 {
        assert!(v.try_insert(i, 1).is_ok());
    }
    assert!(v.try_insert(0, 0).is_err());
    assert_eq!(v.len(), 1000);
}

#[test]
fn test_try_insert_past_the_end_is_err() {
    let mut v: SafeVec<u8, 10> = safe_vec![1, 2];
    assert_eq!(v.try_insert(3, 9), Err(CapacityError(9)));
    assert_eq!(&v[..], [1, 2]);
    assert!(v.try_insert(2, 3).is_ok());
    assert_eq!(&v[..], [1, 2, 3]);
}

#[test]
fn test_try_push_doesnt_panic() {
    let mut v = SafeVec::<_, 1000>::new();
    assert_eq!(v.len(), 0);
    for i in 0..1000 {
        assert!(v.try_push(i).is_ok());
    }
    assert_eq!(v.try_push(7), Err(CapacityError(7)));
    assert_eq!(v.len(), 1000);
}

#[test]
fn test_try_from_vec() {
    let v = vec![1u8; 100];
    assert!(TryInto::<SafeVec<u8, 99>>::try_into(v.clone()).is_err());
    assert!(TryInto::<SafeVec<u8, 100>>::try_into(v.clone()).is_ok());
    assert!(TryInto::<SafeVec<u8, 101>>::try_into(v).is_ok());
}

#[test]
fn test_try_from_slice() {
    let v = vec![1u8; 100];
    assert!(TryInto::<SafeVec<u8, 99>>::try_into(v.as_slice()).is_err());
    assert!(TryInto::<SafeVec<u8, 100>>::try_into(v.as_slice()).is_ok());
    assert!(TryInto::<SafeVec<u8, 101>>::try_into(v.as_slice()).is_ok());
}

#[test]
fn test_try_append() {
    let mut v: SafeVec<_, 10> = SafeVec::new();
    assert!(v.try_append(&mut vec![0u8; 5]).is_ok());
    assert!(v.try_append(&mut vec![0u8; 5]).is_ok());
    let mut other = vec![0u8; 1];
    assert!(v.try_append(&mut other).is_err());
    assert_eq!(other.len(), 1, "a failed append leaves `other` alone");
}

#[test]
fn test_try_extend_from_slice() {
    let mut v: SafeVec<_, 10> = SafeVec::new();
    assert!(v.try_extend_from_slice(&[0u8; 5]).is_ok());
    assert!(v.try_extend_from_slice(&[0u8; 5]).is_ok());
    assert!(v.try_extend_from_slice(&[0u8; 1]).is_err());
}

#[test]
fn test_try_extend_from_within() {
    let mut v: SafeVec<_, 10> = SafeVec::new();
    assert!(v.try_extend_from_slice(&[0u8; 5]).is_ok());
    assert!(v.try_extend_from_within(0..5).is_ok());
    assert!(v.try_extend_from_within(0..1).is_err());
}

#[test]
fn test_try_extend_is_atomic() {
    let mut v: SafeVec<u8, 4> = safe_vec![1, 2];
    // `filter` hides the length from the size hint, so the overflow is found while pushing.
    assert!(
        v.try_extend([3, 4, 5].into_iter().filter(|_| true))
            .is_err()
    );
    assert_eq!(&v[..], [1, 2]);
    assert!(v.try_extend([3, 4].into_iter().filter(|_| true)).is_ok());
    assert_eq!(&v[..], [1, 2, 3, 4]);
}

/// Growing through the fallible API never asks for room for more than `MAX_SIZE` elements.
/// (Upstream checked this with an over-allocating global allocator, which needs `unsafe`.)
#[test]
fn test_growth_never_reserves_past_max_size() {
    let mut v = SafeVec::<u32, 1000>::new();
    for i in 0..1000 {
        v.try_push(i).unwrap();
        assert!(v.capacity() <= 1000, "{}", v.capacity());
    }
    let mut v = SafeVec::<u8, 7>::new();
    v.try_extend_from_slice(&[1, 2, 3]).unwrap();
    v.try_extend_from_within(..).unwrap();
    v.try_push(0).unwrap();
    assert!(v.capacity() <= 7);
}

#[test]
fn test_serde_json_roundtrips() {
    const BIG: usize = 1_000_001;
    let vec: SafeVec<_, BIG> = safe_vec![7u8; BIG];

    let serialized = &serde_json::to_vec(&vec).unwrap();
    let output: SafeVec<_, BIG> = serde_json::from_slice(serialized).unwrap();
    assert_eq!(vec, output);

    let way_too_small: Result<SafeVec<u8, 1>, _> = serde_json::from_slice(serialized);
    assert!(way_too_small.is_err());

    let too_small: Result<SafeVec<u8, 1_000_000>, _> = serde_json::from_slice(serialized);
    assert!(too_small.is_err());

    let too_big: Result<SafeVec<u8, 1_000_002>, _> = serde_json::from_slice(serialized);
    assert!(too_big.is_ok());
}

/// Upstream's `test_bincode_roundtrips`, with postcard (a format with exact size hints).
#[test]
fn test_postcard_roundtrips() {
    const BIG: usize = 1_000_001;
    let vec: SafeVec<_, BIG> = safe_vec![7u8; BIG];

    let serialized = &postcard::to_allocvec(&vec).unwrap();
    let output: SafeVec<_, BIG> = postcard::from_bytes(serialized).unwrap();
    assert_eq!(vec, output);

    let way_too_small: Result<SafeVec<u8, 1>, _> = postcard::from_bytes(serialized);
    assert!(way_too_small.is_err());

    let too_small: Result<SafeVec<u8, 1_000_000>, _> = postcard::from_bytes(serialized);
    assert!(too_small.is_err());

    let too_big: Result<SafeVec<u8, 1_000_002>, _> = postcard::from_bytes(serialized);
    assert!(too_big.is_ok());
}

#[test]
fn test_borsh_roundtrips() {
    const BIG: usize = 1_000_001;
    let vec: SafeVec<_, BIG> = safe_vec![7u8; BIG];

    let serialized = &borsh::to_vec(&vec).unwrap();
    assert_eq!(serialized, &borsh::to_vec(&vec![7u8; BIG]).unwrap());
    let output: SafeVec<_, BIG> = borsh::from_slice(serialized).unwrap();
    assert_eq!(vec, output);

    let way_too_small: Result<SafeVec<u8, 1>, _> = borsh::from_slice(serialized);
    assert!(way_too_small.is_err());

    let too_small: Result<SafeVec<u8, 1_000_000>, _> = borsh::from_slice(serialized);
    assert!(too_small.is_err());

    let too_big: Result<SafeVec<u8, 1_000_002>, _> = borsh::from_slice(serialized);
    assert!(too_big.is_ok());
}

#[test]
fn test_borsh_rejects_bad_input_without_panicking() {
    // A huge claimed length is rejected before anything is allocated for it.
    assert!(borsh::from_slice::<SafeVec<u8, 4>>(&[0xff, 0xff, 0xff, 0xff]).is_err());
    assert!(borsh::from_slice::<SafeVec<u64, { u32::MAX as usize }>>(&[0xff; 4]).is_err());
    // Short input, trailing bytes.
    assert!(borsh::from_slice::<SafeVec<u8, 4>>(&[2, 0, 0, 0, 1]).is_err());
    assert!(borsh::from_slice::<SafeVec<u8, 4>>(&[1, 0, 0, 0, 1, 2]).is_err());
    assert_eq!(
        borsh::from_slice::<SafeVec<u16, 4>>(&[2, 0, 0, 0, 1, 0, 2, 0]).unwrap(),
        SafeVec::<u16, 4>::try_from(vec![1, 2]).unwrap()
    );
}

#[test]
fn test_json_schema() {
    let schema = serde_json::to_value(schemars::schema_for!(SafeVec<u8, 3>)).unwrap();
    assert_eq!(schema["type"], "array");
    assert_eq!(schema["maxItems"], 3);
    assert_eq!(schema["minItems"], 0);
    assert_eq!(schema["title"], "SafeVec_3_of_uint8");
}

#[test]
fn test_arbitrary_respects_the_cap() {
    let data = [0xffu8; 4096];
    let mut u = arbitrary::Unstructured::new(&data);
    let v: SafeVec<u8, 5> = arbitrary::Arbitrary::arbitrary(&mut u).unwrap();
    assert!(v.len() <= 5);
}

// Regressions of upstream's `SafeVec` bugs

/// P5-01: an inclusive end bound copied one element more than the capacity check counted, so
/// a full vector grew past `MAX_SIZE` (and its borsh encoding then failed to decode).
#[test]
fn try_extend_from_within_inclusive_end_is_capped() {
    let mut v: SafeVec<u8, 4> = safe_vec![1, 2, 3, 4];
    assert_eq!(
        v.try_extend_from_within(0..=0),
        Err(ExtendFromWithinError::Capacity(CapacityError(())))
    );
    assert_eq!(v.len(), 4);
    assert!(borsh::from_slice::<SafeVec<u8, 4>>(&borsh::to_vec(&v).unwrap()).is_ok());

    let mut v: SafeVec<u8, 5> = safe_vec![1, 2, 3, 4];
    v.try_extend_from_within(1..=1).unwrap();
    assert_eq!(&v[..], [1, 2, 3, 4, 2]);
    let mut v: SafeVec<u8, 6> = safe_vec![1, 2, 3];
    v.try_extend_from_within((Bound::Excluded(0), Bound::Included(2)))
        .unwrap();
    assert_eq!(&v[..], [1, 2, 3, 2, 3]);
}

/// P5-01: a reversed range or one past the end panicked (an `expect`, then `Vec`'s own
/// bounds check).
#[test]
fn try_extend_from_within_invalid_range_is_err() {
    let mut v: SafeVec<u8, 100> = safe_vec![1, 2, 3];
    let invalid = Err(ExtendFromWithinError::InvalidRange { len: 3 });
    #[allow(clippy::reversed_empty_ranges)]
    let reversed = 2..1;
    assert_eq!(v.try_extend_from_within(reversed), invalid);
    assert_eq!(v.try_extend_from_within(0..4), invalid);
    assert_eq!(v.try_extend_from_within(1..=3), invalid);
    assert_eq!(v.try_extend_from_within(4..), invalid);
    assert_eq!(v.try_extend_from_within(..=usize::MAX), invalid);
    assert_eq!(
        v.try_extend_from_within((Bound::Excluded(usize::MAX), Bound::Unbounded)),
        invalid
    );
    assert_eq!(&v[..], [1, 2, 3]);
    // An empty range at the end is valid.
    v.try_extend_from_within(3..3).unwrap();
    assert_eq!(&v[..], [1, 2, 3]);
}

/// P5-02: the serde decoder divided by the element size, so zero-sized elements panicked
/// (division by zero) in a format with a size hint, and were accepted in one without, while
/// borsh rejects them.
#[test]
fn serde_zero_sized_is_error() {
    let with_size_hint = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(
        std::iter::repeat_n((), 2),
    );
    assert!(<SafeVec<(), 4> as Deserialize>::deserialize(with_size_hint).is_err());
    let bytes = postcard::to_allocvec(&vec![(); 3]).unwrap();
    assert!(postcard::from_bytes::<SafeVec<(), 4>>(&bytes).is_err());
    assert!(serde_json::from_str::<SafeVec<(), 4>>("[null]").is_err());
    assert!(borsh::from_slice::<SafeVec<(), 4>>(&[1, 0, 0, 0]).is_err());
}

/// A sequence whose size hint says 1 but which holds `items`.
struct UnderReported(Vec<u8>);

impl<'de> SeqAccess<'de> for UnderReported {
    type Error = serde::de::value::Error;

    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> std::result::Result<Option<S::Value>, Self::Error> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let item = self.0.remove(0);
        seed.deserialize(serde::de::value::U8Deserializer::new(item))
            .map(Some)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(1)
    }
}

/// P5-03: the decoder read at most as many elements as the size hint claimed and then
/// rejected the rest as over the cap, so valid input with an under-reported hint failed.
#[test]
fn serde_ignores_short_size_hint() {
    let decode = |items: Vec<u8>| {
        <SafeVec<u8, 4> as Deserialize>::deserialize(serde::de::value::SeqAccessDeserializer::new(
            UnderReported(items),
        ))
    };
    assert_eq!(&decode(vec![1, 2, 3]).unwrap()[..], [1, 2, 3]);
    assert_eq!(&decode(vec![1, 2, 3, 4]).unwrap()[..], [1, 2, 3, 4]);
    assert!(decode(vec![1, 2, 3, 4, 5]).is_err());
}

/// A bound, for building any kind of range.
#[derive(Debug, Clone, Copy, proptest_derive::Arbitrary)]
enum B {
    Included(#[proptest(strategy = "0usize..12")] usize),
    Excluded(#[proptest(strategy = "0usize..12")] usize),
    Unbounded,
}

impl B {
    fn bound(self) -> Bound<usize> {
        match self {
            Self::Included(n) => Bound::Included(n),
            Self::Excluded(n) => Bound::Excluded(n),
            Self::Unbounded => Bound::Unbounded,
        }
    }
}

#[derive(Debug, Clone, proptest_derive::Arbitrary)]
enum Op {
    Push(u8),
    Insert(#[proptest(strategy = "0usize..12")] usize, u8),
    ExtendFromSlice(#[proptest(strategy = "proptest::collection::vec(any::<u8>(), 0..6)")] Vec<u8>),
    ExtendFromWithin(B, B),
    Append(#[proptest(strategy = "proptest::collection::vec(any::<u8>(), 0..6)")] Vec<u8>),
    Extend(#[proptest(strategy = "proptest::collection::vec(any::<u8>(), 0..6)")] Vec<u8>),
    Truncate(#[proptest(strategy = "0usize..12")] usize),
    Pop,
    Clear,
    Remove(#[proptest(strategy = "0usize..12")] usize),
    Dedup,
    Retain(u8),
    Drain(
        #[proptest(strategy = "0usize..12")] usize,
        #[proptest(strategy = "0usize..12")] usize,
    ),
}

const N: usize = 8;

/// Applies `op` to `v` and to the model, which spells out the expected semantics: a failed
/// operation changes nothing.
fn apply(v: &mut SafeVec<u8, N>, model: &mut Vec<u8>, op: Op) {
    let fits = |model: &Vec<u8>, extra: usize| model.len() + extra <= N;
    match op {
        Op::Push(x) => {
            assert_eq!(v.try_push(x).is_ok(), fits(model, 1));
            if fits(model, 1) {
                model.push(x);
            }
        }
        Op::Insert(i, x) => {
            let ok = i <= model.len() && fits(model, 1);
            assert_eq!(v.try_insert(i, x).is_ok(), ok);
            if ok {
                model.insert(i, x);
            }
        }
        Op::ExtendFromSlice(s) => {
            assert_eq!(v.try_extend_from_slice(&s).is_ok(), fits(model, s.len()));
            if fits(model, s.len()) {
                model.extend_from_slice(&s);
            }
        }
        Op::ExtendFromWithin(start, end) => {
            let len = model.len();
            let s = match start.bound() {
                Bound::Included(n) => n,
                Bound::Excluded(n) => n + 1,
                Bound::Unbounded => 0,
            };
            let e = match end.bound() {
                Bound::Included(n) => n + 1,
                Bound::Excluded(n) => n,
                Bound::Unbounded => len,
            };
            let result = v.try_extend_from_within((start.bound(), end.bound()));
            if s > e || e > len {
                assert_eq!(result, Err(ExtendFromWithinError::InvalidRange { len }));
            } else if !fits(model, e - s) {
                assert_eq!(result, Err(CapacityError(()).into()));
            } else {
                assert_eq!(result, Ok(()));
                model.extend_from_within(s..e);
            }
        }
        Op::Append(mut other) => {
            let ok = fits(model, other.len());
            let before = other.clone();
            assert_eq!(v.try_append(&mut other).is_ok(), ok);
            if ok {
                assert!(other.is_empty());
                model.extend_from_slice(&before);
            } else {
                assert_eq!(other, before);
            }
        }
        Op::Extend(items) => {
            let ok = fits(model, items.len());
            // Once with an exact size hint, once with none.
            let mut copy = v.clone();
            assert_eq!(v.try_extend(items.clone()).is_ok(), ok);
            assert_eq!(
                copy.try_extend(items.iter().copied().filter(|_| true))
                    .is_ok(),
                ok
            );
            assert_eq!(copy, *v);
            if ok {
                model.extend_from_slice(&items);
            }
        }
        Op::Truncate(n) => {
            v.truncate(n);
            model.truncate(n);
        }
        Op::Pop => assert_eq!(v.pop(), model.pop()),
        Op::Clear => {
            v.clear();
            model.clear();
        }
        Op::Remove(i) => {
            if i < model.len() {
                assert_eq!(v.remove(i), model.remove(i));
            }
        }
        Op::Dedup => {
            v.dedup();
            model.dedup();
        }
        Op::Retain(x) => {
            v.retain(|y| *y != x);
            model.retain(|y| *y != x);
        }
        Op::Drain(a, b) => {
            if a <= b && b <= model.len() {
                assert!(v.drain(a..b).eq(model.drain(a..b)));
            }
        }
    }
}

#[test_strategy::proptest]
fn ops_never_exceed_max_size(
    #[strategy(proptest::collection::vec(any::<Op>(), 0..40))] ops: Vec<Op>,
) {
    let mut v = SafeVec::<u8, N>::new();
    let mut model = Vec::new();
    for op in ops {
        apply(&mut v, &mut model, op);
        prop_assert!(v.len() <= N);
        prop_assert!(v.capacity() <= N);
        prop_assert_eq!(&v[..], &model[..]);
    }
    let encoded = borsh::to_vec(&v).unwrap();
    prop_assert_eq!(borsh::from_slice::<SafeVec<u8, N>>(&encoded).unwrap(), v);
}

#[test_strategy::proptest]
fn roundtrips(v: SafeVec<u16, 5>, nested: SafeVec<SafeVec<u8, 3>, 3>) {
    prop_assert!(v.len() <= 5);
    let borsh_bytes = borsh::to_vec(&v).unwrap();
    prop_assert_eq!(&borsh_bytes, &borsh::to_vec(&Vec::from(v.clone())).unwrap());
    prop_assert_eq!(
        &borsh::from_slice::<SafeVec<u16, 5>>(&borsh_bytes).unwrap(),
        &v
    );
    let json = serde_json::to_string(&v).unwrap();
    prop_assert_eq!(&serde_json::from_str::<SafeVec<u16, 5>>(&json).unwrap(), &v);
    let bin = postcard::to_allocvec(&v).unwrap();
    prop_assert_eq!(&postcard::from_bytes::<SafeVec<u16, 5>>(&bin).unwrap(), &v);

    let bytes = borsh::to_vec(&nested).unwrap();
    prop_assert_eq!(
        borsh::from_slice::<SafeVec<SafeVec<u8, 3>, 3>>(&bytes).unwrap(),
        nested
    );
}

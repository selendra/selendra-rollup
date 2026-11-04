//! Serialization of keys and values stored in state.
//!
//! Containers encode keys with [`StateCodec::KeyCodec`] and values with
//! [`StateCodec::ValueCodec`]. The default codec, [`BorshCodec`], uses borsh for both, so stored
//! bytes follow the rules in `docs/serialization.md`.

use core::fmt;
use std::io::Write;

use selendra_interface::common::HexString;

/// A trait for types that can serialize and deserialize values for storage access.
///
/// # Round-trip precondition
/// Containers decode stored values with [`StateItemDecoder::decode_unwrap`], which panics. That
/// is sound only if, for **every** value `v` of the stored type that can be constructed,
/// `try_decode(encode(v))` succeeds and returns `v`. A type whose decoder is stricter than its
/// encoder breaks this: e.g. `selendra_interface::stf::RawTx` has a public `data` field and an
/// unbounded encoder, but its decoder rejects more than `MAX_RAW_TX_SIZE` bytes, so a stored
/// over-size `RawTx` would panic on every later read. Such a type must enforce its bound at
/// construction, or must not be stored directly. Containers check this precondition with a
/// `debug_assert!` on every write (debug builds only).
pub trait StateItemCodec<V>: StateItemEncoder<V> + StateItemDecoder<V> {}

/// A trait for types that can serialize values into storage.
pub trait StateItemEncoder<V: ?Sized> {
    /// Serializes a value into a writer.
    ///
    /// This method **must** not panic for a writer that cannot fail (such as a [`Vec<u8>`], which
    /// is what this crate passes), as all instances of the value type are supposed to be
    /// serializable. That is a requirement on the value type as much as on the codec: see
    /// [`BorshCodec`] for the values borsh refuses (and this crate then panics on).
    fn encode(&self, value: &V, writer: &mut impl Write);

    /// Serializes a value into a bytes vector.
    ///
    /// This method **must** not panic as all instances of the value type are supposed to be
    /// serializable.
    fn encode_to_vec(&self, value: &V) -> Vec<u8> {
        let mut out = vec![];
        self.encode(value, &mut out);
        out
    }
}

/// A trait for types that can deserialize values from storage.
pub trait StateItemDecoder<V>: Clone + Send + Sync + 'static {
    /// Error type that can arise during deserialization.
    type Error: fmt::Debug;

    /// Tries to deserialize a value from a bytes slice, and returns a [`Result`] with either the
    /// deserialized value or an error.
    ///
    /// Must reject trailing bytes, so each value has one accepted encoding.
    fn try_decode(&self, bytes: &[u8]) -> Result<V, Self::Error>;

    /// Deserializes a value from a bytes slice.
    ///
    /// Containers use this for values they read back from state. See
    /// [`StateReader::get_decoded`](crate::StateReader::get_decoded) for when a failure can
    /// happen (a bug, corrupt state, or an invalid witness in the zk guest) and why panicking is
    /// the intended result.
    ///
    /// # Panics
    /// Panics if the call to [`StateItemDecoder::try_decode`] fails. Use
    /// [`StateItemDecoder::try_decode`] if you need to gracefully handle errors. The message
    /// shows at most the first [`DECODE_PANIC_PREVIEW_BYTES`] bytes and the total length, so a
    /// large value is never formatted whole (a multi-megabyte allocation in the zk guest).
    fn decode_unwrap(&self, bytes: &[u8]) -> V {
        match self.try_decode(bytes) {
            Ok(value) => value,
            Err(err) => panic!(
                "Failed to decode {} value {}, error: {:?}",
                core::any::type_name::<V>(),
                BytesPreview(bytes),
                err
            ),
        }
    }
}

impl<C, V> StateItemCodec<V> for C where C: StateItemEncoder<V> + StateItemDecoder<V> {}

/// How many bytes of an undecodable value [`StateItemDecoder::decode_unwrap`] shows in its panic
/// message.
pub const DECODE_PANIC_PREVIEW_BYTES: usize = 32;

/// `0x`-hex of at most the first [`DECODE_PANIC_PREVIEW_BYTES`] bytes, then `… (N bytes)` if the
/// value is longer.
struct BytesPreview<'a>(&'a [u8]);

impl fmt::Display for BytesPreview<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.get(..DECODE_PANIC_PREVIEW_BYTES) {
            Some(head) if head.len() < self.0.len() => {
                write!(f, "{}… ({} bytes)", HexString(head), self.0.len())
            }
            _ => write!(f, "{}", HexString(self.0)),
        }
    }
}

/// A trait for types that can serialize keys and values, as well as deserializing values for
/// storage access.
///
/// # Type bounds
/// There are no type bounds on [`StateCodec::KeyCodec`] and [`StateCodec::ValueCodec`], so they
/// can be any type at all. That said, you'll find many APIs require these two to implement
/// [`StateItemCodec`].
pub trait StateCodec: Default + Clone + Send + Sync + 'static {
    /// The codec used to serialize keys. See [`StateItemCodec`].
    type KeyCodec;
    /// The codec used to serialize and deserialize values. See [`StateItemCodec`].
    type ValueCodec;

    /// Returns a reference to the type's key codec.
    fn key_codec(&self) -> &Self::KeyCodec;
    /// Returns a reference to the type's value codec.
    fn value_codec(&self) -> &Self::ValueCodec;
}

/// A trait for codecs which know how to serialize a type `Ref` as if it were some other type
/// `Target`.
///
/// A good example of this is [`BorshCodec`], which knows how to serialize a `[T]` as if it were
/// a [`Vec<T>`]: a map keyed by `Vec<T>` can then be queried with a slice.
pub trait EncodeLike<Ref: ?Sized, Target>: StateItemEncoder<Target> {
    /// Encodes a reference to `Ref` as if it were a reference to `Target`.
    fn encode_like(&self, borrowed: &Ref, writer: &mut impl Write);

    /// Encodes a reference to `Ref` as if it were a reference to `Target` and returns a
    /// `Vec<u8>`.
    fn encode_to_vec_like(&self, borrowed: &Ref) -> Vec<u8> {
        let mut writer = vec![];
        self.encode_like(borrowed, &mut writer);
        writer
    }
}

/// All items can be encoded like themselves by all codecs.
impl<C, T> EncodeLike<T, T> for C
where
    C: StateItemCodec<T>,
{
    fn encode_like(&self, borrowed: &T, writer: &mut impl Write) {
        self.encode(borrowed, writer);
    }
}

/// A [`StateCodec`] that uses [`borsh`] for all keys and values.
///
/// Encoding panics wherever borsh returns an error, which for borsh 1.8.1 is:
/// - a collection longer than `u32::MAX` elements (impossible on the 32-bit zk guest);
/// - a collection of zero-sized types;
/// - a NaN `f32`/`f64`, anywhere in the value (borsh refuses to encode NaN);
/// - any error returned by a hand-written [`borsh::BorshSerialize`] impl.
///
/// So key and value types stored with this codec must not contain floats (also banned in
/// consensus code: `docs/serialization.md`), and their `BorshSerialize` must be infallible.
/// Decoding rejects trailing bytes.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct BorshCodec;

impl<V> StateItemEncoder<V> for BorshCodec
where
    V: borsh::BorshSerialize + ?Sized,
{
    fn encode(&self, value: &V, writer: &mut impl Write) {
        borsh::to_writer(writer, value).expect("Failed to serialize value");
    }

    fn encode_to_vec(&self, value: &V) -> Vec<u8> {
        borsh::to_vec(value).expect("Failed to serialize value")
    }
}

impl<V> StateItemDecoder<V> for BorshCodec
where
    V: borsh::BorshDeserialize,
{
    type Error = std::io::Error;

    fn try_decode(&self, bytes: &[u8]) -> Result<V, Self::Error> {
        // Rejects trailing bytes.
        borsh::from_slice(bytes)
    }
}

impl StateCodec for BorshCodec {
    type KeyCodec = Self;
    type ValueCodec = Self;

    fn key_codec(&self) -> &Self::KeyCodec {
        self
    }

    fn value_codec(&self) -> &Self::ValueCodec {
        self
    }
}

// In borsh, a slice is encoded the same way as a vector (a `u32` length, then the elements),
// including the zero-sized-element case, which both refuse.
impl<T> EncodeLike<[T], Vec<T>> for BorshCodec
where
    T: borsh::BorshSerialize,
{
    fn encode_like(&self, borrowed: &[T], writer: &mut impl Write) {
        borsh::to_writer(writer, borrowed).expect("Failed to serialize value");
    }
}

// `HexString` is borsh-encoded exactly like `Vec<u8>`, so a byte slice can stand in for it.
impl EncodeLike<[u8], HexString> for BorshCodec {
    fn encode_like(&self, borrowed: &[u8], writer: &mut impl Write) {
        borsh::to_writer(writer, borrowed).expect("Failed to serialize value");
    }
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::any;
    use proptest::strategy::Strategy;

    use super::*;

    fn arb_vec_i32() -> impl Strategy<Value = Vec<i32>> {
        vec(any::<i32>(), 0..2048)
    }

    #[test_strategy::proptest]
    fn test_borsh_slice_encode_alike(#[strategy(arb_vec_i32())] vec: Vec<i32>) {
        let codec = BorshCodec;
        let mut left = vec![];
        let mut right = vec![];
        <BorshCodec as EncodeLike<[i32], Vec<i32>>>::encode_like(&codec, &vec[..], &mut left);
        codec.encode(&vec, &mut right);
        assert_eq!(left, right);
    }

    #[test_strategy::proptest]
    fn test_borsh_bytes_encode_like_hex_string(bytes: Vec<u8>) {
        let codec = BorshCodec;
        let left = <BorshCodec as EncodeLike<[u8], HexString>>::encode_to_vec_like(&codec, &bytes);
        let right = <BorshCodec as StateItemEncoder<HexString>>::encode_to_vec(
            &codec,
            &HexString(bytes.clone()),
        );
        assert_eq!(left, right);
    }

    #[test]
    fn borsh_decode_rejects_trailing_bytes() {
        let codec = BorshCodec;
        let encoded = codec.encode_to_vec(&7u32);
        assert_eq!(
            StateItemDecoder::<u32>::try_decode(&codec, &encoded).unwrap(),
            7
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(StateItemDecoder::<u32>::try_decode(&codec, &trailing).is_err());
        assert!(StateItemDecoder::<u32>::try_decode(&codec, &[1, 0, 0]).is_err());
    }

    #[test]
    #[should_panic(expected = "Failed to decode u32 value 0x010000, error")]
    fn decode_unwrap_panics_with_the_bytes() {
        let _: u32 = BorshCodec.decode_unwrap(&[1, 0, 0]);
    }

    /// The panic message used to hex-format the whole value (megabytes for a large one).
    #[test]
    fn decode_unwrap_panic_message_is_bounded() {
        let bytes = vec![0xab; 1_000_000];
        let payload = std::panic::catch_unwind(|| {
            let _: u32 = BorshCodec.decode_unwrap(&bytes);
        })
        .unwrap_err();
        let message = payload.downcast_ref::<String>().unwrap();
        let head = format!(
            "0x{}… (1000000 bytes)",
            "ab".repeat(DECODE_PANIC_PREVIEW_BYTES)
        );
        assert!(message.contains(&head), "{message}");
        assert!(message.len() < 300, "{}", message.len());
    }

    #[test]
    fn bytes_preview_shows_short_values_whole() {
        let exact = vec![1; DECODE_PANIC_PREVIEW_BYTES];
        assert_eq!(
            BytesPreview(&exact).to_string(),
            format!("0x{}", "01".repeat(DECODE_PANIC_PREVIEW_BYTES))
        );
        assert_eq!(BytesPreview(&[]).to_string(), "0x");
    }

    /// Pins a documented panic: borsh refuses to encode NaN, so floats must not be stored.
    #[test]
    #[should_panic(expected = "Failed to serialize value")]
    fn borsh_codec_encode_panics_on_nan() {
        let _ = BorshCodec.encode_to_vec(&f64::NAN);
    }
}

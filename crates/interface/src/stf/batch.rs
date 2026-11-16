//! Transaction batch types and utilities.
//!
//! This module defines the core transaction types used throughout Selendra,
//! including fully authenticated transactions ready for DA layer submission.

use base64::Engine;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::Bytes;
use crate::common::deserialize_object_only;

/// Maximum allowed size for a raw transaction in bytes (1MB default)
pub const MAX_RAW_TX_SIZE: usize = 1024 * 1024;

/// Maximum allowed size for a fully baked transaction in bytes 1.05MB default
pub const MAX_FULLY_BAKED_TX_SIZE: usize = (1024 + 50) * 1024;

// A raw transaction behind a one-byte tag, borsh-encoded (`tag ‖ u32 LE length ‖ bytes`), always
// fits in a fully baked transaction: wrapping one can never fail.
const _: () = assert!(MAX_RAW_TX_SIZE + 5 <= MAX_FULLY_BAKED_TX_SIZE);

/// A transaction (or its parts) is larger than its maximum size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("transaction of {size} bytes exceeds maximum allowed size of {max} bytes")]
pub struct TxTooLarge {
    /// The size in bytes (for a [`FullyBakedTx`], data and sequencing data together).
    pub size: usize,
    /// The maximum size in bytes.
    pub max: usize,
}

/// `FullyBakedTx` represents a serialized signed rollup transaction that has been encoded with
/// authentication information and is ready to be placed on the DA layer.
///
/// Its data and sequencing data together are at most [`MAX_FULLY_BAKED_TX_SIZE`] bytes. The
/// fields are private and every constructor checks this, so every value encodes to bytes its
/// decoders accept (the round-trip precondition of stored types).
///
/// JSON: `data` and `sequencing_data` are standard padded base64; only that exact form is
/// accepted, and unknown fields are rejected.
#[serde_as]
#[derive(PartialEq, Eq, Clone, BorshSerialize, Serialize, Default, derive_more::AsRef)]
pub struct FullyBakedTx {
    /// Serialized transaction.
    #[as_ref(forward)]
    #[serde_as(as = "CanonicalBase64")]
    data: Bytes,
    /// Sequencer-provided metadata for each transaction (e.g., timestamps).
    /// This data is NOT signed by users but is added by the sequencer.
    #[serde_as(as = "Option<CanonicalBase64>")]
    sequencing_data: Option<Bytes>,
}

/// Standard padded base64 that decodes only the canonical encoding (padding required, no
/// non-zero trailing bits). `serde_with::base64::Base64` also accepts missing padding, which
/// would give one value several accepted strings.
struct CanonicalBase64;

impl serde_with::SerializeAs<Bytes> for CanonicalBase64 {
    fn serialize_as<S: serde::Serializer>(
        source: &Bytes,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(source))
    }
}

impl<'de> serde_with::DeserializeAs<'de, Bytes> for CanonicalBase64 {
    fn deserialize_as<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Bytes, D::Error> {
        let encoded = <String as Deserialize>::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map(Bytes::from)
            .map_err(serde::de::Error::custom)
    }
}

/// Whether `data_len + seq_len` fits in [`MAX_FULLY_BAKED_TX_SIZE`], given `data_len` already does.
///
/// Computed in `u32` (the width of the encoded lengths) as a subtraction: `data_len + seq_len`
/// overflows for crafted lengths, and with overflow checks on that would panic, which in the zk
/// guest stops the prover. Doing it in `u32` keeps this true on every platform, so the tests
/// catch a regression even where `usize` is 64 bits.
const fn fits_total_size(data_len: u32, seq_len: u32) -> bool {
    const MAX: u32 = MAX_FULLY_BAKED_TX_SIZE as u32;
    data_len <= MAX && seq_len <= MAX - data_len
}

impl BorshDeserialize for FullyBakedTx {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // Deserialize data field
        let data_len_u32 = u32::deserialize_reader(reader)?;
        let data_len = data_len_u32 as usize;

        // Check if data length exceeds maximum allowed size
        if data_len > MAX_FULLY_BAKED_TX_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "FullyBakedTx data size {data_len} exceeds maximum allowed size of {MAX_FULLY_BAKED_TX_SIZE} bytes",
                ),
            ));
        }

        let mut data_vec = vec![0u8; data_len];
        reader.read_exact(&mut data_vec)?;
        let data = Bytes::from(data_vec);

        // Deserialize sequencing_data field
        // Borsh `Option` tag: only 0 and 1 are canonical. Accepting other values would let
        // different byte strings decode to the same transaction.
        let has_sequencing_data = u8::deserialize_reader(reader)?;
        let sequencing_data = if has_sequencing_data > 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("FullyBakedTx has invalid Option tag {has_sequencing_data}"),
            ));
        } else if has_sequencing_data == 1 {
            let seq_len_u32 = u32::deserialize_reader(reader)?;
            let seq_len = seq_len_u32 as usize;

            // Check if sequencing data would make total size exceed limit.
            if !fits_total_size(data_len_u32, seq_len_u32) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "FullyBakedTx total size {data_len} + {seq_len} exceeds maximum allowed size of {MAX_FULLY_BAKED_TX_SIZE} bytes",
                    ),
                ));
            }

            let mut seq_vec = vec![0u8; seq_len];
            reader.read_exact(&mut seq_vec)?;
            Some(Bytes::from(seq_vec))
        } else {
            None
        };

        Ok(Self {
            data,
            sequencing_data,
        })
    }
}

impl<'de> Deserialize<'de> for FullyBakedTx {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct FullyBakedTxHelper {
            #[serde(with = "serde_with::As::<CanonicalBase64>")]
            data: Bytes,
            #[serde(with = "serde_with::As::<Option<CanonicalBase64>>")]
            sequencing_data: Option<Bytes>,
        }

        let helper: FullyBakedTxHelper = deserialize_object_only(deserializer)?;
        FullyBakedTx::new(helper.data)
            .and_then(|tx| tx.with_sequencing_data(helper.sequencing_data))
            .map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for FullyBakedTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FullyBakedTx")
            .field("data", &hex::encode(&self.data))
            .field(
                "sequencing_data",
                &self.sequencing_data.as_ref().map(hex::encode),
            )
            .finish()
    }
}

impl FullyBakedTx {
    /// A transaction with the given data and no sequencing data.
    ///
    /// # Errors
    /// If `data` is longer than [`MAX_FULLY_BAKED_TX_SIZE`].
    pub fn new(data: Bytes) -> Result<Self, TxTooLarge> {
        if data.len() > MAX_FULLY_BAKED_TX_SIZE {
            return Err(TxTooLarge {
                size: data.len(),
                max: MAX_FULLY_BAKED_TX_SIZE,
            });
        }
        Ok(Self {
            data,
            sequencing_data: None,
        })
    }

    /// Replaces the sequencing data.
    ///
    /// # Errors
    /// If the data and the new sequencing data together are longer than
    /// [`MAX_FULLY_BAKED_TX_SIZE`].
    pub fn with_sequencing_data(self, sequencing_data: Option<Bytes>) -> Result<Self, TxTooLarge> {
        let size = self
            .data
            .len()
            .saturating_add(sequencing_data.as_ref().map_or(0, Bytes::len));
        if size > MAX_FULLY_BAKED_TX_SIZE {
            return Err(TxTooLarge {
                size,
                max: MAX_FULLY_BAKED_TX_SIZE,
            });
        }
        Ok(Self {
            data: self.data,
            sequencing_data,
        })
    }

    /// The serialized transaction.
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// The sequencer-provided metadata, if any. Not signed by the user.
    pub fn sequencing_data(&self) -> Option<&Bytes> {
        self.sequencing_data.as_ref()
    }

    /// Returns the total serialized length of the transaction, including both
    /// the transaction data and sequencing metadata (if present).
    /// This is the length that will be sent on the DA layer.
    #[must_use]
    pub fn len(&self) -> usize {
        // borsh: `u32` length + data, the `Option` tag, then `u32` length + sequencing data.
        // Bounded by `MAX_FULLY_BAKED_TX_SIZE + 9`, so it cannot overflow.
        4 + self.data.len() + 1 + self.sequencing_data.as_ref().map_or(0, |d| 4 + d.len())
    }

    /// Returns the combined length of the raw transaction data and sequencing data fields,
    /// without encoding overhead. This is the quantity that [`MAX_FULLY_BAKED_TX_SIZE`] bounds.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.data.len() + self.sequencing_data.as_ref().map_or(0, Bytes::len)
    }

    /// Returns true if the transaction has no data
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty() && self.sequencing_data.is_none()
    }
}

/// Generates data and sequencing data of at most [`MAX_FULLY_BAKED_TX_SIZE`] bytes together.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for FullyBakedTx {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let data_len = u.arbitrary_len::<u8>()?.min(MAX_FULLY_BAKED_TX_SIZE);
        let data = Bytes::copy_from_slice(u.bytes(data_len)?);
        let sequencing_data = if u.arbitrary()? {
            let len = u
                .arbitrary_len::<u8>()?
                .min(MAX_FULLY_BAKED_TX_SIZE - data_len);
            Some(Bytes::copy_from_slice(u.bytes(len)?))
        } else {
            None
        };
        Ok(Self {
            data,
            sequencing_data,
        })
    }
}

/// Generates small transactions (at most 64 bytes of data and of sequencing data).
#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for FullyBakedTx {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        use proptest::prelude::*;
        let bytes = || proptest::collection::vec(any::<u8>(), 0..=64).prop_map(Bytes::from);
        (bytes(), proptest::option::of(bytes()))
            .prop_map(|(data, sequencing_data)| Self {
                data,
                sequencing_data,
            })
            .boxed()
    }
}

/// `RawTx` represents a serialized signed rollup transaction. A `RawTx` needs to be encoded
/// with authentication information before being placed on the DA layer.
///
/// At most [`MAX_RAW_TX_SIZE`] bytes: the field is private and every constructor checks it,
/// so every value encodes to bytes its decoders accept.
#[derive(PartialEq, Eq, Clone, BorshSerialize, Serialize, derive_more::AsRef)]
pub struct RawTx {
    /// Serialized transaction.
    #[as_ref(forward)]
    data: Vec<u8>,
}

impl std::fmt::Debug for RawTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawTx")
            .field("data", &hex::encode(&self.data))
            .finish()
    }
}

impl BorshDeserialize for RawTx {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // First read the length prefix (u32 in borsh for Vec<u8>)
        let len = u32::deserialize_reader(reader)? as usize;

        // Check if length exceeds maximum allowed size
        if len > MAX_RAW_TX_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("RawTx size {len} exceeds maximum allowed size of {MAX_RAW_TX_SIZE} bytes",),
            ));
        }

        // Read the actual data
        let mut data = vec![0u8; len];
        reader.read_exact(&mut data)?;

        Ok(Self { data })
    }
}

impl<'de> Deserialize<'de> for RawTx {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawTxHelper {
            data: Vec<u8>,
        }

        let helper: RawTxHelper = deserialize_object_only(deserializer)?;
        RawTx::new(helper.data).map_err(serde::de::Error::custom)
    }
}

impl RawTx {
    /// A raw transaction with the given bytes.
    ///
    /// # Errors
    /// If `data` is longer than [`MAX_RAW_TX_SIZE`].
    pub fn new(data: Vec<u8>) -> Result<Self, TxTooLarge> {
        if data.len() > MAX_RAW_TX_SIZE {
            return Err(TxTooLarge {
                size: data.len(),
                max: MAX_RAW_TX_SIZE,
            });
        }
        Ok(Self { data })
    }

    /// The serialized transaction.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// The serialized transaction.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Returns the length of the serialized transaction data
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the transaction has no data
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Generates at most [`MAX_RAW_TX_SIZE`] bytes.
#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for RawTx {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.arbitrary_len::<u8>()?.min(MAX_RAW_TX_SIZE);
        Ok(Self {
            data: u.bytes(len)?.to_vec(),
        })
    }
}

/// Generates small transactions (at most 64 bytes).
#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for RawTx {
    type Parameters = ();
    type Strategy = proptest::strategy::Map<
        proptest::collection::VecStrategy<proptest::num::u8::Any>,
        fn(Vec<u8>) -> Self,
    >;

    fn arbitrary_with((): ()) -> Self::Strategy {
        use proptest::strategy::Strategy;
        proptest::collection::vec(proptest::num::u8::ANY, 0..=64)
            .prop_map((|data| Self { data }) as fn(Vec<u8>) -> Self)
    }
}

crate::impl_consensus_type!(RawTx, FullyBakedTx);

#[cfg(test)]
mod tests {
    use super::*;

    /// A transaction built without the size checks, to test the decoders (only code in this
    /// module can do this).
    fn unchecked(data: Vec<u8>, sequencing_data: Option<Vec<u8>>) -> FullyBakedTx {
        FullyBakedTx {
            data: data.into(),
            sequencing_data: sequencing_data.map(Bytes::from),
        }
    }

    #[test]
    fn test_rawtx_borsh_within_limit() {
        // Create a transaction within the size limit
        let data = vec![1u8; 1024]; // 1KB
        let tx = RawTx::new(data.clone()).unwrap();

        // Serialize with borsh
        let serialized = borsh::to_vec(&tx).unwrap();

        // Deserialize should succeed
        let deserialized: RawTx = borsh::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.data, data);
    }

    #[test]
    fn test_rawtx_borsh_exceeds_limit() {
        // Create a transaction that exceeds the size limit
        let data = vec![1u8; MAX_RAW_TX_SIZE + 1];
        let tx = RawTx { data }; // Not constructible outside this module.

        // Serialize with borsh
        let serialized = borsh::to_vec(&tx).unwrap();

        // Deserialize should fail
        let result: Result<RawTx, _> = borsh::from_slice(&serialized);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum allowed size"));
    }

    #[test]
    fn test_rawtx_serde_json_within_limit() {
        // Create a transaction within the size limit
        let data = vec![1u8; 1024]; // 1KB
        let tx = RawTx::new(data.clone()).unwrap();

        // Serialize with serde_json
        let serialized = serde_json::to_string(&tx).unwrap();

        // Deserialize should succeed
        let deserialized: RawTx = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.data, data);
    }

    #[test]
    fn test_rawtx_serde_json_exceeds_limit() {
        // Create a transaction that exceeds the size limit
        let data = vec![1u8; MAX_RAW_TX_SIZE + 1];
        let tx = RawTx { data }; // Not constructible outside this module.

        // Serialize with serde_json
        let serialized = serde_json::to_string(&tx).unwrap();

        // Deserialize should fail
        let result: Result<RawTx, _> = serde_json::from_str(&serialized);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum allowed size"));
    }

    #[test]
    fn test_rawtx_postcard_within_limit() {
        // Create a transaction within the size limit
        let data = vec![1u8; 1024]; // 1KB
        let tx = RawTx::new(data.clone()).unwrap();

        // Serialize with postcard
        let serialized = postcard::to_allocvec(&tx).unwrap();

        // Deserialize should succeed
        let deserialized: RawTx = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(deserialized.data, data);
    }

    #[test]
    fn test_rawtx_postcard_exceeds_limit() {
        // Create a transaction that exceeds the size limit
        let data = vec![1u8; MAX_RAW_TX_SIZE + 1];
        let tx = RawTx { data }; // Not constructible outside this module.

        // Serialize with postcard
        let serialized = postcard::to_allocvec(&tx).unwrap();

        // Deserialize should fail
        // postcard drops custom error messages, so check the error kind instead.
        let result: Result<RawTx, _> = postcard::from_bytes(&serialized);
        assert_eq!(result.unwrap_err(), postcard::Error::SerdeDeCustom);
    }

    #[test]
    fn test_rawtx_exactly_at_limit() {
        // Create a transaction exactly at the size limit
        let data = vec![1u8; MAX_RAW_TX_SIZE];
        let tx = RawTx::new(data.clone()).unwrap();

        // Test borsh
        let borsh_serialized = borsh::to_vec(&tx).unwrap();
        let borsh_result: RawTx = borsh::from_slice(&borsh_serialized).unwrap();
        assert_eq!(borsh_result.data.len(), MAX_RAW_TX_SIZE);

        // Test serde_json
        let json_serialized = serde_json::to_string(&tx).unwrap();
        let json_result: RawTx = serde_json::from_str(&json_serialized).unwrap();
        assert_eq!(json_result.data.len(), MAX_RAW_TX_SIZE);

        // Test postcard
        let postcard_serialized = postcard::to_allocvec(&tx).unwrap();
        let postcard_result: RawTx = postcard::from_bytes(&postcard_serialized).unwrap();
        assert_eq!(postcard_result.data.len(), MAX_RAW_TX_SIZE);
    }

    #[test]
    fn test_rawtx_empty() {
        // Test empty transaction
        let tx = RawTx::new(vec![]).unwrap();

        // Test borsh
        let borsh_serialized = borsh::to_vec(&tx).unwrap();
        let borsh_result: RawTx = borsh::from_slice(&borsh_serialized).unwrap();
        assert!(borsh_result.is_empty());

        // Test serde_json
        let json_serialized = serde_json::to_string(&tx).unwrap();
        let json_result: RawTx = serde_json::from_str(&json_serialized).unwrap();
        assert!(json_result.is_empty());

        // Test postcard
        let postcard_serialized = postcard::to_allocvec(&tx).unwrap();
        let postcard_result: RawTx = postcard::from_bytes(&postcard_serialized).unwrap();
        assert!(postcard_result.is_empty());
    }

    #[test]
    fn test_fullybaked_borsh_within_limit() {
        // Create a transaction within the size limit
        let data = vec![1u8; 1024]; // 1KB
        let tx = FullyBakedTx::new(data.clone().into()).unwrap();

        // Serialize with borsh
        let serialized = borsh::to_vec(&tx).unwrap();

        // Deserialize should succeed
        let deserialized: FullyBakedTx = borsh::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.data.as_ref(), &data);
    }

    #[test]
    fn test_fullybaked_borsh_exceeds_limit() {
        // Create a transaction that exceeds the size limit
        let data = vec![1u8; MAX_FULLY_BAKED_TX_SIZE + 1];
        let tx = unchecked(data, None);

        // Serialize with borsh
        let serialized = borsh::to_vec(&tx).unwrap();

        // Deserialize should fail
        let result: Result<FullyBakedTx, _> = borsh::from_slice(&serialized);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum allowed size"));
    }

    #[test]
    fn test_fullybaked_with_sequencing_data_within_limit() {
        // Create a transaction with sequencing data, both within limit
        let data = vec![1u8; 1024]; // 1KB
        let seq_data = vec![2u8; 512]; // 512 bytes
        let tx = FullyBakedTx::new(data.clone().into())
            .unwrap()
            .with_sequencing_data(Some(seq_data.into()))
            .unwrap();

        // Test borsh
        let serialized = borsh::to_vec(&tx).unwrap();
        let deserialized: FullyBakedTx = borsh::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.data.as_ref(), &data);
        assert!(deserialized.sequencing_data.is_some());
    }

    #[test]
    fn test_fullybaked_total_size_exceeds_limit() {
        // Create a transaction where data + sequencing_data exceeds limit
        let data = vec![1u8; MAX_FULLY_BAKED_TX_SIZE - 500];
        let seq_data = vec![2u8; 600]; // This will push total over limit
        let tx = unchecked(data, Some(seq_data));

        // Serialize with borsh
        let serialized = borsh::to_vec(&tx).unwrap();

        // Deserialize should fail
        let result: Result<FullyBakedTx, _> = borsh::from_slice(&serialized);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("total size"));
    }

    #[test]
    fn test_fullybaked_serde_json_within_limit() {
        // Create a transaction within the size limit
        let data = vec![1u8; 1024]; // 1KB
        let tx = FullyBakedTx::new(data.clone().into()).unwrap();

        // Serialize with serde_json
        let serialized = serde_json::to_string(&tx).unwrap();

        // Deserialize should succeed
        let deserialized: FullyBakedTx = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.data.as_ref(), &data);
    }

    #[test]
    fn test_fullybaked_serde_json_exceeds_limit() {
        // Create a transaction that exceeds the size limit
        let data = vec![1u8; MAX_FULLY_BAKED_TX_SIZE + 1];
        let tx = unchecked(data, None);

        // Serialize with serde_json
        let serialized = serde_json::to_string(&tx).unwrap();

        // Deserialize should fail
        let result: Result<FullyBakedTx, _> = serde_json::from_str(&serialized);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum allowed size"));
    }

    #[test]
    fn test_fullybaked_postcard_within_limit() {
        // Create a transaction within the size limit
        let data = vec![1u8; 1024]; // 1KB
        let tx = FullyBakedTx::new(data.clone().into()).unwrap();

        // Serialize with postcard
        let serialized = postcard::to_allocvec(&tx).unwrap();

        // Deserialize should succeed
        let deserialized: FullyBakedTx = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(deserialized.data.as_ref(), &data);
    }

    #[test]
    fn test_fullybaked_postcard_exceeds_limit() {
        // Create a transaction that exceeds the size limit
        let data = vec![1u8; MAX_FULLY_BAKED_TX_SIZE + 1];
        let tx = unchecked(data, None);

        // Serialize with postcard
        let serialized = postcard::to_allocvec(&tx).unwrap();

        // Deserialize should fail
        // postcard drops custom error messages, so check the error kind instead.
        let result: Result<FullyBakedTx, _> = postcard::from_bytes(&serialized);
        assert_eq!(result.unwrap_err(), postcard::Error::SerdeDeCustom);
    }

    #[test]
    fn test_fullybaked_exactly_at_limit() {
        // Create a transaction exactly at the size limit
        let data = vec![1u8; MAX_FULLY_BAKED_TX_SIZE];
        let tx = FullyBakedTx::new(data.into()).unwrap();

        // Test borsh
        let borsh_serialized = borsh::to_vec(&tx).unwrap();
        let borsh_result: FullyBakedTx = borsh::from_slice(&borsh_serialized).unwrap();
        assert_eq!(borsh_result.data.len(), MAX_FULLY_BAKED_TX_SIZE);

        // Test serde_json
        let json_serialized = serde_json::to_string(&tx).unwrap();
        let json_result: FullyBakedTx = serde_json::from_str(&json_serialized).unwrap();
        assert_eq!(json_result.data.len(), MAX_FULLY_BAKED_TX_SIZE);

        // Test postcard
        let postcard_serialized = postcard::to_allocvec(&tx).unwrap();
        let postcard_result: FullyBakedTx = postcard::from_bytes(&postcard_serialized).unwrap();
        assert_eq!(postcard_result.data.len(), MAX_FULLY_BAKED_TX_SIZE);
    }

    #[test]
    fn test_fullybaked_empty() {
        // Test empty transaction
        let tx = FullyBakedTx::new(vec![].into()).unwrap();

        // Test borsh
        let borsh_serialized = borsh::to_vec(&tx).unwrap();
        let borsh_result: FullyBakedTx = borsh::from_slice(&borsh_serialized).unwrap();
        assert!(borsh_result.is_empty());

        // Test serde_json
        let json_serialized = serde_json::to_string(&tx).unwrap();
        let json_result: FullyBakedTx = serde_json::from_str(&json_serialized).unwrap();
        assert!(json_result.is_empty());

        // Test postcard
        let postcard_serialized = postcard::to_allocvec(&tx).unwrap();
        let postcard_result: FullyBakedTx = postcard::from_bytes(&postcard_serialized).unwrap();
        assert!(postcard_result.is_empty());
    }

    /// Borsh bytes of a `FullyBakedTx` with `data`, then an explicit Option tag and payload.
    fn raw_fully_baked(data: &[u8], tag: u8, seq: Option<(u32, &[u8])>) -> Vec<u8> {
        let mut bytes = (data.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(data);
        bytes.push(tag);
        if let Some((len, payload)) = seq {
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(payload);
        }
        bytes
    }

    #[test]
    fn test_fullybaked_rejects_non_canonical_option_tag() {
        let ok = raw_fully_baked(b"tx", 1, Some((3, b"seq")));
        assert!(borsh::from_slice::<FullyBakedTx>(&ok).is_ok());
        for tag in [2u8, 0x80, 0xff] {
            let bad = raw_fully_baked(b"tx", tag, Some((3, b"seq")));
            assert!(
                borsh::from_slice::<FullyBakedTx>(&bad).is_err(),
                "tag {tag}"
            );
        }
    }

    #[test]
    fn test_fits_total_size_never_overflows() {
        // A naive `data_len + seq_len` would overflow (and panic) on these, on every platform.
        let max = MAX_FULLY_BAKED_TX_SIZE as u32;
        assert!(!fits_total_size(16, u32::MAX));
        assert!(!fits_total_size(u32::MAX, u32::MAX));
        assert!(!fits_total_size(u32::MAX, 0));
        assert!(fits_total_size(16, max - 16));
        assert!(!fits_total_size(16, max - 15));
        assert!(fits_total_size(max, 0));
        assert!(fits_total_size(0, max));
    }

    #[test]
    fn test_fullybaked_huge_sequencing_len_is_an_error_not_a_panic() {
        // On a 32-bit target (the zk guest) `data_len + seq_len` would overflow `usize` here.
        let data = vec![0u8; 16];
        for seq_len in [
            u32::MAX,
            u32::MAX - 15,
            (MAX_FULLY_BAKED_TX_SIZE - 15) as u32,
        ] {
            let bytes = raw_fully_baked(&data, 1, Some((seq_len, &[])));
            assert!(
                borsh::from_slice::<FullyBakedTx>(&bytes).is_err(),
                "{seq_len}"
            );
        }
        // Exactly at the limit is still accepted.
        let seq = vec![1u8; MAX_FULLY_BAKED_TX_SIZE - 16];
        let bytes = raw_fully_baked(&data, 1, Some((seq.len() as u32, &seq)));
        assert!(borsh::from_slice::<FullyBakedTx>(&bytes).is_ok());
    }

    #[test]
    fn test_fullybaked_json_accepts_only_canonical_base64() {
        let tx = FullyBakedTx::new(Bytes::from(vec![0u8]))
            .unwrap()
            .with_sequencing_data(Some(Bytes::from(vec![1u8])))
            .unwrap();
        let canonical = r#"{"data":"AA==","sequencing_data":"AQ=="}"#;
        assert_eq!(serde_json::to_string(&tx).unwrap(), canonical);
        assert_eq!(serde_json::from_str::<FullyBakedTx>(canonical).unwrap(), tx);

        for bad in [
            r#"{"data":"AA","sequencing_data":"AQ=="}"#,
            r#"{"data":"AA=","sequencing_data":"AQ=="}"#,
            r#"{"data":"AB==","sequencing_data":"AQ=="}"#,
            r#"{"data":"AA==","sequencing_data":"AQ"}"#,
            r#"{"data":"AA==","sequencing_data":"AQ==","extra":5}"#,
            r#"["AA==","AQ=="]"#,
        ] {
            assert!(serde_json::from_str::<FullyBakedTx>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_rawtx_json_accepts_only_the_object_form() {
        assert!(serde_json::from_str::<RawTx>(r#"{"data":[1,2]}"#).is_ok());
        assert!(serde_json::from_str::<RawTx>(r#"{"data":[1,2],"extra":5}"#).is_err());
        assert!(serde_json::from_str::<RawTx>(r#"[[1,2]]"#).is_err());
    }

    #[test]
    fn len_is_the_borsh_length() {
        let seq = || Some(Bytes::from(vec![3u8; 7]));
        for tx in [
            FullyBakedTx::default(),
            FullyBakedTx::new(Bytes::from(vec![1u8; 10])).unwrap(),
            FullyBakedTx::new(Bytes::new())
                .unwrap()
                .with_sequencing_data(seq())
                .unwrap(),
            FullyBakedTx::new(Bytes::from(vec![1u8; 10]))
                .unwrap()
                .with_sequencing_data(seq())
                .unwrap(),
        ] {
            assert_eq!(tx.len(), borsh::to_vec(&tx).unwrap().len(), "{tx:?}");
        }
        let at_limit = FullyBakedTx::new(Bytes::from(vec![1u8; MAX_FULLY_BAKED_TX_SIZE - 3]))
            .unwrap()
            .with_sequencing_data(Some(Bytes::from(vec![2u8; 3])))
            .unwrap();
        assert_eq!(at_limit.len(), MAX_FULLY_BAKED_TX_SIZE + 9);
        assert_eq!(at_limit.len(), borsh::to_vec(&at_limit).unwrap().len());
    }

    #[test]
    fn accessors_return_the_parts() {
        let tx = FullyBakedTx::new(Bytes::from_static(b"tx"))
            .unwrap()
            .with_sequencing_data(Some(Bytes::from_static(b"seq")))
            .unwrap();
        assert_eq!(tx.data().as_ref(), b"tx");
        assert_eq!(tx.sequencing_data().unwrap().as_ref(), b"seq");
        let tx = tx.with_sequencing_data(None).unwrap();
        assert_eq!(tx.sequencing_data(), None);
        assert_eq!(tx.payload_len(), 2);

        let raw = RawTx::new(b"raw".to_vec()).unwrap();
        assert_eq!(raw.as_bytes(), b"raw");
        assert_eq!(AsRef::<[u8]>::as_ref(&raw), b"raw");
        assert_eq!(raw.into_bytes(), b"raw");
    }

    /// The inputs are three times the caps, so `arbitrary_len` asks for more than a cap allows;
    /// every cap must be reached by some input (else the test checks nothing).
    #[test]
    fn arbitrary_respects_the_caps() {
        use arbitrary::{Arbitrary, Unstructured};

        // `0x01` everywhere makes every `bool` (the sequencing data's `Option` tag) true;
        // `arbitrary` takes lengths from the end of the input, so only the last bytes vary.
        let mut data = vec![1u8; 3 * MAX_FULLY_BAKED_TX_SIZE];
        let (mut raw_capped, mut data_capped, mut sequencing_capped) = (false, false, false);
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..64 {
            // xorshift64
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let end = data.len() - 8;
            data[end..].copy_from_slice(&state.to_le_bytes());

            let raw = RawTx::arbitrary(&mut Unstructured::new(&data)).unwrap();
            assert!(raw.len() <= MAX_RAW_TX_SIZE);
            raw_capped |= raw.len() == MAX_RAW_TX_SIZE;

            let tx = FullyBakedTx::arbitrary(&mut Unstructured::new(&data)).unwrap();
            assert!(tx.payload_len() <= MAX_FULLY_BAKED_TX_SIZE);
            data_capped |= tx.data().len() == MAX_FULLY_BAKED_TX_SIZE;
            sequencing_capped |= tx.data().len() < MAX_FULLY_BAKED_TX_SIZE
                && tx.payload_len() == MAX_FULLY_BAKED_TX_SIZE;
        }
        assert!(raw_capped && data_capped && sequencing_capped);
    }

    #[test_strategy::proptest]
    fn constructors_roundtrip(raw: RawTx, tx: FullyBakedTx) {
        use proptest::prop_assert_eq;
        let bytes = borsh::to_vec(&raw).unwrap();
        prop_assert_eq!(&borsh::from_slice::<RawTx>(&bytes).unwrap(), &raw);
        prop_assert_eq!(&RawTx::new(raw.as_bytes().to_vec()).unwrap(), &raw);

        let bytes = borsh::to_vec(&tx).unwrap();
        prop_assert_eq!(&borsh::from_slice::<FullyBakedTx>(&bytes).unwrap(), &tx);
        let json = serde_json::to_string(&tx).unwrap();
        prop_assert_eq!(&serde_json::from_str::<FullyBakedTx>(&json).unwrap(), &tx);
        let rebuilt = FullyBakedTx::new(tx.data().clone())
            .and_then(|t| t.with_sequencing_data(tx.sequencing_data().cloned()))
            .unwrap();
        prop_assert_eq!(rebuilt, tx);
    }

    // Regressions of upstream's `RawTx`/`FullyBakedTx` bugs

    /// P5-06: the fields were public and `new` infallible, while the decoders cap the sizes:
    /// an over-size transaction could be built (and stored) whose encoding no decoder accepts.
    #[test]
    fn oversize_tx_cannot_be_constructed() {
        assert_eq!(
            RawTx::new(vec![0; MAX_RAW_TX_SIZE + 1]),
            Err(TxTooLarge {
                size: MAX_RAW_TX_SIZE + 1,
                max: MAX_RAW_TX_SIZE
            })
        );
        assert_eq!(
            FullyBakedTx::new(Bytes::from(vec![0; MAX_FULLY_BAKED_TX_SIZE + 1])),
            Err(TxTooLarge {
                size: MAX_FULLY_BAKED_TX_SIZE + 1,
                max: MAX_FULLY_BAKED_TX_SIZE
            })
        );
        let half = MAX_FULLY_BAKED_TX_SIZE / 2;
        let tx = FullyBakedTx::new(Bytes::from(vec![0; half])).unwrap();
        assert_eq!(
            tx.with_sequencing_data(Some(Bytes::from(vec![
                0;
                MAX_FULLY_BAKED_TX_SIZE - half + 1
            ]))),
            Err(TxTooLarge {
                size: MAX_FULLY_BAKED_TX_SIZE + 1,
                max: MAX_FULLY_BAKED_TX_SIZE
            })
        );

        // At the limit: constructible, and every encoding decodes back to it.
        let raw = RawTx::new(vec![7; MAX_RAW_TX_SIZE]).unwrap();
        assert_eq!(
            borsh::from_slice::<RawTx>(&borsh::to_vec(&raw).unwrap()).unwrap(),
            raw
        );
        let json = serde_json::to_string(&raw).unwrap();
        assert_eq!(serde_json::from_str::<RawTx>(&json).unwrap(), raw);
        let bin = postcard::to_allocvec(&raw).unwrap();
        assert_eq!(postcard::from_bytes::<RawTx>(&bin).unwrap(), raw);

        let tx = FullyBakedTx::new(Bytes::from(vec![7; half]))
            .unwrap()
            .with_sequencing_data(Some(Bytes::from(vec![8; MAX_FULLY_BAKED_TX_SIZE - half])))
            .unwrap();
        assert_eq!(tx.payload_len(), MAX_FULLY_BAKED_TX_SIZE);
        let bytes = borsh::to_vec(&tx).unwrap();
        assert_eq!(borsh::from_slice::<FullyBakedTx>(&bytes).unwrap(), tx);
        let json = serde_json::to_string(&tx).unwrap();
        assert_eq!(serde_json::from_str::<FullyBakedTx>(&json).unwrap(), tx);
        let bin = postcard::to_allocvec(&tx).unwrap();
        assert_eq!(postcard::from_bytes::<FullyBakedTx>(&bin).unwrap(), tx);
    }
}

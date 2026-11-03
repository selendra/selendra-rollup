//! Transaction batch types and utilities.
//!
//! This module defines the core transaction types used throughout Selendra,
//! including fully authenticated transactions ready for DA layer submission.

use base64::Engine;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::Bytes;

/// Maximum allowed size for a raw transaction in bytes (1MB default)
pub const MAX_RAW_TX_SIZE: usize = 1024 * 1024;

/// Maximum allowed size for a fully baked transaction in bytes 1.05MB default
pub const MAX_FULLY_BAKED_TX_SIZE: usize = (1024 + 50) * 1024;

/// `FullyBakedTx` represents a serialized signed rollup transaction that has been encoded with
/// authentication information and is ready to be placed on the DA layer.
///
/// JSON: `data` and `sequencing_data` are standard padded base64; only that exact form is
/// accepted, and unknown fields are rejected.
#[serde_as]
#[derive(PartialEq, Eq, Clone, BorshSerialize, Serialize, Default, derive_more::AsRef)]
pub struct FullyBakedTx {
    /// Serialized transaction.
    #[as_ref(forward)]
    #[serde_as(as = "CanonicalBase64")]
    pub data: Bytes,
    /// Sequencer-provided metadata for each transaction (e.g., timestamps).
    /// This data is NOT signed by users but is added by the sequencer.
    #[serde_as(as = "Option<CanonicalBase64>")]
    pub sequencing_data: Option<Bytes>,
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

/// Deserializes a struct, accepting only the object form in human-readable formats.
///
/// Derived struct impls also accept a JSON array of the field values (`[[1,2]]` for
/// `{"data":[1,2]}`), which would give one value two JSON encodings. Binary formats such as
/// postcard encode structs as sequences, so they keep the derived behavior.
fn deserialize_object_only<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectOnly<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectOnly<T> {
        type Value = T;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }

    if deserializer.is_human_readable() {
        deserializer.deserialize_map(ObjectOnly(std::marker::PhantomData))
    } else {
        T::deserialize(deserializer)
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

        let tx = Self {
            data: helper.data,
            sequencing_data: helper.sequencing_data,
        };

        let total_size = tx.payload_len();
        if total_size > MAX_FULLY_BAKED_TX_SIZE {
            return Err(serde::de::Error::custom(format!(
                "FullyBakedTx total size {total_size} exceeds maximum allowed size of {MAX_FULLY_BAKED_TX_SIZE} bytes",
            )));
        }

        Ok(tx)
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
    /// Construct a `FullyBakedTx` containing the given data
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: Bytes::from_owner(data),
            sequencing_data: None,
        }
    }

    /// Returns the total serialized length of the transaction, including both
    /// the transaction data and sequencing metadata (if present).
    /// This is the length that will be sent on the DA layer.
    #[must_use]
    pub fn len(&self) -> usize {
        borsh::to_vec(self)
            .expect("Serialization to vec is infallible")
            .len()
    }

    /// Returns the combined length of the raw transaction data and sequencing data fields,
    /// without encoding overhead. This is the quantity that [`MAX_FULLY_BAKED_TX_SIZE`] bounds:
    /// the deserializers reject any transaction whose payload length exceeds it.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.data
            .len()
            .saturating_add(self.sequencing_data.as_ref().map_or(0, |d| d.len()))
    }

    /// Returns true if the transaction has no data
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty() && self.sequencing_data.is_none()
    }
}

/// `RawTx` represents a serialized signed rollup transaction. A `RawTx` needs to be encoded
/// with authentication information before being placed on the DA layer.
#[derive(PartialEq, Eq, Clone, BorshSerialize, Serialize, derive_more::AsRef)]
pub struct RawTx {
    /// Serialized transaction.
    #[as_ref(forward)]
    pub data: Vec<u8>,
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

        if helper.data.len() > MAX_RAW_TX_SIZE {
            return Err(serde::de::Error::custom(format!(
                "RawTx size {} exceeds maximum allowed size of {MAX_RAW_TX_SIZE} bytes",
                helper.data.len(),
            )));
        }

        Ok(Self { data: helper.data })
    }
}

impl RawTx {
    /// Construct a `RawTx` containing the given data
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rawtx_borsh_within_limit() {
        // Create a transaction within the size limit
        let data = vec![1u8; 1024]; // 1KB
        let tx = RawTx::new(data.clone());

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
        let tx = RawTx::new(data);

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
        let tx = RawTx::new(data.clone());

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
        let tx = RawTx::new(data);

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
        let tx = RawTx::new(data.clone());

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
        let tx = RawTx::new(data);

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
        let tx = RawTx::new(data.clone());

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
        let tx = RawTx::new(vec![]);

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
        let tx = FullyBakedTx::new(data.clone());

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
        let tx = FullyBakedTx::new(data);

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
        let mut tx = FullyBakedTx::new(data.clone());
        let seq_data = vec![2u8; 512]; // 512 bytes
        tx.sequencing_data = Some(seq_data.into());

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
        let mut tx = FullyBakedTx::new(data);
        let seq_data = vec![2u8; 600]; // This will push total over limit
        tx.sequencing_data = Some(seq_data.into());

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
        let tx = FullyBakedTx::new(data.clone());

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
        let tx = FullyBakedTx::new(data);

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
        let tx = FullyBakedTx::new(data.clone());

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
        let tx = FullyBakedTx::new(data);

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
        let tx = FullyBakedTx::new(data);

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
        let tx = FullyBakedTx::new(vec![]);

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
        let tx = FullyBakedTx {
            data: Bytes::from(vec![0u8]),
            sequencing_data: Some(Bytes::from(vec![1u8])),
        };
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
}

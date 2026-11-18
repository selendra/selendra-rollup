use std::fmt;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::Bytes;
use selendra_interface::common::{HexHash, deserialize_object_only, hex_string_serde};
use selendra_interface::da::{BlockHashTrait, BlockHeaderTrait, CountedBufReader, Time};
#[cfg(feature = "native")]
use selendra_interface::da::{DaProof, RelevantBlobs, RelevantProofs};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::MockAddress;

/// A hash on the mock DA layer (block hash, blob hash, transaction id): 32 bytes.
///
/// borsh: the 32 bytes. `Display`, `FromStr` and JSON: `0x` + 64 lowercase hex digits, and
/// nothing else. Binary serde formats: a sequence of 32 bytes.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
#[serde(transparent)]
pub struct MockHash(#[serde(with = "hex_string_serde")] pub [u8; 32]);

selendra_interface::impl_consensus_type!(MockHash);

impl fmt::Display for MockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&HexHash::new(self.0), f)
    }
}

impl fmt::Debug for MockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for MockHash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HexHash::from_str(s).map(|hash| Self(hash.0))
    }
}

impl AsRef<[u8]> for MockHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for MockHash {
    fn from(hash: [u8; 32]) -> Self {
        Self(hash)
    }
}

impl From<MockHash> for [u8; 32] {
    fn from(hash: MockHash) -> Self {
        hash.0
    }
}

impl BlockHashTrait for MockHash {}

/// The block hash [`MockBlockHeader::new`] gives the block at `height` (and the parent hash it
/// gives the block at `height + 1`): `height` as a big-endian `u128` in the first 16 bytes,
/// then 16 zero bytes. A `u128`, so the hash of the block at `u64::MAX` exists.
fn height_hash(height: u128) -> MockHash {
    let mut hash = [0; 32];
    hash[..16].copy_from_slice(&height.to_be_bytes());
    MockHash(hash)
}

/// A block header of the mock DA layer.
///
/// JSON: an object with exactly the fields `height`, `prev_hash`, `hash` and `time` (the
/// hashes as [`MockHash`] strings, `time` in milliseconds); no unknown fields, no array form.
#[derive(Serialize, PartialEq, Eq, Debug, Clone)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
pub struct MockBlockHeader {
    /// The height of this block.
    pub height: u64,
    /// The hash of the previous block.
    pub prev_hash: MockHash,
    /// The hash of this block.
    pub hash: MockHash,
    /// The time at which this block was created.
    pub time: Time,
}

/// The fields of [`MockBlockHeader`], for its strict JSON decoding.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename = "MockBlockHeader")]
struct MockBlockHeaderFields {
    height: u64,
    prev_hash: MockHash,
    hash: MockHash,
    time: Time,
}

impl<'de> Deserialize<'de> for MockBlockHeader {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let MockBlockHeaderFields {
            height,
            prev_hash,
            hash,
            time,
        } = deserialize_object_only(deserializer)?;
        Ok(Self {
            height,
            prev_hash,
            hash,
            time,
        })
    }
}

impl MockBlockHeader {
    /// The header at `height` with the given time, its hashes derived from the height, so
    /// consecutive headers made this way form a chain: the hash of the block at `height` is
    /// `height + 1` and its parent hash `height`, each as a big-endian `u128` in the first 16
    /// bytes (then zeros).
    pub fn new(height: u64, time: Time) -> Self {
        let height_u128 = u128::from(height);
        Self {
            height,
            prev_hash: height_hash(height_u128),
            hash: height_hash(height_u128 + 1),
            time,
        }
    }

    /// Like [`Self::new`], at the current time.
    pub fn from_height(height: u64) -> Self {
        Self::new(height, Time::now())
    }
}

/// The header at height 0, at the current time.
impl Default for MockBlockHeader {
    fn default() -> Self {
        Self::from_height(0)
    }
}

impl fmt::Display for MockBlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl BlockHeaderTrait for MockBlockHeader {
    type Hash = MockHash;

    fn prev_hash(&self) -> Self::Hash {
        self.prev_hash
    }

    fn hash(&self) -> Self::Hash {
        self.hash
    }

    fn height(&self) -> u64 {
        self.height
    }

    fn time(&self) -> Time {
        self.time.clone()
    }
}

/// A blob on the mock DA layer: its sender, its hash and its data.
///
/// Like every blob, it exposes its data as it is verified ([`BlobReaderTrait`]); on the mock
/// DA layer nothing is verified: [`crate::MockDaVerifier`] accepts every blob. serde only
/// (no borsh): a blob is never stored or signed.
///
/// JSON: an object with exactly the fields `address` and `hash` (as [`MockAddress`] and
/// [`MockHash`] strings) and `blob`, an object with exactly the fields `inner` (the bytes not
/// verified yet) and `accumulator` (the verified bytes), each an array of byte values; no
/// unknown fields, no array forms, no string forms of the bytes.
///
/// [`BlobReaderTrait`]: selendra_interface::da::BlobReaderTrait
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MockBlob {
    pub(crate) address: MockAddress,
    pub(crate) hash: MockHash,
    pub(crate) blob: CountedBufReader<Bytes>,
}

/// The fields of [`MockBlob`], for its strict JSON decoding.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename = "MockBlob")]
struct MockBlobFields {
    address: MockAddress,
    hash: MockHash,
    blob: BlobData,
}

/// A blob's [`CountedBufReader`], decoded strictly.
struct BlobData(CountedBufReader<Bytes>);

/// The fields of a serialized [`CountedBufReader`]. `Vec<u8>`, not `Bytes`: `Bytes` would also
/// accept a JSON string. postcard encodes both the same way (a length, then the bytes).
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename = "CountedBufReader")]
struct BlobDataFields {
    inner: Vec<u8>,
    accumulator: Vec<u8>,
}

impl<'de> Deserialize<'de> for BlobData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let BlobDataFields { inner, accumulator } = deserialize_object_only(deserializer)?;
        // Every pair is a consistent reader: `accumulator` verified, then `inner` still to read
        // (a real source, so the reader can still advance through it).
        Ok(Self(CountedBufReader::from_raw_parts(
            Bytes::from(inner),
            accumulator,
        )))
    }
}

impl<'de> Deserialize<'de> for MockBlob {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let MockBlobFields {
            address,
            hash,
            blob: BlobData(blob),
        } = deserialize_object_only(deserializer)?;
        Ok(Self {
            address,
            hash,
            blob,
        })
    }
}

impl MockBlob {
    /// A blob with the given data, sender and hash. None of its data is verified yet.
    pub fn new(data: Vec<u8>, address: MockAddress, hash: [u8; 32]) -> Self {
        Self {
            address,
            hash: MockHash(hash),
            blob: CountedBufReader::new(Bytes::from(data)),
        }
    }

    /// A blob with the given data and sender, whose hash is `SHA-256(SHA-256(data))`.
    pub fn new_with_hash(data: Vec<u8>, address: MockAddress) -> Self {
        let hash = sha2::Sha256::digest(sha2::Sha256::digest(&data)).into();
        Self::new(data, address, hash)
    }

    /// Marks all of the blob's data as verified (what the guest receives).
    pub fn advance_all(&mut self) {
        self.blob.advance(self.blob.total_len());
    }
}

/// A block of the mock DA layer: its header and the blobs of the rollup's two namespaces.
///
/// JSON: an object with exactly the fields `header` ([`MockBlockHeader`]), `batch_blobs` and
/// `proof_blobs` (arrays of [`MockBlob`]s); no unknown fields, no array form.
#[cfg(feature = "native")]
#[derive(Serialize, Default, PartialEq, Debug, Clone)]
pub struct MockBlock {
    /// The header of this block.
    pub header: MockBlockHeader,
    /// The blobs of the rollup's batch namespace.
    pub batch_blobs: Vec<MockBlob>,
    /// The blobs of the rollup's proof namespace.
    pub proof_blobs: Vec<MockBlob>,
}

/// The fields of [`MockBlock`], for its strict JSON decoding.
#[cfg(feature = "native")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename = "MockBlock")]
struct MockBlockFields {
    header: MockBlockHeader,
    batch_blobs: Vec<MockBlob>,
    proof_blobs: Vec<MockBlob>,
}

#[cfg(feature = "native")]
impl<'de> Deserialize<'de> for MockBlock {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let MockBlockFields {
            header,
            batch_blobs,
            proof_blobs,
        } = deserialize_object_only(deserializer)?;
        Ok(Self {
            header,
            batch_blobs,
            proof_blobs,
        })
    }
}

#[cfg(feature = "native")]
impl selendra_interface::node::da::SlotData for MockBlock {
    type BlockHeader = MockBlockHeader;

    fn hash(&self) -> [u8; 32] {
        self.header.hash.0
    }

    fn header(&self) -> &Self::BlockHeader {
        &self.header
    }

    fn timestamp(&self) -> Time {
        self.header.time.clone()
    }
}

#[cfg(feature = "native")]
impl MockBlock {
    /// The empty block after this one (at the current time).
    ///
    /// # Panics
    ///
    /// If this block's height is `u64::MAX`.
    pub fn next_mock(&self) -> MockBlock {
        let height = self.header.height.checked_add(1);
        Self::default_at_height(height.expect("no mock block after height u64::MAX"))
    }

    /// The empty block at `height` (at the current time).
    pub fn default_at_height(height: u64) -> Self {
        MockBlock {
            header: MockBlockHeader::from_height(height),
            ..Default::default()
        }
    }

    /// All of this block's blobs, as the rollup's relevant blobs.
    pub fn as_relevant_blobs(&self) -> RelevantBlobs<MockBlob> {
        RelevantBlobs {
            proof_blobs: self.proof_blobs.clone(),
            batch_blobs: self.batch_blobs.clone(),
        }
    }

    /// Inclusion and completeness proofs for [`Self::as_relevant_blobs`]: the mock layer's
    /// proofs prove nothing (zero bytes and `()`).
    pub fn get_relevant_proofs(&self) -> RelevantProofs<[u8; 32], ()> {
        let proof = || DaProof {
            inclusion_proof: [0; 32],
            completeness_proof: (),
        };
        RelevantProofs {
            batch: proof(),
            proof: proof(),
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::any;
    use selendra_interface::da::BlobReaderTrait;

    use super::*;

    fn hash(byte: u8) -> MockHash {
        MockHash([byte; 32])
    }

    #[test]
    fn hash_encodings_known_answer() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x0f;
        bytes[31] = 0xf0;
        let hash = MockHash(bytes);
        let hex = "0x0f000000000000000000000000000000000000000000000000000000000000f0";

        assert_eq!(borsh::to_vec(&hash).unwrap(), bytes);
        assert_eq!(hash.to_string(), hex);
        assert_eq!(format!("{hash:?}"), hex);
        assert_eq!(serde_json::to_string(&hash).unwrap(), format!("\"{hex}\""));
        assert_eq!(MockHash::from_str(hex).unwrap(), hash);
        assert_eq!(<[u8; 32]>::from(hash), bytes);
        // `BlockHashTrait`'s conversion from bytes.
        fn from_bytes<H: BlockHashTrait>(bytes: [u8; 32]) -> H {
            H::try_from(bytes).unwrap()
        }
        assert_eq!(from_bytes::<MockHash>(bytes), hash);
    }

    #[test]
    fn hash_accepts_only_canonical_strings() {
        let canonical = hash(0xcd).to_string();
        let no_prefix = canonical.trim_start_matches("0x").to_owned();
        let upper = format!("0x{}", no_prefix.to_ascii_uppercase());
        for bad in [no_prefix.as_str(), upper.as_str(), "0x", "0xcd"] {
            assert!(MockHash::from_str(bad).is_err(), "{bad}");
            assert!(serde_json::from_str::<MockHash>(&format!("\"{bad}\"")).is_err());
        }
        assert!(borsh::from_slice::<MockHash>(&[0xcd; 31]).is_err());
        assert!(borsh::from_slice::<MockHash>(&[0xcd; 33]).is_err());
    }

    /// Hashes derived from the height chain the headers, also at `u64::MAX` (upstream computed
    /// `height + 1` as a `u64`).
    #[test]
    fn headers_from_heights_form_a_chain() {
        let time = Time::from_millis(1_672_531_200_000);
        let header = MockBlockHeader::new(5, time.clone());
        let mut prev = [0u8; 32];
        prev[15] = 5;
        let mut this = [0u8; 32];
        this[15] = 6;
        assert_eq!(header.prev_hash, MockHash(prev));
        assert_eq!(header.hash, MockHash(this));
        assert_eq!(MockBlockHeader::new(6, time.clone()).prev_hash, header.hash);

        let last = MockBlockHeader::new(u64::MAX, time.clone());
        let mut last_hash = [0u8; 32];
        last_hash[7] = 1;
        assert_eq!(last.hash, MockHash(last_hash));
        assert_eq!(
            last.prev_hash,
            MockBlockHeader::new(u64::MAX - 1, time).hash
        );
        assert_ne!(last.hash, last.prev_hash);
    }

    #[test]
    fn header_json_known_answer() {
        let header = MockBlockHeader {
            height: 1,
            prev_hash: hash(1),
            hash: hash(2),
            time: Time::from_millis(1_672_531_200_000),
        };
        let json = format!(
            r#"{{"height":1,"prev_hash":"0x{}","hash":"0x{}","time":1672531200000}}"#,
            "01".repeat(32),
            "02".repeat(32)
        );
        assert_eq!(serde_json::to_string(&header).unwrap(), json);
        assert_eq!(
            serde_json::from_str::<MockBlockHeader>(&json).unwrap(),
            header
        );
        assert_eq!(header.to_string(), format!("{header:?}"));

        let postcard = postcard::to_allocvec(&header).unwrap();
        assert_eq!(
            postcard::from_bytes::<MockBlockHeader>(&postcard).unwrap(),
            header
        );
    }

    #[test]
    fn header_json_is_strict() {
        let fields = format!(
            r#""height":1,"prev_hash":"0x{0}","hash":"0x{0}","time":0"#,
            "01".repeat(32)
        );
        assert!(serde_json::from_str::<MockBlockHeader>(&format!("{{{fields}}}")).is_ok());
        let unknown = format!(r#"{{{fields},"extra":0}}"#);
        assert!(serde_json::from_str::<MockBlockHeader>(&unknown).is_err());
        let array = format!(r#"[1,"0x{0}","0x{0}",0]"#, "01".repeat(32));
        assert!(serde_json::from_str::<MockBlockHeader>(&array).is_err());
    }

    /// `SHA-256(SHA-256(data))`, computed independently with Python's `hashlib`.
    #[test]
    fn blob_hash_known_answer() {
        let blob = MockBlob::new_with_hash(b"selendra".to_vec(), MockAddress::new([7; 32]));
        assert_eq!(
            blob.hash().to_string(),
            "0x9af931bd305c52b52667c734ea2366ac06621633c1ec16af1c46dece4ea1607b"
        );
        let empty = MockBlob::new_with_hash(Vec::new(), MockAddress::new([7; 32]));
        assert_eq!(
            empty.hash().to_string(),
            "0x5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn blob_data_is_verified_only_once_advanced() {
        let sender = MockAddress::new([7; 32]);
        let mut blob = MockBlob::new(vec![1, 2, 3], sender, [9; 32]);
        assert_eq!(blob.sender(), sender);
        assert_eq!(blob.hash(), hash(9));
        assert_eq!(blob.total_len(), 3);
        assert!(blob.verified_data().is_empty());
        blob.advance_all();
        assert_eq!(blob.verified_data(), [1, 2, 3]);
        assert_eq!(blob.total_len(), 3);
        assert!(!blob.rollup_decode_failed());
    }

    /// The JSON and postcard encodings of a blob, half verified.
    #[test]
    fn blob_encodings_known_answer() {
        let mut blob = MockBlob::new(vec![1, 2, 3], MockAddress::new([7; 32]), [9; 32]);
        blob.blob.advance(1);
        let json = format!(
            r#"{{"address":"0x{}","hash":"0x{}","blob":{{"inner":[2,3],"accumulator":[1]}}}}"#,
            "07".repeat(32),
            "09".repeat(32)
        );
        assert_eq!(serde_json::to_string(&blob).unwrap(), json);
        assert_eq!(serde_json::from_str::<MockBlob>(&json).unwrap(), blob);

        // The address, the hash, then the reader's two byte strings: each a length (one-byte
        // varint here), then its bytes.
        let mut postcard = vec![32];
        postcard.extend([7; 32]);
        postcard.push(32);
        postcard.extend([9; 32]);
        postcard.extend([2, 2, 3, 1, 1]);
        assert_eq!(postcard::to_allocvec(&blob).unwrap(), postcard);
        assert_eq!(postcard::from_bytes::<MockBlob>(&postcard).unwrap(), blob);

        blob.advance_all();
        let json = serde_json::to_string(&blob).unwrap();
        assert_eq!(serde_json::from_str::<MockBlob>(&json).unwrap(), blob);
        let postcard = postcard::to_allocvec(&blob).unwrap();
        assert_eq!(postcard::from_bytes::<MockBlob>(&postcard).unwrap(), blob);
    }

    /// Blob JSON has one form: no array forms (of the blob or of its reader), no unknown fields
    /// (in either), no string form of the bytes.
    #[test]
    fn blob_json_is_strict() {
        let address = format!(r#""0x{}""#, "07".repeat(32));
        let hash = format!(r#""0x{}""#, "09".repeat(32));
        let blob =
            |reader: &str| format!(r#"{{"address":{address},"hash":{hash},"blob":{reader}}}"#);
        let reader = r#"{"inner":[1,2,3],"accumulator":[]}"#;
        let expected = MockBlob::new(vec![1, 2, 3], MockAddress::new([7; 32]), [9; 32]);
        assert_eq!(
            serde_json::from_str::<MockBlob>(&blob(reader)).unwrap(),
            expected
        );

        let bad = [
            format!("[{address},{hash},{reader}]"),
            blob("[[1,2,3],[]]"),
            blob(r#"{"inner":[1,2,3],"accumulator":[],"extra":0}"#),
            blob(r#"{"inner":"\u0001\u0002\u0003","accumulator":[]}"#),
            blob(r#"{"inner":[1,2,3],"accumulator":""}"#),
            blob(r#"{"inner":[1,2,256],"accumulator":[]}"#),
            blob(r#"{"inner":[1,2,3]}"#),
            format!(r#"{{"address":{address},"hash":{hash},"blob":{reader},"extra":0}}"#),
        ];
        for json in bad {
            assert!(serde_json::from_str::<MockBlob>(&json).is_err(), "{json}");
        }
    }

    /// A reader's accumulator is the verified data, `inner` the rest: any pair is a reader.
    #[test]
    fn blob_reader_state_round_trips() {
        let json = format!(
            r#"{{"address":"0x{0}","hash":"0x{0}","blob":{{"inner":[1,2,3],"accumulator":[5,5]}}}}"#,
            "07".repeat(32)
        );
        let mut blob = serde_json::from_str::<MockBlob>(&json).unwrap();
        assert_eq!(serde_json::to_string(&blob).unwrap(), json);
        assert_eq!(blob.verified_data(), [5, 5]);
        assert_eq!(blob.total_len(), 5);
        blob.advance_all();
        assert_eq!(blob.verified_data(), [5, 5, 1, 2, 3]);
    }

    #[cfg(feature = "native")]
    #[test]
    fn blocks() {
        use selendra_interface::node::da::SlotData;

        let block = MockBlock::default_at_height(3);
        assert_eq!(
            block.hash(),
            MockBlockHeader::new(3, Time::from_millis(0)).hash.0
        );
        assert_eq!(block.timestamp(), block.header().time);
        let next = block.next_mock();
        assert_eq!(next.header.height, 4);
        assert_eq!(next.header.prev_hash, block.header.hash);

        let mut blob = MockBlob::new(vec![1, 2, 3], MockAddress::new([7; 32]), [9; 32]);
        assert_eq!(blob.advance(2), [1, 2]);
        assert_eq!(blob.full_data(), [1, 2, 3]);
        let block = MockBlock {
            batch_blobs: vec![blob.clone()],
            ..block
        };
        let relevant = block.as_relevant_blobs();
        assert_eq!(relevant.batch_blobs, vec![blob]);
        assert!(relevant.proof_blobs.is_empty());
        let proofs = block.get_relevant_proofs();
        assert_eq!(proofs.batch.inclusion_proof, [0; 32]);

        let json = serde_json::to_string(&block).unwrap();
        assert_eq!(serde_json::from_str::<MockBlock>(&json).unwrap(), block);
    }

    #[cfg(feature = "native")]
    #[test]
    fn block_json_is_strict() {
        let block = MockBlock {
            header: MockBlockHeader::new(1, Time::from_millis(0)),
            ..Default::default()
        };
        let json = serde_json::to_string(&block).unwrap();
        assert_eq!(serde_json::from_str::<MockBlock>(&json).unwrap(), block);

        let serde_json::Value::Object(fields) = serde_json::from_str(&json).unwrap() else {
            panic!("a block is an object");
        };
        // The fields in declaration order (what a derived decoder would accept).
        let array = serde_json::Value::Array(
            ["header", "batch_blobs", "proof_blobs"]
                .map(|name| fields[name].clone())
                .to_vec(),
        );
        assert!(serde_json::from_value::<MockBlock>(array).is_err());
        let mut unknown = fields;
        unknown.insert("extra".to_owned(), 0.into());
        assert!(serde_json::from_value::<MockBlock>(serde_json::Value::Object(unknown)).is_err());
    }

    #[test_strategy::proptest]
    fn hash_round_trips(#[strategy(any::<[u8; 32]>())] bytes: [u8; 32]) {
        let hash = MockHash(bytes);
        let borsh_bytes = borsh::to_vec(&hash).unwrap();
        assert_eq!(borsh::from_slice::<MockHash>(&borsh_bytes).unwrap(), hash);
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(serde_json::from_str::<MockHash>(&json).unwrap(), hash);
        let postcard = postcard::to_allocvec(&hash).unwrap();
        assert_eq!(postcard::from_bytes::<MockHash>(&postcard).unwrap(), hash);
        assert_eq!(hash.to_string().parse::<MockHash>().unwrap(), hash);
    }

    #[test_strategy::proptest]
    fn header_round_trips(height: u64, millis: i64) {
        let header = MockBlockHeader::new(height, Time::from_millis(millis));
        let json = serde_json::to_string(&header).unwrap();
        assert_eq!(
            serde_json::from_str::<MockBlockHeader>(&json).unwrap(),
            header
        );
        assert_eq!(header.height(), height);
        assert_eq!(header.prev_hash(), height_hash(u128::from(height)));
    }
}

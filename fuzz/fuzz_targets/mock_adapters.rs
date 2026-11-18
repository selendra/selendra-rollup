//! The mock adapters (`selendra-mock-da`, `selendra-mock-zkvm`): decoders of their types (no
//! panics, canonical, same value in every encoding), the mock proof verifier (no panics, only
//! well-formed proofs accepted, no trailing bytes) and the mock guest's hints (no panics, every
//! byte consumed).
#![no_main]

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use selendra_interface::zk::aggregated_proof::common::SerializedPubValues;
use selendra_interface::zk::{SerializedZkProof, ZkVerifier, ZkvmGuest};
use selendra_mock_da::{MockAddress, MockBlob, MockBlockHeader, MockDaSpec, MockHash};
use selendra_mock_zkvm::{
    HintError, MockCodeCommitment, MockProof, MockProofError, MockZkGuest, MockZkVerifier,
    encode_hint,
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

/// postcard (prover-internal, not consensus): anything accepted round-trips as a value
/// (postcard accepts over-long varints, so the bytes need not be canonical).
fn postcard_round_trip<T>(data: &[u8])
where
    T: serde::de::DeserializeOwned + serde::Serialize + PartialEq + std::fmt::Debug,
{
    if let Ok(value) = postcard::from_bytes::<T>(data) {
        let bytes = postcard::to_allocvec(&value).unwrap();
        assert_eq!(postcard::from_bytes::<T>(&bytes).unwrap(), value);
    }
}

/// The 32-byte types: borsh (canonical, and the same value as the other encodings).
fn hashes(data: &[u8]) {
    let hash = borsh_canonical::<MockHash>(data);
    let address = borsh_canonical::<MockAddress>(data);
    let commitment = borsh_canonical::<MockCodeCommitment>(data);
    assert_eq!(hash.is_some(), data.len() == 32);
    assert_eq!(address.map(|a| *a.as_bytes()), hash.map(|h| h.0));
    assert_eq!(commitment.map(|c| c.0), hash.map(|h| h.0));
    assert_eq!(
        MockAddress::try_from(data).ok().map(|a| *a.as_bytes()),
        hash.map(|h| h.0)
    );
    if let Some(hash) = hash {
        assert_eq!(MockHash::from_str(&hash.to_string()).unwrap(), hash);
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(serde_json::from_str::<MockHash>(&json).unwrap(), hash);
    }
    if borsh_canonical::<MockDaSpec>(data).is_some() {
        assert!(data.is_empty());
    }
    postcard_round_trip::<MockHash>(data);
    postcard_round_trip::<MockAddress>(data);
    postcard_round_trip::<MockCodeCommitment>(data);
}

type Public = (u32, Vec<u8>);

/// Checks every verifier entry point on `raw` (any bytes) against `program`: they agree, and
/// accept exactly the canonical encoding of a valid proof of `program` whose public data is the
/// canonical encoding of a [`Public`], returning that value.
fn verify(raw: &[u8], program: &MockCodeCommitment) {
    let decoded = borsh_canonical::<MockProof>(raw);
    assert_eq!(MockProof::from_bytes(raw).ok(), decoded);
    let proof = SerializedZkProof {
        raw_proof: raw.to_vec(),
    };
    let pub_values = SerializedPubValues {
        pub_values: raw.to_vec(),
    };

    let verified = MockZkVerifier::verify_with_proof::<Public>(&proof, program);
    let in_band = MockZkVerifier::verify_with_pub_values::<Public>(&pub_values, program);
    let extracted = MockZkVerifier::extract_public_data::<Public>(&proof);
    assert_eq!(verified.as_ref().ok(), in_band.as_ref().ok());
    assert_eq!(
        verified.as_ref().err().map(std::mem::discriminant),
        in_band.as_ref().err().map(std::mem::discriminant)
    );

    let Some(decoded) = decoded else {
        assert!(matches!(verified, Err(MockProofError::Malformed(_))));
        assert!(matches!(extracted, Err(MockProofError::Malformed(_))));
        return;
    };
    let public = borsh_canonical::<Public>(decoded.pub_data());
    assert_eq!(extracted.ok(), public);
    let should_verify = decoded.is_valid() && decoded.code_commitment() == program;
    match verified {
        Ok(value) => {
            assert!(should_verify);
            assert_eq!(Some(value), public);
        }
        Err(MockProofError::Invalid) => assert!(!decoded.is_valid()),
        Err(MockProofError::CodeCommitmentMismatch { claimed, expected }) => {
            assert!(decoded.is_valid());
            assert_ne!(claimed, expected);
            assert_eq!((claimed, expected), (*decoded.code_commitment(), *program));
        }
        Err(MockProofError::PublicData(_)) => assert!(should_verify && public.is_none()),
        Err(MockProofError::Malformed(_)) => panic!("a decoded proof was malformed"),
    }
}

/// Whether decoding `data` as a [`Public`] stays cheap: the byte-string length it claims fits in
/// the input. borsh zeroes `min(claimed length, 1 MiB)` bytes before reading them, and such a
/// claim cannot decode anyway.
fn public_claim_fits(data: &[u8]) -> bool {
    data.get(4..8).is_none_or(|len| {
        usize::try_from(u32::from_le_bytes(len.try_into().unwrap())).unwrap() <= data.len()
    })
}

/// The verifier on the fuzz bytes as a proof: against a program derived from the input (the
/// mismatch path, mostly), and against the proof's own program (the success path, whenever the
/// proof is valid and its public data decodes). And on proofs built around the fuzz bytes as
/// public data: a valid proof verifies exactly when the bytes are a canonical [`Public`], and
/// only against its own program; an invalid one never does.
fn proofs(data: &[u8]) {
    let program = MockCodeCommitment([data.last().copied().unwrap_or(0); 32]);
    verify(data, &program);
    if let Ok(decoded) = MockProof::from_bytes(data) {
        verify(data, decoded.code_commitment());
    }

    let public = borsh_canonical::<Public>(data);
    let other = MockCodeCommitment([!program.0[0]; 32]);
    let built = |is_valid| {
        let raw = MockProof::new(is_valid, data.to_vec(), program)
            .to_bytes()
            .unwrap();
        SerializedZkProof { raw_proof: raw }
    };
    // Rejected before the public data is decoded.
    assert!(matches!(
        MockZkVerifier::verify_with_proof::<Public>(&built(false), &program),
        Err(MockProofError::Invalid)
    ));
    assert!(matches!(
        MockZkVerifier::verify_with_proof::<Public>(&built(true), &other),
        Err(MockProofError::CodeCommitmentMismatch { .. })
    ));
    if !public_claim_fits(data) {
        assert!(public.is_none());
        return;
    }
    for is_valid in [true, false] {
        let proof = built(is_valid);
        verify(&proof.raw_proof, &program);
        verify(&proof.raw_proof, &other);
        let verified = MockZkVerifier::verify_with_proof::<Public>(&proof, &program).ok();
        assert_eq!(verified, if is_valid { public.clone() } else { None });
        let extracted = MockZkVerifier::extract_public_data::<Public>(&proof).ok();
        assert_eq!(extracted, public);
    }
}

type Hint = (u32, bool, Vec<u8>, Option<String>);

/// A hint is read once, from all of its bytes; anything read re-encodes to a hint that reads
/// back the same.
fn hints(data: &[u8]) {
    let guest = MockZkGuest::with_raw_hint(data.to_vec());
    let read = guest.try_read_from_host::<Hint>();
    assert!(matches!(
        guest.try_read_from_host::<Hint>(),
        Err(HintError::Missing)
    ));
    let prefix = postcard::take_from_bytes::<Hint>(data).ok();
    match read {
        Ok(value) => {
            assert_eq!(prefix.map(|(_, rest)| rest.len()), Some(0));
            let bytes = encode_hint(&value).unwrap();
            assert!(bytes.len() <= data.len());
            let again = MockZkGuest::with_raw_hint(bytes);
            assert_eq!(again.read_from_host::<Hint>(), value);
        }
        Err(HintError::TrailingBytes(n)) => {
            let rest = prefix.unwrap().1.len();
            assert!(rest > 0 && u64::try_from(rest).unwrap() == n);
        }
        Err(HintError::Malformed(_)) => assert!(prefix.is_none()),
        Err(HintError::Missing) => panic!("the hint was there"),
    }

    // Commits concatenate borsh encodings.
    let guest = MockZkGuest::default();
    let len = u32::try_from(data.len()).unwrap();
    guest.commit(&len);
    guest.commit(&data.to_vec());
    let committed = guest.take_committed_bytes();
    let decoded: (u32, Vec<u8>) = borsh::from_slice(&committed).unwrap();
    assert_eq!(decoded, (len, data.to_vec()));
}

fn text(s: &str) {
    if let Some(hash) = str_canonical::<MockHash>(s) {
        assert_eq!(MockAddress::from_str(s).unwrap().as_bytes(), &hash.0);
    } else {
        assert!(MockAddress::from_str(s).is_err());
    }
    let _ = str_canonical::<MockAddress>(s);
    let _ = json_canonical::<MockHash>(s);
    let _ = json_canonical::<MockAddress>(s);
    let _ = json_canonical::<MockCodeCommitment>(s);
    let _ = json_canonical::<MockBlockHeader>(s);
    if let Some(blob) = json_canonical::<MockBlob>(s) {
        let json = serde_json::to_string(&blob).unwrap();
        assert_eq!(serde_json::from_str::<MockBlob>(&json).unwrap(), blob);
    }
}

fuzz_target!(|data: &[u8]| {
    hashes(data);
    proofs(data);
    hints(data);
    postcard_round_trip::<MockBlockHeader>(data);
    postcard_round_trip::<MockBlob>(data);
    if let Ok(s) = std::str::from_utf8(data) {
        text(s);
    }
});

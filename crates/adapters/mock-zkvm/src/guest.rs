use std::sync::{Mutex, MutexGuard, PoisonError};

use borsh::BorshSerialize;
use selendra_interface::zk::ZkvmGuest;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::MockZkVerifier;

/// Encodes a hint for [`MockZkGuest`]: postcard.
pub fn encode_hint<T: Serialize>(item: &T) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_allocvec(item)
}

/// Why [`MockZkGuest`] could not read its hint.
#[derive(Debug, thiserror::Error)]
pub enum HintError {
    /// There is no hint (none was given, or it was read already).
    #[error("the mock guest has no hint to read")]
    Missing,
    /// The hint does not decode as the expected type.
    #[error("the mock guest's hint does not decode: {0}")]
    Malformed(#[source] postcard::Error),
    /// The hint decodes from a prefix of its bytes.
    #[error("the mock guest's hint has {0} trailing bytes")]
    TrailingBytes(u64),
}

/// The guest of the mock zkVM: it runs natively, reads one hint and collects the public output.
///
/// The hint is the postcard encoding of one value ([`encode_hint`]), and must be consumed
/// whole: trailing bytes are an error. The public output is the concatenation of the borsh
/// encodings of every committed item, like SP1's `commit_slice`.
#[derive(Debug, Default)]
pub struct MockZkGuest {
    hint: Mutex<Option<Vec<u8>>>,
    committed: Mutex<Vec<u8>>,
}

/// Locks `mutex`, also if a thread panicked holding it (the data is plain bytes).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl MockZkGuest {
    /// A guest whose hint is `item` ([`encode_hint`]).
    pub fn with_hint<T: Serialize>(item: &T) -> Result<Self, postcard::Error> {
        encode_hint(item).map(Self::with_raw_hint)
    }

    /// A guest whose hint is `hint`, as is (e.g. a malformed hint).
    pub fn with_raw_hint(hint: Vec<u8>) -> Self {
        Self {
            hint: Mutex::new(Some(hint)),
            committed: Mutex::default(),
        }
    }

    /// Reads (and consumes) the hint. It must decode as a `T` from all of its bytes.
    pub fn try_read_from_host<T: DeserializeOwned>(&self) -> Result<T, HintError> {
        let hint = lock(&self.hint).take().ok_or(HintError::Missing)?;
        let (value, rest) = postcard::take_from_bytes::<T>(&hint).map_err(HintError::Malformed)?;
        if !rest.is_empty() {
            let trailing = u64::try_from(rest.len()).unwrap_or(u64::MAX);
            return Err(HintError::TrailingBytes(trailing));
        }
        Ok(value)
    }

    /// Takes the public output committed so far (the concatenated borsh encodings).
    pub fn take_committed_bytes(&self) -> Vec<u8> {
        std::mem::take(&mut *lock(&self.committed))
    }
}

impl ZkvmGuest for MockZkGuest {
    type Verifier = MockZkVerifier;

    /// Reads the hint ([`MockZkGuest::try_read_from_host`]).
    ///
    /// # Panics
    ///
    /// If there is no hint, or it does not decode as a `T` from all of its bytes. A guest
    /// cannot continue without its hint: like a real zkVM's guest, it aborts (no proof).
    fn read_from_host<T: DeserializeOwned>(&self) -> T {
        match self.try_read_from_host() {
            Ok(value) => value,
            Err(err) => panic!("invalid mock guest hint: {err}"),
        }
    }

    /// Appends the borsh encoding of `item` to the public output.
    ///
    /// # Panics
    ///
    /// If `item`'s `BorshSerialize` fails, which a consensus type's never does
    /// (`docs/serialization.md`).
    fn commit<T: BorshSerialize>(&self, item: &T) {
        let mut committed = lock(&self.committed);
        let len = committed.len();
        if let Err(err) = item.serialize(&mut *committed) {
            committed.truncate(len);
            panic!("the mock guest's public output does not encode: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Hint = (u32, Vec<u8>, Option<String>);

    fn hint() -> Hint {
        (300, vec![1, 2, 3], Some("selendra".to_owned()))
    }

    #[test]
    fn hint_round_trips_once() {
        let guest = MockZkGuest::with_hint(&hint()).unwrap();
        assert_eq!(guest.read_from_host::<Hint>(), hint());
        assert!(matches!(
            guest.try_read_from_host::<Hint>(),
            Err(HintError::Missing)
        ));
        assert!(matches!(
            MockZkGuest::default().try_read_from_host::<Hint>(),
            Err(HintError::Missing)
        ));
    }

    /// postcard: `300` is the varint `ac 02`, then each length a varint, `Some` a `01` tag.
    #[test]
    fn hint_encoding_known_answer() {
        let mut expected = vec![0xac, 0x02, 3, 1, 2, 3, 1, 8];
        expected.extend(b"selendra");
        assert_eq!(encode_hint(&hint()).unwrap(), expected);
    }

    #[test]
    fn commits_are_concatenated_borsh() {
        let guest = MockZkGuest::default();
        guest.commit(&7u32);
        guest.commit(&vec![9u8]);
        assert_eq!(guest.take_committed_bytes(), [7, 0, 0, 0, 1, 0, 0, 0, 9]);
        assert!(guest.take_committed_bytes().is_empty());
    }

    #[test]
    #[should_panic(expected = "invalid mock guest hint")]
    fn read_from_host_panics_on_a_bad_hint() {
        MockZkGuest::with_raw_hint(vec![2]).read_from_host::<bool>();
    }

    // Regressions of upstream's mock zkVM bugs

    /// P5-42: upstream's guest decoded its hint with `bincode::deserialize`, which ignores
    /// trailing bytes (one hint, many encodings). Ours requires every byte to be consumed.
    #[test]
    fn mock_hint_rejects_trailing_bytes() {
        let mut bytes = encode_hint(&hint()).unwrap();
        bytes.push(0);
        let guest = MockZkGuest::with_raw_hint(bytes);
        assert!(matches!(
            guest.try_read_from_host::<Hint>(),
            Err(HintError::TrailingBytes(1))
        ));
    }

    /// P5-42: a malformed hint is an error from `try_read_from_host` (upstream only had the
    /// panicking read), so native callers and fuzzers can check hints without panicking.
    #[test]
    fn malformed_hint_is_an_error() {
        for bad in [vec![], vec![2], vec![0xff; 11]] {
            let guest = MockZkGuest::with_raw_hint(bad);
            assert!(matches!(
                guest.try_read_from_host::<(bool, u64)>(),
                Err(HintError::Malformed(_))
            ));
        }
    }
}

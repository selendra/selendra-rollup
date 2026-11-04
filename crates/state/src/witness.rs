//! Witnesses: the hints the native prover records for the zk guest ([`Witness`],
//! [`ArrayWitness`]).

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::HexString;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// A witness is a value produced during native execution that is then used by the zkVM circuit
/// to produce proofs.
///
/// Witnesses abstract storage access inside the zkVM: for every read the native code performs,
/// the native storage adds a hint, and the guest storage reads the same hint back. Hints are
/// replayed by [`Witness::get_hint`] in the same order they were added by
/// [`Witness::add_hint`]. A hint is the borsh encoding of a value (`docs/serialization.md`,
/// "Witness hints").
///
/// # Hints are untrusted
/// In the zk guest every hint comes from the prover. A hint is only a claim: the guest
/// [`Storage`](crate::Storage) checks every read against the previous state root in
/// [`compute_state_update`](crate::Storage::compute_state_update). A witness that runs out of
/// hints, or whose next hint does not decode as the requested type, is an **invalid witness**:
/// [`get_hint`](Witness::get_hint) panics, and that is the intended result (no proof can be
/// produced from it). It must never become a recoverable error that execution continues past,
/// or control flow would depend on unverified bytes.
pub trait Witness:
    Default + Serialize + DeserializeOwned + BorshSerialize + BorshDeserialize
{
    /// Adds a "hint" to the witness, which can be later read by the zkVM circuit.
    ///
    /// This method **should** only be called from the native execution environment.
    ///
    /// # Panics
    /// If `hint` can't be borsh-encoded (see [`BorshCodec`](crate::BorshCodec) for when borsh
    /// refuses). Hints are storage values, leaves and proofs, whose encoding never fails.
    fn add_hint<T: BorshSerialize>(&self, hint: &T);

    /// Removes the next hint and decodes it as a `T`, rejecting trailing bytes (each hint has
    /// exactly one accepted encoding).
    ///
    /// # Errors
    /// If there is no hint left, or the next hint does not decode as a `T`. The hint is consumed
    /// either way.
    fn try_get_hint<T: BorshDeserialize>(&self) -> Result<T, InvalidWitness>;

    /// Removes the next hint and decodes it as a `T`.
    ///
    /// # Panics
    /// If the witness is invalid ([`Witness::try_get_hint`] fails): see the trait docs for why
    /// panicking is the intended result.
    fn get_hint<T: BorshDeserialize>(&self) -> T {
        match self.try_get_hint() {
            Ok(hint) => hint,
            Err(err) => panic!("{err}"),
        }
    }

    /// Returns true if no hint is left.
    fn is_empty(&self) -> bool;

    /// Checks that every hint was consumed.
    ///
    /// Upstream never checks this. Leftover hints cannot change what the guest computes (hints
    /// are read in order, and every read is checked against the state root), but they make the
    /// witness for one execution malleable.
    // TODO(Phase 4, NOMT item / SP1 guest): decide whether the guest calls this after
    // `compute_state_update` (see TODO.md).
    fn ensure_consumed(&self) -> Result<(), InvalidWitness> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(InvalidWitness::NotConsumed)
        }
    }
}

/// Why a witness is invalid. See [`Witness`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidWitness {
    /// A hint was requested but none is left.
    #[error("invalid witness: no hint left for a `{type_name}`")]
    Exhausted {
        /// The type that was requested.
        type_name: &'static str,
    },
    /// The next hint does not decode as the requested type.
    #[error("invalid witness: hint of {len} bytes is not a `{type_name}`: {reason}")]
    Undecodable {
        /// The type that was requested.
        type_name: &'static str,
        /// The length of the hint.
        len: usize,
        /// The decoding error (borsh's message: bounded, never contains the hint itself).
        reason: String,
    },
    /// Hints are left after execution ([`Witness::ensure_consumed`]).
    #[error("invalid witness: unconsumed hints left")]
    NotConsumed,
}

/// A [`VecDeque`]-based implementation of [`Witness`] with no special logic.
///
/// # Example
///
/// ```
/// use selendra_state::{ArrayWitness, Witness};
///
/// let witness = ArrayWitness::default();
///
/// witness.add_hint(&1u64);
/// witness.add_hint(&2u64);
///
/// assert_eq!(witness.get_hint::<u64>(), 1u64);
/// assert_eq!(witness.get_hint::<u64>(), 2u64);
/// assert!(witness.is_empty());
/// ```
///
/// # Encodings
/// The remaining hints, in order. borsh: like a `Vec<Vec<u8>>`. serde: a sequence of hints,
/// each one a `0x`-prefixed lowercase hex string in human-readable formats (JSON) and a byte
/// sequence in binary ones. Both are canonical.
///
/// The hints sit behind a [`Mutex`] because [`Witness`] takes `&self` and storages require
/// `Send + Sync` witnesses. The lock is never held while a hint is encoded or decoded, so
/// hint access cannot panic while holding it; a poisoned lock (e.g. a panicking serializer
/// while the whole witness is serialized) is recovered all the same, never `unwrap`ped, so there
/// is one code path natively and in the guest.
#[derive(Default, Debug)]
pub struct ArrayWitness {
    hints: Mutex<VecDeque<Vec<u8>>>,
}

impl ArrayWitness {
    fn hints(&self) -> MutexGuard<'_, VecDeque<Vec<u8>>> {
        self.hints.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The number of hints left.
    pub fn len(&self) -> usize {
        self.hints().len()
    }

    /// Returns true if no hint is left (same as [`Witness::is_empty`]).
    pub fn is_empty(&self) -> bool {
        self.hints().is_empty()
    }

    /// Builds a witness from encoded hints (the first is read first).
    pub fn from_hints(hints: Vec<Vec<u8>>) -> Self {
        Self {
            hints: Mutex::new(hints.into()),
        }
    }
}

impl Witness for ArrayWitness {
    fn add_hint<T: BorshSerialize>(&self, hint: &T) {
        let encoded = borsh::to_vec(hint).expect("a witness hint must be borsh-encodable");
        self.hints().push_back(encoded);
    }

    fn try_get_hint<T: BorshDeserialize>(&self) -> Result<T, InvalidWitness> {
        let type_name = core::any::type_name::<T>();
        // The guard is a temporary: the lock is released before decoding.
        let hint = self
            .hints()
            .pop_front()
            .ok_or(InvalidWitness::Exhausted { type_name })?;
        // `from_slice` rejects trailing bytes. Upstream used `T::deserialize(&mut slice)`, which
        // ignores them, so every hint had infinitely many accepted encodings.
        borsh::from_slice(&hint).map_err(|err| InvalidWitness::Undecodable {
            type_name,
            len: hint.len(),
            reason: err.to_string(),
        })
    }

    fn is_empty(&self) -> bool {
        ArrayWitness::is_empty(self)
    }
}

impl BorshSerialize for ArrayWitness {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // `VecDeque` is borsh-encoded like a `Vec`.
        BorshSerialize::serialize(&*self.hints(), writer)
    }
}

impl BorshDeserialize for ArrayWitness {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        Vec::<Vec<u8>>::deserialize_reader(reader).map(Self::from_hints)
    }
}

impl Serialize for ArrayWitness {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hints = self.hints();
        serializer.collect_seq(hints.iter().map(HexString::new))
    }
}

impl<'de> serde::Deserialize<'de> for ArrayWitness {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hints = <Vec<HexString<Vec<u8>>> as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self::from_hints(hints.into_iter().map(|h| h.0).collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SlotValue, StorageProof};

    #[test]
    fn hints_are_replayed_in_order() {
        let witness = ArrayWitness::default();
        witness.add_hint(&Some(SlotValue::from(vec![1, 2])));
        witness.add_hint(&None::<SlotValue>);
        witness.add_hint(&7u8);
        assert_eq!(witness.len(), 3);
        assert_eq!(
            witness.get_hint::<Option<SlotValue>>(),
            Some(SlotValue::from(vec![1, 2]))
        );
        assert_eq!(witness.get_hint::<Option<SlotValue>>(), None);
        assert_eq!(witness.ensure_consumed(), Err(InvalidWitness::NotConsumed));
        assert_eq!(witness.get_hint::<u8>(), 7);
        assert!(witness.is_empty());
        assert_eq!(witness.ensure_consumed(), Ok(()));
    }

    /// Upstream decoded hints with `T::deserialize(&mut slice)`, which ignores trailing bytes.
    #[test]
    fn hints_with_trailing_bytes_are_rejected() {
        let witness = ArrayWitness::from_hints(vec![vec![7, 0, 0, 0, 0], vec![7, 0, 0, 0]]);
        assert!(matches!(
            witness.try_get_hint::<u32>(),
            Err(InvalidWitness::Undecodable { len: 5, .. })
        ));
        // The bad hint was consumed; the next one decodes.
        assert_eq!(witness.try_get_hint::<u32>(), Ok(7));
        assert_eq!(
            witness.try_get_hint::<u32>(),
            Err(InvalidWitness::Exhausted { type_name: "u32" })
        );
    }

    #[test]
    fn non_canonical_option_tags_are_rejected() {
        let witness = ArrayWitness::from_hints(vec![vec![2]]);
        assert!(witness.try_get_hint::<Option<SlotValue>>().is_err());
    }

    #[test]
    #[should_panic(expected = "invalid witness: no hint left")]
    fn get_hint_panics_on_an_exhausted_witness() {
        let _: u8 = ArrayWitness::default().get_hint();
    }

    #[test]
    #[should_panic(expected = "invalid witness: hint of 1 bytes is not a `u32`")]
    fn get_hint_panics_on_an_undecodable_hint() {
        let _: u32 = ArrayWitness::from_hints(vec![vec![1]]).get_hint();
    }

    /// A panic while the lock is held must not make later accesses panic.
    #[test]
    fn a_poisoned_lock_is_recovered() {
        let witness = ArrayWitness::from_hints(vec![vec![1]]);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = witness.hints.lock();
            panic!("poison");
        }));
        assert!(witness.hints.is_poisoned());
        assert_eq!(witness.get_hint::<u8>(), 1);
        witness.add_hint(&2u8);
        assert_eq!(witness.len(), 1);
    }

    #[test]
    fn borsh_encoding_is_a_vec_of_byte_vecs() {
        let witness = ArrayWitness::default();
        witness.add_hint(&1u8);
        witness.add_hint(&258u16);
        let bytes = borsh::to_vec(&witness).unwrap();
        assert_eq!(bytes, borsh::to_vec(&vec![vec![1u8], vec![2, 1]]).unwrap());
        let decoded: ArrayWitness = borsh::from_slice(&bytes).unwrap();
        assert_eq!(borsh::to_vec(&decoded).unwrap(), bytes);
        assert_eq!(decoded.get_hint::<u8>(), 1);
        assert_eq!(decoded.get_hint::<u16>(), 258);
        // Trailing bytes and short length prefixes are rejected.
        assert!(borsh::from_slice::<ArrayWitness>(&[bytes.as_slice(), &[0]].concat()).is_err());
        assert!(borsh::from_slice::<ArrayWitness>(&[1, 0, 0, 0, 2, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn json_encoding_is_canonical_hex() {
        let witness = ArrayWitness::from_hints(vec![vec![0xab], vec![]]);
        let json = serde_json::to_string(&witness).unwrap();
        assert_eq!(json, r#"["0xab","0x"]"#);
        let decoded: ArrayWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
        for bad in [r#"["0xAB"]"#, r#"["ab"]"#, r#"[[171]]"#, r#"{"hints":[]}"#] {
            assert!(serde_json::from_str::<ArrayWitness>(bad).is_err(), "{bad}");
        }
    }

    #[test_strategy::proptest]
    fn encodings_roundtrip(hints: Vec<Vec<u8>>) {
        let witness = ArrayWitness::from_hints(hints.clone());
        let bytes = borsh::to_vec(&witness).unwrap();
        let decoded: ArrayWitness = borsh::from_slice(&bytes).unwrap();
        assert_eq!(borsh::to_vec(&decoded).unwrap(), bytes);
        let json = serde_json::to_string(&witness).unwrap();
        let decoded: ArrayWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
        let binary = postcard::to_allocvec(&witness).unwrap();
        let decoded: ArrayWitness = postcard::from_bytes(&binary).unwrap();
        assert_eq!(decoded.len(), hints.len());
        for hint in hints {
            assert_eq!(decoded.hints().pop_front().unwrap(), hint);
        }
    }

    /// Storage proofs and other hints are decoded with the same strictness.
    #[test]
    fn structured_hints_roundtrip() {
        let witness = ArrayWitness::default();
        let proof = StorageProof {
            key: crate::SlotKey::from_parts(&crate::Prefix::new(1, 2), &[3]),
            value: Some(SlotValue::from(vec![4])),
            proof: vec![5u8],
            namespace: crate::ProvableNamespace::Kernel,
        };
        witness.add_hint(&proof);
        assert_eq!(witness.get_hint::<StorageProof<Vec<u8>>>(), proof);
    }
}

//! Which `selendra-state` types are consensus types
//! ([`ConsensusType`](selendra_interface::common::ConsensusType), `docs/serialization.md`
//! "Consensus types"), checked at compile time in every build, the zk guest's included.
//!
//! Every public borsh type of this crate is one: keys and values ([`Prefix`], [`SlotKey`],
//! [`SlotValue`]), namespaces ([`Namespace`], [`ProvableNamespace`]), leaves ([`NodeLeaf`]),
//! proofs ([`StorageProof`], [`NomtProof`]), roots ([`StorageRoot`]) and the witness
//! ([`ArrayWitness`]). Each impl says why its encoding is the same natively and in the 32-bit
//! guest, and has one accepted encoding. [`Storage::Proof`](crate::Storage::Proof) and
//! [`Storage::Root`](crate::Storage::Root) are bounded by the trait, and so are witness hints
//! ([`Witness::add_hint`](crate::Witness::add_hint)), so generic code can store or sign a
//! storage proof and the guest decodes no hint a 32-bit `usize` could make diverge.

use selendra_interface::common::ConsensusType;

use crate::{
    ArrayWitness, DefaultStorageSpec, Namespace, NodeLeaf, NomtProof, Prefix, ProvableNamespace,
    SlotKey, SlotValue, StateHasher, StorageProof, StorageRoot,
};

/// Fails to compile if one of these types is not a consensus type.
const _: () = {
    const fn consensus<T: ConsensusType + ?Sized>() {}
    consensus::<Prefix>();
    consensus::<SlotKey>();
    consensus::<SlotValue>();
    consensus::<Namespace>();
    consensus::<ProvableNamespace>();
    consensus::<NodeLeaf>();
    consensus::<NomtProof>();
    consensus::<StorageProof<NomtProof>>();
    consensus::<StorageRoot<DefaultStorageSpec<StateHasher>>>();
    consensus::<ArrayWitness>();
};

/// Generic code gets the same from the `Storage` bounds: a storage's proof and root, and a
/// storage proof, are consensus types for every storage.
#[expect(dead_code, reason = "compile-time check only")]
fn storage_types_are_consensus_types<St: crate::Storage>() {
    fn consensus<T: ConsensusType + ?Sized>() {}
    consensus::<St::Proof>();
    consensus::<St::Root>();
    consensus::<StorageProof<St::Proof>>();
}

#[cfg(test)]
mod tests {
    use borsh::{BorshDeserialize, BorshSerialize};

    use super::*;
    use crate::Witness;
    use crate::nomt::proof_test_utils::three_terminal_proof;

    /// Decodes `bytes` with `borsh::from_slice` (whole input) and checks that the value
    /// re-encodes to exactly `bytes`.
    fn roundtrip<T: BorshSerialize + BorshDeserialize>(value: &T) -> T {
        let bytes = borsh::to_vec(value).unwrap();
        let decoded: T = borsh::from_slice(&bytes).unwrap();
        assert_eq!(borsh::to_vec(&decoded).unwrap(), bytes);
        // Trailing bytes are rejected: each value has one accepted encoding.
        assert!(borsh::from_slice::<T>(&[bytes.as_slice(), &[0]].concat()).is_err());
        decoded
    }

    fn namespace(kernel: bool) -> ProvableNamespace {
        if kernel {
            ProvableNamespace::Kernel
        } else {
            ProvableNamespace::User
        }
    }

    #[test_strategy::proptest]
    fn prefix_roundtrips_canonically(module: u8, item: u8) {
        let prefix = Prefix::new(module, item);
        assert_eq!(roundtrip(&prefix), prefix);
        assert!(borsh::from_slice::<Prefix>(&[module]).is_err());
    }

    #[test_strategy::proptest]
    fn namespaces_roundtrip_canonically(tag: u8) {
        // Tags 0..=2 (`Namespace`) and 0..=1 (`ProvableNamespace`) only.
        match borsh::from_slice::<Namespace>(&[tag]) {
            Ok(ns) => assert_eq!(roundtrip(&ns), ns),
            Err(_) => assert!(tag > 2),
        }
        match borsh::from_slice::<ProvableNamespace>(&[tag]) {
            Ok(ns) => assert_eq!(roundtrip(&ns), ns),
            Err(_) => assert!(tag > 1),
        }
    }

    #[test_strategy::proptest]
    fn node_leaf_roundtrips_canonically(size: u32, val_hash: [u8; 32]) {
        let leaf = NodeLeaf { size, val_hash };
        assert_eq!(roundtrip(&leaf), leaf);
        assert_eq!(roundtrip(&Some(leaf)), Some(leaf));
    }

    #[test_strategy::proptest]
    fn storage_proof_roundtrips_canonically(
        module: u8,
        item: u8,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
        kernel: bool,
    ) {
        let proof = StorageProof {
            key: SlotKey::from_parts(&Prefix::new(module, item), &key),
            value: value.map(SlotValue::from),
            proof: NomtProof::new(three_terminal_proof()).unwrap(),
            namespace: namespace(kernel),
        };
        assert_eq!(roundtrip(&proof), proof);
    }

    /// The tags and the inner proof of a `StorageProof<NomtProof>` are checked: an `Option` tag
    /// other than 0/1, a namespace tag other than 0/1, a key under 2 bytes, and a non-canonical
    /// inner proof are rejected.
    #[test]
    fn storage_proof_rejects_non_canonical_bytes() {
        let proof = StorageProof {
            key: SlotKey::from_parts(&Prefix::new(1, 2), &[3]),
            value: Some(SlotValue::from(vec![0xab])),
            proof: NomtProof::new(three_terminal_proof()).unwrap(),
            namespace: ProvableNamespace::User,
        };
        let bytes = borsh::to_vec(&proof).unwrap();
        assert_eq!(
            borsh::from_slice::<StorageProof<NomtProof>>(&bytes).unwrap(),
            proof
        );
        let decode = |bytes: &[u8]| borsh::from_slice::<StorageProof<NomtProof>>(bytes);
        // key: [3, 0, 0, 0, 1, 2, 3]; value: [1 (Some), 1, 0, 0, 0, 0xab]; proof; namespace.
        let mut option_tag = bytes.clone();
        option_tag[7] = 2;
        assert!(decode(&option_tag).is_err());
        let mut namespace_tag = bytes.clone();
        *namespace_tag.last_mut().unwrap() = 2;
        assert!(decode(&namespace_tag).is_err());
        let short_key = [&[1, 0, 0, 0, 1][..], &bytes[7..]].concat();
        assert!(decode(&short_key).is_err());
        // A bit past the terminator's depth (see `nomt::proof`'s tests): the same proof to
        // nomt-core, another encoding.
        let mut inner = bytes.clone();
        let terminator_at = 13 + crate::nomt::proof_test_utils::TERMINATOR_AT;
        assert_eq!(inner[terminator_at], 0b1000_0000);
        inner[terminator_at] |= 0b0010_0000;
        assert!(decode(&inner).is_err());
        assert!(decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    #[test_strategy::proptest]
    fn array_witness_roundtrips_canonically(hints: Vec<Vec<u8>>) {
        let witness = ArrayWitness::from_hints(hints.clone());
        let decoded = roundtrip(&witness);
        assert_eq!(decoded.len(), hints.len());
        for hint in hints {
            let witness = ArrayWitness::from_hints(vec![borsh::to_vec(&hint).unwrap()]);
            assert_eq!(witness.get_hint::<Vec<u8>>(), hint);
        }
    }

    /// A length prefix longer than the hints that follow is rejected (no partial witness).
    #[test]
    fn array_witness_rejects_non_canonical_bytes() {
        let bytes = borsh::to_vec(&ArrayWitness::from_hints(vec![vec![7]])).unwrap();
        assert_eq!(bytes, [1, 0, 0, 0, 1, 0, 0, 0, 7]);
        assert!(borsh::from_slice::<ArrayWitness>(&[2, 0, 0, 0, 1, 0, 0, 0, 7]).is_err());
        assert!(borsh::from_slice::<ArrayWitness>(&[1, 0, 0, 0, 2, 0, 0, 0, 7]).is_err());
        assert!(borsh::from_slice::<ArrayWitness>(&[1, 0, 0, 0, 1, 0, 0, 0, 7, 0]).is_err());
    }
}

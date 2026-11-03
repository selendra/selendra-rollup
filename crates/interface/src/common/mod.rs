//! Common types used throughout Selendra.

mod hex_string;
mod slot_numbering;

pub use hex_string::*;
pub use slot_numbering::*;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    /// Maps and sets in consensus types rely on borsh's `de_strict_order` feature: keys must be
    /// strictly increasing, so each map has exactly one encoding.
    #[test]
    fn borsh_maps_require_strictly_increasing_keys() {
        let sorted = [2, 0, 0, 0, 1, 8, 2, 9];
        let map: BTreeMap<u8, u8> = borsh::from_slice(&sorted).unwrap();
        assert_eq!(borsh::to_vec(&map).unwrap(), sorted);

        let unsorted = [2, 0, 0, 0, 2, 9, 1, 8];
        let duplicate = [2, 0, 0, 0, 1, 7, 1, 8];
        assert!(borsh::from_slice::<BTreeMap<u8, u8>>(&unsorted).is_err());
        assert!(borsh::from_slice::<BTreeMap<u8, u8>>(&duplicate).is_err());
        assert!(borsh::from_slice::<BTreeSet<u8>>(&[2, 0, 0, 0, 2, 1]).is_err());
        assert!(borsh::from_slice::<BTreeSet<u8>>(&[2, 0, 0, 0, 1, 1]).is_err());
    }
}

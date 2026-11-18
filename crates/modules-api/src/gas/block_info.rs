//! [`BlockGasInfo`]: a rollup block's gas limit, gas used and base fee.

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::deserialize_object_only;
use serde::{Deserialize, Serialize};

use crate::Gas;

/// A rollup block's gas: its limit, the gas it used, and its base fee per unit of gas. The
/// chain-state module (Phase 6) stores one per block.
///
/// - borsh: `gas_limit`, `gas_used` (each `N` `u64`s), then `base_fee_per_gas` (`N` `u128`s),
///   all little-endian, no length prefixes (for `GasUnit<2>`: 64 bytes);
/// - JSON: an object with exactly `gas_limit`, `gas_used`, `base_fee_per_gas` (no unknown
///   fields, no array form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, BorshSerialize, BorshDeserialize)]
// The derived impl takes `GU: Gas` from the struct (it implies serde for `GU` and its price).
#[serde(bound = "")]
pub struct BlockGasInfo<GU: Gas> {
    /// The block's gas limit (adjusted over time for proving and execution performance).
    gas_limit: GU,
    /// The gas the block used: zero when the block starts, set when it ends.
    gas_used: GU,
    /// The base fee per unit of gas. With `gas_used`, it gives the block's total base fee.
    base_fee_per_gas: GU::Price,
}

/// The fields of [`BlockGasInfo`], for its strict JSON decoding.
#[derive(Deserialize)]
#[serde(bound = "", deny_unknown_fields, rename = "BlockGasInfo")]
struct BlockGasInfoFields<GU: Gas> {
    gas_limit: GU,
    gas_used: GU,
    base_fee_per_gas: GU::Price,
}

/// JSON: an object only (the derive also accepts an array of the fields).
impl<'de, GU: Gas> Deserialize<'de> for BlockGasInfo<GU> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let BlockGasInfoFields {
            gas_limit,
            gas_used,
            base_fee_per_gas,
        } = deserialize_object_only(deserializer)?;
        Ok(Self {
            gas_limit,
            gas_used,
            base_fee_per_gas,
        })
    }
}

impl<GU: Gas> selendra_interface::common::ConsensusType for BlockGasInfo<GU> {}

impl<GU: Gas> BlockGasInfo<GU> {
    /// A block with `gas_limit` and `base_fee_per_gas` that has used no gas yet.
    pub fn new(gas_limit: GU, base_fee_per_gas: GU::Price) -> Self {
        Self::with_usage(gas_limit, base_fee_per_gas, GU::ZEROED)
    }

    /// A block with `gas_limit`, `base_fee_per_gas`, and `gas_used`.
    pub fn with_usage(gas_limit: GU, base_fee_per_gas: GU::Price, gas_used: GU) -> Self {
        Self {
            gas_limit,
            gas_used,
            base_fee_per_gas,
        }
    }

    /// Sets the gas the block used.
    pub fn update_gas_used(&mut self, gas_used: GU) {
        self.gas_used = gas_used;
    }

    /// The block's gas limit.
    pub const fn gas_limit(&self) -> &GU {
        &self.gas_limit
    }

    /// The gas the block used.
    pub const fn gas_used(&self) -> &GU {
        &self.gas_used
    }

    /// The block's base fee per unit of gas.
    pub const fn base_fee_per_gas(&self) -> &GU::Price {
        &self.base_fee_per_gas
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;
    use crate::{Amount, GasArray, GasPrice, GasUnit};

    fn info() -> BlockGasInfo<GasUnit<2>> {
        BlockGasInfo::with_usage(
            GasUnit::from([0x0102, 3]),
            GasPrice::from([Amount::new(5), Amount::new(0x0607)]),
            GasUnit::from([4, u64::MAX]),
        )
    }

    #[test]
    fn block_gas_info_known_answer_encoding() {
        let mut expected = Vec::new();
        expected.extend([0x02, 0x01, 0, 0, 0, 0, 0, 0]); // gas_limit[0]
        expected.extend([3, 0, 0, 0, 0, 0, 0, 0]); // gas_limit[1]
        expected.extend([4, 0, 0, 0, 0, 0, 0, 0]); // gas_used[0]
        expected.extend([0xff; 8]); // gas_used[1]
        expected.extend([5]); // base_fee_per_gas[0]
        expected.extend([0; 15]);
        expected.extend([0x07, 0x06]); // base_fee_per_gas[1]
        expected.extend([0; 14]);
        assert_eq!(expected.len(), 64);
        assert_eq!(borsh::to_vec(&info()).unwrap(), expected);
        assert_eq!(
            borsh::from_slice::<BlockGasInfo<GasUnit<2>>>(&expected).unwrap(),
            info()
        );
        assert!(borsh::from_slice::<BlockGasInfo<GasUnit<2>>>(&expected[..63]).is_err());
        let mut long = expected.clone();
        long.push(0);
        assert!(borsh::from_slice::<BlockGasInfo<GasUnit<2>>>(&long).is_err());
    }

    #[test]
    fn block_gas_info_json() {
        let json = serde_json::to_string(&info()).unwrap();
        assert_eq!(
            json,
            r#"{"gas_limit":[258,3],"gas_used":[4,18446744073709551615],"base_fee_per_gas":["5","1543"]}"#
        );
        assert_eq!(
            serde_json::from_str::<BlockGasInfo<GasUnit<2>>>(&json).unwrap(),
            info()
        );
        for rejected in [
            r#"{"gas_limit":[258,3],"gas_used":[4,1],"base_fee_per_gas":["5","1"],"x":1}"#,
            r#"{"gas_limit":[258,3],"gas_used":[4,1]}"#,
            r#"[[258,3],[4,1],["5","1"]]"#,
        ] {
            assert!(
                serde_json::from_str::<BlockGasInfo<GasUnit<2>>>(rejected).is_err(),
                "{rejected} accepted"
            );
        }
    }

    #[test]
    fn new_block_has_used_nothing() {
        let mut block = BlockGasInfo::new(GasUnit::<2>::from([10, 20]), GasPrice::ZEROED);
        assert_eq!(block.gas_used(), &GasUnit::ZEROED);
        assert_eq!(block.gas_limit(), &GasUnit::from([10, 20]));
        assert_eq!(block.base_fee_per_gas(), &GasPrice::ZEROED);
        block.update_gas_used(GasUnit::from([1, 2]));
        assert_eq!(block.gas_used(), &GasUnit::from([1, 2]));
    }

    #[proptest]
    fn block_gas_info_round_trips(limit: [u64; 2], used: [u64; 2], fee: [u128; 2]) {
        let info = BlockGasInfo::with_usage(
            GasUnit::from(limit),
            GasPrice::from(fee.map(Amount::new)),
            GasUnit::from(used),
        );
        let bytes = borsh::to_vec(&info).unwrap();
        assert_eq!(
            borsh::from_slice::<BlockGasInfo<GasUnit<2>>>(&bytes).unwrap(),
            info
        );
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(
            serde_json::from_str::<BlockGasInfo<GasUnit<2>>>(&json).unwrap(),
            info
        );
        let binary = postcard::to_allocvec(&info).unwrap();
        assert_eq!(
            postcard::from_bytes::<BlockGasInfo<GasUnit<2>>>(&binary).unwrap(),
            info
        );
    }
}

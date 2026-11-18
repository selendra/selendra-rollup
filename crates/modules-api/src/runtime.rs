//! Runtime-wide types: [`OperatingMode`].

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// How the rollup is secured: zk proofs, or a trusted operator (launch).
///
/// borsh: one byte, the explicit tag (`1` = `Zk`, `2` = `Operator`); `0` is never assigned
/// (upstream's first variant was `Optimistic`, not ported). JSON: `"zk"` / `"operator"`.
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
    Debug,
    PartialEq,
    Eq,
    Copy,
    Clone,
    Hash,
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
#[borsh(use_discriminant = true)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum OperatingMode {
    /// Every state transition is proven with zk proofs.
    Zk = 1,
    /// A trusted operator runs the rollup (launch, before provers).
    Operator = 2,
}

selendra_interface::impl_consensus_type!(OperatingMode);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operating_mode_tags_are_pinned() {
        assert_eq!(borsh::to_vec(&OperatingMode::Zk).unwrap(), [1]);
        assert_eq!(borsh::to_vec(&OperatingMode::Operator).unwrap(), [2]);
        assert_eq!(
            borsh::from_slice::<OperatingMode>(&[1]).unwrap(),
            OperatingMode::Zk
        );
        assert_eq!(
            borsh::from_slice::<OperatingMode>(&[2]).unwrap(),
            OperatingMode::Operator
        );
        for rejected in [&[0][..], &[3], &[255], &[], &[1, 0]] {
            assert!(borsh::from_slice::<OperatingMode>(rejected).is_err());
        }
        assert_eq!(serde_json::to_string(&OperatingMode::Zk).unwrap(), "\"zk\"");
        assert_eq!(
            serde_json::to_string(&OperatingMode::Operator).unwrap(),
            "\"operator\""
        );
        for rejected in ["\"Zk\"", "\"optimistic\"", "1", "null"] {
            assert!(serde_json::from_str::<OperatingMode>(rejected).is_err());
        }
    }
}

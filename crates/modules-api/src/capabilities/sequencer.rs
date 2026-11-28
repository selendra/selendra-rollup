//! The sequencer's capabilities: whether it is the preferred one ([`SequencerAuthorization`]),
//! and its rewards and penalties ([`SequencerRemuneration`]).

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::da::DaSpec;
use serde::{Deserialize, Serialize};

use crate::transaction::SequencerReward;
use crate::{Amount, ConsensusType, InfallibleKernelStateAccessor, InfallibleStateAccessor, Spec};

/// A sequencer allowed to sequence: its rollup address and staked balance.
///
/// borsh: `address`, then `balance` (`u128` LE). JSON: an object with exactly these fields. A
/// consensus type (the sequencer registry stores it, Phase 6).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    ConsensusType,
)]
#[serde(bound = "", deny_unknown_fields)]
pub struct AllowedSequencer<S: Spec> {
    /// The sequencer's rollup address.
    pub address: S::Address,
    /// Its staked balance.
    pub balance: Amount,
}

/// Authorizes the sequencer to submit and process batches.
pub trait SequencerAuthorization<S: Spec> {
    /// Whether `sequencer` is the preferred sequencer (e.g. by its current balance).
    fn is_preferred_sequencer(
        &self,
        sequencer: &<S::Da as DaSpec>::Address,
        state: &mut impl InfallibleStateAccessor,
    ) -> bool;
}

impl<S: Spec, T: SequencerAuthorization<S> + ?Sized> SequencerAuthorization<S> for &mut T {
    fn is_preferred_sequencer(
        &self,
        sequencer: &<S::Da as DaSpec>::Address,
        state: &mut impl InfallibleStateAccessor,
    ) -> bool {
        (**self).is_preferred_sequencer(sequencer, state)
    }
}

/// Rewards and slashes the sequencer.
///
/// Coupled with the [`GasEnforcer`](super::GasEnforcer) and the blob selector (Phase 8): they
/// move the same funds.
pub trait SequencerRemuneration<S: Spec> {
    /// Rewards the sequencer for a forced registration it processed correctly; if the
    /// registration was reverted, refunds `sequencer_rollup_address` instead.
    ///
    /// Unmetered: keep it cheap.
    fn reward_sequencer_or_refund<A: InfallibleStateAccessor + InfallibleKernelStateAccessor>(
        &mut self,
        sequencer: &<S::Da as DaSpec>::Address,
        sequencer_rollup_address: &S::Address,
        reward: SequencerReward,
        state: &mut A,
    );

    /// The preferred sequencer, if there is one.
    fn preferred_sequencer(
        &self,
        state: &mut impl InfallibleStateAccessor,
    ) -> Option<<S::Da as DaSpec>::Address>;
}

impl<S: Spec, T: SequencerRemuneration<S> + ?Sized> SequencerRemuneration<S> for &mut T {
    fn reward_sequencer_or_refund<A: InfallibleStateAccessor + InfallibleKernelStateAccessor>(
        &mut self,
        sequencer: &<S::Da as DaSpec>::Address,
        sequencer_rollup_address: &S::Address,
        reward: SequencerReward,
        state: &mut A,
    ) {
        (**self).reward_sequencer_or_refund(sequencer, sequencer_rollup_address, reward, state);
    }

    fn preferred_sequencer(
        &self,
        state: &mut impl InfallibleStateAccessor,
    ) -> Option<<S::Da as DaSpec>::Address> {
        (**self).preferred_sequencer(state)
    }
}

#[cfg(test)]
mod tests {
    use selendra_primitives::{Address, MultiAddressEvm};

    use super::*;
    use crate::test_utils::TestSpec;

    /// Known answer: the address (a `Standard` tag `0` and its 28 bytes), then the balance.
    #[test]
    fn allowed_sequencer_encodings() {
        let sequencer = AllowedSequencer::<TestSpec> {
            address: MultiAddressEvm::Standard(Address::new([7; 28])),
            balance: Amount::new(0x0102),
        };
        let bytes = borsh::to_vec(&sequencer).unwrap();
        let address = borsh::to_vec(&sequencer.address).unwrap();
        let mut expected = address.clone();
        expected.extend([2, 1]);
        expected.extend([0; 14]);
        assert_eq!(bytes, expected);
        assert_eq!(
            borsh::from_slice::<AllowedSequencer<TestSpec>>(&bytes).unwrap(),
            sequencer
        );
        let json = serde_json::to_string(&sequencer).unwrap();
        assert_eq!(
            serde_json::from_str::<AllowedSequencer<TestSpec>>(&json).unwrap(),
            sequencer
        );
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["extra"] = 1.into();
        assert!(serde_json::from_value::<AllowedSequencer<TestSpec>>(value).is_err());
        assert_eq!(value_balance(&json), "258");
    }

    fn value_balance(json: &str) -> String {
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        value["balance"].as_str().unwrap().to_owned()
    }
}

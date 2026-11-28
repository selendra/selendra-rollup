//! [`GasEnforcer`]: reserving a transaction's gas and settling it, and [`Rewards`], what a
//! sequencer accumulates over a batch.

use selendra_interface::da::DaSpec;
use selendra_state::VersionReader;

use crate::transaction::{AuthenticatedTransactionData, ProverReward, RemainingFunds};
use crate::{
    Amount, Context, Gas, InfallibleKernelStateAccessor, InfallibleStateAccessor, OperatingMode,
    Spec, StateAccessor,
};

/// What a sequencer accumulated over a batch: rewards for the transactions it included, and
/// penalties for those it should not have (each charged from its escrow).
///
/// Built by the state transition function (Phase 8; upstream `batch.rs`), passed to
/// [`GasEnforcer::return_escrowed_funds_to_sequencer`]. The fields are private: it is built with
/// [`new`](Self::new) or accumulated from [`ZERO`](Self::ZERO).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rewards {
    accumulated_reward: Amount,
    accumulated_penalty: Amount,
}

impl Rewards {
    /// No reward and no penalty.
    pub const ZERO: Self = Self::new(Amount::ZERO, Amount::ZERO);

    /// `accumulated_reward` and `accumulated_penalty`.
    pub const fn new(accumulated_reward: Amount, accumulated_penalty: Amount) -> Self {
        Self {
            accumulated_reward,
            accumulated_penalty,
        }
    }

    /// The rewards accumulated.
    pub const fn accumulated_reward(&self) -> Amount {
        self.accumulated_reward
    }

    /// The penalties accumulated.
    pub const fn accumulated_penalty(&self) -> Amount {
        self.accumulated_penalty
    }

    /// Adds `reward` to the rewards, or `None` on overflow (nothing changes then).
    #[must_use = "`None` means nothing was added"]
    pub const fn checked_add_reward(&mut self, reward: Amount) -> Option<()> {
        match self.accumulated_reward.checked_add(reward) {
            Some(total) => {
                self.accumulated_reward = total;
                Some(())
            }
            None => None,
        }
    }

    /// Adds `penalty` to the penalties, or `None` on overflow (nothing changes then).
    #[must_use = "`None` means nothing was added"]
    pub const fn checked_add_penalty(&mut self, penalty: Amount) -> Option<()> {
        match self.accumulated_penalty.checked_add(penalty) {
            Some(total) => {
                self.accumulated_penalty = total;
                Some(())
            }
            None => None,
        }
    }
}

/// The net reward: `reward - penalty`, with a `-` sign when the penalties are larger.
impl core::fmt::Display for Rewards {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.accumulated_reward >= self.accumulated_penalty {
            write!(
                f,
                "{}",
                self.accumulated_reward
                    .saturating_sub(self.accumulated_penalty)
            )
        } else {
            write!(
                f,
                "-{}",
                self.accumulated_penalty
                    .saturating_sub(self.accumulated_reward)
            )
        }
    }
}

/// Enforces gas limits and settles gas: reserves a transaction's fees before it runs, refunds
/// what it did not use and rewards the prover after.
///
/// Its implementation is coupled with [`SequencerRemuneration`](super::SequencerRemuneration)
/// and the blob selector (Phase 8), which may reserve gas for a blob's decoding: they move the
/// same funds. Phase 6 changes this trait for fee tokens and fee payers (TODO.md, multi-token
/// gas and sponsored fees).
pub trait GasEnforcer<S: Spec> {
    /// Checks that the transaction has enough funds for its gas, and reserves them.
    ///
    /// It must reserve at least the cost of the pre-execution checks, and fail if the funds do
    /// not cover them. It should take the reserved funds from the payer now: the payer's
    /// balance may change while the transaction runs.
    ///
    /// # Errors
    /// The transaction cannot pay: it is not run.
    fn try_reserve_gas(
        &mut self,
        tx: &AuthenticatedTransactionData<S>,
        gas_price: <S::Gas as Gas>::Price,
        context: &mut Context<S>,
        state: &mut impl StateAccessor,
    ) -> anyhow::Result<()>;

    /// Like [`try_reserve_gas`](Self::try_reserve_gas), for a proof submitted by `sender`.
    ///
    /// # Errors
    /// The sender cannot pay: the proof is not processed.
    fn try_reserve_gas_for_proof(
        &mut self,
        tx: &AuthenticatedTransactionData<S>,
        gas_price: <S::Gas as Gas>::Price,
        sender: &S::Address,
        state: &mut impl StateAccessor,
    ) -> anyhow::Result<()>;

    /// Rewards the prover with `reward` (out of the reserved funds). Must not fail: the caller
    /// reserved enough.
    fn reward_prover(
        &mut self,
        reward: &ProverReward,
        operating_mode: OperatingMode,
        state: &mut impl InfallibleStateAccessor,
    );

    /// Refunds `remaining_funds` (the reserved funds the transaction did not use) to `payer`.
    /// Must not fail: the caller reserved enough.
    fn refund_remaining_gas(
        &mut self,
        payer: &S::Address,
        remaining_funds: &RemainingFunds,
        state: &mut impl InfallibleStateAccessor,
    );

    /// Pays the prover `funds_used` from the sequencer's balance: the authentication of a
    /// transaction that did not pay for itself.
    ///
    /// Unmetered: keep it cheap (a transfer between known accounts). Coupled with
    /// [`SequencerRemuneration`](super::SequencerRemuneration).
    ///
    /// # Errors
    /// The sequencer cannot pay.
    fn reward_prover_from_sequencer_balance(
        &mut self,
        funds_used: Amount,
        sequencer: &S::Address,
        operating_mode: OperatingMode,
        state: &mut impl InfallibleStateAccessor,
    ) -> anyhow::Result<()>;

    /// Returns what is left of the sequencer's escrow, `initial_escrow` plus its batch's
    /// `rewards` minus their penalties, to `sequencer`.
    ///
    /// Unmetered: keep it cheap. Coupled with
    /// [`SequencerRemuneration`](super::SequencerRemuneration).
    fn return_escrowed_funds_to_sequencer<
        A: InfallibleStateAccessor + InfallibleKernelStateAccessor + VersionReader,
    >(
        &mut self,
        initial_escrow: Amount,
        rewards: Rewards,
        sequencer: &<S::Da as DaSpec>::Address,
        state: &mut A,
    );
}

impl<S: Spec, T: GasEnforcer<S> + ?Sized> GasEnforcer<S> for &mut T {
    fn try_reserve_gas(
        &mut self,
        tx: &AuthenticatedTransactionData<S>,
        gas_price: <S::Gas as Gas>::Price,
        context: &mut Context<S>,
        state: &mut impl StateAccessor,
    ) -> anyhow::Result<()> {
        (**self).try_reserve_gas(tx, gas_price, context, state)
    }

    fn try_reserve_gas_for_proof(
        &mut self,
        tx: &AuthenticatedTransactionData<S>,
        gas_price: <S::Gas as Gas>::Price,
        sender: &S::Address,
        state: &mut impl StateAccessor,
    ) -> anyhow::Result<()> {
        (**self).try_reserve_gas_for_proof(tx, gas_price, sender, state)
    }

    fn reward_prover(
        &mut self,
        reward: &ProverReward,
        operating_mode: OperatingMode,
        state: &mut impl InfallibleStateAccessor,
    ) {
        (**self).reward_prover(reward, operating_mode, state);
    }

    fn refund_remaining_gas(
        &mut self,
        payer: &S::Address,
        remaining_funds: &RemainingFunds,
        state: &mut impl InfallibleStateAccessor,
    ) {
        (**self).refund_remaining_gas(payer, remaining_funds, state);
    }

    fn reward_prover_from_sequencer_balance(
        &mut self,
        funds_used: Amount,
        sequencer: &S::Address,
        operating_mode: OperatingMode,
        state: &mut impl InfallibleStateAccessor,
    ) -> anyhow::Result<()> {
        (**self).reward_prover_from_sequencer_balance(funds_used, sequencer, operating_mode, state)
    }

    fn return_escrowed_funds_to_sequencer<
        A: InfallibleStateAccessor + InfallibleKernelStateAccessor + VersionReader,
    >(
        &mut self,
        initial_escrow: Amount,
        rewards: Rewards,
        sequencer: &<S::Da as DaSpec>::Address,
        state: &mut A,
    ) {
        (**self).return_escrowed_funds_to_sequencer(initial_escrow, rewards, sequencer, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewards_accumulate_checked_and_display_the_net() {
        let mut rewards = Rewards::ZERO;
        assert_eq!(rewards, Rewards::default());
        assert_eq!(rewards.checked_add_reward(Amount::new(7)), Some(()));
        assert_eq!(rewards.checked_add_penalty(Amount::new(3)), Some(()));
        assert_eq!(rewards.accumulated_reward(), Amount::new(7));
        assert_eq!(rewards.accumulated_penalty(), Amount::new(3));
        assert_eq!(rewards.to_string(), "4");
        assert_eq!(
            Rewards::new(Amount::new(1), Amount::new(5)).to_string(),
            "-4"
        );
        assert_eq!(Rewards::ZERO.to_string(), "0");

        // An overflow changes nothing.
        let mut full = Rewards::new(Amount::MAX, Amount::MAX);
        assert_eq!(full.checked_add_reward(Amount::new(1)), None);
        assert_eq!(full.checked_add_penalty(Amount::new(1)), None);
        assert_eq!(full, Rewards::new(Amount::MAX, Amount::MAX));
        assert_eq!(full.to_string(), "0");
    }
}

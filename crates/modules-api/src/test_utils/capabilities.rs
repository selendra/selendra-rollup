//! [`MockCapabilities`]: every capability, over in-memory maps.

use std::collections::{BTreeMap, BTreeSet};

use selendra_interface::crypto::CredentialId;
use selendra_interface::da::DaSpec;
use selendra_interface::stf::{ExecutionContext, InvalidProofError};
use selendra_interface::zk::aggregated_proof::SerializedAggregatedProof;
use selendra_interface::{Bytes, TxHash};
use selendra_state::{StateReader, User, VersionReader};

use crate::capabilities::{
    GasEnforcer, Guard, HasCapabilities, ProofProcessor, Rewards, SequencerAuthorization,
    SequencerRemuneration, SpecAggregatedProofPublicData, TransactionAuthorizer,
};
use crate::transaction::{AuthenticatedTransactionData, AuthorizationData};
use crate::transaction::{ProverReward, RemainingFunds, SequencerReward};
use crate::{
    Amount, Context, Gas, InfallibleKernelStateAccessor, InfallibleStateAccessor, OperatingMode,
    SequencerType, Spec, StateAccessor, TxState,
};

/// Every capability of a runtime, over in-memory maps instead of module state: balances,
/// reservations, the address overrides each credential may use, and the transactions attempted.
/// It touches no state, so the state accessors the capabilities receive are not read.
///
/// For tests of the code that drives the capabilities (the state transition function, Phase 8)
/// and of runtimes overriding one of them ([`HasCapabilities`] is implemented with
/// `Capabilities = &mut MockCapabilities`). Its rules are simple, not the standard ones (Phase
/// 6's bank, accounts and sequencer registry):
/// - [`GasEnforcer`]: reserving takes `max_fee` from the sender's (the proof sender's) balance
///   and fails without it; a refund adds to the payer's balance; the prover's rewards and the
///   escrow returned to sequencers are recorded;
/// - [`TransactionAuthorizer`]: the sender is the credential's default address, or its address
///   override if [`allow_override`](Self::allow_override) allowed it for that credential; a
///   non-malleable hash marked attempted is not unique any more;
/// - [`SequencerAuthorization`]/[`SequencerRemuneration`]: one preferred sequencer, if set;
///   rewards are recorded;
/// - [`ProofProcessor`]: every proof is rejected (`PreconditionNotMet`).
#[derive(Debug, Clone)]
pub struct MockCapabilities<S: Spec> {
    balances: BTreeMap<S::Address, Amount>,
    reserved: BTreeMap<S::Address, Amount>,
    overrides: BTreeSet<(S::Address, CredentialId)>,
    attempted: BTreeSet<TxHash>,
    preferred_sequencer: Option<<S::Da as DaSpec>::Address>,
    prover_rewards: Amount,
    sequencer_rewards: Vec<(<S::Da as DaSpec>::Address, Amount)>,
    returned_escrow: Vec<(<S::Da as DaSpec>::Address, Amount, Rewards)>,
}

impl<S: Spec> Default for MockCapabilities<S> {
    fn default() -> Self {
        Self {
            balances: BTreeMap::new(),
            reserved: BTreeMap::new(),
            overrides: BTreeSet::new(),
            attempted: BTreeSet::new(),
            preferred_sequencer: None,
            prover_rewards: Amount::ZERO,
            sequencer_rewards: Vec::new(),
            returned_escrow: Vec::new(),
        }
    }
}

impl<S: Spec> MockCapabilities<S> {
    /// No balances, no preferred sequencer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `address`'s balance.
    pub fn set_balance(&mut self, address: S::Address, amount: Amount) {
        self.balances.insert(address, amount);
    }

    /// `address`'s balance (zero if it has none).
    pub fn balance(&self, address: &S::Address) -> Amount {
        self.balances.get(address).copied().unwrap_or(Amount::ZERO)
    }

    /// What was reserved from `address` so far (reservations are never released: refunds go
    /// to the balance).
    pub fn reserved(&self, address: &S::Address) -> Amount {
        self.reserved.get(address).copied().unwrap_or(Amount::ZERO)
    }

    /// Lets `credential` run transactions as `address` (an address override).
    pub fn allow_override(&mut self, address: S::Address, credential: CredentialId) {
        self.overrides.insert((address, credential));
    }

    /// Makes `sequencer` the preferred sequencer.
    pub fn set_preferred_sequencer(&mut self, sequencer: <S::Da as DaSpec>::Address) {
        self.preferred_sequencer = Some(sequencer);
    }

    /// Whether the transaction with `non_malleable_hash` was marked attempted.
    pub fn was_attempted(&self, non_malleable_hash: &TxHash) -> bool {
        self.attempted.contains(non_malleable_hash)
    }

    /// The prover's rewards so far.
    pub const fn prover_rewards(&self) -> Amount {
        self.prover_rewards
    }

    /// The sequencer rewards (or refunds) paid so far, in order.
    pub fn sequencer_rewards(&self) -> &[(<S::Da as DaSpec>::Address, Amount)] {
        &self.sequencer_rewards
    }

    /// The escrows returned to sequencers so far, in order: the sequencer, the initial escrow
    /// and its batch's rewards.
    pub fn returned_escrow(&self) -> &[(<S::Da as DaSpec>::Address, Amount, Rewards)] {
        &self.returned_escrow
    }

    fn reserve(&mut self, payer: S::Address, amount: Amount) -> anyhow::Result<()> {
        let balance = self.balance(&payer);
        let Some(left) = balance.checked_sub(amount) else {
            anyhow::bail!("{payer} has {balance}, cannot reserve {amount}");
        };
        let reserved = self
            .reserved(&payer)
            .checked_add(amount)
            .ok_or_else(|| anyhow::anyhow!("the reservation of {payer} overflows"))?;
        self.balances.insert(payer, left);
        self.reserved.insert(payer, reserved);
        Ok(())
    }

    fn credit(&mut self, address: S::Address, amount: Amount) {
        let balance = self.balance(&address).saturating_add(amount);
        self.balances.insert(address, balance);
    }

    fn sender(&self, auth_data: &AuthorizationData<S>) -> anyhow::Result<S::Address> {
        match auth_data.address_override() {
            None => Ok(*auth_data.default_address()),
            Some(address)
                if self
                    .overrides
                    .contains(&(*address, *auth_data.credential_id())) =>
            {
                Ok(*address)
            }
            Some(address) => anyhow::bail!("the credential may not act as {address}"),
        }
    }
}

impl<S: Spec> GasEnforcer<S> for MockCapabilities<S> {
    fn try_reserve_gas(
        &mut self,
        tx: &AuthenticatedTransactionData<S>,
        _gas_price: <S::Gas as Gas>::Price,
        context: &mut Context<S>,
        _state: &mut impl StateAccessor,
    ) -> anyhow::Result<()> {
        self.reserve(*context.sender(), tx.0.max_fee)
    }

    fn try_reserve_gas_for_proof(
        &mut self,
        tx: &AuthenticatedTransactionData<S>,
        _gas_price: <S::Gas as Gas>::Price,
        sender: &S::Address,
        _state: &mut impl StateAccessor,
    ) -> anyhow::Result<()> {
        self.reserve(*sender, tx.0.max_fee)
    }

    fn reward_prover(
        &mut self,
        reward: &ProverReward,
        _operating_mode: OperatingMode,
        _state: &mut impl InfallibleStateAccessor,
    ) {
        self.prover_rewards = self.prover_rewards.saturating_add(reward.amount());
    }

    fn refund_remaining_gas(
        &mut self,
        payer: &S::Address,
        remaining_funds: &RemainingFunds,
        _state: &mut impl InfallibleStateAccessor,
    ) {
        self.credit(*payer, remaining_funds.amount());
    }

    fn reward_prover_from_sequencer_balance(
        &mut self,
        funds_used: Amount,
        sequencer: &S::Address,
        _operating_mode: OperatingMode,
        _state: &mut impl InfallibleStateAccessor,
    ) -> anyhow::Result<()> {
        let balance = self.balance(sequencer);
        let Some(left) = balance.checked_sub(funds_used) else {
            anyhow::bail!("the sequencer {sequencer} has {balance}, cannot pay {funds_used}");
        };
        self.balances.insert(*sequencer, left);
        self.prover_rewards = self.prover_rewards.saturating_add(funds_used);
        Ok(())
    }

    fn return_escrowed_funds_to_sequencer<
        A: InfallibleStateAccessor + InfallibleKernelStateAccessor + VersionReader,
    >(
        &mut self,
        initial_escrow: Amount,
        rewards: Rewards,
        sequencer: &<S::Da as DaSpec>::Address,
        _state: &mut A,
    ) {
        self.returned_escrow
            .push((*sequencer, initial_escrow, rewards));
    }
}

impl<S: Spec> TransactionAuthorizer<S> for MockCapabilities<S> {
    fn resolve_context(
        &mut self,
        auth_data: &AuthorizationData<S>,
        sequencer: &<S::Da as DaSpec>::Address,
        sequencer_rollup_address: S::Address,
        _state: &mut impl StateReader<User>,
        _sequencing_data: Option<Bytes>,
        execution_context: ExecutionContext,
        sequencer_type: SequencerType,
    ) -> anyhow::Result<Context<S>> {
        Ok(Context::new(
            self.sender(auth_data)?,
            auth_data.credential().clone(),
            sequencer_rollup_address,
            *sequencer,
            execution_context,
            sequencer_type,
        ))
    }

    fn resolve_unregistered_context(
        &mut self,
        auth_data: &AuthorizationData<S>,
        sequencer: &<S::Da as DaSpec>::Address,
        _state: &mut impl StateReader<User>,
        execution_context: ExecutionContext,
    ) -> anyhow::Result<Context<S>> {
        let sender = self.sender(auth_data)?;
        Ok(Context::new(
            sender,
            auth_data.credential().clone(),
            sender,
            *sequencer,
            execution_context,
            SequencerType::NonPreferred,
        ))
    }

    fn check_uniqueness(
        &self,
        auth_data: &AuthorizationData<S>,
        _context: &Context<S>,
        _execution_context: &ExecutionContext,
        _state: &mut impl StateReader<User>,
    ) -> anyhow::Result<()> {
        if self.was_attempted(auth_data.non_malleable_hash()) {
            anyhow::bail!("the transaction {} was attempted", auth_data.tx_hash());
        }
        Ok(())
    }

    fn mark_tx_attempted(
        &mut self,
        auth_data: &AuthorizationData<S>,
        _sequencer: &<S::Da as DaSpec>::Address,
        _state: &mut impl StateAccessor,
    ) -> anyhow::Result<()> {
        self.attempted.insert(*auth_data.non_malleable_hash());
        Ok(())
    }
}

impl<S: Spec> SequencerAuthorization<S> for MockCapabilities<S> {
    fn is_preferred_sequencer(
        &self,
        sequencer: &<S::Da as DaSpec>::Address,
        _state: &mut impl InfallibleStateAccessor,
    ) -> bool {
        self.preferred_sequencer.as_ref() == Some(sequencer)
    }
}

impl<S: Spec> SequencerRemuneration<S> for MockCapabilities<S> {
    fn reward_sequencer_or_refund<A: InfallibleStateAccessor + InfallibleKernelStateAccessor>(
        &mut self,
        sequencer: &<S::Da as DaSpec>::Address,
        _sequencer_rollup_address: &S::Address,
        reward: SequencerReward,
        _state: &mut A,
    ) {
        self.sequencer_rewards.push((*sequencer, reward.amount()));
    }

    fn preferred_sequencer(
        &self,
        _state: &mut impl InfallibleStateAccessor,
    ) -> Option<<S::Da as DaSpec>::Address> {
        self.preferred_sequencer
    }
}

impl<S: Spec> ProofProcessor<S> for MockCapabilities<S> {
    fn process_aggregated_proof<ST: TxState<S>>(
        &mut self,
        _proof: SerializedAggregatedProof,
        _prover_address: &S::Address,
        _execution_context: ExecutionContext,
        _state: &mut ST,
    ) -> Result<(SpecAggregatedProofPublicData<S>, SerializedAggregatedProof), InvalidProofError>
    {
        Err(InvalidProofError::PreconditionNotMet(
            "the mock capabilities process no proofs".to_owned(),
        ))
    }
}

/// The mock is its own runtime's capabilities: every accessor returns it.
impl<S: Spec> HasCapabilities<S> for MockCapabilities<S> {
    type Capabilities<'a>
        = &'a mut Self
    where
        Self: 'a;

    fn capabilities(&mut self) -> Guard<&mut Self> {
        Guard::new(self)
    }
}

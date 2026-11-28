//! The capabilities through `HasCapabilities`: the mock's rules, and a runtime overriding one
//! capability.

use selendra_interface::common::HexHash;
use selendra_interface::stf::ExecutionContext;
use selendra_primitives::crypto::Ed25519PublicKey;
use selendra_primitives::{Address, MultiAddressEvm};
use selendra_state::{ArrayWitness, TxScratchpad};

use super::*;
use crate::test_utils::{MockAddress, MockCapabilities, MockKernel, TestSpec, TestStorage};
use crate::transaction::{AuthenticatedTransactionData, AuthorizationData, UniquenessData};
use crate::{
    Amount, BasicGasMeter, Context, Credential, Gas, GasArray, GasPrice, GasUnit, PriorityFeeBips,
    SequencerType, StateAccessor, TxDetails, WorkingSet,
};

type S = TestSpec;

fn key() -> Ed25519PublicKey {
    "0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        .parse()
        .unwrap()
}

fn auth_data(address_override: Option<MultiAddressEvm>) -> AuthorizationData<S> {
    AuthorizationData::new(
        UniquenessData::Nonce(0),
        HexHash::new([1; 32]),
        HexHash::new([2; 32]),
        Credential::Ed25519(key()),
        address_override,
    )
}

fn tx(max_fee: u128) -> AuthenticatedTransactionData<S> {
    TxDetails {
        max_priority_fee_bips: PriorityFeeBips(0),
        max_fee: Amount::new(max_fee),
        gas_limit: None,
        runtime_version: 1,
    }
    .into()
}

fn working_set() -> WorkingSet<S> {
    let checkpoint = MockKernel::checkpoint(TestStorage::default(), ArrayWitness::default());
    WorkingSet::new(
        TxScratchpad::new(checkpoint),
        BasicGasMeter::new_with_gas(GasUnit::from([1_000_000; 2]), GasPrice::ZEROED),
    )
}

const SEQUENCER: MockAddress = MockAddress::new([7; 32]);

fn sequencer_address() -> MultiAddressEvm {
    MultiAddressEvm::Standard(Address::new([8; 28]))
}

fn resolve<H: HasCapabilities<S>>(
    runtime: &mut H,
    auth: &AuthorizationData<S>,
    state: &mut WorkingSet<S>,
) -> anyhow::Result<Context<S>> {
    runtime.transaction_authorizer().resolve_context(
        auth,
        &SEQUENCER,
        sequencer_address(),
        state,
        None,
        ExecutionContext::Node,
        SequencerType::NonPreferred,
    )
}

/// What the state transition function would do through any runtime: resolve the context, check
/// uniqueness, reserve the gas, mark the transaction attempted.
fn pre_execute<H: HasCapabilities<S>>(
    runtime: &mut H,
    auth: &AuthorizationData<S>,
    max_fee: u128,
) -> anyhow::Result<Context<S>> {
    let mut state = working_set();
    let mut context = resolve(runtime, auth, &mut state)?;
    runtime.transaction_authorizer().check_uniqueness(
        auth,
        &context,
        &ExecutionContext::Node,
        &mut state,
    )?;
    runtime.gas_enforcer().try_reserve_gas(
        &tx(max_fee),
        <<S as crate::Spec>::Gas as Gas>::Price::ZEROED,
        &mut context,
        &mut state,
    )?;
    runtime
        .transaction_authorizer()
        .mark_tx_attempted(auth, &SEQUENCER, &mut state)?;
    Ok(context)
}

#[test]
fn mock_capabilities_rules() {
    let mut mock = MockCapabilities::<S>::new();
    let auth = auth_data(None);
    let sender = *auth.default_address();
    mock.set_balance(sender, Amount::new(100));

    // Not enough funds: nothing reserved.
    assert!(pre_execute(&mut mock, &auth, 101).is_err());
    assert_eq!(mock.balance(&sender), Amount::new(100));
    assert!(!mock.was_attempted(auth.non_malleable_hash()));

    let context = pre_execute(&mut mock, &auth, 60).unwrap();
    assert_eq!(context.sender(), &sender);
    assert_eq!(context.sender_credential(), &Credential::Ed25519(key()));
    assert_eq!(context.sequencer(), &sequencer_address());
    assert_eq!(mock.balance(&sender), Amount::new(40));
    assert_eq!(mock.reserved(&sender), Amount::new(60));
    assert!(mock.was_attempted(auth.non_malleable_hash()));
    // The same transaction again is not unique.
    assert!(pre_execute(&mut mock, &auth, 1).is_err());

    // An address override needs to be allowed for the credential.
    let other = MultiAddressEvm::Standard(Address::new([3; 28]));
    let overriding = AuthorizationData::<S>::new(
        UniquenessData::Nonce(1),
        HexHash::new([4; 32]),
        HexHash::new([5; 32]),
        Credential::Ed25519(key()),
        Some(other),
    );
    let mut state = working_set();
    assert!(resolve(&mut mock, &overriding, &mut state).is_err());
    mock.allow_override(other, *overriding.credential_id());
    assert_eq!(
        resolve(&mut mock, &overriding, &mut state)
            .unwrap()
            .sender(),
        &other
    );

    // The sequencer capabilities.
    let mut checkpoint = MockKernel::checkpoint(TestStorage::default(), ArrayWitness::default());
    let mut block = crate::BlockState::<S>::new(&mut checkpoint);
    assert!(
        !mock
            .sequencer_authorization()
            .is_preferred_sequencer(&SEQUENCER, &mut block)
    );
    mock.set_preferred_sequencer(SEQUENCER);
    assert!(
        mock.sequencer_authorization()
            .is_preferred_sequencer(&SEQUENCER, &mut block)
    );
    assert_eq!(
        mock.sequencer_remuneration()
            .preferred_sequencer(&mut block),
        Some(SEQUENCER)
    );
    assert!(
        mock.gas_enforcer()
            .reward_prover_from_sequencer_balance(
                Amount::new(1),
                &sequencer_address(),
                crate::OperatingMode::Zk,
                &mut block,
            )
            .is_err()
    );
    mock.set_balance(sequencer_address(), Amount::new(5));
    mock.gas_enforcer()
        .reward_prover_from_sequencer_balance(
            Amount::new(2),
            &sequencer_address(),
            crate::OperatingMode::Zk,
            &mut block,
        )
        .unwrap();
    assert_eq!(mock.balance(&sequencer_address()), Amount::new(3));
    assert_eq!(mock.prover_rewards(), Amount::new(2));
    mock.gas_enforcer().return_escrowed_funds_to_sequencer(
        Amount::new(9),
        Rewards::new(Amount::new(1), Amount::ZERO),
        &SEQUENCER,
        &mut block,
    );
    assert_eq!(
        mock.returned_escrow(),
        [(
            SEQUENCER,
            Amount::new(9),
            Rewards::new(Amount::new(1), Amount::ZERO)
        )]
    );

    // No proofs.
    let mut state = working_set();
    assert!(
        mock.proof_processor()
            .process_aggregated_proof(
                selendra_interface::zk::aggregated_proof::SerializedAggregatedProof {
                    raw_aggregated_proof: Vec::new(),
                },
                &sender,
                ExecutionContext::Node,
                &mut state,
            )
            .is_err()
    );
}

/// A gas enforcer that lets every transaction through for free and counts its calls.
#[derive(Debug, Default)]
struct FreeGas {
    reservations: u32,
}

impl GasEnforcer<S> for FreeGas {
    fn try_reserve_gas(
        &mut self,
        _tx: &AuthenticatedTransactionData<S>,
        _gas_price: <<S as crate::Spec>::Gas as Gas>::Price,
        _context: &mut Context<S>,
        _state: &mut impl StateAccessor,
    ) -> anyhow::Result<()> {
        self.reservations += 1;
        Ok(())
    }

    fn try_reserve_gas_for_proof(
        &mut self,
        _tx: &AuthenticatedTransactionData<S>,
        _gas_price: <<S as crate::Spec>::Gas as Gas>::Price,
        _sender: &MultiAddressEvm,
        _state: &mut impl StateAccessor,
    ) -> anyhow::Result<()> {
        self.reservations += 1;
        Ok(())
    }

    fn reward_prover(
        &mut self,
        _reward: &crate::transaction::ProverReward,
        _operating_mode: crate::OperatingMode,
        _state: &mut impl crate::InfallibleStateAccessor,
    ) {
    }

    fn refund_remaining_gas(
        &mut self,
        _payer: &MultiAddressEvm,
        _remaining_funds: &crate::transaction::RemainingFunds,
        _state: &mut impl crate::InfallibleStateAccessor,
    ) {
    }

    fn reward_prover_from_sequencer_balance(
        &mut self,
        _funds_used: Amount,
        _sequencer: &MultiAddressEvm,
        _operating_mode: crate::OperatingMode,
        _state: &mut impl crate::InfallibleStateAccessor,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn return_escrowed_funds_to_sequencer<
        A: crate::InfallibleStateAccessor
            + crate::InfallibleKernelStateAccessor
            + selendra_state::VersionReader,
    >(
        &mut self,
        _initial_escrow: Amount,
        _rewards: Rewards,
        _sequencer: &MockAddress,
        _state: &mut A,
    ) {
    }
}

/// A runtime with the mock capabilities, except its gas enforcer.
#[derive(Debug, Default)]
struct OverridingRuntime {
    capabilities: MockCapabilities<S>,
    gas: FreeGas,
}

impl HasCapabilities<S> for OverridingRuntime {
    type Capabilities<'a> = &'a mut MockCapabilities<S>;

    fn capabilities(&mut self) -> Guard<Self::Capabilities<'_>> {
        Guard::new(&mut self.capabilities)
    }

    fn gas_enforcer(&mut self) -> impl GasEnforcer<S> {
        &mut self.gas
    }
}

/// An overridden capability is the one code reaching it through `HasCapabilities` uses: the
/// runtime's free gas enforcer reserves (the sender has no balance in the mock, so the mock's
/// enforcer would refuse), while the other capabilities are still the mock's.
#[test]
fn overridden_gas_enforcer_is_used() {
    let auth = auth_data(None);
    let mut runtime = OverridingRuntime::default();
    pre_execute(&mut runtime, &auth, 1_000).unwrap();
    assert_eq!(runtime.gas.reservations, 1);
    assert_eq!(
        runtime.capabilities.reserved(auth.default_address()),
        Amount::ZERO
    );
    // The authorizer is still the mock's: it marked the transaction attempted.
    assert!(
        runtime
            .capabilities
            .was_attempted(auth.non_malleable_hash())
    );
    assert!(pre_execute(&mut runtime, &auth, 1_000).is_err());
    assert_eq!(runtime.gas.reservations, 1);

    // Without the override, the mock's enforcer refuses.
    let mut mock = MockCapabilities::<S>::new();
    assert!(pre_execute(&mut mock, &auth, 1_000).is_err());
}

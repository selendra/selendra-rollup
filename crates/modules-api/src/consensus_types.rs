//! Which `selendra-modules-api` types are consensus types
//! ([`ConsensusType`](selendra_interface::common::ConsensusType), `docs/serialization.md`
//! "Consensus types" and "Module system types"), checked at compile time in every build, the
//! zk guest's included: every public borsh type of this crate, and a spec's gas, price and
//! address. (A module's call messages and events are bounded by it in `Module`.)

use selendra_interface::common::ConsensusType;

use crate::{
    Amount, BlockGasInfo, GasPrice, GasUnit, ModuleId, NotInstantiable, OperatingMode,
    PriorityFeeBips, SelendraSpec, SequencerType, Spec, TxDetails,
};

/// Fails to compile if one of these types is not a consensus type.
const _: () = {
    const fn consensus<T: ConsensusType + ?Sized>() {}
    consensus::<Amount>();
    consensus::<GasUnit<2>>();
    consensus::<GasPrice<2>>();
    consensus::<BlockGasInfo<GasUnit<2>>>();
    consensus::<ModuleId>();
    consensus::<OperatingMode>();
    consensus::<SequencerType>();
    consensus::<PriorityFeeBips>();
    consensus::<NotInstantiable>();
    consensus::<SelendraSpec<(), (), ()>>();
};

/// Generic code gets the same from the `Spec` bounds.
#[expect(dead_code, reason = "compile-time check only")]
fn spec_types_are_consensus_types<S: Spec>() {
    fn consensus<T: ConsensusType + ?Sized>() {}
    consensus::<S::Gas>();
    consensus::<<S::Gas as crate::Gas>::Price>();
    consensus::<S::Address>();
    consensus::<BlockGasInfo<S::Gas>>();
    consensus::<TxDetails<S>>();
}

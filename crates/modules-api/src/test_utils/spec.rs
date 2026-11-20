//! [`DistinctCostSpec`]: a test spec whose gas costs are all distinct.

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_state::metered::StateAccessCosts;
use serde::{Deserialize, Serialize};

use super::TestSpec;
use crate::{GAS_DIMENSIONS, GasSchedule, GasUnit, SchemeCosts, Spec};

/// Shorthand for the costs below.
const fn gas(dimensions: [u64; GAS_DIMENSIONS]) -> GasUnit<GAS_DIMENSIONS> {
    GasUnit::from_dimensions(dimensions)
}

/// [`DistinctCostSpec`]'s gas schedule: every cost a different prime, and different in each
/// dimension, so a charge that reads the wrong cost (or swaps the dimensions) gives another
/// amount of gas. (`SELENDRA_GAS_SCHEDULE`'s placeholders are mostly `[1, 1]`: a known answer
/// on it cannot tell most costs apart.)
pub const DISTINCT_GAS_SCHEDULE: GasSchedule<GasUnit<GAS_DIMENSIONS>> = GasSchedule {
    state: StateAccessCosts {
        access: gas([2, 3]),
        hash_update: gas([5, 7]),
        hash_per_byte: gas([11, 13]),
        read: gas([17, 19]),
        read_per_byte: gas([23, 29]),
        write: gas([31, 37]),
        write_per_byte: gas([41, 43]),
        decode_per_byte: gas([47, 53]),
        accessory_write: gas([59, 61]),
        accessory_write_per_byte: gas([67, 71]),
        scope_open: gas([73, 79]),
    },
    encode_per_byte: gas([83, 89]),
    pubkey_decode: SchemeCosts {
        ed25519: gas([97, 101]),
        secp256k1: gas([103, 107]),
    },
    sig_verify: SchemeCosts {
        ed25519: gas([109, 113]),
        secp256k1: gas([127, 131]),
    },
    sig_per_byte: SchemeCosts {
        ed25519: gas([137, 139]),
        secp256k1: gas([149, 151]),
    },
    event_base: gas([157, 163]),
    event_per_byte: gas([167, 173]),
};

/// [`TestSpec`] with [`DISTINCT_GAS_SCHEDULE`]: for known answers that pin which cost each
/// charge reads.
#[derive(
    Default,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct DistinctCostSpec;

impl Spec for DistinctCostSpec {
    type Da = <TestSpec as Spec>::Da;
    type Gas = <TestSpec as Spec>::Gas;
    type Address = <TestSpec as Spec>::Address;
    type Storage = <TestSpec as Spec>::Storage;
    type CryptoSpec = <TestSpec as Spec>::CryptoSpec;
    type InnerZkvm = <TestSpec as Spec>::InnerZkvm;
    type OuterZkvm = <TestSpec as Spec>::OuterZkvm;

    const GAS_SCHEDULE: GasSchedule<Self::Gas> = DISTINCT_GAS_SCHEDULE;
}

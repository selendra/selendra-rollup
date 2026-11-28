//! [`GasSchedule`]: the gas cost of each metered operation.

use selendra_state::metered::StateAccessCosts;

use crate::{GAS_DIMENSIONS, GasUnit};

/// A cost per signature scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemeCosts<G> {
    /// ed25519 (native `sel1…` accounts).
    pub ed25519: G,
    /// secp256k1 (Ethereum-style keys).
    pub secp256k1: G,
}

impl<G: Copy> SchemeCosts<G> {
    /// The same cost for every scheme.
    pub const fn uniform(cost: G) -> Self {
        Self {
            ed25519: cost,
            secp256k1: cost,
        }
    }
}

/// The gas cost of each metered operation: a spec's [`Spec::GAS_SCHEDULE`](crate::Spec).
///
/// Per-operation costs only. The block gas limit, the initial base fee and the transaction gas
/// limits are runtime values (Phase 6's `fee-params` state): the slot meter and the
/// transaction meters are built with them, they are not part of the schedule (upstream's
/// `GasSpec` had them as compile-time constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasSchedule<G> {
    /// State access, including hashing (`hash_update`, `hash_per_byte`), borsh decoding of
    /// state values (`decode_per_byte`) and opening a nested scope. The formulas are in
    /// `selendra_state::metered` (`costs.rs`) and `docs/serialization.md`.
    pub state: StateAccessCosts<G>,
    /// Cost per byte borsh-encoded (e.g. the signing payload a transaction's signature is
    /// checked against).
    pub encode_per_byte: G,
    /// Cost of decoding one public key (curve point decompression and checks), per scheme.
    ///
    /// The native authenticator charges it per key a transaction carries (its multisig's unused
    /// keys included). For a V0 secp256k1 transaction it also covers deriving the key's
    /// credential id and default address: both are its Ethereum address, derived once (a
    /// decompression and a keccak256 of 64 bytes), on top of the decode's own decompression.
    pub pubkey_decode: SchemeCosts<G>,
    /// Fixed cost of verifying one signature, per scheme.
    pub sig_verify: SchemeCosts<G>,
    /// Cost per byte of signed message, per scheme.
    pub sig_per_byte: SchemeCosts<G>,
    /// Fixed cost of emitting an event.
    pub event_base: G,
    /// Cost per byte of an emitted event (its key and its borsh encoding).
    pub event_per_byte: G,
}

impl<G> GasSchedule<G> {
    /// The state-access costs.
    pub const fn state_access_costs(&self) -> &StateAccessCosts<G> {
        &self.state
    }
}

/// Shorthand for the placeholders below.
const fn gas(dimensions: [u64; GAS_DIMENSIONS]) -> GasUnit<GAS_DIMENSIONS> {
    GasUnit::from_dimensions(dimensions)
}

/// The gas schedule of [`SelendraSpec`](crate::SelendraSpec): placeholders until Phase 6
/// calibrates them for SP1 (the SP1 microbenchmarks).
///
/// The values are upstream's (`constants.toml`) where upstream had the cost:
/// `access` = `GAS_TO_CHARGE_PER_STORAGE_ACCESS`, `read` = `GAS_TO_CHARGE_PER_READ`,
/// `read_per_byte` = `GAS_TO_CHARGE_PER_BYTE_READ`, `write` = `BIAS_STORAGE_UPDATE`,
/// `write_per_byte` = `GAS_TO_CHARGE_PER_BYTE_STORAGE_UPDATE`, `hash_update` =
/// `GAS_TO_CHARGE_HASH_UPDATE`, `hash_per_byte` = `GAS_TO_CHARGE_PER_BYTE_HASH_UPDATE`,
/// `decode_per_byte` = `BORSH_PER_BYTE_READ`, `sig_verify` =
/// `DEFAULT_FIXED_GAS_TO_CHARGE_PER_SIGNATURE_VERIFICATION`, `sig_per_byte` =
/// `DEFAULT_GAS_TO_CHARGE_PER_BYTE_SIGNATURE_VERIFICATION`. Upstream charged nothing for the
/// others; their placeholders are priced like the nearest upstream cost:
/// - accessory writes like a provable write (`write`, `write_per_byte`);
/// - opening a scope like one storage access (one journal entry);
/// - encoding like decoding (`BORSH_PER_BYTE_READ`);
/// - a public-key decode (a curve point decompression) at half a signature verification;
/// - an event like an accessory write.
pub const SELENDRA_GAS_SCHEDULE: GasSchedule<GasUnit<GAS_DIMENSIONS>> = GasSchedule {
    state: StateAccessCosts {
        access: gas([1, 1]),
        hash_update: gas([30, 30]),
        hash_per_byte: gas([10, 10]),
        read: gas([1, 1]),
        read_per_byte: gas([1, 1]),
        write: gas([1, 1]),
        write_per_byte: gas([1, 1]),
        decode_per_byte: gas([1, 1]),
        accessory_write: gas([1, 1]),
        accessory_write_per_byte: gas([1, 1]),
        scope_open: gas([1, 1]),
    },
    encode_per_byte: gas([1, 1]),
    pubkey_decode: SchemeCosts::uniform(gas([50, 50])),
    sig_verify: SchemeCosts::uniform(gas([100, 100])),
    sig_per_byte: SchemeCosts::uniform(gas([1, 1])),
    event_base: gas([1, 1]),
    event_per_byte: gas([1, 1]),
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestSpec;
    use crate::{GasArray, Spec};

    /// Every cost of the schedule is set (none is zero), and the spec uses it.
    #[test]
    fn selendra_schedule_sets_every_cost() {
        let s = SELENDRA_GAS_SCHEDULE;
        let state = s.state_access_costs();
        for cost in [
            state.access,
            state.hash_update,
            state.hash_per_byte,
            state.read,
            state.read_per_byte,
            state.write,
            state.write_per_byte,
            state.decode_per_byte,
            state.accessory_write,
            state.accessory_write_per_byte,
            state.scope_open,
            s.encode_per_byte,
            s.pubkey_decode.ed25519,
            s.pubkey_decode.secp256k1,
            s.sig_verify.ed25519,
            s.sig_verify.secp256k1,
            s.sig_per_byte.ed25519,
            s.sig_per_byte.secp256k1,
            s.event_base,
            s.event_per_byte,
        ] {
            assert!(
                GasUnit::ZEROED.dim_is_less_than(cost),
                "{cost} is zero somewhere"
            );
        }
        assert_eq!(TestSpec::GAS_SCHEDULE, SELENDRA_GAS_SCHEDULE);
        assert_eq!(state.hash_update, GasUnit::from([30, 30]));
        assert_eq!(state.hash_per_byte, GasUnit::from([10, 10]));
        assert_eq!(s.sig_verify.ed25519, GasUnit::from([100, 100]));
    }
}

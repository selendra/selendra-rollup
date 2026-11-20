//! Gas for state access: the gas type and meter the metered accessors charge
//! ([`StateGas`], [`StateGasMeter`]), the per-operation costs ([`StateAccessCosts`]) and the
//! charging formulas, and the bound on written values ([`MAX_STATE_VALUE_SIZE`]).
//!
//! The formulas (all arithmetic checked: an overflow is a `GasOverflow` failure, never a panic
//! or a wrap):
//!
//! | Operation | Charged before touching storage | Then, if the value is present (`size` bytes) |
//! |---|---|---|
//! | read (`get`) | `access + hash_update + hash_per_byte·key_len + read` | `read_per_byte·size + hash_update + hash_per_byte·size` |
//! | read and decode (`get_decoded`) | the same | the same `+ decode_per_byte·size` |
//! | `set` (`len` bytes, User/Kernel) | `access + hash_update + hash_per_byte·key_len + write + write_per_byte·len + hash_update + hash_per_byte·len` | |
//! | `delete` (User/Kernel) | `set` with `len = 0` | |
//! | Accessory `set`/`delete` | `accessory_write + accessory_write_per_byte·(key_len + len)` (`len = 0` for a delete) | |
//! | open a nested scope (`open_scope`) | `scope_open`, before the scope is pushed | |
//!
//! `key_len` is the whole [`SlotKey`](crate::SlotKey) (prefix included). Upstream charged the
//! same terms one by one; charging them as one or two sums changes only the gas used by an
//! access that fails, and keeps the meter's error the first refused charge.
//!
//! Upstream charged nothing for opening a scope (`to_revertable`), so the scopes a call opens,
//! each a journal entry that later writes add undo records to, were bounded only by the number
//! of calls (a module looping over user input could open any number for free). Closing one is
//! not charged (it only drops or merges what was already paid for), nor is the phase's base
//! scope (the state transition function opens it).

use std::fmt::Debug;

/// The largest value a metered write accepts, in bytes (1 MiB). A larger one fails with
/// `ValueTooLarge` (checked on the value's length, before any gas is charged).
///
/// Unmetered writes (the kernel, block hooks: Phase 8) are only `debug_assert!`ed against it so
/// far: a release-mode panic on a user-sized value would halt the chain. (Genesis writes are
/// metered: `selendra-modules-api`'s `GenesisStateAccessor`.)
pub const MAX_STATE_VALUE_SIZE: usize = 1 << 20;

/// A gas amount the metered accessors can compute with: checked addition and scaling by a
/// byte count. Implemented by the module system's multi-dimensional gas (Phase 5,
/// `selendra-modules-api`), and here for `u64` (one dimension).
pub trait StateGas: Copy + Eq + Debug + Send + Sync + 'static {
    /// No gas.
    const ZERO: Self;

    /// `self + rhs`, or `None` on overflow.
    fn checked_add(self, rhs: Self) -> Option<Self>;

    /// `self · n`, or `None` on overflow.
    fn checked_scale(self, n: u32) -> Option<Self>;
}

impl StateGas for u64 {
    const ZERO: Self = 0;

    fn checked_add(self, rhs: Self) -> Option<Self> {
        u64::checked_add(self, rhs)
    }

    fn checked_scale(self, n: u32) -> Option<Self> {
        self.checked_mul(u64::from(n))
    }
}

/// A gas meter the metered accessors charge.
pub trait StateGasMeter {
    /// The gas it counts.
    type Gas: StateGas;

    /// Why a charge was refused (e.g. out of gas). Cloned into the phase's failure record.
    type Error: std::error::Error + Clone + Send + Sync + 'static;

    /// Charges `gas`.
    ///
    /// Must be atomic: on `Err` nothing has changed (no partial charge).
    fn charge(&mut self, gas: Self::Gas) -> Result<(), Self::Error>;
}

/// The gas cost of each state-access term (see the module docs for the formulas). The values
/// come from the spec's gas schedule (`Spec::GAS_SCHEDULE`, `selendra-modules-api`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateAccessCosts<G> {
    /// Fixed cost of any provable access (upstream `GAS_TO_CHARGE_PER_STORAGE_ACCESS`).
    pub access: G,
    /// Fixed cost of one hash update (upstream `GAS_TO_CHARGE_HASH_UPDATE`).
    pub hash_update: G,
    /// Cost per hashed byte (upstream `GAS_TO_CHARGE_PER_BYTE_HASH_UPDATE`).
    pub hash_per_byte: G,
    /// Fixed cost of a read (upstream `GAS_TO_CHARGE_PER_READ`).
    pub read: G,
    /// Cost per byte read (upstream `GAS_TO_CHARGE_PER_BYTE_READ`).
    pub read_per_byte: G,
    /// Fixed cost of a provable write or delete (upstream `BIAS_STORAGE_UPDATE`).
    pub write: G,
    /// Cost per byte written (upstream `GAS_TO_CHARGE_PER_BYTE_STORAGE_UPDATE`).
    pub write_per_byte: G,
    /// Cost per byte decoded by `get_decoded` (upstream `BORSH_PER_BYTE_READ`).
    pub decode_per_byte: G,
    /// Fixed cost of an accessory write or delete (upstream: free).
    pub accessory_write: G,
    /// Cost per byte of key and value of an accessory write (upstream: free).
    pub accessory_write_per_byte: G,
    /// Fixed cost of opening a nested scope (upstream `to_revertable`: free).
    pub scope_open: G,
}

/// `a + b + …`, or `None` on overflow.
fn sum<G: StateGas>(terms: impl IntoIterator<Item = Option<G>>) -> Option<G> {
    terms
        .into_iter()
        .try_fold(G::ZERO, |total, term| total.checked_add(term?))
}

impl<G: StateGas> StateAccessCosts<G> {
    /// `access + hash_update + hash_per_byte·key_len`: locating and hashing a key.
    fn access_key(&self, key_len: u32) -> Option<G> {
        sum([
            Some(self.access),
            Some(self.hash_update),
            self.hash_per_byte.checked_scale(key_len),
        ])
    }

    /// `hash_update + hash_per_byte·len`: hashing a value.
    fn hash_value(&self, len: u32) -> Option<G> {
        sum([
            Some(self.hash_update),
            self.hash_per_byte.checked_scale(len),
        ])
    }

    /// Charged before a read touches storage: `access + hash_update + hash_per_byte·key_len +
    /// read`.
    pub(crate) fn read_key(&self, key_len: u32) -> Option<G> {
        sum([self.access_key(key_len), Some(self.read)])
    }

    /// Charged once the read value is known to be present (`size` bytes): `read_per_byte·size
    /// + hash_update + hash_per_byte·size`, plus `decode_per_byte·size` if it is decoded.
    pub(crate) fn read_value(&self, size: u32, decoded: bool) -> Option<G> {
        let decode = if decoded {
            self.decode_per_byte.checked_scale(size)
        } else {
            Some(G::ZERO)
        };
        sum([
            self.read_per_byte.checked_scale(size),
            self.hash_value(size),
            decode,
        ])
    }

    /// A provable write of `len` bytes (a delete: `len = 0`): `access + hash_update +
    /// hash_per_byte·key_len + write + write_per_byte·len + hash_update + hash_per_byte·len`.
    pub(crate) fn write(&self, key_len: u32, len: u32) -> Option<G> {
        sum([
            self.access_key(key_len),
            Some(self.write),
            self.write_per_byte.checked_scale(len),
            self.hash_value(len),
        ])
    }

    /// An accessory write of `len` bytes (a delete: `len = 0`): `accessory_write +
    /// accessory_write_per_byte·(key_len + len)`.
    pub(crate) fn accessory_write(&self, key_len: u32, len: u32) -> Option<G> {
        sum([
            Some(self.accessory_write),
            self.accessory_write_per_byte
                .checked_scale(key_len.checked_add(len)?),
        ])
    }
}

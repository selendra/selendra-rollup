//! Why a metered state access failed ([`StateAccessError`]) and which access it was
//! ([`StateOp`]).

use std::fmt;

use super::costs::{MAX_EVENT_KEY_LEN, MAX_STATE_VALUE_SIZE};
use crate::{Namespace, SlotKey};

/// The access that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateOp {
    /// A read (`get`, `get_decoded`).
    Read {
        /// The namespace read.
        namespace: Namespace,
        /// The key read.
        key: SlotKey,
    },
    /// A write (`set`).
    Write {
        /// The namespace written.
        namespace: Namespace,
        /// The key written.
        key: SlotKey,
    },
    /// A delete.
    Delete {
        /// The namespace written.
        namespace: Namespace,
        /// The key deleted.
        key: SlotKey,
    },
    /// A direct charge (`MeteredRef::charge`), e.g. for computation.
    Charge,
    /// Opening a nested scope (`MeteredRef::open_scope`).
    OpenScope,
}

impl fmt::Display for StateOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { namespace, key } => write!(f, "read of {key} in {namespace:?}"),
            Self::Write { namespace, key } => write!(f, "write of {key} in {namespace:?}"),
            Self::Delete { namespace, key } => write!(f, "delete of {key} in {namespace:?}"),
            Self::Charge => f.write_str("charge"),
            Self::OpenScope => f.write_str("scope open"),
        }
    }
}

/// Why a metered state access failed. `E` is the meter's error
/// ([`StateGasMeter::Error`](super::StateGasMeter::Error)).
///
/// Every failure but [`Poisoned`](Self::Poisoned) **poisons** the metered phase
/// ([`MeteredTx`](super::MeteredTx)): it is recorded, every later access returns
/// [`Poisoned`](Self::Poisoned) before touching the meter or storage, and the phase's writes are
/// reverted when it is finalized, whatever the module returned. So catching the error and
/// carrying on can neither keep a container operation's partial writes nor add witness hints.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateAccessError<E> {
    /// The meter refused a charge (e.g. out of gas). Nothing was charged for it.
    #[error("{op}: the gas meter refused the charge: {source}")]
    OutOfGas {
        /// The access charged for.
        op: StateOp,
        /// The meter's error.
        #[source]
        source: E,
    },
    /// The access's gas overflowed (with the meter's arithmetic, or a key longer than
    /// `u32::MAX` bytes). Nothing was charged for it.
    #[error("{op}: its gas cost overflows")]
    GasOverflow {
        /// The access charged for.
        op: StateOp,
    },
    /// A metered write of more than [`MAX_STATE_VALUE_SIZE`] bytes. Nothing was charged for it.
    #[error("{op}: {len} bytes is more than the maximum of {MAX_STATE_VALUE_SIZE}")]
    ValueTooLarge {
        /// The write.
        op: StateOp,
        /// The value's length in bytes.
        len: usize,
    },
    /// An event key of more than [`MAX_EVENT_KEY_LEN`] bytes
    /// ([`MeteredRef::check_event_key`](super::MeteredRef::check_event_key)). Nothing was charged
    /// for the event. The node's ledger cannot store such a key, so no transaction may emit one.
    #[error("event key: {len} bytes is more than the maximum of {MAX_EVENT_KEY_LEN}")]
    EventKeyTooLong {
        /// The key's length in bytes.
        len: usize,
    },
    /// A scope was closed out of order, with a token of another phase or one already closed, or
    /// accessed through an accessor whose scope is no longer open.
    #[error("a state scope was misused (closed out of order, stale or from another phase)")]
    ScopeMisuse,
    /// An earlier access of the phase failed: the phase is reverted, and nothing is accessed
    /// any more.
    #[error("an earlier state access of this phase failed; it will be reverted")]
    Poisoned,
}

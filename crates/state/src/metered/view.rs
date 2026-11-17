//! [`MeteredView`]: read-only information on a metered phase.

use super::costs::StateGasMeter;
use super::tx::TxInner;
use crate::{CheckpointVersions, Storage};

/// Read-only information on a metered phase, from `&self`
/// ([`Metered::metered_view`](super::Metered::metered_view)): the versions it executes at, its
/// meter and whether it is poisoned. It reads no state: `VersionReader` and the module-facing
/// gas getters take `&self` (upstream's signatures), so they go through it, while every state
/// access needs `&mut` ([`MeteredRef`](super::MeteredRef)).
pub struct MeteredView<'a, M> {
    versions: CheckpointVersions,
    meter: &'a M,
    poisoned: bool,
}

impl<M: std::fmt::Debug> std::fmt::Debug for MeteredView<'_, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeteredView")
            .field("versions", &self.versions)
            .field("meter", &self.meter)
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl<'a, M: StateGasMeter> MeteredView<'a, M> {
    pub(crate) fn new<St: Storage>(tx: &'a TxInner<St, M>) -> Self {
        Self {
            versions: tx.scratchpad.versions(),
            meter: &tx.meter,
            poisoned: tx.failure.is_some(),
        }
    }

    /// The versions of the checkpoint the phase runs on.
    pub fn versions(&self) -> CheckpointVersions {
        self.versions
    }

    /// The phase's meter (read-only).
    pub fn meter(&self) -> &'a M {
        self.meter
    }

    /// Whether an access of the phase failed: the phase will be reverted, and every access
    /// returns `Poisoned`.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

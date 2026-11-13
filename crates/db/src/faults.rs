//! Fault injection for tests: a hook (`CommitHook`, `test-utils` only) that one
//! [`DbGroup`](crate::DbGroup) instance calls at fixed points of its commits and of its startup
//! crash recovery, and that a storage manager on it calls between the commits of a
//! finalization ([`CommitPoint`]).
//!
//! A hook returning `Err` is an injected fault: the operation fails there, as if the process had
//! died at that point. Every write of the state databases is synced to disk before the next
//! point is reached, so dropping the databases and reopening them afterwards finds what a kill
//! at that point would have left (`kill_9_mid_commit` checks it against real kills). A hook may
//! also block, to pause a commit while other threads read (`harness::Gate`).
//!
//! Hooks are per instance: no global state and no environment variables (upstream armed one
//! process-wide gate and read crash points from the environment, so its tests could not run in
//! parallel). Without the `test-utils` feature there is no hook, and every point is a no-op.

use crate::recovery::RecoveryStep;

/// A point where the commit hook runs: in [`DbGroup::commit`](crate::DbGroup::commit), in the
/// startup crash recovery of [`DbGroup::open`](crate::DbGroup::open), or between the commits
/// of a storage manager's finalization ([`BetweenSegments`](Self::BetweenSegments)).
///
/// A commit writes, in this order: the NOMT kernel tree, the NOMT user tree, the ledger DB, the
/// accessory DB, the flat archival DB, the flat live DB. Its points sit between these writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitPoint {
    /// Before the NOMT kernel tree: nothing of the commit is written.
    BeforeKernelNomt,
    /// Before the NOMT user tree: the kernel tree is written.
    BeforeUserNomt,
    /// Before the ledger DB: both NOMT trees are written.
    BeforeLedger,
    /// Before the accessory DB: both NOMT trees and the ledger DB are written.
    BeforeAccessory,
    /// Before the flat archival DB: the NOMT trees, the ledger DB and the accessory DB are
    /// written.
    BeforeArchival,
    /// Before the flat live DB: everything else is written.
    ///
    /// The hook runs while the flat store's value caches are locked for writing, but only the
    /// flat store's prefix iterators wait for that lock. Readers on other threads go on: a point
    /// read that finds the lock taken reads the database itself, root reads take no lock, and
    /// NOMT is no longer locked by the commit. So they still see the live DB's version `L` as
    /// the newest, while NOMT is at `L + 1`: a `get_with_proof` passes every one of its fetch
    /// steps without waiting and then fails its root check, and retries (pinned by
    /// `get_with_proof_does_not_wait_for_a_commit_paused_before_live`).
    BeforeLive,
    /// After the flat live DB: the commit is complete (an `Err` here still fails the commit, and
    /// poisons the databases).
    AfterLive,
    /// Between the commits of two blocks of one finalization of the storage manager
    /// ([`NomtStorageManager::finalize`](crate::NomtStorageManager)): the older block is
    /// committed and the overlays lock is released, so readers go on. An `Err` here fails the
    /// finalization with the older blocks committed (nothing is half written, nothing is
    /// poisoned).
    BetweenSegments,
    /// Before one step of startup crash recovery (only steps that have work to do).
    Recovery(RecoveryStep),
}

impl CommitPoint {
    /// The points of a commit, in order.
    pub const COMMIT: [Self; 7] = [
        Self::BeforeKernelNomt,
        Self::BeforeUserNomt,
        Self::BeforeLedger,
        Self::BeforeAccessory,
        Self::BeforeArchival,
        Self::BeforeLive,
        Self::AfterLive,
    ];
}

/// A commit hook: called at every [`CommitPoint`] a [`DbGroup`](crate::DbGroup) reaches; an
/// `Err` fails the operation there (an injected fault).
#[cfg(any(test, feature = "test-utils"))]
pub type CommitHook = std::sync::Arc<dyn Fn(CommitPoint) -> anyhow::Result<()> + Send + Sync>;

/// A hook that fails at `point` (every time it is reached) and passes everywhere else.
#[cfg(any(test, feature = "test-utils"))]
pub fn fail_at(point: CommitPoint) -> CommitHook {
    std::sync::Arc::new(move |reached| {
        anyhow::ensure!(reached != point, "injected fault at {point:?}");
        Ok(())
    })
}

/// The commit hook of one [`DbGroup`](crate::DbGroup), if any (never outside tests).
#[derive(Clone, Default)]
pub(crate) struct Faults {
    #[cfg(any(test, feature = "test-utils"))]
    hook: Option<CommitHook>,
}

impl Faults {
    /// Calls `hook` at every point.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn new(hook: Option<CommitHook>) -> Self {
        Self { hook }
    }

    /// Runs the hook at `point`. `Err`: a fault injected there.
    #[inline]
    pub(crate) fn hit(&self, point: CommitPoint) -> anyhow::Result<()> {
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(hook) = &self.hook {
            return hook(point);
        }
        let _: CommitPoint = point;
        Ok(())
    }
}

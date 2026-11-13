//! The NOMT state trees ([`NomtStateDb`]: one database per provable namespace) and the sessions
//! that read and update them ([`NomtSessionBuilder`]).
//!
//! NOMT stores only `H(key) → val_hash_and_size` (36 bytes) per slot, not the values: values are
//! read from the flat store ([`FlatStateDb`](crate::FlatStateDb)).

use core::fmt;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, RwLock};

use anyhow::Context;
use nomt::hasher::BinaryHasher;
use nomt::{FinishedSession, InvalidAncestors, Nomt, Overlay, Session, SessionParams};
use rockbound::cache::delta_reader::DeltaReader;
use selendra_interface::common::{HexString, SlotNumber};
use selendra_interface::reexports::digest::Digest;
use selendra_interface::reexports::digest::typenum::U32;
use selendra_state::StorageRoot;
use selendra_state::namespaces::ProvableNamespace;

use crate::config::{NomtNamespaceConfig, StateDbConfig};
use crate::faults::{CommitPoint, Faults};
use crate::prover::StaleStorage;
use crate::recovery::RecoveryStep;
use crate::schema::StateRootHashes;

const KERNEL: &str = "kernel";
const USER: &str = "user";

/// The roots of the two state trees: `user`, `kernel`.
///
/// Stored as 64 bytes, `user ‖ kernel`: the same bytes as [`StorageRoot`]'s borsh encoding (and
/// as its own borsh encoding, in the ledger's slots).
#[derive(Clone, Copy, PartialEq, Eq, Hash, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct NomtRoots {
    /// The root of the user tree.
    pub user: [u8; 32],
    /// The root of the kernel tree.
    pub kernel: [u8; 32],
}

impl NomtRoots {
    /// The length of [`to_bytes`](Self::to_bytes).
    pub const LENGTH: usize = 64;

    /// Both trees empty (NOMT's terminator, all zeros): the state before genesis.
    pub const PRE_GENESIS: Self = Self {
        user: nomt::trie::TERMINATOR,
        kernel: nomt::trie::TERMINATOR,
    };

    /// `user ‖ kernel`.
    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        let mut bytes = [0u8; Self::LENGTH];
        bytes[..32].copy_from_slice(&self.user);
        bytes[32..].copy_from_slice(&self.kernel);
        bytes
    }

    /// The inverse of [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        let mut user = [0u8; 32];
        let mut kernel = [0u8; 32];
        user.copy_from_slice(&bytes[..32]);
        kernel.copy_from_slice(&bytes[32..]);
        Self { user, kernel }
    }
}

impl fmt::Display for NomtRoots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "user {}, kernel {}",
            HexString(self.user),
            HexString(self.kernel)
        )
    }
}

impl fmt::Debug for NomtRoots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NomtRoots({self})")
    }
}

impl<S> From<NomtRoots> for StorageRoot<S> {
    fn from(roots: NomtRoots) -> Self {
        StorageRoot::new(roots.user, roots.kernel)
    }
}

impl<S> From<StorageRoot<S>> for NomtRoots {
    fn from(root: StorageRoot<S>) -> Self {
        Self {
            user: root.user_root(),
            kernel: root.kernel_root(),
        }
    }
}

/// Whether a NOMT session records a witness (the proofs the zk guest verifies).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessMode {
    /// Record a witness.
    On,
    /// No witness.
    Off,
}

impl WitnessMode {
    /// [`WitnessMode::On`] if `with_witness`.
    pub fn from_bool(with_witness: bool) -> Self {
        if with_witness { Self::On } else { Self::Off }
    }

    /// Whether this is [`WitnessMode::On`].
    pub fn is_on(self) -> bool {
        self == Self::On
    }

    fn nomt(self) -> nomt::WitnessMode {
        match self {
            Self::On => nomt::WitnessMode::read_write(),
            Self::Off => nomt::WitnessMode::disabled(),
        }
    }
}

/// The two NOMT state trees: one database per provable namespace.
///
/// Only [`DbGroup`](crate::DbGroup) opens and commits them: opening runs the hasher guard
/// first ([`DbGroup::open`](crate::DbGroup::open)), and a commit writes the flat store and the
/// accessory DB in step with the trees ([`DbGroup::commit`](crate::DbGroup::commit)), from
/// sessions this crate opened on these trees. Outside code cannot open the trees, commit to
/// them alone, or bring in sessions of another NOMT database (whose nodes may be hashed with
/// another hasher: NOMT only checks an overlay's previous root, never its hasher). Each of
/// these fails to compile only because the item is private (the last example compiles with
/// the same names; the error codes are checked only on nightly):
///
/// ```compile_fail,E0624
/// # fn f(config: &selendra_db::StateDbConfig) {
/// let _ = selendra_db::NomtStateDb::<selendra_state::StateHasher>::open_no_grow(config);
/// # }
/// ```
///
/// ```compile_fail,E0624
/// # use selendra_db::{NomtStateDb, StateOverlay};
/// # fn f(trees: &NomtStateDb<selendra_state::StateHasher>, overlay: StateOverlay) {
/// let _ = trees.commit(overlay, &Default::default());
/// # }
/// ```
///
/// ```compile_fail,E0624
/// # fn f(user: nomt::FinishedSession, kernel: nomt::FinishedSession) {
/// let _ = selendra_db::StateFinishedSession::new(user, kernel);
/// # }
/// ```
///
/// ```compile_fail,E0599
/// # fn f(group: &selendra_db::DbGroup<selendra_state::StateHasher>) {
/// let _ = group.nomt();
/// # }
/// ```
///
/// What stays public opens through the guard, or only reads:
///
/// ```
/// # use selendra_db::{DbGroup, NomtRoots, NomtStateDb, StateDbConfig, StateFinishedSession};
/// # use selendra_db::StateOverlay;
/// # use selendra_state::StateHasher as H;
/// # fn f(config: &StateDbConfig, group: &DbGroup<H>, trees: &NomtStateDb<H>,
/// #     finished: StateFinishedSession, _: nomt::FinishedSession) {
/// let _ = DbGroup::<H>::open(config);
/// let _: NomtRoots = group.roots();
/// let _: NomtRoots = trees.root_hashes();
/// let overlay: StateOverlay = finished.into_state_overlay();
/// let _: NomtRoots = overlay.prev_roots();
/// # }
/// ```
pub struct NomtStateDb<H> {
    user: Nomt<BinaryHasher<H>>,
    kernel: Nomt<BinaryHasher<H>>,
}

impl<H> fmt::Debug for NomtStateDb<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NomtStateDb")
    }
}

impl<H: Digest<OutputSize = U32> + Send + Sync> NomtStateDb<H> {
    /// Opens (or creates) both trees under [`StateDbConfig::path`], without growing their hash
    /// tables ([`grow_to_config`](Self::grow_to_config) does, once crash recovery is done).
    ///
    /// Opening writes nothing hashed with `H` (NOMT finishes its own write-ahead-log replay or
    /// an interrupted rehash).
    ///
    /// # Errors
    /// - On Linux, if io_uring is unavailable: NOMT has no other I/O backend there (its I/O
    ///   workers would panic). Docker's default seccomp profile blocks io_uring, and NOMT needs
    ///   Linux 6.0 or later.
    /// - If a tree has more buckets than configured (shrinking is not supported), or on I/O
    ///   errors.
    pub(crate) fn open_no_grow(config: &StateDbConfig) -> anyhow::Result<Self> {
        check_io_uring()?;
        let kernel = open_tree(KERNEL, &config.kernel, &config.kernel_nomt_path())?;
        let user = open_tree(USER, &config.user, &config.user_nomt_path())?;
        Ok(Self { user, kernel })
    }

    /// Opens both trees and grows them to the configured bucket count (tests of this module).
    #[cfg(test)]
    pub(crate) fn new(config: &StateDbConfig) -> anyhow::Result<Self> {
        Self::open_no_grow(config)?.grow_to_config(config, &Faults::default())
    }

    /// Grows a tree whose hash table has fewer buckets than configured (closing, growing and
    /// reopening it). `faults` is called once before the first tree is grown
    /// ([`RecoveryStep::Grow`]).
    ///
    /// # Errors
    /// If growing or reopening a tree fails. Growing is crash-safe (NOMT finishes an
    /// interrupted rehash when the tree is opened again).
    pub(crate) fn grow_to_config(
        self,
        config: &StateDbConfig,
        faults: &Faults,
    ) -> anyhow::Result<Self> {
        let Self { user, kernel } = self;
        if needs_growing(&kernel, &config.kernel)? || needs_growing(&user, &config.user)? {
            faults.hit(CommitPoint::Recovery(RecoveryStep::Grow))?;
        }
        let kernel = grow_tree(KERNEL, kernel, &config.kernel, &config.kernel_nomt_path())?;
        let user = grow_tree(USER, user, &config.user, &config.user_nomt_path())?;
        Ok(Self { user, kernel })
    }

    /// Commits a block's changes: the kernel tree first, then the user tree. `faults` is
    /// called in between ([`CommitPoint::BeforeUserNomt`]).
    ///
    /// # Errors
    /// If `overlay` does not build on the committed roots (checked before anything is written),
    /// or if NOMT fails. If the user commit fails after the kernel commit succeeded, the trees
    /// are out of step: the caller must stop (crash recovery rolls the kernel tree back).
    pub(crate) fn commit(&self, overlay: StateOverlay, faults: &Faults) -> anyhow::Result<()> {
        let StateOverlay {
            user,
            kernel,
            prev_roots,
        } = overlay;
        let committed = self.root_hashes();
        anyhow::ensure!(
            committed == prev_roots,
            "the NOMT changes build on roots ({prev_roots}) other than the committed ones ({committed})"
        );
        kernel
            .commit(&self.kernel)
            .context("kernel namespace commit")?;
        warn_if_nearly_full(KERNEL, &self.kernel);
        faults.hit(CommitPoint::BeforeUserNomt)?;
        user.commit(&self.user).context("user namespace commit")?;
        warn_if_nearly_full(USER, &self.user);
        Ok(())
    }

    /// Rolls back the newest commit in one tree's rollback log (NOMT's `rollback(1)`, for
    /// startup crash recovery), and removes it from the log.
    ///
    /// A second call without a commit in between can succeed too: after a restart, NOMT 1.0.5's
    /// log can hold more than the last commit, although `max_rollback_log_len(1)` is set (it
    /// prunes its on-disk range one sync late: the last two commits, and one more for every
    /// restart between commits; see the `recovery` module docs). So the caller decides by the
    /// tree's root whether to roll it back, never by the log running out.
    ///
    /// # Errors
    /// If nothing is logged to roll back, or on I/O errors.
    pub(crate) fn rollback_one(&self, namespace: ProvableNamespace) -> anyhow::Result<()> {
        let (name, tree) = match namespace {
            ProvableNamespace::User => (USER, &self.user),
            ProvableNamespace::Kernel => (KERNEL, &self.kernel),
        };
        tree.rollback(1)
            .with_context(|| format!("rolling back the last commit of the {name} NOMT tree"))
    }

    /// The committed roots of both trees.
    pub fn root_hashes(&self) -> NomtRoots {
        NomtRoots {
            user: self.user.root().into_inner(),
            kernel: self.kernel.root().into_inner(),
        }
    }

    /// The hash-table bucket counts of the user and kernel trees (tests).
    #[cfg(test)]
    pub(crate) fn bucket_counts(&self) -> (usize, usize) {
        (
            self.user.hash_table_utilization().capacity,
            self.kernel.hash_table_utilization().capacity,
        )
    }
}

/// Fails if NOMT cannot use io_uring (Linux only; other Unix systems use a thread pool).
fn check_io_uring() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    match nomt::check_iou_permissions() {
        nomt::IoUringPermission::Allowed => {}
        nomt::IoUringPermission::Denied => anyhow::bail!(
            "NOMT needs io_uring, which is denied in this environment (e.g. Docker's default \
             seccomp profile blocks it): allow the io_uring syscalls"
        ),
        nomt::IoUringPermission::NotSupported => anyhow::bail!(
            "NOMT needs io_uring with IORING_SETUP_SINGLE_ISSUER, which needs Linux 6.0 or later"
        ),
    }
    Ok(())
}

/// The bucket count `config` asks for, as NOMT counts them.
fn configured_buckets(config: &NomtNamespaceConfig) -> anyhow::Result<usize> {
    usize::try_from(config.hashtable_buckets.get())
        .context("hash-table bucket count does not fit in usize")
}

/// Opens one tree. Fails if it has more hash-table buckets than configured.
fn open_tree<H: Digest<OutputSize = U32> + Send + Sync>(
    name: &'static str,
    config: &NomtNamespaceConfig,
    path: &std::path::Path,
) -> anyhow::Result<Nomt<BinaryHasher<H>>> {
    let configured = configured_buckets(config)?;
    let nomt = Nomt::<BinaryHasher<H>>::open(config.nomt_options(path))
        .with_context(|| format!("failed to open the {name} NOMT database"))?;
    let current = nomt.hash_table_utilization().capacity;
    anyhow::ensure!(
        current <= configured,
        "the configured NOMT hash-table bucket count of the {name} tree ({configured}) is \
         smaller than the existing one on disk ({current}); shrinking is not supported"
    );
    Ok(nomt)
}

/// Whether a tree has fewer hash-table buckets than configured.
fn needs_growing<H: Digest<OutputSize = U32> + Send + Sync>(
    nomt: &Nomt<BinaryHasher<H>>,
    config: &NomtNamespaceConfig,
) -> anyhow::Result<bool> {
    Ok(nomt.hash_table_utilization().capacity < configured_buckets(config)?)
}

/// Grows one tree's hash table to the configured bucket count if it has fewer: closes the
/// tree, grows it and reopens it.
fn grow_tree<H: Digest<OutputSize = U32> + Send + Sync>(
    name: &'static str,
    nomt: Nomt<BinaryHasher<H>>,
    config: &NomtNamespaceConfig,
    path: &std::path::Path,
) -> anyhow::Result<Nomt<BinaryHasher<H>>> {
    if !needs_growing(&nomt, config)? {
        return Ok(nomt);
    }
    let configured = configured_buckets(config)?;
    let current = nomt.hash_table_utilization().capacity;
    drop(nomt);
    tracing::info!(
        tree = name,
        current_buckets = current,
        configured_buckets = configured,
        "Growing the NOMT hash table to the configured bucket count"
    );
    nomt::grow_hashtable(&config.nomt_options(path)).with_context(|| {
        format!("failed to grow the {name} NOMT hash table from {current} to {configured} buckets")
    })?;
    let nomt = Nomt::<BinaryHasher<H>>::open(config.nomt_options(path))
        .with_context(|| format!("failed to open the {name} NOMT database"))?;
    let grown = nomt.hash_table_utilization().capacity;
    anyhow::ensure!(
        grown == configured,
        "the {name} NOMT hash table has {grown} buckets after growing it, expected {configured}"
    );
    Ok(nomt)
}

/// Logs a warning when more than 90% of a tree's hash-table buckets are used: lookups slow down
/// and commits can fail as it fills up. Grow it by configuring more buckets and restarting.
fn warn_if_nearly_full<H: Digest<OutputSize = U32> + Send + Sync>(
    name: &'static str,
    nomt: &Nomt<BinaryHasher<H>>,
) {
    let utilization = nomt.hash_table_utilization();
    // occupied / capacity > 0.9, in integers (`float_arithmetic` is denied).
    let occupied = u128::try_from(utilization.occupied).unwrap_or(u128::MAX);
    let capacity = u128::try_from(utilization.capacity).unwrap_or(u128::MAX);
    if occupied.saturating_mul(10) > capacity.saturating_mul(9) {
        tracing::warn!(
            tree = name,
            occupied = utilization.occupied,
            capacity = utilization.capacity,
            "The NOMT hash table is over 90% full: configure more buckets"
        );
    }
}

/// The uncommitted changes of one block to both trees, in memory. They can be committed
/// (inside this crate: [`DbGroup::commit`](crate::DbGroup::commit)) or used as the base of
/// later sessions ([`NomtSessionBuilder`]).
pub struct StateOverlay {
    user: Overlay,
    kernel: Overlay,
    prev_roots: NomtRoots,
}

impl StateOverlay {
    /// The roots after these changes.
    pub fn roots(&self) -> NomtRoots {
        NomtRoots {
            user: self.user.root().into_inner(),
            kernel: self.kernel.root().into_inner(),
        }
    }

    /// The roots these changes build on.
    pub fn prev_roots(&self) -> NomtRoots {
        self.prev_roots
    }
}

/// The finished sessions of both trees for one block.
///
/// Built only inside this crate, from sessions on our trees (see [`NomtStateDb`]).
pub struct StateFinishedSession {
    user: FinishedSession,
    kernel: FinishedSession,
}

impl StateFinishedSession {
    /// Combines the finished sessions of the two trees.
    pub(crate) fn new(user: FinishedSession, kernel: FinishedSession) -> Self {
        Self { user, kernel }
    }

    /// The roots after these changes.
    pub fn roots(&self) -> NomtRoots {
        NomtRoots {
            user: self.user.root().into_inner(),
            kernel: self.kernel.root().into_inner(),
        }
    }

    /// The roots these changes build on.
    pub fn prev_roots(&self) -> NomtRoots {
        NomtRoots {
            user: self.user.prev_root().into_inner(),
            kernel: self.kernel.prev_root().into_inner(),
        }
    }

    /// Converts the sessions into an in-memory overlay.
    pub fn into_state_overlay(self) -> StateOverlay {
        let prev_roots = self.prev_roots();
        StateOverlay {
            user: self.user.into_overlay(),
            kernel: self.kernel.into_overlay(),
            prev_roots,
        }
    }
}

/// The uncommitted overlays of all blocks a storage manager holds, by block reference.
pub type SharedOverlays<K> = Arc<RwLock<HashMap<K, StateOverlay>>>;

/// An uncommitted block a [`NomtSessionBuilder`] builds on: its overlay's key in the shared map,
/// its version and the roots after it.
#[derive(Clone, Debug)]
pub(crate) struct OverlayRef<K> {
    pub(crate) key: K,
    pub(crate) version: SlotNumber,
    pub(crate) roots: NomtRoots,
}

/// The committed root of each version: the flat live DB's root table, without uncommitted
/// snapshots. The flat live DB is written last by a commit, so a version is here only once its
/// commit is complete.
#[derive(Clone)]
pub(crate) struct CommittedRoots(DeltaReader);

impl CommittedRoots {
    /// The root table of the flat live DB `live_db`.
    pub(crate) fn new(live_db: Arc<rockbound::DB>) -> Self {
        Self(DeltaReader::new(live_db, Vec::new()))
    }

    /// The committed root of exactly `version` (`None` if `version` is not committed).
    pub(crate) fn root_at(&self, version: SlotNumber) -> anyhow::Result<Option<NomtRoots>> {
        self.0.get::<StateRootHashes>(&version)
    }

    /// The newest committed version (`None`: nothing committed).
    pub(crate) fn latest_version(&self) -> anyhow::Result<Option<SlotNumber>> {
        Ok(self
            .0
            .get_largest::<StateRootHashes>()?
            .map(|(version, _)| version))
    }
}

/// Opens NOMT sessions on the committed trees plus a chain of uncommitted overlays.
///
/// A session holds NOMT's read lock: committing to the same tree blocks until every session on
/// it is dropped. Drop sessions before committing on the same thread, or it deadlocks.
///
/// Sessions are opened only inside this crate (by the storages): a raw session reads and
/// writes the trees without the flat store, and a thread holding one while opening another can
/// deadlock behind a commit, so `begin_both_sessions` (both trees under one lock) is the only
/// way to hold two.
///
/// **Overlays that are gone.** A storage manager removes a block's overlay from the shared map
/// when it commits the block (under the map's write lock, so a session sees either the overlay
/// on the old trees or the committed trees), and when it discards the block's fork. A session
/// therefore checks the overlays it does not find: the newest of them must be committed, with
/// the same roots (the flat live DB's root at its version), and the overlays it finds must build
/// on the committed trees. Otherwise the storage is on a discarded fork, and opening a session
/// fails with [`StaleStorage`] (`discarded_fork`). Upstream assumed every missing overlay was
/// committed, so a storage on a discarded fork opened its sessions on the winning fork's trees.
pub struct NomtSessionBuilder<H, K> {
    state_db: Arc<NomtStateDb<H>>,
    /// Newest first (as [`SessionParams::overlay`] expects).
    relevant_snapshot_refs: Vec<OverlayRef<K>>,
    all_snapshots: SharedOverlays<K>,
    committed: CommittedRoots,
}

impl<H, K: Clone> Clone for NomtSessionBuilder<H, K> {
    fn clone(&self) -> Self {
        Self {
            state_db: self.state_db.clone(),
            relevant_snapshot_refs: self.relevant_snapshot_refs.clone(),
            all_snapshots: self.all_snapshots.clone(),
            committed: self.committed.clone(),
        }
    }
}

impl<H, K> fmt::Debug for NomtSessionBuilder<H, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NomtSessionBuilder")
            .field("overlays", &self.relevant_snapshot_refs.len())
            .finish_non_exhaustive()
    }
}

/// The sessions of both trees, opened together ([`NomtSessionBuilder::begin_both_sessions`]).
pub(crate) struct SessionsContainer<H> {
    /// The user tree's session.
    pub(crate) user: Session<BinaryHasher<H>>,
    /// The kernel tree's session.
    pub(crate) kernel: Session<BinaryHasher<H>>,
}

impl<H, K> NomtSessionBuilder<H, K> {
    /// A builder whose sessions see the committed trees plus the overlays
    /// `relevant_snapshot_refs` (newest first, consecutive versions) of `all_snapshots`; the
    /// ones missing from `all_snapshots` are checked against `committed` (see the type docs).
    pub(crate) fn new(
        state_db: Arc<NomtStateDb<H>>,
        relevant_snapshot_refs: Vec<OverlayRef<K>>,
        all_snapshots: SharedOverlays<K>,
        committed: CommittedRoots,
    ) -> Self {
        Self {
            state_db,
            relevant_snapshot_refs,
            all_snapshots,
            committed,
        }
    }

    /// The newest committed version (`None`: nothing committed).
    pub(crate) fn committed_version(&self) -> anyhow::Result<Option<SlotNumber>> {
        self.committed.latest_version()
    }

    /// The committed root of exactly `version` (`None`: not committed).
    pub(crate) fn committed_root_at(
        &self,
        version: SlotNumber,
    ) -> anyhow::Result<Option<NomtRoots>> {
        self.committed.root_at(version)
    }
}

impl<H, K> NomtSessionBuilder<H, K>
where
    H: Digest<OutputSize = U32> + Send + Sync,
    K: Eq + Hash,
{
    /// Runs `f` on the relevant overlays (newest first) under the snapshots read lock, once
    /// they are checked (see the type docs).
    ///
    /// # Errors
    /// [`StaleStorage`] (`discarded_fork`) if this builder's blocks are on a discarded fork;
    /// an `Err` if the lock is poisoned, a newer overlay is missing while an older one is still
    /// there (a bug: overlays are committed oldest first), or on read errors.
    fn with_overlays<R>(&self, f: impl FnOnce(&[&StateOverlay]) -> R) -> anyhow::Result<R> {
        let snapshots = self
            .all_snapshots
            .read()
            .map_err(|_| anyhow::anyhow!("the NOMT overlays lock is poisoned"))?;
        let mut overlays: Vec<&StateOverlay> =
            Vec::with_capacity(self.relevant_snapshot_refs.len());
        let mut newest_missing: Option<&OverlayRef<K>> = None;
        for overlay_ref in &self.relevant_snapshot_refs {
            match snapshots.get(&overlay_ref.key) {
                Some(overlay) => {
                    if let Some(missing) = newest_missing {
                        tracing::warn!(
                            missing_version = %missing.version,
                            present_version = %overlay_ref.version,
                            "A NOMT overlay is gone while an older one of its chain is still there"
                        );
                        anyhow::bail!(
                            "bug: the NOMT overlay of version {} is gone while the older one of \
                             version {} is still there (overlays are committed oldest first)",
                            missing.version,
                            overlay_ref.version
                        );
                    }
                    overlays.push(overlay);
                }
                None => {
                    newest_missing.get_or_insert(overlay_ref);
                }
            }
        }
        if let Some(missing) = newest_missing {
            // Committed (with every older one): the trees hold it. Checking the newest is
            // enough, and costs one read.
            let committed = self.committed.root_at(missing.version)?;
            if committed != Some(missing.roots) {
                return Err(self.discarded_fork()?.into());
            }
            tracing::trace!(version = %missing.version, "NOMT overlays committed up to this version");
        }
        if let Some(oldest) = overlays.last() {
            // The oldest uncommitted overlay builds on the committed trees.
            if oldest.prev_roots() != self.state_db.root_hashes() {
                return Err(self.discarded_fork()?.into());
            }
        }
        Ok(f(&overlays))
    }

    /// The error of a builder on a discarded fork.
    fn discarded_fork(&self) -> anyhow::Result<StaleStorage> {
        Ok(StaleStorage {
            storage_version: self.relevant_snapshot_refs.first().map(|r| r.version),
            committed_version: self.committed.latest_version()?,
            discarded_fork: true,
        })
    }

    /// Opens a session on the user tree, without a witness.
    pub(crate) fn begin_user_session_without_witness(
        &self,
    ) -> anyhow::Result<Session<BinaryHasher<H>>> {
        self.with_overlays(|overlays| {
            let params = session_params(USER, overlays.iter().map(|o| &o.user), WitnessMode::Off)?;
            Ok(self.state_db.user.begin_session(params))
        })?
    }

    /// Opens a session on the kernel tree, without a witness.
    pub(crate) fn begin_kernel_session_without_witness(
        &self,
    ) -> anyhow::Result<Session<BinaryHasher<H>>> {
        self.with_overlays(|overlays| {
            let params =
                session_params(KERNEL, overlays.iter().map(|o| &o.kernel), WitnessMode::Off)?;
            Ok(self.state_db.kernel.begin_session(params))
        })?
    }

    /// Opens sessions on both trees under one read lock, so a thread never holds one session
    /// while waiting to open the other.
    pub(crate) fn begin_both_sessions(
        &self,
        witness_mode: WitnessMode,
    ) -> anyhow::Result<SessionsContainer<H>> {
        self.with_overlays(|overlays| {
            let kernel_params =
                session_params(KERNEL, overlays.iter().map(|o| &o.kernel), witness_mode)?;
            let user_params = session_params(USER, overlays.iter().map(|o| &o.user), witness_mode)?;
            let kernel = self.state_db.kernel.begin_session(kernel_params);
            let user = self.state_db.user.begin_session(user_params);
            Ok(SessionsContainer { user, kernel })
        })?
    }
}

fn session_params<'a>(
    name: &'static str,
    overlays: impl IntoIterator<Item = &'a Overlay>,
    witness_mode: WitnessMode,
) -> anyhow::Result<SessionParams> {
    let params = SessionParams::default()
        .overlay(overlays)
        .map_err(|error| {
            let reason = match error {
                InvalidAncestors::NotAncestor => {
                    "an overlay is not an ancestor of the previous one"
                }
                InvalidAncestors::Incomplete => "the chain of uncommitted overlays is incomplete",
            };
            anyhow::anyhow!("cannot open a {name} NOMT session: {reason}")
        })?;
    Ok(params.witness_mode(witness_mode.nomt()))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::path::Path;

    use nomt::KeyReadWrite;
    use nomt::trie::KeyPath;
    use sha2::{Digest, Sha256};

    use super::*;

    type H = Sha256;

    fn from_key(key: u64) -> (KeyPath, Option<Vec<u8>>) {
        let raw_data = key.to_be_bytes();
        (H::digest(raw_data).into(), Some(raw_data.to_vec()))
    }

    fn config_with_buckets(path: &Path, buckets: u32) -> StateDbConfig {
        let mut config = StateDbConfig::for_tests(path);
        let buckets = NonZeroU32::new(buckets).unwrap();
        config.user.hashtable_buckets = buckets;
        config.kernel.hashtable_buckets = buckets;
        config
    }

    fn finish(session: Session<BinaryHasher<H>>, key: u64) -> FinishedSession {
        let (key_path, data) = from_key(key);
        session
            .finish(vec![(key_path, KeyReadWrite::Write(data))])
            .unwrap()
    }

    fn commit_value(state_db: &NomtStateDb<H>, key: u64) {
        let user = finish(state_db.user.begin_session(SessionParams::default()), key);
        let kernel = finish(state_db.kernel.begin_session(SessionParams::default()), key);
        let overlay = StateFinishedSession::new(user, kernel).into_state_overlay();
        state_db.commit(overlay, &Faults::default()).unwrap();
    }

    fn assert_value(state_db: &NomtStateDb<H>, key: u64) {
        let (key_path, expected_value) = from_key(key);
        let user_session = state_db.user.begin_session(SessionParams::default());
        assert_eq!(user_session.read(key_path).unwrap(), expected_value);
        let kernel_session = state_db.kernel.begin_session(SessionParams::default());
        assert_eq!(kernel_session.read(key_path).unwrap(), expected_value);
    }

    #[test]
    fn opening_existing_db_grows_hashtable_to_configured_bucket_count() {
        let temp_dir = crate::test_utils::tempdir();
        let state_db = NomtStateDb::<H>::new(&config_with_buckets(temp_dir.path(), 4096)).unwrap();
        commit_value(&state_db, 7);
        let roots_before_growth = state_db.root_hashes();
        drop(state_db);

        let state_db = NomtStateDb::<H>::new(&config_with_buckets(temp_dir.path(), 8192)).unwrap();
        assert_eq!(state_db.user.hash_table_utilization().capacity, 8192);
        assert_eq!(state_db.kernel.hash_table_utilization().capacity, 8192);
        assert_eq!(state_db.root_hashes(), roots_before_growth);
        assert_value(&state_db, 7);
    }

    #[test]
    fn opening_existing_db_rejects_smaller_configured_bucket_count() {
        let temp_dir = crate::test_utils::tempdir();
        drop(NomtStateDb::<H>::new(&config_with_buckets(temp_dir.path(), 8192)).unwrap());

        let err = NomtStateDb::<H>::new(&config_with_buckets(temp_dir.path(), 4096))
            .expect_err("opening with fewer NOMT hash-table buckets should fail");
        let err = format!("{err:#}");
        assert!(err.contains("shrinking is not supported"), "{err}");
        assert!(err.contains("kernel"), "{err}");
    }

    #[test]
    fn commit_rejects_an_overlay_on_other_roots() {
        let temp_dir = crate::test_utils::tempdir();
        let state_db = NomtStateDb::<H>::new(&StateDbConfig::for_tests(temp_dir.path())).unwrap();
        // Two blocks built on the same (empty) state: the second no longer applies.
        let first = StateFinishedSession::new(
            finish(state_db.user.begin_session(SessionParams::default()), 1),
            finish(state_db.kernel.begin_session(SessionParams::default()), 1),
        )
        .into_state_overlay();
        let second = StateFinishedSession::new(
            finish(state_db.user.begin_session(SessionParams::default()), 2),
            finish(state_db.kernel.begin_session(SessionParams::default()), 2),
        )
        .into_state_overlay();
        assert_eq!(first.prev_roots(), NomtRoots::PRE_GENESIS);
        let roots = first.roots();
        state_db.commit(first, &Faults::default()).unwrap();
        assert_eq!(state_db.root_hashes(), roots);

        let err = state_db.commit(second, &Faults::default()).unwrap_err();
        assert!(
            err.to_string().contains("other than the committed"),
            "{err}"
        );
        // Nothing was written.
        assert_eq!(state_db.root_hashes(), roots);
    }

    /// The flat live DB's root table next to the trees (a version is committed once its root
    /// is there).
    fn committed_roots(dir: &Path) -> (crate::FlatStateDb, CommittedRoots) {
        let flat = crate::FlatStateDb::new(dir, 1_000_000, 1_000_000).unwrap();
        let committed = CommittedRoots::new(flat.live_db().clone());
        (flat, committed)
    }

    /// Commits `overlay` as `version` the way `DbGroup` does: the trees, then the root (the
    /// flat live DB is written last).
    fn commit_overlay(
        state_db: &NomtStateDb<H>,
        flat: &crate::FlatStateDb,
        overlay: StateOverlay,
        version: u64,
    ) {
        let roots = overlay.roots();
        state_db.commit(overlay, &Faults::default()).unwrap();
        flat.live_db()
            .put::<StateRootHashes>(&SlotNumber::new(version), &roots)
            .unwrap();
    }

    /// The overlays of the blocks `0..rounds`, each built on the one before: its refs (newest
    /// first) in `all_overlays`.
    fn chain_of_overlays(
        state_db: &Arc<NomtStateDb<H>>,
        all_overlays: &SharedOverlays<u64>,
        committed: &CommittedRoots,
        rounds: u64,
    ) -> Vec<OverlayRef<u64>> {
        let mut refs: Vec<OverlayRef<u64>> = Vec::new();
        for this_ref in 0..rounds {
            let builder = NomtSessionBuilder::<H, u64>::new(
                state_db.clone(),
                refs.clone(),
                all_overlays.clone(),
                committed.clone(),
            );
            let user = finish(
                builder.begin_user_session_without_witness().unwrap(),
                this_ref,
            );
            let kernel = finish(
                builder.begin_kernel_session_without_witness().unwrap(),
                this_ref,
            );
            let overlay = StateFinishedSession::new(user, kernel).into_state_overlay();
            refs.insert(
                0,
                OverlayRef {
                    key: this_ref,
                    version: SlotNumber::new(this_ref),
                    roots: overlay.roots(),
                },
            );
            all_overlays.write().unwrap().insert(this_ref, overlay);
        }
        refs
    }

    #[test]
    fn test_session_can_be_built_while_finalized() {
        let temp_dir = crate::test_utils::tempdir();
        let state_db =
            Arc::new(NomtStateDb::<H>::new(&StateDbConfig::for_tests(temp_dir.path())).unwrap());
        let (flat, committed) = committed_roots(temp_dir.path());

        // First produce some overlays with data.
        let all_overlays: SharedOverlays<u64> = Arc::default();
        let rounds = 10;
        let refs = chain_of_overlays(&state_db, &all_overlays, &committed, rounds);

        let check_builder = NomtSessionBuilder::<H, u64>::new(
            state_db.clone(),
            refs,
            all_overlays.clone(),
            committed,
        );
        for committing_ref in 0..rounds {
            let sessions = check_builder.begin_both_sessions(WitnessMode::Off).unwrap();
            for this_ref in 0..rounds {
                let (key_path, expected_value) = from_key(this_ref);
                assert_eq!(
                    sessions.user.read(key_path).unwrap(),
                    expected_value,
                    "failed to check value for ref: {this_ref}"
                );
                assert_eq!(sessions.kernel.read(key_path).unwrap(), expected_value);
            }
            drop(sessions);
            // Committed under the write lock, as the storage manager does.
            let mut overlays = all_overlays.write().unwrap();
            let overlay = overlays.remove(&committing_ref).unwrap();
            commit_overlay(&state_db, &flat, overlay, committing_ref);
        }
    }

    /// B6, critique #1: a missing overlay must be committed (its version's committed root is
    /// its root); otherwise the builder's blocks are on a discarded fork, and no session opens
    /// (upstream assumed every missing overlay committed, and opened the session on the other
    /// fork's trees). The overlays present must build on the committed trees.
    #[test]
    fn missing_overlays_must_be_committed() {
        let temp_dir = crate::test_utils::tempdir();
        let state_db =
            Arc::new(NomtStateDb::<H>::new(&StateDbConfig::for_tests(temp_dir.path())).unwrap());
        let (flat, committed) = committed_roots(temp_dir.path());
        let all_overlays: SharedOverlays<u64> = Arc::default();
        let refs = chain_of_overlays(&state_db, &all_overlays, &committed, 2);
        let builder = |refs: Vec<OverlayRef<u64>>| {
            NomtSessionBuilder::<H, u64>::new(
                state_db.clone(),
                refs,
                all_overlays.clone(),
                committed.clone(),
            )
        };
        let stale = |result: anyhow::Result<SessionsContainer<H>>| {
            let err = result.err().expect("a stale storage");
            err.downcast_ref::<StaleStorage>().cloned().unwrap()
        };

        // Another block 0 (a sibling, on another fork) is committed: block 0's overlay is
        // dropped with its fork.
        let sibling = StateFinishedSession::new(
            finish(state_db.user.begin_session(SessionParams::default()), 7),
            finish(state_db.kernel.begin_session(SessionParams::default()), 7),
        )
        .into_state_overlay();
        {
            let mut overlays = all_overlays.write().unwrap();
            commit_overlay(&state_db, &flat, sibling, 0);
            overlays.clear();
        }
        assert_eq!(
            stale(builder(refs.clone()).begin_both_sessions(WitnessMode::Off)),
            StaleStorage {
                storage_version: Some(SlotNumber::new(1)),
                committed_version: Some(SlotNumber::GENESIS),
                discarded_fork: true,
            }
        );
        // Only the newer block's overlay gone (not committed): the same.
        assert!(
            builder(refs[..1].to_vec())
                .begin_user_session_without_witness()
                .err()
                .unwrap()
                .downcast_ref::<StaleStorage>()
                .is_some()
        );
    }

    /// The overlays present must build on the committed trees, and a newer overlay cannot be
    /// gone while an older one is there (overlays are committed oldest first).
    #[test]
    fn present_overlays_must_build_on_the_committed_trees() {
        let temp_dir = crate::test_utils::tempdir();
        let state_db =
            Arc::new(NomtStateDb::<H>::new(&StateDbConfig::for_tests(temp_dir.path())).unwrap());
        let (flat, committed) = committed_roots(temp_dir.path());
        let all_overlays: SharedOverlays<u64> = Arc::default();
        let refs = chain_of_overlays(&state_db, &all_overlays, &committed, 2);
        let builder = |refs: Vec<OverlayRef<u64>>| {
            NomtSessionBuilder::<H, u64>::new(
                state_db.clone(),
                refs,
                all_overlays.clone(),
                committed.clone(),
            )
        };
        // The newer overlay removed, the older one still there.
        let newer = all_overlays.write().unwrap().remove(&1).unwrap();
        let err = builder(refs.clone())
            .begin_both_sessions(WitnessMode::Off)
            .err()
            .unwrap();
        assert!(
            format!("{err:#}").contains("is gone while the older one"),
            "{err:#}"
        );
        drop(newer);

        // The trees committed past the older overlay's parent (a sibling of it): it no longer
        // applies.
        let sibling = StateFinishedSession::new(
            finish(state_db.user.begin_session(SessionParams::default()), 7),
            finish(state_db.kernel.begin_session(SessionParams::default()), 7),
        )
        .into_state_overlay();
        commit_overlay(&state_db, &flat, sibling, 0);
        let err = builder(refs[1..].to_vec())
            .begin_both_sessions(WitnessMode::Off)
            .err()
            .unwrap();
        assert!(err.downcast_ref::<StaleStorage>().unwrap().discarded_fork);
    }

    #[test]
    fn roots_convert_to_and_from_storage_root() {
        let roots = NomtRoots {
            user: [1; 32],
            kernel: [2; 32],
        };
        let root: StorageRoot<()> = roots.into();
        assert_eq!(root.as_ref(), roots.to_bytes());
        assert_eq!(borsh::to_vec(&root).unwrap(), roots.to_bytes());
        assert_eq!(NomtRoots::from(root), roots);
        assert_eq!(NomtRoots::from_bytes(roots.to_bytes()), roots);
        assert_eq!(
            NomtRoots::from(StorageRoot::<()>::PRE_GENESIS),
            NomtRoots::PRE_GENESIS
        );
    }
}

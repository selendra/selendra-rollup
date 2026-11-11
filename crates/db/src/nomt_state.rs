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
use selendra_interface::common::HexString;
use selendra_interface::reexports::digest::Digest;
use selendra_interface::reexports::digest::typenum::U32;
use selendra_state::StorageRoot;

use crate::config::{NomtNamespaceConfig, StateDbConfig};

const KERNEL: &str = "kernel";
const USER: &str = "user";

/// The roots of the two state trees: `user`, `kernel`.
///
/// Stored as 64 bytes, `user ‖ kernel`: the same bytes as [`StorageRoot`]'s borsh encoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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
/// let _ = selendra_db::NomtStateDb::<selendra_state::StateHasher>::new(config);
/// # }
/// ```
///
/// ```compile_fail,E0624
/// # use selendra_db::{NomtStateDb, StateOverlay};
/// # fn f(trees: &NomtStateDb<selendra_state::StateHasher>, overlay: StateOverlay) {
/// let _ = trees.commit(overlay);
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
    /// Opens (or creates) both trees under [`StateDbConfig::path`].
    ///
    /// A tree with fewer hash-table buckets than configured is grown first.
    ///
    /// # Errors
    /// - On Linux, if io_uring is unavailable: NOMT has no other I/O backend there (its I/O
    ///   workers would panic). Docker's default seccomp profile blocks io_uring, and NOMT needs
    ///   Linux 6.0 or later.
    /// - If a tree has more buckets than configured (shrinking is not supported), or on I/O
    ///   errors.
    pub(crate) fn new(config: &StateDbConfig) -> anyhow::Result<Self> {
        check_io_uring()?;
        let kernel = open_tree(KERNEL, &config.kernel, &config.kernel_nomt_path())?;
        let user = open_tree(USER, &config.user, &config.user_nomt_path())?;
        Ok(Self { user, kernel })
    }

    /// Commits a block's changes: the kernel tree first, then the user tree.
    ///
    /// # Errors
    /// If `overlay` does not build on the committed roots (checked before anything is written),
    /// or if NOMT fails. If the user commit fails after the kernel commit succeeded, the trees
    /// are out of step: the caller must stop (crash recovery rolls the kernel tree back).
    pub(crate) fn commit(&self, overlay: StateOverlay) -> anyhow::Result<()> {
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
        user.commit(&self.user).context("user namespace commit")?;
        warn_if_nearly_full(USER, &self.user);
        Ok(())
    }

    /// The committed roots of both trees.
    pub fn root_hashes(&self) -> NomtRoots {
        NomtRoots {
            user: self.user.root().into_inner(),
            kernel: self.kernel.root().into_inner(),
        }
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

/// Opens one tree, growing its hash table first if it has fewer buckets than configured.
fn open_tree<H: Digest<OutputSize = U32> + Send + Sync>(
    name: &'static str,
    config: &NomtNamespaceConfig,
    path: &std::path::Path,
) -> anyhow::Result<Nomt<BinaryHasher<H>>> {
    let configured = usize::try_from(config.hashtable_buckets.get())
        .context("hash-table bucket count does not fit in usize")?;
    let nomt = Nomt::<BinaryHasher<H>>::open(config.nomt_options(path))
        .with_context(|| format!("failed to open the {name} NOMT database"))?;
    let current = nomt.hash_table_utilization().capacity;
    anyhow::ensure!(
        current <= configured,
        "the configured NOMT hash-table bucket count of the {name} tree ({configured}) is \
         smaller than the existing one on disk ({current}); shrinking is not supported"
    );
    if current == configured {
        return Ok(nomt);
    }

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

/// Opens NOMT sessions on the committed trees plus a chain of uncommitted overlays.
///
/// A session holds NOMT's read lock: committing to the same tree blocks until every session on
/// it is dropped. Drop sessions before committing on the same thread, or it deadlocks.
///
/// Sessions are opened only inside this crate (by the storages): a raw session reads and
/// writes the trees without the flat store, and a thread holding one while opening another can
/// deadlock behind a commit, so `begin_both_sessions` (both trees under one lock) is the only
/// way to hold two.
pub struct NomtSessionBuilder<H, K> {
    state_db: Arc<NomtStateDb<H>>,
    /// Newest first (as [`SessionParams::overlay`] expects).
    relevant_snapshot_refs: Vec<K>,
    all_snapshots: SharedOverlays<K>,
}

impl<H, K: Clone> Clone for NomtSessionBuilder<H, K> {
    fn clone(&self) -> Self {
        Self {
            state_db: self.state_db.clone(),
            relevant_snapshot_refs: self.relevant_snapshot_refs.clone(),
            all_snapshots: self.all_snapshots.clone(),
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
    /// A builder whose sessions see the committed trees plus the overlays `relevant_snapshot_refs`
    /// (newest first) of `all_snapshots`. Refs missing from `all_snapshots` are skipped: they are
    /// assumed committed.
    pub fn new(
        state_db: Arc<NomtStateDb<H>>,
        relevant_snapshot_refs: Vec<K>,
        all_snapshots: SharedOverlays<K>,
    ) -> Self {
        Self {
            state_db,
            relevant_snapshot_refs,
            all_snapshots,
        }
    }

    /// A builder whose sessions see only the committed trees.
    pub fn from_committed(state_db: Arc<NomtStateDb<H>>) -> Self {
        Self::new(state_db, Vec::new(), Arc::default())
    }
}

impl<H, K> NomtSessionBuilder<H, K>
where
    H: Digest<OutputSize = U32> + Send + Sync,
    K: Eq + Hash,
{
    /// Runs `f` on the relevant overlays (newest first) under the snapshots read lock.
    fn with_overlays<R>(&self, f: impl FnOnce(&[&StateOverlay]) -> R) -> anyhow::Result<R> {
        let snapshots = self
            .all_snapshots
            .read()
            .map_err(|_| anyhow::anyhow!("the NOMT overlays lock is poisoned"))?;
        let overlays: Vec<&StateOverlay> = self
            .relevant_snapshot_refs
            .iter()
            .filter_map(|overlay_ref| {
                let overlay = snapshots.get(overlay_ref);
                if overlay.is_none() {
                    // Assumed committed. That holds without forks: with forks, a missing
                    // overlay may belong to a discarded fork, and the session then no longer
                    // matches the flat-store reader (which holds its own snapshots).
                    tracing::debug!("NOMT overlay not found, assuming it has been committed");
                }
                overlay
            })
            .collect();
        Ok(f(&overlays))
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
        state_db.commit(overlay).unwrap();
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
        state_db.commit(first).unwrap();
        assert_eq!(state_db.root_hashes(), roots);

        let err = state_db.commit(second).unwrap_err();
        assert!(
            err.to_string().contains("other than the committed"),
            "{err}"
        );
        // Nothing was written.
        assert_eq!(state_db.root_hashes(), roots);
    }

    #[test]
    fn test_session_can_be_built_while_finalized() {
        let temp_dir = crate::test_utils::tempdir();
        let state_db =
            Arc::new(NomtStateDb::<H>::new(&StateDbConfig::for_tests(temp_dir.path())).unwrap());

        // First produce some overlays with data.
        let all_overlays: SharedOverlays<u64> = Arc::default();
        let rounds = 10;
        for this_ref in 0..rounds {
            let overlay_refs = (0..this_ref).rev().collect::<Vec<_>>();
            let builder = NomtSessionBuilder::<H, u64>::new(
                state_db.clone(),
                overlay_refs,
                all_overlays.clone(),
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
            all_overlays.write().unwrap().insert(this_ref, overlay);
        }

        let overlay_refs = (0..rounds).rev().collect::<Vec<_>>();
        let check_builder =
            NomtSessionBuilder::<H, u64>::new(state_db.clone(), overlay_refs, all_overlays.clone());
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
            let overlay = all_overlays
                .write()
                .unwrap()
                .remove(&committing_ref)
                .unwrap();
            state_db.commit(overlay).unwrap();
        }
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

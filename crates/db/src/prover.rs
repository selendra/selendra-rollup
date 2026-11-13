//! [`NomtProverStorage`]: the native storage of the NOMT backend. It reads values from the flat
//! store, computes state updates with NOMT sessions and records the witness the zk guest's
//! [`NomtVerifierStorage`](selendra_state::NomtVerifierStorage) consumes.

use core::fmt;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::hash::Hash;
use std::time::{Duration, Instant};

use anyhow::Context;
use nomt::hasher::BinaryHasher;
use nomt::trie::KeyPath;
use nomt::{FinishedSession, KeyReadWrite, Session};
use selendra_interface::common::SlotNumber;
use selendra_state::namespaces::{
    Accessory, CompileTimeNamespace, Namespace, ProvableCompileTimeNamespace, ProvableNamespace,
};
use selendra_state::{
    MerkleProofSpec, NativeStorage, NodeLeaf, NodeLeafAndMaybeValue, NomtProof,
    OrderedReadsAndWrites, ProofOutput, SlotKey, SlotValue, StateAccesses, StateRoot, StateUpdate,
    Storage, StorageProof, StorageRoot, Witness, key_path, leaf_value_bytes, namespace_needs_proof,
    verify_namespace, verify_storage_proof,
};

use crate::{
    AccessoryDb, HistoricalStateReader, HistoricalValueError, NomtChangeSet, NomtRoots,
    NomtSessionBuilder, SessionsContainer, StateFinishedSession, StorageReaders, WitnessMode,
};

#[cfg(test)]
mod tests;

type NomtSession<H> = Session<BinaryHasher<H>>;

/// A storage that can no longer compute a state update or open a NOMT session: a newer version
/// was committed after it was created (it is *stale*: NOMT keeps only the newest trees), or its
/// blocks were discarded by a finalization on another fork (`discarded_fork`).
///
/// [`compute_state_update`](Storage::compute_state_update) and
/// [`get_with_proof`](NativeStorage::get_with_proof) return it inside their `anyhow::Error`
/// (`downcast_ref::<StaleStorage>()`): the caller retries with a new storage (upstream's
/// sequencer `expect`ed here). `get_with_proof` does not retry it itself, since waiting does not
/// help. The storage's bound reads still see its own version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleStorage {
    /// The storage's version (`None`: it sees an empty state).
    pub storage_version: Option<SlotNumber>,
    /// The newest committed version when the error was raised.
    pub committed_version: Option<SlotNumber>,
    /// Whether the storage's uncommitted blocks were discarded (another fork was finalized).
    pub discarded_fork: bool,
}

impl fmt::Display for StaleStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = if self.discarded_fork {
            "it is on a discarded fork"
        } else {
            "a newer version was committed"
        };
        write!(
            f,
            "stale storage (version {:?}, newest committed version {:?}): {reason}; create a \
             new storage",
            self.storage_version.map(|v| v.get()),
            self.committed_version.map(|v| v.get())
        )
    }
}

impl std::error::Error for StaleStorage {}

/// Why one attempt of [`NativeStorage::get_with_proof`] failed.
#[derive(Debug)]
pub(crate) enum GetWithProofError {
    /// The flat store and NOMT were read at different versions (a commit was in progress):
    /// retry.
    StateRootMismatch,
    Other(anyhow::Error),
}

/// The points of [`NomtProverStorage::get_with_proof_once_with`] where its hook runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchStep {
    /// After the first read of the newest root (step 1).
    RootRead,
    /// After the value read (step 2).
    ValueRead,
    /// After the second read of the newest root, before the NOMT session is opened (between
    /// steps 3 and 4): the last point before the attempt may block behind a commit.
    BeforeSession,
    /// Right after the NOMT session is opened (step 4), before the roots are compared.
    AfterSessionOpen,
}

impl fmt::Display for GetWithProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateRootMismatch => {
                write!(f, "State root mismatch between pre-fetch and post-fetch")
            }
            Self::Other(err) => write!(f, "{err:#}"),
        }
    }
}

impl From<anyhow::Error> for GetWithProofError {
    fn from(err: anyhow::Error) -> Self {
        Self::Other(err)
    }
}

/// A [`Storage`] for native execution (the node and the prover), on the NOMT state trees and the
/// flat value store ([`DbGroup`](crate::DbGroup)).
///
/// A storage is a view of the state as of one version (its
/// [`latest_version`](NativeStorage::latest_version)): the newest committed version, plus the
/// uncommitted blocks a storage manager built it on (snapshots of the flat store, the accessory
/// DB and the ledger, and NOMT overlays). Its reads ([`Storage::get`], [`Storage::get_leaf`],
/// [`NativeStorage::get_accessory`]) keep returning that version's values after newer versions
/// are committed (through the flat store's archival rows and its own snapshots), also after its
/// blocks were discarded. Its state update can only be computed while its base is the newest
/// committed version: NOMT keeps no history, so
/// [`compute_state_update`](Storage::compute_state_update) of a stale storage fails with
/// [`StaleStorage`].
///
/// Storages are `Clone + Send + Sync` and outlive the storage manager's finalizations.
///
/// # Witness
/// With [`WitnessMode::On`] it records the hints of the witness protocol (see
/// [`Storage`]): one `Option<NodeLeaf>` per `get_leaf`, one `Option<SlotValue>` per `get` and
/// per `put_in_witness`, then in `compute_state_update` one [`NomtProof`] for the user namespace
/// and then one for the kernel namespace, each only if the namespace was accessed
/// ([`namespace_needs_proof`], shared with the verifier). Before adding a proof, it checks it the
/// way the guest will ([`verify_namespace`]): its reads must match the NOMT tree and the proof
/// must give NOMT's new root, or `compute_state_update` fails (a node whose flat store and NOMT
/// disagree must not produce a witness the guest rejects). Historical and unbound reads add no
/// hints. With [`WitnessMode::Off`] it adds nothing, and reads are not checked against NOMT.
///
/// # Errors and panics
/// The [`NativeStorage`] methods that return a bare `Option` or value panic if a database read
/// fails, like upstream: `None` means "absent", so an error cannot be reported as one.
pub struct NomtProverStorage<S: MerkleProofSpec, K> {
    session_builder: NomtSessionBuilder<S::Hasher, K>,
    historical_state: HistoricalStateReader,
    accessory: AccessoryDb,
    witness_mode: WitnessMode,
}

// Hand-written: a derive would require `S: Clone` (a marker).
impl<S: MerkleProofSpec, K: Clone> Clone for NomtProverStorage<S, K> {
    fn clone(&self) -> Self {
        Self {
            session_builder: self.session_builder.clone(),
            historical_state: self.historical_state.clone(),
            accessory: self.accessory.clone(),
            witness_mode: self.witness_mode,
        }
    }
}

impl<S: MerkleProofSpec, K> fmt::Debug for NomtProverStorage<S, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NomtProverStorage")
            .field("version", &self.historical_state.last_version())
            .field("witness_mode", &self.witness_mode)
            .finish_non_exhaustive()
    }
}

/// The output of [`NomtProverStorage::compute_state_update`]: the finished NOMT sessions of both
/// trees, the value writes, the accessory writes added after it ([`StateUpdate`]) and the new
/// root. [`Storage::materialize_changes`] turns it into a [`NomtChangeSet`] for
/// [`DbGroup::commit`](crate::DbGroup::commit).
pub struct NomtStateUpdate<S> {
    state: StateFinishedSession,
    user_writes: Vec<(SlotKey, Option<SlotValue>)>,
    kernel_writes: Vec<(SlotKey, Option<SlotValue>)>,
    accessory: Vec<(SlotKey, Option<SlotValue>)>,
    root: StorageRoot<S>,
}

impl<S> NomtStateUpdate<S> {
    /// The root after this update.
    pub fn root(&self) -> StorageRoot<S> {
        self.root
    }
}

impl<S> fmt::Debug for NomtStateUpdate<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NomtStateUpdate")
            .field("root", &NomtRoots::from(self.root))
            .field("user_writes", &self.user_writes.len())
            .field("kernel_writes", &self.kernel_writes.len())
            .field("accessory", &self.accessory.len())
            .finish_non_exhaustive()
    }
}

impl<S> StateUpdate for NomtStateUpdate<S> {
    fn add_accessory_item(&mut self, key: SlotKey, value: Option<SlotValue>) {
        self.accessory.push((key, value));
    }

    fn get_accessory_items(&self) -> impl Iterator<Item = &(SlotKey, Option<SlotValue>)> {
        self.accessory.iter()
    }
}

/// The NOMT accesses of one namespace, sorted by key path (upstream `to_nomt_accesses`). A read
/// carries the `val_hash_and_size` read, a write the new one (`None`: delete); a key both read
/// and written is `ReadThenWrite`. Key paths and leaf bytes come from `selendra-state`
/// ([`key_path`], [`leaf_value_bytes`]), the verifier's own definitions.
///
/// A delete of a key that is absent from the tree (`is_absent`, asked for every delete) becomes
/// a read of its absence. It is the same for the tree and its proof, but NOMT 1.0.5 panics
/// committing a session whose only value changes are such deletes into an empty database (an
/// underflow in `beatree/ops/update/leaf_stage.rs`, `filter_leaves_changeset`); upstream passed
/// them through. Every read and write keeps an entry, so the result is empty iff
/// [`namespace_needs_proof`] is false.
///
/// # Errors
/// If two reads or two writes have the same key path (a SHA-256 collision, or duplicate keys in
/// `accesses`), or `is_absent` fails.
fn to_nomt_accesses<S: MerkleProofSpec>(
    accesses: &OrderedReadsAndWrites,
    mut is_absent: impl FnMut(&KeyPath) -> anyhow::Result<bool>,
) -> anyhow::Result<Vec<(KeyPath, KeyReadWrite)>> {
    // A `BTreeMap`, so the accesses are sorted: NOMT checks the order only in debug builds.
    let mut merged: BTreeMap<KeyPath, KeyReadWrite> = BTreeMap::new();
    for (key, leaf) in &accesses.ordered_reads {
        let read = leaf.map(|leaf| leaf_value_bytes(&leaf).to_vec());
        if merged
            .insert(key_path::<S>(key), KeyReadWrite::Read(read))
            .is_some()
        {
            anyhow::bail!("two reads of the key path of key {key}");
        }
    }
    for (key, value) in &accesses.ordered_writes {
        let key_path = key_path::<S>(key);
        let write = value
            .as_ref()
            .map(|value| leaf_value_bytes(&NodeLeaf::make_leaf::<S::Hasher>(value)).to_vec());
        let absent_delete = write.is_none() && is_absent(&key_path)?;
        match merged.entry(key_path) {
            Entry::Vacant(entry) => {
                entry.insert(if absent_delete {
                    KeyReadWrite::Read(None)
                } else {
                    KeyReadWrite::Write(write)
                });
            }
            Entry::Occupied(mut entry) => {
                anyhow::ensure!(
                    matches!(entry.get(), KeyReadWrite::Read(_)),
                    "two writes to the key path of key {key}"
                );
                if !absent_delete {
                    entry.get_mut().write(write);
                }
            }
        }
    }
    Ok(merged.into_iter().collect())
}

impl<S: MerkleProofSpec, K: Clone + Eq + Hash> NomtProverStorage<S, K> {
    /// A storage over `readers` ([`DbGroup::readers`](crate::DbGroup::readers)), at their
    /// version, recording a witness iff `witness_mode` is on.
    ///
    /// Upstream also took a `strict_mode` flag (the previous-root check and debug-only
    /// cross-checks of the flat store against NOMT); the root check is always on here and the
    /// cross-check is the witness self-check (see the type docs).
    pub fn create(readers: StorageReaders<S::Hasher, K>, witness_mode: WitnessMode) -> Self {
        let StorageReaders {
            session_builder,
            historical_state,
            accessory,
        } = readers;
        Self {
            session_builder,
            historical_state,
            accessory,
            witness_mode,
        }
    }

    /// The root of the state this storage sees (the pre-genesis root if it is empty): the root
    /// to pass to [`compute_state_update`](Storage::compute_state_update).
    ///
    /// # Errors
    /// If no root is stored for its version, or on read errors.
    pub fn root(&self) -> anyhow::Result<StorageRoot<S>> {
        self.own_root()
    }

    /// Whether this storage sees an empty state (no version committed before it was created).
    pub fn is_empty(&self) -> bool {
        self.historical_state.get_next_version() == SlotNumber::GENESIS
    }

    /// Whether this storage records a witness.
    pub fn witness_mode(&self) -> WitnessMode {
        self.witness_mode
    }

    /// The session builder (tests that hold NOMT sessions).
    #[cfg(test)]
    pub(crate) fn session_builder(&self) -> &NomtSessionBuilder<S::Hasher, K> {
        &self.session_builder
    }

    /// `witness` if this storage records one.
    fn recorded<'w>(&self, witness: &'w S::Witness) -> Option<&'w S::Witness> {
        self.witness_mode.is_on().then_some(witness)
    }

    /// The version a read of `version` (`None`: this storage's) reads at: `Ok(None)` if there
    /// is nothing to read (an empty storage), `Ok(Some(None))` for this storage's version (read
    /// through the value caches), `Ok(Some(Some(v)))` for a historical read at `v` (bypasses
    /// the caches, so queries do not thrash them).
    ///
    /// # Errors
    /// [`HistoricalValueError::FutureVersion`] if `version` is after this storage's version
    /// (upstream: `Ok(None)`, "absent").
    fn version_to_read(
        &self,
        version: Option<SlotNumber>,
    ) -> Result<Option<Option<SlotNumber>>, HistoricalValueError> {
        let next_version = self.historical_state.get_next_version();
        match version {
            None if self.is_empty() => Ok(None),
            None => Ok(Some(None)),
            Some(version) if version >= next_version => Err(HistoricalValueError::FutureVersion {
                requested_version: version.get(),
                latest_version: self.historical_state.last_version().map(|v| v.get()),
            }),
            Some(version) => Ok(Some(Some(version))),
        }
    }

    /// Panics on a failed bound read (`None` would mean "absent"). A pruned version means this
    /// storage is older than the pruning window (upstream's warning).
    fn read_failed(&self, what: &str, key: &SlotKey, error: &anyhow::Error) -> ! {
        tracing::warn!(slot = ?self.latest_version(), %key, "reader observed pruned-version race");
        panic!("Database error while getting the {what} of key {key}: {error:?}");
    }

    /// The result of a read that cannot observe [`HistoricalValueError::PrunedVersion`] (unbound
    /// reads: they read the newest state, committed or in this storage's snapshots, never the
    /// archival rows; accessory reads; root reads): the value, or a panic on a database error,
    /// since `None` means "absent".
    fn resolve_unbound_read<T>(
        result: anyhow::Result<Option<T>>,
        source: &'static str,
    ) -> Option<T> {
        match result {
            Ok(value) => value,
            Err(error) => {
                debug_assert!(
                    !matches!(
                        error.downcast_ref::<HistoricalValueError>(),
                        Some(HistoricalValueError::PrunedVersion { .. })
                    ),
                    "unbound reads should never observe PrunedVersion (source={source})"
                );
                panic!("Unable to read from {source}: {error:?}");
            }
        }
    }

    /// The newest value of `key` in a provable namespace (unbound): committed, or in this
    /// storage's snapshots newer than the committed version.
    fn read_provable_value_unbound(
        &self,
        namespace: ProvableNamespace,
        key: &SlotKey,
    ) -> anyhow::Result<Option<SlotValue>> {
        self.historical_state.get_value_unbound(namespace, key)
    }

    /// The newest value of `key` (unbound: committed, or in this storage's snapshots); panics on
    /// a database error.
    fn read_value_unbound<N: CompileTimeNamespace>(&self, key: &SlotKey) -> Option<SlotValue> {
        match N::NAMESPACE {
            Namespace::User => Self::resolve_unbound_read(
                self.read_provable_value_unbound(ProvableNamespace::User, key),
                "the user flat store",
            ),
            Namespace::Kernel => Self::resolve_unbound_read(
                self.read_provable_value_unbound(ProvableNamespace::Kernel, key),
                "the kernel flat store",
            ),
            Namespace::Accessory => Self::resolve_unbound_read(
                self.accessory.get_value_option(key, SlotNumber::MAX),
                "the accessory DB",
            ),
        }
    }

    /// The value of `key` at `version` (`None`: this storage's version).
    fn read_value<N: CompileTimeNamespace>(
        &self,
        key: &SlotKey,
        version: Option<SlotNumber>,
    ) -> anyhow::Result<Option<SlotValue>> {
        let Some(resolved_version) = self.version_to_read(version)? else {
            return Ok(None);
        };
        let provable = |namespace| match resolved_version {
            None => self.historical_state.get_value(namespace, key),
            Some(version) => self
                .historical_state
                .get_value_historical(namespace, key, version),
        };
        match N::NAMESPACE {
            Namespace::User => provable(ProvableNamespace::User),
            Namespace::Kernel => provable(ProvableNamespace::Kernel),
            Namespace::Accessory => self
                .accessory
                .get_value_bound(key, resolved_version.unwrap_or(self.latest_version())),
        }
    }

    /// The leaf of `key` at `version`, with the value loaded. Adds the bare leaf to `witness` if
    /// given.
    fn do_get_leaf<N: ProvableCompileTimeNamespace>(
        &self,
        key: &SlotKey,
        version: Option<SlotNumber>,
        witness: Option<&S::Witness>,
    ) -> anyhow::Result<Option<NodeLeafAndMaybeValue>> {
        let value = self.read_value::<N>(key, version)?;
        if let Some(witness) = witness {
            witness.add_hint(&value.as_ref().map(NodeLeaf::make_leaf::<S::Hasher>));
        }
        Ok(value.map(NodeLeafAndMaybeValue::with_fetched_value::<S::Hasher>))
    }

    /// The newest version and its root (unbound: committed, or of this storage's snapshots).
    fn latest_root_and_version_unbound(
        &self,
    ) -> anyhow::Result<Option<(SlotNumber, StorageRoot<S>)>> {
        Ok(self
            .historical_state
            .latest_root_and_version_unbound()?
            .map(|(version, roots)| (version, roots.into())))
    }

    /// The root of the state this storage sees: the root committed at its version, or the
    /// pre-genesis root if it is empty.
    fn own_root(&self) -> anyhow::Result<StorageRoot<S>> {
        let Some(version) = self.historical_state.last_version() else {
            return Ok(StorageRoot::PRE_GENESIS);
        };
        match self.historical_state.get_root_hash(version)? {
            Some((found, roots)) if found == version => Ok(roots.into()),
            found => anyhow::bail!(
                "no root is stored for version {version} (the newest at or below it: {:?})",
                found.map(|(found, _)| found)
            ),
        }
    }

    fn begin_session_without_witness(
        &self,
        namespace: ProvableNamespace,
    ) -> anyhow::Result<NomtSession<S::Hasher>> {
        match namespace {
            ProvableNamespace::User => self.session_builder.begin_user_session_without_witness(),
            ProvableNamespace::Kernel => {
                self.session_builder.begin_kernel_session_without_witness()
            }
        }
    }

    /// One attempt of [`NativeStorage::get_with_proof`].
    ///
    /// NOMT keeps only the newest tree, so the proof is of the newest state: the newest
    /// committed one, or the newest of this storage's uncommitted blocks if it has any (unbound
    /// reads see both: the newest committed version or a newer one of this storage's
    /// snapshots). The value must be read from the flat store at the same version. They are
    /// committed one after the other ([`DbGroup::commit`](crate::DbGroup::commit): NOMT first,
    /// the flat live DB last), so:
    /// 1. read the newest root from the flat store;
    /// 2. read the value from the flat store (unbound: the newest value, not this storage's
    ///    version);
    /// 3. read the newest root from the flat store again;
    /// 4. open a NOMT session (NOMT cannot commit while it is open; a storage manager's
    ///    finalization holds the overlays lock while it commits, so the session waits for it);
    /// 5. if the two flat-store reads give different versions or roots, or NOMT's root differs
    ///    from theirs, a commit was in progress: [`GetWithProofError::StateRootMismatch`]
    ///    (retry);
    /// 6. prove the key with the session, then drop it.
    ///
    /// Reading the root before and after the value rules out both interleavings of a single
    /// root read with a flat-store commit. Comparing the versions too (they only increase)
    /// rules out several commits during the value read: two commits whose second restores the
    /// namespace leave its root unchanged, but the value read in between is the first one's.
    pub(crate) fn get_with_proof_once<N: ProvableCompileTimeNamespace>(
        &self,
        key: SlotKey,
    ) -> Result<ProofOutput<Self>, GetWithProofError> {
        self.get_with_proof_once_with::<N>(key, |_| {})
    }

    /// [`get_with_proof_once`](Self::get_with_proof_once), calling `between` at each
    /// [`FetchStep`]: after steps 1 and 2 (tests commit there), after step 3 and after the
    /// session opened (tests synchronize with a paused commit there).
    pub(crate) fn get_with_proof_once_with<N: ProvableCompileTimeNamespace>(
        &self,
        key: SlotKey,
        mut between: impl FnMut(FetchStep),
    ) -> Result<ProofOutput<Self>, GetWithProofError> {
        let namespace = N::PROVABLE_NAMESPACE;
        let (pre_fetch_version, pre_fetch_root) =
            self.latest_root_and_version_unbound()?.ok_or_else(|| {
                anyhow::anyhow!("no state is committed yet: there is nothing to prove")
            })?;
        between(FetchStep::RootRead);
        let value = self.read_provable_value_unbound(namespace, &key)?;
        between(FetchStep::ValueRead);
        let (version, post_fetch_root) = self
            .latest_root_and_version_unbound()?
            .ok_or_else(|| anyhow::anyhow!("the committed state roots disappeared"))?;
        between(FetchStep::BeforeSession);

        let session = self.begin_session_without_witness(namespace)?;
        between(FetchStep::AfterSessionOpen);
        let post_fetch_namespace_root = post_fetch_root.namespace_root(namespace);
        if pre_fetch_version != version
            || pre_fetch_root.namespace_root(namespace) != post_fetch_namespace_root
            || post_fetch_namespace_root != session.prev_root().into_inner()
        {
            return Err(GetWithProofError::StateRootMismatch);
        }
        let path_proof = session.prove(key_path::<S>(&key))?;
        drop(session);
        let proof = NomtProof::from_path_proofs(vec![path_proof])
            .context("NOMT's path proof is not a well-formed multi-proof")?;

        Ok((
            StorageProof {
                key,
                value,
                proof,
                namespace,
            },
            version,
            post_fetch_root,
        ))
    }

    /// One namespace of [`compute_state_update`](Storage::compute_state_update): finishes its
    /// session and, with the witness on and if the namespace was accessed, adds its checked
    /// multi-proof to `witness`.
    fn finish_namespace(
        &self,
        session: NomtSession<S::Hasher>,
        accesses: &OrderedReadsAndWrites,
        witness: &S::Witness,
    ) -> anyhow::Result<FinishedSession> {
        let prev_root = session.prev_root().into_inner();
        let nomt_accesses =
            to_nomt_accesses::<S>(accesses, |key_path| Ok(session.read(*key_path)?.is_none()))?;
        let mut finished = session.finish(nomt_accesses)?;
        if self.witness_mode.is_on() && namespace_needs_proof(accesses) {
            let nomt_witness = finished
                .take_witness()
                .context("NOMT recorded no witness for a session opened with one")?;
            let proof = NomtProof::from_path_proofs(
                nomt_witness
                    .path_proofs
                    .into_iter()
                    .map(|path| path.inner)
                    .collect(),
            )
            .context("NOMT's witness is not a well-formed multi-proof")?;
            // The guest's check, natively (upstream had only debug-build cross-checks): reads
            // from the flat store that do not match the tree would give a witness the guest
            // rejects.
            let root = verify_namespace::<S>(prev_root, accesses, &proof).context(
                "self-check of the witness failed: the reads do not match the NOMT tree (the \
                 flat store and NOMT disagree)",
            )?;
            anyhow::ensure!(
                root == finished.root().into_inner(),
                "self-check of the witness failed: the multi-proof gives another root than NOMT"
            );
            witness.add_hint(&proof);
        }
        Ok(finished)
    }
}

impl<S: MerkleProofSpec, K: Clone + Eq + Hash> Storage for NomtProverStorage<S, K> {
    type Hasher = S::Hasher;
    type Witness = S::Witness;
    type Proof = NomtProof;
    type Root = StorageRoot<S>;
    type StateUpdate = NomtStateUpdate<S>;
    type ChangeSet = NomtChangeSet;

    const PRE_GENESIS_ROOT: StorageRoot<S> = StorageRoot::PRE_GENESIS;

    fn put_in_witness(&self, value: Option<SlotValue>, witness: &S::Witness) {
        if let Some(witness) = self.recorded(witness) {
            witness.add_hint(&value);
        }
    }

    /// # Panics
    /// If the read fails (including a pruned version: this storage is too old).
    fn get_leaf<N: ProvableCompileTimeNamespace>(
        &self,
        key: &SlotKey,
        witness: &S::Witness,
    ) -> Option<NodeLeafAndMaybeValue> {
        match self.do_get_leaf::<N>(key, None, self.recorded(witness)) {
            Ok(leaf) => leaf,
            Err(error) => self.read_failed("leaf", key, &error),
        }
    }

    /// # Panics
    /// If the read fails (including a pruned version: this storage is too old).
    fn get<N: ProvableCompileTimeNamespace>(
        &self,
        key: &SlotKey,
        witness: &S::Witness,
    ) -> Option<SlotValue> {
        match self.read_value::<N>(key, None) {
            Ok(value) => {
                if let Some(witness) = self.recorded(witness) {
                    witness.add_hint(&value);
                }
                value
            }
            Err(error) => self.read_failed("value", key, &error),
        }
    }

    /// # Errors
    /// - [`StaleStorage`] (inside the `anyhow::Error`) if the storage is stale: a newer version
    ///   was committed since it was created (the NOMT trees are no longer at its root), or its
    ///   blocks were discarded (upstream: only a root check, and only in strict mode).
    /// - If `prev_state_root` is not this storage's root: the caller passed the wrong root
    ///   (upstream did not check it outside strict mode).
    /// - With the witness on, if a read does not match the NOMT tree (see the type docs).
    /// - If NOMT fails, or two accesses have the same key path.
    fn compute_state_update(
        &self,
        state_accesses: StateAccesses,
        witness: &S::Witness,
        prev_state_root: StorageRoot<S>,
    ) -> anyhow::Result<(StorageRoot<S>, NomtStateUpdate<S>)> {
        let next_version = self.historical_state.get_next_version();
        let own_root = self.own_root()?;
        // Both sessions under one lock (`begin_both_sessions`); they block NOMT commits until
        // finished. Opening them fails with `StaleStorage` if this storage's blocks were
        // discarded.
        let SessionsContainer { user, kernel } = self
            .session_builder
            .begin_both_sessions(self.witness_mode)?;
        let session_root = StorageRoot::new(
            user.prev_root().into_inner(),
            kernel.prev_root().into_inner(),
        );
        if session_root != own_root {
            return Err(StaleStorage {
                storage_version: self.historical_state.last_version(),
                committed_version: self.session_builder.committed_version()?,
                discarded_fork: false,
            }
            .into());
        }
        anyhow::ensure!(
            own_root == prev_state_root,
            "wrong previous root (next version {next_version}): the passed previous root \
             {prev_state_root} is not this storage's root {own_root} (not a stale storage: the \
             NOMT trees are at its root)"
        );

        let StateAccesses {
            user: user_accesses,
            kernel: kernel_accesses,
        } = state_accesses;
        // User first, then kernel: the order of the proof hints.
        let user = self
            .finish_namespace(user, &user_accesses, witness)
            .context("user namespace")?;
        let kernel = self
            .finish_namespace(kernel, &kernel_accesses, witness)
            .context("kernel namespace")?;
        let root = StorageRoot::new(user.root().into_inner(), kernel.root().into_inner());
        Ok((
            root,
            NomtStateUpdate {
                state: StateFinishedSession::new(user, kernel),
                user_writes: user_accesses.ordered_writes,
                kernel_writes: kernel_accesses.ordered_writes,
                accessory: Vec::new(),
                root,
            },
        ))
    }

    /// Materializes the update as the changes of the version after this storage's.
    ///
    /// # Panics
    /// If a key or root cannot be encoded for the databases (never, with the schemas'
    /// encodings).
    fn materialize_changes(self, state_update: NomtStateUpdate<S>) -> NomtChangeSet {
        let version = self.historical_state.get_next_version();
        let NomtStateUpdate {
            state,
            user_writes,
            kernel_writes,
            accessory,
            root,
        } = state_update;
        let historical_state = HistoricalStateReader::materialize_values(
            user_writes,
            kernel_writes,
            root.into(),
            version,
        )
        .expect("encoding the flat-store changes cannot fail");
        let accessory = AccessoryDb::materialize_values(accessory, version)
            .expect("encoding the accessory changes cannot fail");
        NomtChangeSet::new(state, historical_state, accessory)
    }

    fn open_proof(
        state_root: StorageRoot<S>,
        proof: StorageProof<NomtProof>,
    ) -> anyhow::Result<(SlotKey, Option<SlotValue>)> {
        verify_storage_proof(state_root, proof)
    }
}

impl<S: MerkleProofSpec, K: Clone + Eq + Hash> NativeStorage for NomtProverStorage<S, K> {
    fn latest_version(&self) -> SlotNumber {
        self.historical_state
            .last_version()
            .unwrap_or(SlotNumber::GENESIS)
    }

    /// The newest version this storage can see: the newest committed one, or the newest of its
    /// own uncommitted blocks if newer. Genesis also when nothing is committed (as upstream).
    fn latest_version_unbound(&self) -> SlotNumber {
        Self::resolve_unbound_read(
            self.historical_state.last_version_unbound(),
            "the state-root table",
        )
        .unwrap_or(SlotNumber::GENESIS)
    }

    fn get_historical<N: ProvableCompileTimeNamespace>(
        &self,
        key: &SlotKey,
        version: Option<SlotNumber>,
        _witness: &S::Witness,
    ) -> anyhow::Result<Option<SlotValue>> {
        self.read_value::<N>(key, version)
    }

    fn get_leaf_historical<N: ProvableCompileTimeNamespace>(
        &self,
        key: &SlotKey,
        version: Option<SlotNumber>,
        _witness: &S::Witness,
    ) -> anyhow::Result<Option<NodeLeafAndMaybeValue>> {
        self.do_get_leaf::<N>(key, version, None)
    }

    fn get_accessory(&self, key: &SlotKey) -> Option<SlotValue> {
        match self.read_value::<Accessory>(key, None) {
            Ok(value) => value,
            Err(error) => self.read_failed("accessory value", key, &error),
        }
    }

    fn get_accessory_historical(
        &self,
        key: &SlotKey,
        version: Option<SlotNumber>,
    ) -> anyhow::Result<Option<SlotValue>> {
        self.read_value::<Accessory>(key, version)
    }

    /// Proves the newest value (not this storage's version): the newest committed one, or the
    /// newest of this storage's uncommitted blocks if it has any, retrying for up to 375 ms while a
    /// commit is in progress. Blocks the thread while retrying, and while a storage manager
    /// commits: call it from a blocking context in async code.
    ///
    /// # Errors
    /// [`StaleStorage`] (`discarded_fork`, inside the `anyhow::Error`) at once, without
    /// retrying, if this storage's blocks were discarded; a root mismatch once the retries ran
    /// out; read errors.
    fn get_with_proof<N: ProvableCompileTimeNamespace>(
        &self,
        key: SlotKey,
    ) -> anyhow::Result<ProofOutput<Self>> {
        // Well under an RPC's 500 ms budget; one blocked attempt usually lands after the commit
        // in progress, so a few short retries suffice.
        const RETRY_DEADLINE: Duration = Duration::from_millis(375);
        const RETRY_BACKOFFS_MS: [u64; 3] = [2, 10, 25];

        let start = Instant::now();
        let mut attempts = 0usize;
        loop {
            attempts = attempts.saturating_add(1);
            match self.get_with_proof_once::<N>(key.clone()) {
                Ok(result) => return Ok(result),
                Err(GetWithProofError::Other(error)) => return Err(error),
                Err(GetWithProofError::StateRootMismatch) => {
                    let elapsed = start.elapsed();
                    let backoff = RETRY_BACKOFFS_MS.get(attempts.saturating_sub(1));
                    let Some(&backoff_ms) = backoff.filter(|_| elapsed < RETRY_DEADLINE) else {
                        anyhow::bail!(
                            "{} after {attempts} attempts over {elapsed:?}",
                            GetWithProofError::StateRootMismatch
                        );
                    };
                    let remaining = RETRY_DEADLINE.saturating_sub(elapsed);
                    std::thread::sleep(Duration::from_millis(backoff_ms).min(remaining));
                }
            }
        }
    }

    fn get_root_hash(&self, version: SlotNumber) -> Option<StorageRoot<S>> {
        // Bound: only versions this storage sees.
        self.version_to_read(Some(version)).ok()?;
        let (found, roots) = Self::resolve_unbound_read(
            self.historical_state.get_root_hash(version),
            "the state-root table",
        )?;
        // Every committed version stores its root, so this holds unless it was removed.
        (found == version).then(|| roots.into())
    }

    fn get_root_hash_unbound(&self, version: SlotNumber) -> Option<StorageRoot<S>> {
        Self::resolve_unbound_read(
            self.historical_state.get_root_hash(version),
            "the state-root table",
        )
        .map(|(_, roots)| roots.into())
    }

    /// The newest value of `key`, whatever this storage's version: the newest committed one, or
    /// the newest of this storage's snapshots (uncommitted blocks) that are newer than the
    /// committed version.
    ///
    /// On a storage whose blocks were discarded (another fork was committed), this mixes its
    /// snapshots newer than the committed version with the committed state (TODO.md, storage
    /// manager item); bound reads and proofs do not.
    fn get_unbound<N: CompileTimeNamespace>(&self, key: SlotKey) -> Option<SlotValue> {
        self.read_value_unbound::<N>(&key)
    }

    /// The newest accessory value of `key` at or below `max_version` (`None`: any), whatever
    /// this storage's version: in the committed accessory DB or in this storage's snapshots
    /// (uncommitted blocks).
    ///
    /// On a storage whose blocks were discarded, this mixes its snapshots with the committed
    /// state, as [`get_unbound`](NativeStorage::get_unbound) does.
    fn get_accessory_unbound(
        &self,
        key: SlotKey,
        max_version: Option<SlotNumber>,
    ) -> Option<SlotValue> {
        Self::resolve_unbound_read(
            self.accessory
                .get_value_option(&key, max_version.unwrap_or(SlotNumber::MAX)),
            "the accessory DB",
        )
    }

    /// # Errors
    /// If `cursor` does not start with `prefix`, if a version newer than this storage's has been
    /// committed (the flat store's live table no longer matches it), or if this storage is on a
    /// discarded fork ([`StaleStorage`]).
    ///
    /// # Panics
    /// The iterator panics if a read fails (it yields plain pairs: ending early would read as
    /// "no more keys").
    ///
    /// # Locking
    /// The iterator holds the flat store's lock until it is dropped, and commits wait for it.
    /// While it is alive, do not commit or finalize on this thread, and do not open NOMT
    /// sessions on it (`get_with_proof`, `compute_state_update`) if a storage manager may
    /// finalize on another: the finalization holds the overlays lock the session waits for while
    /// it waits for the iterator, a deadlock. Collect the iterator or drop it first.
    fn maybe_iter_user_values_with_prefix(
        &self,
        prefix: SlotKey,
        cursor: Option<SlotKey>,
    ) -> anyhow::Result<Option<impl Iterator<Item = (SlotKey, SlotValue)>>> {
        self.iter_values_with_prefix(ProvableNamespace::User, prefix, cursor)
    }

    /// See [`maybe_iter_user_values_with_prefix`](Self::maybe_iter_user_values_with_prefix).
    fn maybe_iter_kernel_values_with_prefix(
        &self,
        prefix: SlotKey,
        cursor: Option<SlotKey>,
    ) -> anyhow::Result<Option<impl Iterator<Item = (SlotKey, SlotValue)>>> {
        self.iter_values_with_prefix(ProvableNamespace::Kernel, prefix, cursor)
    }
}

impl<S: MerkleProofSpec, K> NomtProverStorage<S, K> {
    /// Both `maybe_iter_*`: deleted keys are not yielded (rockbound skips them).
    ///
    /// The iterator merges this storage's snapshots newer than the committed version with the
    /// flat store's live table, so its snapshots at or below the committed version must be the
    /// committed blocks: checked by root, while the iterator holds the flat store's lock (no
    /// commit completes meanwhile). A storage on a discarded fork fails with [`StaleStorage`]
    /// (rockbound took them for committed, so it iterated the other fork's values).
    fn iter_values_with_prefix(
        &self,
        namespace: ProvableNamespace,
        prefix: SlotKey,
        cursor: Option<SlotKey>,
    ) -> anyhow::Result<Option<impl Iterator<Item = (SlotKey, SlotValue)> + '_>> {
        let iter = self
            .historical_state
            .iter_values_with_prefix(namespace, &prefix, cursor)?;
        if let Some(committed) = self.session_builder.committed_version()?
            && self
                .historical_state
                .last_version()
                .is_some_and(|version| version >= committed)
        {
            let own = self
                .historical_state
                .get_root_hash(committed)?
                .filter(|(found, _)| *found == committed)
                .map(|(_, roots)| roots);
            if own != self.session_builder.committed_root_at(committed)? {
                return Err(StaleStorage {
                    storage_version: self.historical_state.last_version(),
                    committed_version: Some(committed),
                    discarded_fork: true,
                }
                .into());
            }
        }
        Ok(Some(iter.map(move |item| {
            item.unwrap_or_else(|error| {
                panic!("Database error while iterating over the {namespace:?} values: {error:?}")
            })
        })))
    }
}

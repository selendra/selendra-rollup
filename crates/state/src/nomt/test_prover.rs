//! A minimal NOMT prover storage for the verifier's tests: real NOMT databases (one per
//! provable namespace, in a temporary directory) holding the leaves, and the values in memory.
//!
//! Like upstream's `NomtProverStorage`, NOMT stores each slot as key path `H(key)` → value
//! `val_hash_and_size`, the witness gets one hint per read (`Option<NodeLeaf>` for a leaf,
//! `Option<SlotValue>` for a value) and one [`NomtProof`] per accessed namespace (user, then
//! kernel), built from the NOMT session's witness. Only the latest state is kept: each block is
//! committed before the next one starts.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use ::nomt::hasher::BinaryHasher;
use ::nomt::{FinishedSession, KeyReadWrite, Nomt, Options, SessionParams, WitnessMode};
use nomt_core::trie::KeyPath;
use sha2::{Digest, Sha256};

use super::{NomtProof, namespace_needs_proof, verify_namespace, verify_storage_proof};
use crate::namespaces::{ProvableCompileTimeNamespace, ProvableNamespace};
use crate::storage::{NodeLeaf, NodeLeafAndMaybeValue};
use crate::{
    ArrayWitness, DefaultStorageSpec, OrderedReadsAndWrites, SlotKey, SlotValue, StateAccesses,
    StateCheckpoint, StateRoot, StateUpdate, Storage, StorageProof, StorageRoot, Witness,
};

/// The spec of the tests: SHA-256 and an `ArrayWitness`.
pub(crate) type Spec = DefaultStorageSpec<Sha256>;
/// The root of the tests.
pub(crate) type Root = StorageRoot<Spec>;
type Hasher = BinaryHasher<Sha256>;

/// The values of one namespace.
pub(crate) type Values = BTreeMap<SlotKey, SlotValue>;

struct Namespace {
    nomt: Nomt<Hasher>,
    values: Mutex<Values>,
}

/// A small NOMT database at `path`.
pub(crate) fn open_nomt(path: &std::path::Path) -> Nomt<Hasher> {
    let mut options = Options::new();
    options.path(path);
    options.commit_concurrency(1);
    options.hashtable_buckets(1_000);
    options.preallocate_ht(false);
    options.page_cache_size(4);
    options.leaf_cache_size(4);
    Nomt::open(options).expect("open NOMT")
}

impl Namespace {
    fn open(path: &std::path::Path) -> Self {
        Self {
            nomt: open_nomt(path),
            values: Mutex::default(),
        }
    }

    fn values(&self) -> MutexGuard<'_, Values> {
        self.values.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn root(&self) -> [u8; 32] {
        self.nomt.root().into_inner()
    }
}

struct Inner {
    user: Namespace,
    kernel: Namespace,
    // Last: dropped after the databases.
    _dir: tempfile::TempDir,
}

/// See the module docs.
#[derive(Clone)]
pub(crate) struct NomtTestProver(Arc<Inner>);

impl std::fmt::Debug for NomtTestProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NomtTestProver({})", self.root())
    }
}

/// The finished NOMT session (if the namespace was accessed) and the value writes of one
/// namespace.
pub(crate) struct NamespaceUpdate {
    session: Option<FinishedSession>,
    writes: Vec<(SlotKey, Option<SlotValue>)>,
}

/// The state update of [`NomtTestProver`] (accessory items are dropped).
pub(crate) struct NomtTestUpdate {
    user: NamespaceUpdate,
    kernel: NamespaceUpdate,
}

impl StateUpdate for NomtTestUpdate {
    fn add_accessory_item(&mut self, _key: SlotKey, _value: Option<SlotValue>) {}

    fn get_accessory_items(&self) -> impl Iterator<Item = &(SlotKey, Option<SlotValue>)> {
        std::iter::empty()
    }
}

fn key_path(key: &SlotKey) -> KeyPath {
    Sha256::digest(key.as_ref()).into()
}

/// The NOMT accesses of a namespace, sorted by key path (upstream `to_nomt_accesses`): reads
/// carry the read `val_hash_and_size`, writes the new one.
///
/// A delete of a key that is absent from `values` (the committed state) becomes a read of its
/// absence: the same for the tree and its proof, but NOMT 1.0.5 panics committing a session
/// whose only value changes are such deletes into an empty database (an underflow in
/// `beatree/ops/update/leaf_stage.rs`, `filter_leaves_changeset`). Upstream's prover passes
/// them through.
fn to_nomt_accesses(
    accesses: &OrderedReadsAndWrites,
    values: &Values,
) -> Vec<(KeyPath, KeyReadWrite)> {
    let mut merged: BTreeMap<KeyPath, KeyReadWrite> = BTreeMap::new();
    for (key, leaf) in &accesses.ordered_reads {
        let read = leaf.map(|leaf| leaf.combine_val_hash_and_size().to_vec());
        let previous = merged.insert(key_path(key), KeyReadWrite::Read(read));
        assert!(previous.is_none(), "duplicate read of {key}");
    }
    for (key, value) in &accesses.ordered_writes {
        let write = value
            .as_ref()
            .map(|value| value.combine_val_hash_and_size::<Sha256>().to_vec());
        let no_op = write.is_none() && !values.contains_key(key);
        match merged.entry(key_path(key)) {
            Entry::Vacant(entry) => {
                entry.insert(if no_op {
                    KeyReadWrite::Read(None)
                } else {
                    KeyReadWrite::Write(write)
                });
            }
            Entry::Occupied(mut entry) => {
                assert!(
                    matches!(entry.get(), KeyReadWrite::Read(_)),
                    "duplicate write of {key}"
                );
                if !no_op {
                    entry.get_mut().write(write);
                }
            }
        }
    }
    merged.into_iter().collect()
}

impl NomtTestProver {
    /// An empty storage.
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary directory");
        let user = Namespace::open(&dir.path().join("user"));
        let kernel = Namespace::open(&dir.path().join("kernel"));
        Self(Arc::new(Inner {
            user,
            kernel,
            _dir: dir,
        }))
    }

    fn namespace(&self, namespace: ProvableNamespace) -> &Namespace {
        match namespace {
            ProvableNamespace::User => &self.0.user,
            ProvableNamespace::Kernel => &self.0.kernel,
        }
    }

    /// The root of the committed state.
    pub(crate) fn root(&self) -> Root {
        StorageRoot::new(self.0.user.root(), self.0.kernel.root())
    }

    /// The committed values of a namespace.
    pub(crate) fn values(&self, namespace: ProvableNamespace) -> Values {
        self.namespace(namespace).values().clone()
    }

    /// Runs `f` on a checkpoint over this storage, then commits it; returns the new root.
    pub(crate) fn commit_with(&self, f: impl FnOnce(&mut StateCheckpoint<Self>)) -> Root {
        let mut checkpoint = StateCheckpoint::new(self.clone());
        f(&mut checkpoint);
        let (root, update, _accessory, _witness, storage) =
            checkpoint.materialize_update(self.root());
        storage.materialize_changes(update);
        assert_eq!(self.root(), root);
        root
    }

    /// A proof of `key`'s current value (or absence) in `namespace`.
    pub(crate) fn prove(
        &self,
        namespace: ProvableNamespace,
        key: &SlotKey,
    ) -> StorageProof<NomtProof> {
        let ns = self.namespace(namespace);
        let session = ns.nomt.begin_session(SessionParams::default());
        let path_proof = session.prove(key_path(key)).expect("NOMT proof");
        drop(session);
        StorageProof {
            key: key.clone(),
            value: ns.values().get(key).cloned(),
            proof: NomtProof::from_path_proofs(vec![path_proof])
                .expect("NOMT proof is well-formed"),
            namespace,
        }
    }

    fn update_namespace(
        &self,
        namespace: ProvableNamespace,
        accesses: OrderedReadsAndWrites,
        witness: &ArrayWitness,
        prev_root: [u8; 32],
    ) -> anyhow::Result<([u8; 32], NamespaceUpdate)> {
        let ns = self.namespace(namespace);
        if !namespace_needs_proof(&accesses) {
            return Ok((
                prev_root,
                NamespaceUpdate {
                    session: None,
                    writes: Vec::new(),
                },
            ));
        }
        let session = ns
            .nomt
            .begin_session(SessionParams::default().witness_mode(WitnessMode::read_write()));
        anyhow::ensure!(
            session.prev_root().into_inner() == prev_root,
            "{namespace:?}: stale storage"
        );
        let nomt_accesses = to_nomt_accesses(&accesses, &ns.values());
        let mut finished = session.finish(nomt_accesses)?;
        let nomt_witness = finished.take_witness().expect("witness mode is on");
        let proof = NomtProof::from_path_proofs(
            nomt_witness
                .path_proofs
                .into_iter()
                .map(|path| path.inner)
                .collect(),
        )?;
        // The prover's self-check (upstream relied on debug-only checks): its own reads must
        // verify against its tree, or the guest would reject the witness.
        let root = verify_namespace::<Spec>(prev_root, &accesses, &proof)?;
        anyhow::ensure!(
            root == finished.root().into_inner(),
            "{namespace:?}: NOMT and the multi-proof disagree on the new root"
        );
        witness.add_hint(&proof);
        Ok((
            root,
            NamespaceUpdate {
                session: Some(finished),
                writes: accesses.ordered_writes,
            },
        ))
    }
}

impl Storage for NomtTestProver {
    type Hasher = Sha256;
    type Witness = ArrayWitness;
    type Proof = NomtProof;
    type Root = Root;
    type StateUpdate = NomtTestUpdate;
    type ChangeSet = ();

    const PRE_GENESIS_ROOT: Root = StorageRoot::PRE_GENESIS;

    fn put_in_witness(&self, value: Option<SlotValue>, witness: &ArrayWitness) {
        witness.add_hint(&value);
    }

    fn get_leaf<N: ProvableCompileTimeNamespace>(
        &self,
        key: &SlotKey,
        witness: &ArrayWitness,
    ) -> Option<NodeLeafAndMaybeValue> {
        let value = self
            .namespace(N::PROVABLE_NAMESPACE)
            .values()
            .get(key)
            .cloned();
        witness.add_hint(&value.as_ref().map(NodeLeaf::make_leaf::<Sha256>));
        value.map(NodeLeafAndMaybeValue::with_fetched_value::<Sha256>)
    }

    fn get<N: ProvableCompileTimeNamespace>(
        &self,
        key: &SlotKey,
        witness: &ArrayWitness,
    ) -> Option<SlotValue> {
        let value = self
            .namespace(N::PROVABLE_NAMESPACE)
            .values()
            .get(key)
            .cloned();
        witness.add_hint(&value);
        value
    }

    fn compute_state_update(
        &self,
        state_accesses: StateAccesses,
        witness: &ArrayWitness,
        prev_state_root: Root,
    ) -> anyhow::Result<(Root, NomtTestUpdate)> {
        let StateAccesses { user, kernel } = state_accesses;
        let (user_root, user) = self.update_namespace(
            ProvableNamespace::User,
            user,
            witness,
            prev_state_root.namespace_root(ProvableNamespace::User),
        )?;
        let (kernel_root, kernel) = self.update_namespace(
            ProvableNamespace::Kernel,
            kernel,
            witness,
            prev_state_root.namespace_root(ProvableNamespace::Kernel),
        )?;
        Ok((
            StorageRoot::new(user_root, kernel_root),
            NomtTestUpdate { user, kernel },
        ))
    }

    fn materialize_changes(self, update: NomtTestUpdate) {
        for (namespace, update) in [
            (ProvableNamespace::Kernel, update.kernel),
            (ProvableNamespace::User, update.user),
        ] {
            let ns = self.namespace(namespace);
            if let Some(session) = update.session {
                session.commit(&ns.nomt).expect("NOMT commit");
            }
            let mut values = ns.values();
            for (key, value) in update.writes {
                match value {
                    Some(value) => values.insert(key, value),
                    None => values.remove(&key),
                };
            }
        }
    }

    fn open_proof(
        state_root: Root,
        proof: StorageProof<NomtProof>,
    ) -> anyhow::Result<(SlotKey, Option<SlotValue>)> {
        verify_storage_proof(state_root, proof)
    }
}

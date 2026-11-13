//! An in-memory [`Storage`] for tests that models the witness protocol.
//!
//! - **Prover** mode holds the committed state (`BTreeMap`s) and records a hint for every read,
//!   like a native storage.
//! - **Verifier** mode holds nothing: it answers reads only from witness hints, like the zk
//!   guest, and verifies them in `compute_state_update`.
//!
//! The root of a namespace is `SHA-256(borsh(map))` (`[0; 32]` when empty), the global root
//! `SHA-256(user_root ‖ kernel_root)`. Since that commits to the whole map, the "multi-proof"
//! the prover puts in the witness for `compute_state_update` (and the proof of
//! `get_with_proof`) is the whole map of the namespace: inefficient, but it lets the verifier
//! check every read and compute the new root exactly like a real zk storage would.

use std::collections::BTreeMap;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::{HexString, hex_string_serde};
use sha2::{Digest, Sha256};

use crate::namespaces::{ProvableCompileTimeNamespace, ProvableNamespace};
use crate::storage::{NodeLeaf, NodeLeafAndMaybeValue};
use crate::{
    ArrayWitness, OrderedReadsAndWrites, SlotKey, SlotValue, StateAccesses, StateCheckpoint,
    StateRoot, StateUpdate, Storage, StorageProof, Witness,
};

/// The contents of one provable namespace.
pub(crate) type NamespaceState = BTreeMap<SlotKey, SlotValue>;

/// The root of a namespace.
pub(crate) fn namespace_root(state: &NamespaceState) -> [u8; 32] {
    if state.is_empty() {
        [0; 32]
    } else {
        Sha256::digest(borsh::to_vec(state).unwrap()).into()
    }
}

/// `user_root ‖ kernel_root`.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub(crate) struct TestRoot(#[serde(with = "hex_string_serde")] [u8; 64]);

impl TestRoot {
    const fn from_roots(user: [u8; 32], kernel: [u8; 32]) -> Self {
        let mut bytes = [0u8; 64];
        let mut i = 0;
        while i < 32 {
            bytes[i] = user[i];
            bytes[i + 32] = kernel[i];
            i += 1;
        }
        Self(bytes)
    }
}

impl std::fmt::Debug for TestRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestRoot({self})")
    }
}

impl std::fmt::Display for TestRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HexString(&self.0))
    }
}

impl AsRef<[u8]> for TestRoot {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl StateRoot for TestRoot {
    fn global_root(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }

    fn namespace_root(&self, namespace: ProvableNamespace) -> [u8; 32] {
        let (user, kernel) = self.0.split_at(32);
        let half = match namespace {
            ProvableNamespace::User => user,
            ProvableNamespace::Kernel => kernel,
        };
        half.try_into().unwrap()
    }

    fn from_namespace_roots(user_root: [u8; 32], kernel_root: [u8; 32]) -> Self {
        Self::from_roots(user_root, kernel_root)
    }
}

/// Committed state of a prover storage.
#[derive(Debug, Default)]
pub(crate) struct Committed {
    pub(crate) user: NamespaceState,
    pub(crate) kernel: NamespaceState,
    pub(crate) accessory: NamespaceState,
    /// Number of commits so far.
    pub(crate) version: u64,
}

impl Committed {
    fn namespace(&self, namespace: ProvableNamespace) -> &NamespaceState {
        match namespace {
            ProvableNamespace::User => &self.user,
            ProvableNamespace::Kernel => &self.kernel,
        }
    }

    fn root(&self) -> TestRoot {
        TestRoot::from_roots(namespace_root(&self.user), namespace_root(&self.kernel))
    }
}

/// See the module docs.
#[derive(Debug, Clone)]
pub(crate) enum TestStorage {
    Prover(Arc<Committed>),
    Verifier,
}

impl Default for TestStorage {
    fn default() -> Self {
        Self::Prover(Arc::default())
    }
}

/// The state after an update, and the accessory items added to it.
#[derive(Debug)]
pub(crate) struct TestStateUpdate {
    user: NamespaceState,
    kernel: NamespaceState,
    accessory: Vec<(SlotKey, Option<SlotValue>)>,
}

impl StateUpdate for TestStateUpdate {
    fn add_accessory_item(&mut self, key: SlotKey, value: Option<SlotValue>) {
        self.accessory.push((key, value));
    }

    fn get_accessory_items(&self) -> impl Iterator<Item = &(SlotKey, Option<SlotValue>)> {
        self.accessory.iter()
    }
}

impl TestStorage {
    pub(crate) fn committed(&self) -> &Committed {
        match self {
            Self::Prover(committed) => committed,
            Self::Verifier => panic!("a verifier storage holds no state"),
        }
    }

    /// The root of the committed state (prover only).
    pub(crate) fn root(&self) -> TestRoot {
        self.committed().root()
    }

    /// Runs `f` on a checkpoint over this storage, then commits it (with the accessory writes).
    pub(crate) fn commit_with(self, f: impl FnOnce(&mut StateCheckpoint<Self>)) -> Self {
        let prev_root = self.root();
        let mut checkpoint = StateCheckpoint::new(self);
        f(&mut checkpoint);
        let (_root, mut update, accessory, _witness, storage) =
            checkpoint.materialize_update(prev_root);
        update.add_accessory_items(accessory.freeze());
        storage.materialize_changes(update)
    }

    /// Checks the reads of one namespace against `state` (its contents under the previous
    /// root) and applies the writes.
    fn apply(
        namespace: ProvableNamespace,
        mut state: NamespaceState,
        accesses: OrderedReadsAndWrites,
    ) -> anyhow::Result<NamespaceState> {
        for (key, leaf) in accesses.ordered_reads {
            let actual = state.get(&key).map(NodeLeaf::make_leaf::<Sha256>);
            anyhow::ensure!(
                actual == leaf,
                "read of {key} in {namespace:?} does not match the previous state"
            );
        }
        for (key, value) in accesses.ordered_writes {
            match value {
                Some(value) => state.insert(key, value),
                None => state.remove(&key),
            };
        }
        Ok(state)
    }

    /// One namespace of `compute_state_update`: returns the new state, or `None` if the
    /// namespace was not accessed (its root stays).
    fn update_namespace(
        &self,
        namespace: ProvableNamespace,
        accesses: OrderedReadsAndWrites,
        witness: &ArrayWitness,
        prev_root: [u8; 32],
    ) -> anyhow::Result<Option<NamespaceState>> {
        if accesses.ordered_reads.is_empty() && accesses.ordered_writes.is_empty() {
            return Ok(None);
        }
        let state = match self {
            Self::Prover(committed) => {
                let state = committed.namespace(namespace).clone();
                witness.add_hint(&state);
                state
            }
            Self::Verifier => witness.try_get_hint::<NamespaceState>()?,
        };
        anyhow::ensure!(
            namespace_root(&state) == prev_root,
            "{namespace:?} state does not match the previous root (stale storage or invalid witness)"
        );
        Self::apply(namespace, state, accesses).map(Some)
    }
}

impl Storage for TestStorage {
    type Hasher = Sha256;
    type Witness = ArrayWitness;
    /// The whole namespace map.
    type Proof = NamespaceState;
    type Root = TestRoot;
    type StateUpdate = TestStateUpdate;
    type ChangeSet = TestStorage;

    const PRE_GENESIS_ROOT: TestRoot = TestRoot::from_roots([0; 32], [0; 32]);

    fn put_in_witness(&self, value: Option<SlotValue>, witness: &ArrayWitness) {
        if let Self::Prover(_) = self {
            witness.add_hint(&value);
        }
    }

    fn get_leaf<N: ProvableCompileTimeNamespace>(
        &self,
        key: &SlotKey,
        witness: &ArrayWitness,
    ) -> Option<NodeLeafAndMaybeValue> {
        match self {
            Self::Prover(committed) => {
                let value = committed.namespace(N::PROVABLE_NAMESPACE).get(key).cloned();
                witness.add_hint(&value.as_ref().map(NodeLeaf::make_leaf::<Sha256>));
                value.map(NodeLeafAndMaybeValue::with_fetched_value::<Sha256>)
            }
            Self::Verifier => witness
                .get_hint::<Option<NodeLeaf>>()
                .map(NodeLeafAndMaybeValue::without_value),
        }
    }

    fn get<N: ProvableCompileTimeNamespace>(
        &self,
        key: &SlotKey,
        witness: &ArrayWitness,
    ) -> Option<SlotValue> {
        match self {
            Self::Prover(committed) => {
                let value = committed.namespace(N::PROVABLE_NAMESPACE).get(key).cloned();
                witness.add_hint(&value);
                value
            }
            Self::Verifier => witness.get_hint(),
        }
    }

    fn compute_state_update(
        &self,
        state_accesses: StateAccesses,
        witness: &ArrayWitness,
        prev_state_root: TestRoot,
    ) -> anyhow::Result<(TestRoot, TestStateUpdate)> {
        let StateAccesses { user, kernel } = state_accesses;
        let prev_user = prev_state_root.namespace_root(ProvableNamespace::User);
        let prev_kernel = prev_state_root.namespace_root(ProvableNamespace::Kernel);
        let new_user = self.update_namespace(ProvableNamespace::User, user, witness, prev_user)?;
        let new_kernel =
            self.update_namespace(ProvableNamespace::Kernel, kernel, witness, prev_kernel)?;
        let root = TestRoot::from_roots(
            new_user.as_ref().map_or(prev_user, namespace_root),
            new_kernel.as_ref().map_or(prev_kernel, namespace_root),
        );
        // Untouched namespaces keep the committed state (empty for a verifier, which never
        // materializes).
        let (user, kernel) = match self {
            Self::Prover(committed) => (
                new_user.unwrap_or_else(|| committed.user.clone()),
                new_kernel.unwrap_or_else(|| committed.kernel.clone()),
            ),
            Self::Verifier => (new_user.unwrap_or_default(), new_kernel.unwrap_or_default()),
        };
        Ok((
            root,
            TestStateUpdate {
                user,
                kernel,
                accessory: Vec::new(),
            },
        ))
    }

    fn materialize_changes(self, update: TestStateUpdate) -> TestStorage {
        let Self::Prover(committed) = self else {
            return self;
        };
        let mut accessory = committed.accessory.clone();
        for (key, value) in update.accessory {
            match value {
                Some(value) => accessory.insert(key, value),
                None => accessory.remove(&key),
            };
        }
        Self::Prover(Arc::new(Committed {
            user: update.user,
            kernel: update.kernel,
            accessory,
            version: committed.version.saturating_add(1),
        }))
    }

    fn open_proof(
        state_root: TestRoot,
        proof: StorageProof<NamespaceState>,
    ) -> anyhow::Result<(SlotKey, Option<SlotValue>)> {
        let StorageProof {
            key,
            value,
            proof,
            namespace,
        } = proof;
        anyhow::ensure!(
            namespace_root(&proof) == state_root.namespace_root(namespace),
            "proof does not match the {namespace:?} root"
        );
        anyhow::ensure!(
            proof.get(&key) == value.as_ref(),
            "proven value of {key} does not match the proof"
        );
        Ok((key, value))
    }
}

#[cfg(feature = "native")]
pub(crate) use native::ProvenTestAccessor;

#[cfg(feature = "native")]
mod native {
    use std::convert::Infallible;

    use selendra_interface::common::SlotNumber;

    use super::{Committed, TestStorage};
    use crate::namespaces::{
        CompileTimeNamespace, Kernel, Namespace, ProvableCompileTimeNamespace, User,
    };
    use crate::storage::{NodeLeaf, NodeLeafAndMaybeValue};
    use crate::{
        NativeStorage, ProofOutput, ProvenStateAccessor, SlotKey, SlotValue, StateReader,
        StorageProof,
    };

    impl TestStorage {
        fn at_version(&self, version: Option<SlotNumber>) -> anyhow::Result<&Committed> {
            let committed = self.committed();
            match version {
                Some(v) if v.get() != committed.version => {
                    anyhow::bail!("version {v:?} is not available")
                }
                _ => Ok(committed),
            }
        }

        fn iter_prefix<'a>(
            state: &'a super::NamespaceState,
            prefix: SlotKey,
            cursor: Option<SlotKey>,
        ) -> impl Iterator<Item = (SlotKey, SlotValue)> + 'a {
            let start = cursor.unwrap_or_else(|| prefix.clone());
            state
                .range(start..)
                .take_while(move |(key, _)| key.as_ref().starts_with(prefix.as_ref()))
                .map(|(key, value)| (key.clone(), value.clone()))
        }
    }

    impl NativeStorage for TestStorage {
        fn latest_version(&self) -> SlotNumber {
            SlotNumber::new(self.committed().version)
        }

        fn latest_version_unbound(&self) -> SlotNumber {
            self.latest_version()
        }

        fn get_historical<N: ProvableCompileTimeNamespace>(
            &self,
            key: &SlotKey,
            version: Option<SlotNumber>,
            _witness: &Self::Witness,
        ) -> anyhow::Result<Option<SlotValue>> {
            Ok(self
                .at_version(version)?
                .namespace(N::PROVABLE_NAMESPACE)
                .get(key)
                .cloned())
        }

        fn get_leaf_historical<N: ProvableCompileTimeNamespace>(
            &self,
            key: &SlotKey,
            version: Option<SlotNumber>,
            witness: &Self::Witness,
        ) -> anyhow::Result<Option<NodeLeafAndMaybeValue>> {
            Ok(self
                .get_historical::<N>(key, version, witness)?
                .map(NodeLeafAndMaybeValue::with_fetched_value::<sha2::Sha256>))
        }

        fn get_accessory(&self, key: &SlotKey) -> Option<SlotValue> {
            self.committed().accessory.get(key).cloned()
        }

        fn get_accessory_historical(
            &self,
            key: &SlotKey,
            version: Option<SlotNumber>,
        ) -> anyhow::Result<Option<SlotValue>> {
            Ok(self.at_version(version)?.accessory.get(key).cloned())
        }

        fn get_with_proof<N: ProvableCompileTimeNamespace>(
            &self,
            key: SlotKey,
        ) -> anyhow::Result<ProofOutput<Self>> {
            let committed = self.committed();
            let proof = committed.namespace(N::PROVABLE_NAMESPACE).clone();
            let value = proof.get(&key).cloned();
            Ok((
                StorageProof {
                    key,
                    value,
                    proof,
                    namespace: N::PROVABLE_NAMESPACE,
                },
                self.latest_version(),
                committed.root(),
            ))
        }

        fn get_root_hash(&self, version: SlotNumber) -> Option<Self::Root> {
            self.at_version(Some(version)).ok().map(Committed::root)
        }

        fn get_root_hash_unbound(&self, version: SlotNumber) -> Option<Self::Root> {
            (version >= self.latest_version()).then(|| self.root())
        }

        fn get_unbound<N: CompileTimeNamespace>(&self, key: SlotKey) -> Option<SlotValue> {
            let committed = self.committed();
            let state = match N::NAMESPACE {
                Namespace::User => &committed.user,
                Namespace::Kernel => &committed.kernel,
                Namespace::Accessory => &committed.accessory,
            };
            state.get(&key).cloned()
        }

        fn get_accessory_unbound(
            &self,
            key: SlotKey,
            _max_version: Option<SlotNumber>,
        ) -> anyhow::Result<Option<SlotValue>> {
            Ok(self.get_accessory(&key))
        }

        fn maybe_iter_user_values_with_prefix(
            &self,
            prefix: SlotKey,
            cursor: Option<SlotKey>,
        ) -> anyhow::Result<Option<impl Iterator<Item = (SlotKey, SlotValue)>>> {
            Ok(Some(Self::iter_prefix(
                &self.committed().user,
                prefix,
                cursor,
            )))
        }

        fn maybe_iter_kernel_values_with_prefix(
            &self,
            prefix: SlotKey,
            cursor: Option<SlotKey>,
        ) -> anyhow::Result<Option<impl Iterator<Item = (SlotKey, SlotValue)>>> {
            Ok(Some(Self::iter_prefix(
                &self.committed().kernel,
                prefix,
                cursor,
            )))
        }
    }

    /// An API-like accessor: reads committed state and proves it (the role of
    /// `ApiStateAccessor`, Phase 13).
    pub(crate) struct ProvenTestAccessor(pub(crate) TestStorage);

    macro_rules! impl_proven {
        ($namespace:ty) => {
            impl StateReader<$namespace> for ProvenTestAccessor {
                type Error = Infallible;

                fn get(&mut self, key: &SlotKey) -> Result<Option<SlotValue>, Self::Error> {
                    Ok(self.0.get_unbound::<$namespace>(key.clone()))
                }
            }

            impl ProvenStateAccessor<$namespace> for ProvenTestAccessor {
                type Proof = super::NamespaceState;

                fn get_global_latest_with_proof(
                    &mut self,
                    key: SlotKey,
                ) -> Option<StorageProof<Self::Proof>> {
                    self.0
                        .get_with_proof::<$namespace>(key)
                        .ok()
                        .map(|(proof, _, _)| proof)
                }
            }
        };
    }

    impl_proven!(User);
    impl_proven!(Kernel);

    #[test]
    fn native_reads_and_versions() {
        use crate::{BorshCodec, KernelStateMap, Prefix, StateMap};

        let storage = TestStorage::default().commit_with(|state| {
            let mut map = StateMap::<u8, u8>::with_codec(Prefix::new(1, 1), BorshCodec);
            let Ok(()) = map.set(&1, &2, state);
            let mut kernel = KernelStateMap::<u8, u8>::with_codec(Prefix::new(1, 1), BorshCodec);
            let Ok(()) = kernel.set(&1, &3, state);
        });
        let key = SlotKey::from_parts(&Prefix::new(1, 1), &[1]);
        let witness = Default::default();
        assert_eq!(storage.latest_version(), SlotNumber::new(1));
        assert_eq!(storage.latest_version_unbound(), SlotNumber::new(1));
        assert_eq!(
            storage
                .get_historical::<User>(&key, Some(SlotNumber::new(1)), &witness)
                .unwrap(),
            Some(SlotValue::from(vec![2]))
        );
        assert!(
            storage
                .get_historical::<User>(&key, Some(SlotNumber::new(0)), &witness)
                .is_err()
        );
        assert_eq!(
            storage
                .get_leaf_historical::<Kernel>(&key, None, &witness)
                .unwrap()
                .map(|l| *l.leaf()),
            Some(NodeLeaf::make_leaf::<sha2::Sha256>(&SlotValue::from(vec![
                3
            ])))
        );
        assert_eq!(
            storage.get_root_hash(SlotNumber::new(1)),
            Some(storage.root())
        );
        assert_eq!(storage.get_root_hash(SlotNumber::new(2)), None);
        assert_eq!(storage.get_latest_root_hash(), Some(storage.root()));
        assert_eq!(storage.get_latest_root_hash_unbound(), Some(storage.root()));
        assert_eq!(storage.get_accessory_historical(&key, None).unwrap(), None);
        assert_eq!(storage.get_accessory_unbound(key, None).unwrap(), None);
        // Witness-free: native reads add no hints.
        assert!(crate::Witness::is_empty(&witness));
    }
}

//! The [`Storage`] interface state checkpoints read from and commit to, the leaves and proofs
//! storages work with, and the [`MerkleProofSpec`] choosing a hash function and witness.

use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::reexports::digest::Digest;
use selendra_interface::reexports::digest::consts::U32;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::cache::StateAccesses;
use crate::namespaces::{ProvableCompileTimeNamespace, ProvableNamespace};
use crate::witness::{ArrayWitness, Witness};
use crate::{SlotKey, SlotValue};

/// How much of a value a read loaded (see [`ProvableStorageCache`](crate::ProvableStorageCache)
/// for the size-then-value read protocol).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReadType {
    /// Only the leaf (size and hash) is known: the zk guest's answer to a size query.
    GetSizeValueNotFetched,
    /// A size query that loaded the full value (native): it is put in the witness only if the
    /// value is later read.
    GetSizeValueFetched(SlotValue),
    /// The value was read.
    Read(SlotValue),
}

/// The leaf of a value read from storage, and the value if it was loaded.
///
/// Not serialized: the leaf goes into witnesses as a bare [`NodeLeaf`] hint, never with a
/// `ReadType` tag the guest would have to check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeLeafAndMaybeValue {
    pub(crate) leaf: NodeLeaf,
    pub(crate) value: ReadType,
}

impl NodeLeafAndMaybeValue {
    /// The size of the value (from the leaf).
    pub fn size(&self) -> u32 {
        self.leaf.size
    }

    /// The leaf.
    pub fn leaf(&self) -> &NodeLeaf {
        &self.leaf
    }

    /// A value that was read in full.
    pub fn new_read<H: Digest<OutputSize = U32>>(value: SlotValue) -> Self {
        Self {
            leaf: NodeLeaf::make_leaf::<H>(&value),
            value: ReadType::Read(value),
        }
    }

    /// The answer of a native storage to a size query: the full value was loaded, and will be
    /// put in the witness if it is read later.
    pub fn with_fetched_value<H: Digest<OutputSize = U32>>(value: SlotValue) -> Self {
        Self {
            leaf: NodeLeaf::make_leaf::<H>(&value),
            value: ReadType::GetSizeValueFetched(value),
        }
    }

    /// The answer of a zk storage to a size query: only the leaf, taken from the witness. If
    /// the value is later read, it is checked against this leaf.
    pub fn without_value(leaf: NodeLeaf) -> Self {
        Self {
            leaf,
            value: ReadType::GetSizeValueNotFetched,
        }
    }
}

/// Size and hash of a value saved in the state.
///
/// borsh: `size` (u32 LE), then `val_hash` (32 bytes): 36 bytes, canonical. This is the
/// encoding of a leaf hint in a witness; the bytes a leaf commits to in the state tree are
/// [`NodeLeaf::combine_val_hash_and_size`] (hash first).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize)]
pub struct NodeLeaf {
    /// The size of the value ([`SlotValue::size`]).
    pub size: u32,
    /// The hash of the value.
    pub val_hash: [u8; 32],
}

impl NodeLeaf {
    /// The leaf of `value`: its size and `H(value)`.
    pub fn make_leaf<H: Digest<OutputSize = U32>>(value: &SlotValue) -> NodeLeaf {
        NodeLeaf {
            size: value.size(),
            val_hash: H::digest(value.value()).into(),
        }
    }

    /// The bytes the state tree commits to for this leaf: see [`val_hash_and_size`].
    pub fn combine_val_hash_and_size(&self) -> [u8; VAL_HASH_AND_SIZE_LEN] {
        val_hash_and_size(self.val_hash, self.size)
    }
}

impl SlotValue {
    /// The bytes the state tree commits to for this value: `H(value) ‖ size` (see
    /// [`val_hash_and_size`]).
    pub fn combine_val_hash_and_size<H: Digest<OutputSize = U32>>(
        &self,
    ) -> [u8; VAL_HASH_AND_SIZE_LEN] {
        NodeLeaf::make_leaf::<H>(self).combine_val_hash_and_size()
    }
}

/// The length of [`val_hash_and_size`]'s output.
pub const VAL_HASH_AND_SIZE_LEN: usize = 36;

/// Combines a value hash with the value's size: `val_hash (32 bytes) ‖ size (u32 LE, 4 bytes)`.
///
/// This is what a state-tree leaf commits to (NOMT hashes it again into the leaf's value
/// hash), so changing it changes every state root. Upstream returned a `Vec` (with a capacity
/// of 40 for 36 bytes); the layout is the same.
pub fn val_hash_and_size(val_hash: [u8; 32], size: u32) -> [u8; VAL_HASH_AND_SIZE_LEN] {
    let mut out = [0u8; VAL_HASH_AND_SIZE_LEN];
    let (hash, size_bytes) = out.split_at_mut(32);
    hash.copy_from_slice(&val_hash);
    size_bytes.copy_from_slice(&size.to_le_bytes());
    out
}

/// A proof that a particular storage key has a particular value, or is absent.
///
/// Verify it with [`Storage::open_proof`], or better with the container's `verify_proof`
/// (e.g. [`NamespacedStateMap::verify_proof`](crate::NamespacedStateMap::verify_proof)), which
/// also checks that the key belongs to that container.
///
/// borsh: the fields in order (`value` as a borsh `Option`, tag `0`/`1`). JSON: an object with
/// exactly these four fields (all required, `value` may be `null`); `key`/`value` are
/// `0x`-hex, `namespace` a string. Both are canonical if `P`'s encodings are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, BorshDeserialize, BorshSerialize)]
pub struct StorageProof<P> {
    /// The key which is proven.
    pub key: SlotKey,
    /// The value, if any, which is proven.
    pub value: Option<SlotValue>,
    /// The cryptographic proof.
    pub proof: P,
    /// The namespace of the key.
    pub namespace: ProvableNamespace,
}

impl<'de, P: Deserialize<'de>> Deserialize<'de> for StorageProof<P> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Deserializes a field that must be present (derived impls default a missing `Option`
        /// field to `None`, which would give `{"value":null}` a second encoding).
        fn required<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
            deserializer: D,
        ) -> Result<T, D::Error> {
            T::deserialize(deserializer)
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename = "StorageProof")]
        struct Helper<P> {
            key: SlotKey,
            #[serde(deserialize_with = "required")]
            value: Option<SlotValue>,
            proof: P,
            namespace: ProvableNamespace,
        }

        let Helper {
            key,
            value,
            proof,
            namespace,
        } = selendra_interface::common::deserialize_object_only(deserializer)?;
        Ok(Self {
            key,
            value,
            proof,
            namespace,
        })
    }
}

/// A trait implemented by state updates that can be committed to the database.
pub trait StateUpdate {
    /// Adds a non-provable ("accessory") state change to the state update after the rest of the
    /// update is finalized.
    fn add_accessory_item(&mut self, key: SlotKey, value: Option<SlotValue>);

    /// Adds a collection of non-provable ("accessory") state changes to the state update after
    /// the rest of the update is finalized.
    fn add_accessory_items(&mut self, items: Vec<(SlotKey, Option<SlotValue>)>) {
        for (key, value) in items {
            self.add_accessory_item(key, value);
        }
    }

    /// Returns an iterator over the accessory items modified by this state update.
    fn get_accessory_items(&self) -> impl Iterator<Item = &(SlotKey, Option<SlotValue>)>;
}

impl StateUpdate for () {
    fn add_accessory_item(&mut self, _key: SlotKey, _value: Option<SlotValue>) {
        // Silently discard the input. This is safe, since the accessory state is *not*
        // consensus critical. This implementation is intended for the zk guest only; native
        // storages must keep accessory items.
    }

    fn get_accessory_items(&self) -> impl Iterator<Item = &(SlotKey, Option<SlotValue>)> {
        std::iter::empty()
    }
}

/// A trait that represents the root hash of a state tree.
pub trait StateRoot:
    Serialize
    + DeserializeOwned
    + fmt::Debug
    + fmt::Display
    + Clone
    + BorshSerialize
    + BorshDeserialize
    + Eq
    + Send
    + Sync
    + AsRef<[u8]>
{
    /// Gets the global root hash of the storage, i.e. the root hash of the entire tree for all
    /// namespaces. We always require a one-way conversion from the state root to a 32-byte
    /// array. This can be implemented by hashing the state root even if the root itself is not
    /// 32 bytes.
    fn global_root(&self) -> [u8; 32];

    /// Gets the root hash of a specific namespace.
    fn namespace_root(&self, namespace: ProvableNamespace) -> [u8; 32];

    /// Builds a storage root from underlying namespace roots.
    fn from_namespace_roots(user_root: [u8; 32], kernel_root: [u8; 32]) -> Self;
}

/// An interface for retrieving values from the storage and producing the change set of new
/// write operations.
///
/// # The witness protocol
/// The same block is executed twice: natively, by a storage that holds the state (the
/// "prover" storage), and in the zk guest, by a storage that holds nothing but the previous
/// state root (the "verifier" storage). They must agree:
/// - every [`get_leaf`](Storage::get_leaf) and [`get`](Storage::get) of the native storage adds
///   exactly one hint to the witness, and the guest storage answers the same call by consuming
///   exactly one hint (ignoring the key: hints are positional);
/// - [`put_in_witness`](Storage::put_in_witness) is called by the cache when a value whose
///   leaf was fetched is later read in full. The native storage adds the value as a hint; the
///   guest storage does nothing, and its cache reads the hint with [`get`](Storage::get) and
///   checks it against the leaf;
/// - [`compute_state_update`](Storage::compute_state_update) may add (natively) and consume (in
///   the guest) further hints, e.g. a multi-proof.
///
/// Soundness rests on [`compute_state_update`](Storage::compute_state_update): the guest
/// storage **must** check every read in the [`StateAccesses`] against `prev_state_root` (and
/// fail otherwise), since until then each read is an unverified hint.
pub trait Storage: Clone + fmt::Debug {
    /// The hash function of the state tree.
    type Hasher: Digest<OutputSize = U32> + Send + Sync;

    /// The witness type for this storage instance.
    type Witness: Witness + Send + Sync + fmt::Debug;

    /// A cryptographic proof that a particular key has a particular value, or is absent.
    type Proof: Serialize
        + DeserializeOwned
        + fmt::Debug
        + Clone
        + BorshSerialize
        + BorshDeserialize
        + Send
        + Sync
        + PartialEq
        + Eq;

    /// A cryptographic commitment to the contents of this storage.
    type Root: StateRoot;

    /// State update that will be committed to the database.
    type StateUpdate: StateUpdate;

    /// Collection of all the writes that have been made on top of this instance of the
    /// storage.
    type ChangeSet: Send + Sync;

    /// The root hash of storage *before* genesis, when it's completely empty.
    const PRE_GENESIS_ROOT: Self::Root;

    /// Puts a value read in full after its leaf was fetched into the witness (native storages;
    /// a no-op in the guest). See the witness protocol above.
    fn put_in_witness(&self, value: Option<SlotValue>, witness: &Self::Witness);

    /// Gets the leaf of the value (its size and hash), without necessarily loading the value.
    fn get_leaf<N: ProvableCompileTimeNamespace>(
        &self,
        key: &SlotKey,
        witness: &Self::Witness,
    ) -> Option<NodeLeafAndMaybeValue>;

    /// Returns the value corresponding to the key or `None` if the key is absent.
    fn get<N: ProvableCompileTimeNamespace>(
        &self,
        key: &SlotKey,
        witness: &Self::Witness,
    ) -> Option<SlotValue>;

    /// Calculates the new state root but does not commit any changes to the database.
    ///
    /// # Errors
    /// If a read in `state_accesses` does not match the state under `prev_state_root` (in the
    /// guest: an invalid witness), or the storage fails or is stale.
    fn compute_state_update(
        &self,
        state_accesses: StateAccesses,
        witness: &Self::Witness,
        prev_state_root: Self::Root,
    ) -> anyhow::Result<(Self::Root, Self::StateUpdate)>;

    /// Materializes changes from the given [`Storage::StateUpdate`] into a
    /// [`Storage::ChangeSet`].
    fn materialize_changes(self, state_update: Self::StateUpdate) -> Self::ChangeSet;

    /// Opens a storage access proof and validates it against a state root. Returns the opened
    /// (key, value) pair on success.
    ///
    /// This only proves that the key has that value in the proof's namespace; it does not
    /// check which container the key belongs to (the containers' `verify_proof` do).
    fn open_proof(
        state_root: Self::Root,
        proof: StorageProof<Self::Proof>,
    ) -> anyhow::Result<(SlotKey, Option<SlotValue>)>;
}

#[cfg(feature = "native")]
pub use native::{NativeStorage, ProofOutput};

#[cfg(feature = "native")]
mod native {
    use selendra_interface::common::SlotNumber;

    use super::{NodeLeafAndMaybeValue, Storage, StorageProof};
    use crate::namespaces::{CompileTimeNamespace, ProvableCompileTimeNamespace};
    use crate::{SlotKey, SlotValue};

    /// A proof of a value, the slot number it was proven at and the root it was proven against.
    pub type ProofOutput<S> = (
        StorageProof<<S as Storage>::Proof>,
        SlotNumber,
        <S as Storage>::Root,
    );

    /// A [`Storage`] that is suitable for use in native execution environments (outside of the
    /// zkVM).
    ///
    /// Accessory state is read only here: the state transition function may write it but never
    /// read it (it is not provable, so the guest could not answer), which is why
    /// `get_accessory` lives here and not on [`Storage`] as upstream.
    ///
    /// Historical reads (`*_historical`, `*_unbound`) are node-side queries of past state:
    /// call them on the storage directly, with a throwaway witness, and never feed their
    /// results into a [`StateCheckpoint`](crate::StateCheckpoint) or its caches. A read
    /// recorded there becomes a first read that the state update verifies against the
    /// *previous* root, and serves every later read of the key in the block, so a value from
    /// another version would shadow current state natively (the guest reads the current value
    /// from the witness) or fail the state update. Upstream's cache `*_historical` methods,
    /// which did exactly that, were never called and are not ported.
    ///
    /// # Panics
    /// Methods that return a bare `Option` or value (`get_accessory`, `get_root_hash*`,
    /// `get_unbound`, `get_accessory_unbound`, `latest_version_unbound`, and [`Storage::get`] /
    /// [`Storage::get_leaf`]) and the iterators of `maybe_iter_*` panic if a database read fails,
    /// including a read of a pruned version: `None` means "absent", so an error cannot be
    /// returned as one. The methods returning `anyhow::Result` return such errors.
    ///
    /// # Locking (database-backed storages)
    /// A database commit waits for the readers of the same databases: drop the storage's
    /// iterators (and any database session) before committing on the same thread, and keep one
    /// live iterator per thread (a second one can wait behind a queued commit that waits for
    /// the first). [`get_with_proof`](Self::get_with_proof) may sleep and retry while a commit
    /// is in progress: call it from a blocking context in async code. Do not call it (or any
    /// method that opens a database session) on a thread that holds a live iterator while a
    /// storage manager may finalize on another: the finalization's commit waits for the
    /// iterator while holding a lock the session waits for. Collect the iterator first.
    pub trait NativeStorage: Storage {
        /// Gets the latest version available in the current instance storage.
        fn latest_version(&self) -> SlotNumber;

        /// Gets the latest version that can be committed from any other instance of the
        /// storage.
        fn latest_version_unbound(&self) -> SlotNumber;

        /// Returns the value corresponding to the key or `None` if the key is absent, at
        /// `version` (`None`: this storage's version).
        ///
        /// # Errors
        /// If `version` is after the newest version of this storage (a future version is an
        /// error, not "absent"; upstream returned `Ok(None)`), if it has been pruned, or if the
        /// read fails.
        fn get_historical<N: ProvableCompileTimeNamespace>(
            &self,
            key: &SlotKey,
            version: Option<SlotNumber>,
            witness: &Self::Witness,
        ) -> anyhow::Result<Option<SlotValue>>;

        /// Gets the leaf of the value at the given version. This method does not need to load
        /// the full value into memory.
        ///
        /// # Errors
        /// If `version` is after the newest version of this storage (a future version is an
        /// error, not "absent"; upstream returned `Ok(None)`), if it has been pruned, or if the
        /// read fails.
        fn get_leaf_historical<N: ProvableCompileTimeNamespace>(
            &self,
            key: &SlotKey,
            version: Option<SlotNumber>,
            witness: &Self::Witness,
        ) -> anyhow::Result<Option<NodeLeafAndMaybeValue>>;

        /// Returns the accessory value corresponding to the key or `None` if the key is absent.
        fn get_accessory(&self, key: &SlotKey) -> Option<SlotValue>;

        /// Gets the accessory value at the given version or `None` if the key is absent.
        ///
        /// # Errors
        /// If `version` is after the newest version of this storage (a future version is an
        /// error, not "absent"; upstream returned `Ok(None)`), if it has been pruned, or if the
        /// read fails.
        fn get_accessory_historical(
            &self,
            key: &SlotKey,
            version: Option<SlotNumber>,
        ) -> anyhow::Result<Option<SlotValue>>;

        /// Returns the value corresponding to the key or `None` if the key is absent, and a
        /// proof to get the value.
        ///
        /// The value may be of a newer version than this storage's (a storage that keeps no
        /// tree history, like the NOMT one, proves the newest state it sees: the newest
        /// committed state, or the newest of its own uncommitted blocks if a storage manager
        /// built it on some): the returned slot number and root say which version and root it is
        /// proven against.
        ///
        /// # Errors
        /// If storage is empty or the version is not yet available.
        fn get_with_proof<N: ProvableCompileTimeNamespace>(
            &self,
            key: SlotKey,
        ) -> anyhow::Result<ProofOutput<Self>>;

        /// Gets the root (both namespace roots) of the tree at the requested version.
        ///
        /// `version` is interpreted as a post-commit version: the returned root is the state
        /// *after* the X-th commit was applied. Returns `Some(root)` iff a root has been
        /// committed at `version`, else `None`.
        ///
        /// Note: [`Storage::PRE_GENESIS_ROOT`] is a separately-managed sentinel for "before any
        /// commits"; it is not retrievable through this method. Callers that want a pre-genesis
        /// fallback should use `.unwrap_or(Self::PRE_GENESIS_ROOT)`.
        fn get_root_hash(&self, version: SlotNumber) -> Option<Self::Root>;

        /// Gets the root (both namespace roots) of the tree at the requested version.
        ///
        /// The requested version is not checked against the latest version of this instance.
        /// Returns the root committed at the largest committed version `<= version`, or `None`
        /// if no version `<= version` has been committed or it has been pruned. In particular,
        /// requesting a version beyond the latest committed one yields the latest committed
        /// root, not `None`.
        fn get_root_hash_unbound(&self, version: SlotNumber) -> Option<Self::Root>;

        /// Gets the root hash at the latest version.
        fn get_latest_root_hash(&self) -> Option<Self::Root> {
            self.get_root_hash(self.latest_version())
        }

        /// Gets the root hash at the latest version (unbound).
        fn get_latest_root_hash_unbound(&self) -> Option<Self::Root> {
            self.get_root_hash_unbound(self.latest_version_unbound())
        }

        /// Gets the newest value for the given key, regardless of the version number associated
        /// with this storage: the newest committed one, or, for a storage on uncommitted blocks
        /// (built by a storage manager), the newest of those blocks' values newer than the
        /// committed state.
        fn get_unbound<N: CompileTimeNamespace>(&self, key: SlotKey) -> Option<SlotValue>;

        /// Gets the newest accessory value for the given key at or below `max_version` (`None`:
        /// any), regardless of the version number associated with this storage: committed, or,
        /// for a storage on uncommitted blocks (built by a storage manager), of those blocks.
        fn get_accessory_unbound(
            &self,
            key: SlotKey,
            max_version: Option<SlotNumber>,
        ) -> Option<SlotValue>;

        /// Iterates over the user key/value pairs of this storage's version (committed, or of
        /// its own uncommitted blocks if a storage manager built it on some) whose key starts
        /// with `prefix`, in ascending key order, starting at `cursor` (inclusive) if given.
        ///
        /// Returns `None` if the storage does not support iteration. Values written by an
        /// uncommitted [`StateCheckpoint`](crate::StateCheckpoint) are not seen.
        fn maybe_iter_user_values_with_prefix(
            &self,
            prefix: SlotKey,
            cursor: Option<SlotKey>,
        ) -> anyhow::Result<Option<impl Iterator<Item = (SlotKey, SlotValue)>>>;

        /// Like [`NativeStorage::maybe_iter_user_values_with_prefix`], for the kernel
        /// namespace.
        fn maybe_iter_kernel_values_with_prefix(
            &self,
            prefix: SlotKey,
            cursor: Option<SlotKey>,
        ) -> anyhow::Result<Option<impl Iterator<Item = (SlotKey, SlotValue)>>>;
    }
}

/// A trait specifying the hash function and format of the witness used in merkle proofs for
/// storage access.
pub trait MerkleProofSpec: Send + Sync {
    /// The structure that accumulates the witness data.
    type Witness: Witness + Send + Sync + fmt::Debug;
    /// The hash function used to compute the merkle root.
    type Hasher: Digest<OutputSize = U32> + Send + Sync;
}

/// The default [`MerkleProofSpec`]: an [`ArrayWitness`] and the hash function `H`.
///
/// This type is typically found as a type parameter for NOMT-backed storage.
pub struct DefaultStorageSpec<H> {
    _marker: core::marker::PhantomData<fn() -> H>,
}

impl<H> Clone for DefaultStorageSpec<H> {
    fn clone(&self) -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }
}

impl<H> fmt::Debug for DefaultStorageSpec<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DefaultStorageSpec")
    }
}

impl<H: Digest<OutputSize = U32> + Send + Sync> MerkleProofSpec for DefaultStorageSpec<H> {
    type Witness = ArrayWitness;
    type Hasher = H;
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::*;
    use crate::Prefix;

    #[test]
    fn val_hash_and_size_layout_is_pinned() {
        let hash = [7u8; 32];
        let combined = val_hash_and_size(hash, 0x0102_0304);
        assert_eq!(combined[..32], hash);
        assert_eq!(combined[32..], [4, 3, 2, 1]);

        let value = SlotValue::from(vec![1, 2, 3]);
        let leaf = NodeLeaf::make_leaf::<Sha256>(&value);
        assert_eq!(leaf.size, 3);
        assert_eq!(leaf.val_hash, <[u8; 32]>::from(Sha256::digest([1, 2, 3])));
        assert_eq!(
            value.combine_val_hash_and_size::<Sha256>(),
            leaf.combine_val_hash_and_size()
        );
        assert_eq!(
            hex_of(&value.combine_val_hash_and_size::<Sha256>()),
            "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb8103000000"
        );
    }

    fn hex_of(bytes: &[u8]) -> String {
        selendra_interface::common::HexString(bytes).to_string()[2..].to_string()
    }

    #[test]
    fn node_leaf_borsh_is_size_then_hash() {
        let leaf = NodeLeaf {
            size: 5,
            val_hash: [9; 32],
        };
        let bytes = borsh::to_vec(&leaf).unwrap();
        assert_eq!(bytes.len(), 36);
        assert_eq!(bytes[..4], [5, 0, 0, 0]);
        assert_eq!(bytes[4..], [9; 32]);
        assert_eq!(borsh::from_slice::<NodeLeaf>(&bytes).unwrap(), leaf);
        assert!(borsh::from_slice::<NodeLeaf>(&bytes[..35]).is_err());
        assert!(borsh::from_slice::<NodeLeaf>(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn leaf_constructors() {
        let value = SlotValue::from(vec![1]);
        let read = NodeLeafAndMaybeValue::new_read::<Sha256>(value.clone());
        let fetched = NodeLeafAndMaybeValue::with_fetched_value::<Sha256>(value.clone());
        assert_eq!(read.leaf(), fetched.leaf());
        assert_eq!(read.size(), 1);
        assert_eq!(read.value, ReadType::Read(value.clone()));
        assert_eq!(fetched.value, ReadType::GetSizeValueFetched(value));
        let bare = NodeLeafAndMaybeValue::without_value(*read.leaf());
        assert_eq!(bare.value, ReadType::GetSizeValueNotFetched);
        assert_eq!(bare.leaf(), read.leaf());
    }

    fn proof() -> StorageProof<Vec<u8>> {
        StorageProof {
            key: SlotKey::from_parts(&Prefix::new(1, 2), &[3]),
            value: Some(SlotValue::from(vec![0xab])),
            proof: vec![1, 2],
            namespace: ProvableNamespace::User,
        }
    }

    #[test]
    fn storage_proof_borsh_is_the_fields_in_order() {
        let proof = proof();
        let bytes = borsh::to_vec(&proof).unwrap();
        assert_eq!(
            bytes,
            [
                &[3, 0, 0, 0, 1, 2, 3][..], // key
                &[1, 1, 0, 0, 0, 0xab],     // value: Some, then the bytes
                &[2, 0, 0, 0, 1, 2],        // proof
                &[0],                       // namespace
            ]
            .concat()
        );
        assert_eq!(
            borsh::from_slice::<StorageProof<Vec<u8>>>(&bytes).unwrap(),
            proof
        );
        let mut bad_tag = bytes.clone();
        bad_tag[7] = 2;
        assert!(borsh::from_slice::<StorageProof<Vec<u8>>>(&bad_tag).is_err());
        let mut bad_ns = bytes.clone();
        *bad_ns.last_mut().unwrap() = 2;
        assert!(borsh::from_slice::<StorageProof<Vec<u8>>>(&bad_ns).is_err());
    }

    #[test]
    fn storage_proof_json_is_canonical() {
        let proof = proof();
        let json = serde_json::to_string(&proof).unwrap();
        assert_eq!(
            json,
            r#"{"key":"0x010203","value":"0xab","proof":[1,2],"namespace":"user"}"#
        );
        assert_eq!(
            serde_json::from_str::<StorageProof<Vec<u8>>>(&json).unwrap(),
            proof
        );
        let absent = StorageProof {
            value: None,
            ..proof.clone()
        };
        let json_absent = serde_json::to_string(&absent).unwrap();
        assert!(json_absent.contains(r#""value":null"#));
        assert_eq!(
            serde_json::from_str::<StorageProof<Vec<u8>>>(&json_absent).unwrap(),
            absent
        );
        for bad in [
            // missing `value` (derived serde would read it as `null`)
            r#"{"key":"0x010203","proof":[1,2],"namespace":"user"}"#,
            // unknown field
            r#"{"key":"0x010203","value":null,"proof":[1,2],"namespace":"user","x":1}"#,
            // array form
            r#"["0x010203",null,[1,2],"user"]"#,
            // non-canonical hex
            r#"{"key":"0x0102AB","value":null,"proof":[1,2],"namespace":"user"}"#,
            // too-short key
            r#"{"key":"0x01","value":null,"proof":[1,2],"namespace":"user"}"#,
        ] {
            assert!(
                serde_json::from_str::<StorageProof<Vec<u8>>>(bad).is_err(),
                "{bad}"
            );
        }
        let binary = postcard::to_allocvec(&proof).unwrap();
        assert_eq!(
            postcard::from_bytes::<StorageProof<Vec<u8>>>(&binary).unwrap(),
            proof
        );
    }

    #[test]
    fn unit_state_update_discards_accessory_items() {
        let mut update = ();
        update.add_accessory_items(vec![(
            SlotKey::singleton(&Prefix::new(1, 1)),
            Some(SlotValue::from(vec![1])),
        )]);
        assert_eq!(update.get_accessory_items().count(), 0);
    }

    #[test]
    fn default_storage_spec_is_clone_and_debug() {
        let spec = DefaultStorageSpec::<Sha256> {
            _marker: core::marker::PhantomData,
        };
        assert_eq!(format!("{:?}", spec.clone()), "DefaultStorageSpec");
        fn assert_spec<S: MerkleProofSpec<Witness = ArrayWitness, Hasher = Sha256>>() {}
        assert_spec::<DefaultStorageSpec<Sha256>>();
    }
}

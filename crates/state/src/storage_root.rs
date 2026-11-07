//! [`StorageRoot`]: the state root of the NOMT-backed storages, one tree root per provable
//! namespace.

use core::fmt;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use selendra_interface::common::{HexString, hex_string_serde};
use selendra_interface::reexports::digest::Digest;
use serde::{Deserialize, Serialize};

use crate::namespaces::ProvableNamespace;
use crate::storage::{MerkleProofSpec, StateRoot};

/// The domain tag of [`StorageRoot::global_root`]: `H(GLOBAL_ROOT_TAG ‖ user_root ‖ kernel_root)`.
///
/// Without a tag the preimage would be `user_root ‖ kernel_root`: 64 bytes, exactly the shape of
/// a NOMT internal node (`H(left ‖ right)`, MSB cleared). The global root would then be (up to
/// one bit) the root of a tree with the user tree on the left and the kernel tree on the right,
/// so a proof against that imaginary tree could be presented as a proof against the global root.
/// The tag makes the preimage 86 bytes and never a valid node preimage.
pub const GLOBAL_ROOT_TAG: &[u8] = b"SELENDRA/state-root/v1";

/// The combined root of the user and kernel state trees: the user root is the first 32 bytes,
/// the kernel root the last 32.
///
/// Both roots are kept (not just a hash of them) so that proofs can be checked against the
/// root of their own namespace. `S` chooses the hash of [`StateRoot::global_root`].
///
/// # Encodings
/// - borsh: the 64 bytes, raw (no length prefix). It is stored by the node and committed to in
///   proofs: changing it is a fork.
/// - serde: one `0x`-prefixed lowercase hex string of the 64 bytes in human-readable formats
///   (JSON; [`Display`](fmt::Display) prints the same), a sequence of 64 bytes in binary ones.
///   Decoding rejects anything else (wrong length, missing `0x`, uppercase).
pub struct StorageRoot<S> {
    root_hashes: [u8; 64],
    _spec: PhantomData<fn() -> S>,
}

impl<S> StorageRoot<S> {
    /// The root of an empty storage: both trees are empty (NOMT's
    /// [`TERMINATOR`](nomt_core::trie::TERMINATOR), 32 zero bytes, each).
    pub const PRE_GENESIS: Self =
        Self::new(nomt_core::trie::TERMINATOR, nomt_core::trie::TERMINATOR);

    /// Combines the roots of the user and kernel trees.
    pub const fn new(user_root: [u8; 32], kernel_root: [u8; 32]) -> Self {
        let mut root_hashes = [0u8; 64];
        let mut i = 0;
        // No `for` loops or `copy_from_slice` in a `const fn`.
        while i < 32 {
            root_hashes[i] = user_root[i];
            root_hashes[i + 32] = kernel_root[i];
            i += 1;
        }
        Self {
            root_hashes,
            _spec: PhantomData,
        }
    }

    /// The root of the user tree (the first 32 bytes).
    pub fn user_root(&self) -> [u8; 32] {
        let mut root = [0u8; 32];
        root.copy_from_slice(&self.root_hashes[..32]);
        root
    }

    /// The root of the kernel tree (the last 32 bytes).
    pub fn kernel_root(&self) -> [u8; 32] {
        let mut root = [0u8; 32];
        root.copy_from_slice(&self.root_hashes[32..]);
        root
    }
}

// Hand-written: derives would require `S: Clone` (etc.), but `S` is only a marker.
impl<S> Clone for StorageRoot<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for StorageRoot<S> {}

impl<S> PartialEq for StorageRoot<S> {
    fn eq(&self, other: &Self) -> bool {
        self.root_hashes == other.root_hashes
    }
}

impl<S> Eq for StorageRoot<S> {}

impl<S> Hash for StorageRoot<S> {
    fn hash<Hs: Hasher>(&self, state: &mut Hs) {
        self.root_hashes.hash(state);
    }
}

impl<S> fmt::Debug for StorageRoot<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StorageRoot({self})")
    }
}

impl<S> fmt::Display for StorageRoot<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&HexString(&self.root_hashes), f)
    }
}

impl<S> AsRef<[u8]> for StorageRoot<S> {
    fn as_ref(&self) -> &[u8] {
        &self.root_hashes
    }
}

impl<S> BorshSerialize for StorageRoot<S> {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // A `[u8; 64]` is borsh-encoded as its raw bytes.
        BorshSerialize::serialize(&self.root_hashes, writer)
    }
}

impl<S> BorshDeserialize for StorageRoot<S> {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let root_hashes = <[u8; 64]>::deserialize_reader(reader)?;
        Ok(Self {
            root_hashes,
            _spec: PhantomData,
        })
    }
}

impl<S> Serialize for StorageRoot<S> {
    fn serialize<Sr: serde::Serializer>(&self, serializer: Sr) -> Result<Sr::Ok, Sr::Error> {
        hex_string_serde::serialize(self.root_hashes, serializer)
    }
}

impl<'de, S> Deserialize<'de> for StorageRoot<S> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let root_hashes: [u8; 64] = hex_string_serde::deserialize(deserializer)?;
        Ok(Self {
            root_hashes,
            _spec: PhantomData,
        })
    }
}

impl<S: MerkleProofSpec> StateRoot for StorageRoot<S> {
    /// `S::Hasher(GLOBAL_ROOT_TAG ‖ user_root ‖ kernel_root)` (see [`GLOBAL_ROOT_TAG`] for why
    /// the tag; upstream hashed `user_root ‖ kernel_root`).
    fn global_root(&self) -> [u8; 32] {
        let mut hasher = <S::Hasher as Digest>::new();
        Digest::update(&mut hasher, GLOBAL_ROOT_TAG);
        Digest::update(&mut hasher, self.root_hashes);
        Digest::finalize(hasher).into()
    }

    fn namespace_root(&self, namespace: ProvableNamespace) -> [u8; 32] {
        match namespace {
            ProvableNamespace::User => self.user_root(),
            ProvableNamespace::Kernel => self.kernel_root(),
        }
    }

    fn from_namespace_roots(user_root: [u8; 32], kernel_root: [u8; 32]) -> Self {
        Self::new(user_root, kernel_root)
    }
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::*;
    use crate::DefaultStorageSpec;

    type Root = StorageRoot<DefaultStorageSpec<Sha256>>;

    fn root() -> Root {
        let mut user = [0u8; 32];
        let mut kernel = [0u8; 32];
        for i in 0..32u8 {
            user[usize::from(i)] = i;
            kernel[usize::from(i)] = 0xff - i;
        }
        Root::new(user, kernel)
    }

    #[test]
    fn layout_is_user_then_kernel() {
        let root = root();
        assert_eq!(root.as_ref()[..32], root.user_root());
        assert_eq!(root.as_ref()[32..], root.kernel_root());
        assert_eq!(
            root.namespace_root(ProvableNamespace::User),
            root.user_root()
        );
        assert_eq!(
            root.namespace_root(ProvableNamespace::Kernel),
            root.kernel_root()
        );
        assert_eq!(
            Root::from_namespace_roots(root.user_root(), root.kernel_root()),
            root
        );
        assert_eq!(Root::PRE_GENESIS.as_ref(), [0u8; 64]);
        assert_ne!(Root::new([1; 32], [2; 32]), Root::new([2; 32], [1; 32]));
    }

    #[test]
    fn borsh_is_the_64_raw_bytes() {
        let root = root();
        let bytes = borsh::to_vec(&root).unwrap();
        assert_eq!(bytes, root.as_ref());
        assert_eq!(borsh::from_slice::<Root>(&bytes).unwrap(), root);
        assert!(borsh::from_slice::<Root>(&bytes[..63]).is_err());
        assert!(borsh::from_slice::<Root>(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn json_is_one_canonical_hex_string() {
        let root = Root::new([0xab; 32], [0x01; 32]);
        let hex = format!("0x{}{}", "ab".repeat(32), "01".repeat(32));
        let json = serde_json::to_string(&root).unwrap();
        assert_eq!(json, format!("\"{hex}\""));
        assert_eq!(root.to_string(), hex);
        assert_eq!(format!("{root:?}"), format!("StorageRoot({hex})"));
        assert_eq!(serde_json::from_str::<Root>(&json).unwrap(), root);
        for bad in [
            format!("\"{}\"", &hex[2..]),             // no 0x
            format!("\"{}\"", hex.to_uppercase()),    // uppercase
            format!("\"0x{}\"", "AB".repeat(64)),     // uppercase digits
            format!("\"{}\"", &hex[..hex.len() - 2]), // 63 bytes
            format!("\"{hex}00\""),                   // 65 bytes
            format!("\"{}\"", &hex[..hex.len() - 1]), // odd length
            format!("[{}]", vec!["1"; 64].join(",")), // array form
            format!("{{\"root_hashes\":\"{hex}\"}}"), // object form
        ] {
            assert!(serde_json::from_str::<Root>(&bad).is_err(), "{bad}");
        }
        let binary = postcard::to_allocvec(&root).unwrap();
        assert_eq!(postcard::from_bytes::<Root>(&binary).unwrap(), root);
    }

    /// The global root is a consensus value (it is what the zk proof commits to): pinned.
    #[test]
    fn global_root_is_tagged_sha256() {
        let root = root();
        let expected: [u8; 32] = Sha256::new()
            .chain_update(b"SELENDRA/state-root/v1")
            .chain_update(root.user_root())
            .chain_update(root.kernel_root())
            .finalize()
            .into();
        assert_eq!(root.global_root(), expected);
        assert_eq!(
            HexString(root.global_root()).to_string(),
            "0x697fb886d1c66617a505f81bae534aec2def0e3efd472c93ba95a044098da5ac"
        );
        // Not upstream's untagged `H(user ‖ kernel)`.
        let untagged: [u8; 32] = Sha256::digest(root.as_ref()).into();
        assert_ne!(root.global_root(), untagged);
        assert_eq!(
            HexString(Root::PRE_GENESIS.global_root()).to_string(),
            "0xf47d4e573e5b2d5c704dab9cf25e6e17c14c3675344d4cb0240709bb8c568ad2"
        );
    }

    #[test]
    fn traits_need_no_bounds_on_the_spec() {
        struct NotClone;
        let a = StorageRoot::<NotClone>::new([1; 32], [2; 32]);
        let b = a;
        assert_eq!(a, b);
        let mut set = std::collections::HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }
}

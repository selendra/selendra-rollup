//! [`NomtProof`]: a NOMT multi-proof with one accepted encoding, which nomt-core can verify
//! without panicking.

use std::io::Read;

use borsh::{BorshDeserialize, BorshSerialize};
use nomt_core::proof::{MultiPathProof, MultiProof, PathProof, PathProofTerminal};
use nomt_core::trie_pos::TriePosition;
use selendra_interface::common::HexString;
use serde::{Deserialize, Serialize};

/// The deepest a terminal can be: key paths are 256 bits.
const MAX_DEPTH: usize = 256;

/// Why a [`MultiProof`] is not a valid [`NomtProof`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidNomtProof {
    /// A terminator position is deeper than 256 bits.
    #[error("path {index}: terminator depth {depth} exceeds 256")]
    TerminatorTooDeep {
        /// The index of the path in the proof.
        index: usize,
        /// The depth of the terminator position.
        depth: u16,
    },
    /// A terminator position is not in its canonical form: bits past its depth set, or a
    /// `node_index` that does not match its path.
    #[error("path {index}: non-canonical terminator position")]
    NonCanonicalTerminator {
        /// The index of the path in the proof.
        index: usize,
    },
    /// A path's depth is not where its terminal can be.
    #[error("path {index}: depth {depth} is out of range")]
    DepthOutOfRange {
        /// The index of the path in the proof.
        index: usize,
        /// The claimed depth.
        depth: usize,
    },
    /// The terminal paths are not strictly ascending.
    #[error("path {index} is not after the previous path")]
    PathsNotAscending {
        /// The index of the first path out of order.
        index: usize,
    },
    /// One terminal path is a prefix of the next one (one terminal would sit inside the other's
    /// sub-trie).
    #[error("the path before path {index} is a prefix of it")]
    PathIsPrefix {
        /// The index of the longer path.
        index: usize,
    },
    /// The number of siblings is not the number the proof's paths need.
    #[error("{actual} siblings, but the paths need {expected}")]
    SiblingCount {
        /// The number the paths need.
        expected: usize,
        /// The number in the proof.
        actual: usize,
    },
    /// The bytes decoded but are not the canonical encoding of the decoded proof.
    #[error("non-canonical encoding")]
    NonCanonicalEncoding,
    /// A path proof given to [`NomtProof::from_path_proofs`] has a number of siblings its
    /// terminal cannot have: fewer than one past the bits it shares with a neighbouring path
    /// proof, more than 256, or (for a terminator) other than the terminator's depth.
    #[error(
        "path proof {index} (in sorted order): {siblings} siblings, but it needs {min}..={max}"
    )]
    PathProofSiblings {
        /// The index of the path proof, in terminal path order.
        index: usize,
        /// The number of siblings it has.
        siblings: usize,
        /// The fewest it can have.
        min: usize,
        /// The most it can have.
        max: usize,
    },
}

/// A NOMT [`MultiProof`] that is well-formed: the [`Storage::Proof`](crate::Storage::Proof) of
/// the NOMT storages and their multi-proof witness hint.
///
/// nomt-core's `MultiProof` is malleable and trusts its input: a `TriePosition` compares and
/// verifies only its first `depth` bits, so the bits past them and its `node_index` can take any
/// value (many encodings of one proof), and verification indexes and slices by the proof's
/// depths and sibling count unchecked (it panics on a depth over 256, too few siblings, a depth
/// shallower than the paths need, or one path a prefix of another). A `NomtProof` can only be
/// built from a proof that passes these checks:
/// - every terminator position is at most 256 bits deep and canonical: the bits past its depth
///   are zero and its `node_index` is the one derived from its path (it equals
///   `TriePosition::from_path_and_depth` of its masked path, or the root position at depth 0),
///   and its depth is the path's depth;
/// - the terminal paths are strictly ascending, and none is a prefix of the next one;
/// - each path's depth is where verification can place its terminal, and the number of
///   siblings is exactly what verification consumes (computed by a hash-free walk of
///   nomt-core's `verify_range` bisection).
///
/// Then nomt-core's `verify_multi_proof` and `verify_multi_proof_update` do not panic on it.
/// Being well-formed says nothing about the proof's validity: verify it against a root.
///
/// # Encodings
/// - borsh: nomt-core's borsh encoding of the `MultiProof`. Decoding checks the above and that
///   the input is the canonical encoding of the result, so each proof has one encoding.
/// - serde: the borsh bytes as one `0x`-prefixed lowercase hex string in human-readable formats
///   (JSON), a byte sequence in binary ones. nomt-core's derived serde form (an object of
///   number arrays) is not used: it accepts unknown fields and the array form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NomtProof(MultiProof);

impl NomtProof {
    /// Checks that `proof` is well-formed (see the type docs).
    ///
    /// # Errors
    /// If it is not.
    pub fn new(proof: MultiProof) -> Result<Self, InvalidNomtProof> {
        validate(&proof)?;
        Ok(Self(proof))
    }

    /// Builds the multi-proof of NOMT path proofs (e.g. those of a NOMT session's witness).
    ///
    /// The path proofs are sorted by terminal path first (`MultiProof::from_path_proofs` needs
    /// them sorted, which a NOMT witness does not guarantee: nomt issue #904), and terminator
    /// positions are put in canonical form (verification ignores the bits this changes).
    ///
    /// Never panics: the path proofs are checked before nomt-core's `from_path_proofs` (which
    /// indexes them unchecked) sees them.
    ///
    /// # Errors
    /// If two path proofs have the same terminal path or one is a prefix of another, if a path
    /// proof's sibling count does not fit its terminal ([`InvalidNomtProof::PathProofSiblings`]:
    /// too few for the path it shares with a neighbour, more than 256, or a terminator's count
    /// other than its depth), or if the resulting multi-proof is not well-formed. A NOMT witness
    /// never has such path proofs.
    pub fn from_path_proofs(mut path_proofs: Vec<PathProof>) -> Result<Self, InvalidNomtProof> {
        for (index, path_proof) in path_proofs.iter_mut().enumerate() {
            if let PathProofTerminal::Terminator(position) = &mut path_proof.terminal {
                // First: `path()` (sorting below) panics on a position deeper than 256 bits.
                check_terminator_depth(index, position)?;
                *position = canonical_position(position.raw_path(), position.depth());
            }
        }
        path_proofs.sort_by(|a, b| a.terminal.path().cmp(b.terminal.path()));
        check_path_proofs(&path_proofs)?;
        Self::new(MultiProof::from_path_proofs(path_proofs))
    }

    /// The multi-proof.
    pub fn inner(&self) -> &MultiProof {
        &self.0
    }

    /// The multi-proof.
    pub fn into_inner(self) -> MultiProof {
        self.0
    }
}

impl AsRef<MultiProof> for NomtProof {
    fn as_ref(&self) -> &MultiProof {
        &self.0
    }
}

impl TryFrom<MultiProof> for NomtProof {
    type Error = InvalidNomtProof;

    fn try_from(proof: MultiProof) -> Result<Self, Self::Error> {
        Self::new(proof)
    }
}

impl From<NomtProof> for MultiProof {
    fn from(proof: NomtProof) -> Self {
        proof.0
    }
}

fn check_terminator_depth(index: usize, position: &TriePosition) -> Result<(), InvalidNomtProof> {
    if usize::from(position.depth()) > MAX_DEPTH {
        return Err(InvalidNomtProof::TerminatorTooDeep {
            index,
            depth: position.depth(),
        });
    }
    Ok(())
}

/// The canonical position at `depth` (at most 256) on `path`: the bits past `depth` cleared and
/// `node_index` derived from the path.
fn canonical_position(mut path: [u8; 32], depth: u16) -> TriePosition {
    let depth_bits = usize::from(depth);
    for (i, byte) in path.iter_mut().enumerate() {
        let start = i * 8;
        if start >= depth_bits {
            *byte = 0;
        } else if start + 8 > depth_bits {
            // Keep the first `depth_bits - start` (1..=7) bits (most significant first).
            *byte &= 0xffu8 << (8 - (depth_bits - start));
        }
    }
    if depth == 0 {
        // `from_path_and_depth` panics on depth 0: the root position.
        TriePosition::new()
    } else {
        TriePosition::from_path_and_depth(path, depth)
    }
}

/// The order of two adjacent terminals: strictly ascending, and the first not a prefix of the
/// second. `index` is the second one's.
fn check_order(
    index: usize,
    prev: &PathProofTerminal,
    next: &PathProofTerminal,
) -> Result<(), InvalidNomtProof> {
    let (prev, next) = (prev.path(), next.path());
    // A prefix sorts first, so ascending order alone allows it.
    if next <= prev {
        return Err(InvalidNomtProof::PathsNotAscending { index });
    }
    if next.starts_with(prev) {
        return Err(InvalidNomtProof::PathIsPrefix { index });
    }
    Ok(())
}

/// The number of leading bits two terminal paths share.
fn shared_bits(a: &PathProofTerminal, b: &PathProofTerminal) -> usize {
    a.path()
        .iter()
        .by_vals()
        .zip(b.path().iter().by_vals())
        .take_while(|(a, b)| a == b)
        .count()
}

/// Checks sorted path proofs (terminator depths already checked) so that nomt-core's
/// `MultiProof::from_path_proofs` cannot panic on them:
/// - it bisects on the first bit where the first and last proofs of a range differ, and indexes
///   every proof's path at that bit: the paths must be strictly ascending and prefix-free (as in
///   [`validate`]), so that bit exists in each;
/// - while all proofs of a range share a bit `b`, it takes the first proof's sibling `b`: a proof
///   sharing `n` bits with its successor needs at least `n` siblings. A proof's own remainder
///   starts one past its deepest split from a neighbour, so a proof with fewer siblings than
///   that would get a depth too shallow for its terminal: at least `n + 1`, with `n` the most
///   bits it shares with either neighbour (a lone proof: 0);
/// - a terminal is at most 256 bits deep, and a terminator is at its depth (one sibling per
///   bit above it).
fn check_path_proofs(path_proofs: &[PathProof]) -> Result<(), InvalidNomtProof> {
    for (index, pair) in path_proofs.windows(2).enumerate() {
        check_order(index + 1, &pair[0].terminal, &pair[1].terminal)?;
    }
    for (index, proof) in path_proofs.iter().enumerate() {
        let shared_with = |other: Option<&PathProof>| {
            other.map_or(0, |other| shared_bits(&proof.terminal, &other.terminal) + 1)
        };
        let prev = index.checked_sub(1).and_then(|i| path_proofs.get(i));
        let min = shared_with(prev).max(shared_with(path_proofs.get(index + 1)));
        let (min, max) = match &proof.terminal {
            PathProofTerminal::Leaf(_) => (min, MAX_DEPTH),
            PathProofTerminal::Terminator(position) => {
                let depth = usize::from(position.depth());
                (min.max(depth), depth)
            }
        };
        let siblings = proof.siblings.len();
        if !(min..=max).contains(&siblings) {
            return Err(InvalidNomtProof::PathProofSiblings {
                index,
                siblings,
                min,
                max,
            });
        }
    }
    Ok(())
}

/// The checks of [`NomtProof`] (see its docs). Never panics.
fn validate(proof: &MultiProof) -> Result<(), InvalidNomtProof> {
    let paths = &proof.paths;
    // First, so that `path()` (which slices by the position's depth) cannot panic below.
    for (index, path) in paths.iter().enumerate() {
        if let PathProofTerminal::Terminator(position) = &path.terminal {
            check_terminator_depth(index, position)?;
            let canonical = canonical_position(position.raw_path(), position.depth());
            // `TriePosition`'s `PartialEq` ignores the bits past `depth` and `node_index`:
            // compare the encodings (which cover every field).
            if borsh::to_vec(position).ok() != borsh::to_vec(&canonical).ok()
                || usize::from(position.depth()) != path.depth
            {
                return Err(InvalidNomtProof::NonCanonicalTerminator { index });
            }
        }
    }
    for (index, pair) in paths.windows(2).enumerate() {
        check_order(index + 1, &pair[0].terminal, &pair[1].terminal)?;
    }
    // In sorted order, the paths that start with a given prefix are contiguous: no path being a
    // prefix of the next one means no path is a prefix of any other.
    let expected = if paths.is_empty() {
        0
    } else {
        siblings_needed(0, 0, paths)?
    };
    if proof.siblings.len() != expected {
        return Err(InvalidNomtProof::SiblingCount {
            expected,
            actual: proof.siblings.len(),
        });
    }
    Ok(())
}

/// The number of siblings nomt-core's `verify_range(start_depth, paths, ..)` consumes, by the
/// same recursion without hashing, checking every bound it indexes or slices by. `paths` (at
/// `offset` in the proof) is non-empty, strictly ascending and prefix-free.
///
/// Recursion depth: each bisection is one bit deeper than its parent, so at most 257 levels.
fn siblings_needed(
    start_depth: usize,
    offset: usize,
    paths: &[MultiPathProof],
) -> Result<usize, InvalidNomtProof> {
    let (first, last) = match paths {
        [] => return unreachable_shape(offset, start_depth),
        [single] => {
            // `verify_range` takes `depth - start_depth` siblings and slices the terminal's path
            // at `start_depth..depth`.
            let depth = single.depth;
            return if (start_depth..=single.terminal.path().len()).contains(&depth) {
                Ok(depth - start_depth)
            } else {
                Err(InvalidNomtProof::DepthOutOfRange {
                    index: offset,
                    depth,
                })
            };
        }
        [first, .., last] => (first.terminal.path(), last.terminal.path()),
    };
    let (Some(first_rest), Some(last_rest)) = (first.get(start_depth..), last.get(start_depth..))
    else {
        return unreachable_shape(offset, start_depth);
    };
    let common_bits = first_rest
        .iter()
        .by_vals()
        .zip(last_rest.iter().by_vals())
        .take_while(|(a, b)| a == b)
        .count();
    // The bit the paths are bisected on. It exists in the first and last path (they are
    // distinct and neither is a prefix of the other), hence in every path between them, and is
    // `0` in the first and `1` in the last.
    let bisect_bit = start_depth + common_bits;
    if bisect_bit >= first.len() || bisect_bit >= last.len() {
        return unreachable_shape(offset, start_depth);
    }
    let mid = paths.partition_point(|path| {
        path.terminal
            .path()
            .get(bisect_bit)
            .is_some_and(|bit| !*bit)
    });
    if mid == 0 || mid == paths.len() {
        return unreachable_shape(offset, start_depth);
    }
    let left = siblings_needed(bisect_bit + 1, offset, &paths[..mid])?;
    let right = siblings_needed(bisect_bit + 1, offset + mid, &paths[mid..])?;
    common_bits
        .checked_add(left)
        .and_then(|n| n.checked_add(right))
        .ok_or(InvalidNomtProof::SiblingCount {
            expected: usize::MAX,
            actual: 0,
        })
}

/// A range shape that sorted, prefix-free paths cannot have. Reported as a depth error rather
/// than asserted, so that validation can never panic.
fn unreachable_shape<T>(offset: usize, start_depth: usize) -> Result<T, InvalidNomtProof> {
    Err(InvalidNomtProof::DepthOutOfRange {
        index: offset,
        depth: start_depth,
    })
}

impl BorshSerialize for NomtProof {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0, writer)
    }
}

impl BorshDeserialize for NomtProof {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut recording = Recording {
            inner: reader,
            read: Vec::new(),
        };
        let proof = MultiProof::deserialize_reader(&mut recording)?;
        let invalid =
            |err: InvalidNomtProof| std::io::Error::new(std::io::ErrorKind::InvalidData, err);
        let proof = Self::new(proof).map_err(invalid)?;
        // borsh reads exactly the bytes it decodes, so `read` is the input of this proof.
        if borsh::to_vec(&proof)? != recording.read {
            return Err(invalid(InvalidNomtProof::NonCanonicalEncoding));
        }
        Ok(proof)
    }
}

/// A reader that keeps a copy of what was read.
struct Recording<'a, R> {
    inner: &'a mut R,
    read: Vec<u8>,
}

impl<R: Read> Read for Recording<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read.extend_from_slice(buf.get(..n).unwrap_or(buf));
        Ok(n)
    }
}

impl Serialize for NomtProof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = borsh::to_vec(self).map_err(serde::ser::Error::custom)?;
        Serialize::serialize(&HexString(bytes), serializer)
    }
}

impl<'de> Deserialize<'de> for NomtProof {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let HexString(bytes) = <HexString<Vec<u8>> as Deserialize>::deserialize(deserializer)?;
        borsh::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use nomt_core::hasher::NodeHasher;
    use nomt_core::proof::{MultiPathProof, PathProofTerminal, verify_multi_proof};
    use nomt_core::trie::{InternalData, LeafData, Node, TERMINATOR};
    use proptest::prelude::*;
    use sha2::Sha256;

    use super::*;

    pub(crate) type Hasher = nomt_core::hasher::BinaryHasher<Sha256>;

    pub(crate) fn leaf(key_path: [u8; 32], value_hash: [u8; 32]) -> PathProofTerminal {
        PathProofTerminal::Leaf(LeafData {
            key_path,
            value_hash,
        })
    }

    /// A key path starting with the bits `prefix` (MSB first), then `fill`.
    pub(crate) fn path_with(prefix: &[bool], fill: u8) -> [u8; 32] {
        let mut path = [fill; 32];
        for (i, bit) in prefix.iter().enumerate() {
            let mask = 0x80u8 >> (i % 8);
            if *bit {
                path[i / 8] |= mask;
            } else {
                path[i / 8] &= !mask;
            }
        }
        path
    }

    fn terminator(prefix: &[bool]) -> PathProofTerminal {
        let depth = u16::try_from(prefix.len()).unwrap();
        PathProofTerminal::Terminator(canonical_position(path_with(prefix, 0), depth))
    }

    fn multi(terminal: PathProofTerminal, depth: usize) -> MultiPathProof {
        MultiPathProof { terminal, depth }
    }

    /// A proof of a trie with a leaf under `0`, a terminator at `10` and a leaf at `11`:
    /// `root = H(leaf0, H(TERMINATOR, leaf11))`. No siblings are needed.
    pub(crate) fn three_terminal_proof() -> MultiProof {
        MultiProof {
            paths: vec![
                multi(leaf(path_with(&[false], 0x11), [1; 32]), 1),
                multi(terminator(&[true, false]), 2),
                multi(leaf(path_with(&[true, true], 0x22), [2; 32]), 2),
            ],
            siblings: vec![],
        }
    }

    /// The root `proof` proves (a test-only mirror of nomt-core's `verify_range` with hashing),
    /// so that verification of an arbitrary well-formed proof can be driven past the root check.
    pub(crate) fn implied_root(proof: &MultiProof) -> Node {
        fn hash_up(mut node: Node, bits: &[bool], siblings: &[Node]) -> Node {
            // Siblings are top-down; hash bottom-up.
            for (bit, sibling) in bits.iter().rev().zip(siblings.iter().rev()) {
                let data = if *bit {
                    InternalData {
                        left: *sibling,
                        right: node,
                    }
                } else {
                    InternalData {
                        left: node,
                        right: *sibling,
                    }
                };
                node = Hasher::hash_internal(&data);
            }
            node
        }
        fn bits(terminal: &PathProofTerminal) -> Vec<bool> {
            terminal.path().iter().by_vals().collect()
        }
        fn range(start: usize, paths: &[MultiPathProof], siblings: &[Node]) -> (Node, usize) {
            if paths.len() == 1 {
                let path = &paths[0];
                let n = path.depth - start;
                let node = path.terminal.node::<Hasher>();
                return (
                    hash_up(
                        node,
                        &bits(&path.terminal)[start..path.depth],
                        &siblings[..n],
                    ),
                    n,
                );
            }
            let (first, last) = (
                bits(&paths[0].terminal),
                bits(&paths[paths.len() - 1].terminal),
            );
            let common = first[start..]
                .iter()
                .zip(&last[start..])
                .take_while(|(a, b)| a == b)
                .count();
            let bisect = start + common;
            let mid = paths.partition_point(|p| !bits(&p.terminal)[bisect]);
            let (left, l) = range(bisect + 1, &paths[..mid], &siblings[common..]);
            let (right, r) = range(bisect + 1, &paths[mid..], &siblings[common + l..]);
            let node = Hasher::hash_internal(&InternalData { left, right });
            (
                hash_up(node, &first[start..bisect], &siblings[..common]),
                common + l + r,
            )
        }
        if proof.paths.is_empty() {
            return TERMINATOR;
        }
        range(0, &proof.paths, &proof.siblings).0
    }

    fn bytes(proof: &MultiProof) -> Vec<u8> {
        borsh::to_vec(proof).unwrap()
    }

    fn decode(bytes: &[u8]) -> Result<NomtProof, String> {
        borsh::from_slice::<NomtProof>(bytes).map_err(|e| e.to_string())
    }

    #[test]
    fn a_well_formed_proof_roundtrips_and_verifies() {
        let proof = three_terminal_proof();
        let nomt = NomtProof::new(proof.clone()).unwrap();
        let encoded = bytes(&proof);
        assert_eq!(borsh::to_vec(&nomt).unwrap(), encoded);
        assert_eq!(decode(&encoded).unwrap(), nomt);
        let root = implied_root(&proof);
        assert!(verify_multi_proof::<Hasher>(&proof, root).is_ok());
        // JSON: the borsh bytes as hex.
        let json = serde_json::to_string(&nomt).unwrap();
        assert_eq!(json, format!("\"{}\"", HexString(&encoded)));
        assert_eq!(serde_json::from_str::<NomtProof>(&json).unwrap(), nomt);
        assert!(serde_json::from_str::<NomtProof>(&json.to_uppercase()).is_err());
        assert!(serde_json::from_str::<NomtProof>(&json.replace("0x", "")).is_err());
        let binary = postcard::to_allocvec(&nomt).unwrap();
        assert_eq!(postcard::from_bytes::<NomtProof>(&binary).unwrap(), nomt);
        // Trailing bytes are rejected.
        assert!(decode(&[encoded.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn the_empty_proof_proves_the_empty_trie() {
        let proof = MultiProof {
            paths: vec![],
            siblings: vec![],
        };
        let nomt = NomtProof::new(proof.clone()).unwrap();
        assert_eq!(decode(&bytes(&proof)).unwrap(), nomt);
        assert!(verify_multi_proof::<Hasher>(&proof, TERMINATOR).is_ok());
        // A root terminator (what NOMT proves keys of an empty trie with).
        let root_terminator = MultiProof {
            paths: vec![multi(PathProofTerminal::Terminator(TriePosition::new()), 0)],
            siblings: vec![],
        };
        NomtProof::new(root_terminator.clone()).unwrap();
        assert!(verify_multi_proof::<Hasher>(&root_terminator, TERMINATOR).is_ok());
        // Siblings without paths.
        let extra = MultiProof {
            paths: vec![],
            siblings: vec![[1; 32]],
        };
        assert_eq!(
            NomtProof::new(extra),
            Err(InvalidNomtProof::SiblingCount {
                expected: 0,
                actual: 1
            })
        );
    }

    /// Byte offset of the first terminator position's fields in `three_terminal_proof`'s
    /// encoding: paths length (4) | path 0: tag (1) + leaf (64) + depth (8) | path 1: tag (1).
    const TERMINATOR_AT: usize = 4 + 1 + 64 + 8 + 1;

    #[test]
    fn a_non_canonical_terminator_is_rejected() {
        let encoded = bytes(&three_terminal_proof());
        // The position is the canonical `10` at depth 2: path, then depth (u16), node_index (u64).
        assert_eq!(encoded[TERMINATOR_AT], 0b1000_0000);
        assert_eq!(encoded[TERMINATOR_AT + 32..TERMINATOR_AT + 34], [2, 0]);
        // A bit past the depth: the same proof to nomt-core (`PartialEq` too), another encoding.
        let mut tail_bit = encoded.clone();
        tail_bit[TERMINATOR_AT] |= 0b0010_0000;
        let decoded: MultiProof = borsh::from_slice(&tail_bit).unwrap();
        assert_eq!(decoded, three_terminal_proof());
        assert!(verify_multi_proof::<Hasher>(&decoded, implied_root(&decoded)).is_ok());
        assert!(
            decode(&tail_bit)
                .unwrap_err()
                .contains("non-canonical terminator")
        );
        assert_eq!(
            NomtProof::new(decoded),
            Err(InvalidNomtProof::NonCanonicalTerminator { index: 1 })
        );
        // A last-byte bit, and a wrong `node_index`.
        let mut last_bit = encoded.clone();
        last_bit[TERMINATOR_AT + 31] |= 1;
        assert!(decode(&last_bit).is_err());
        let mut node_index = encoded.clone();
        node_index[TERMINATOR_AT + 34] ^= 1;
        assert!(decode(&node_index).is_err());
        // A terminator depth that differs from its path's depth.
        let mut proof = three_terminal_proof();
        proof.paths[1].terminal = terminator(&[true, false, false]);
        assert_eq!(
            NomtProof::new(proof),
            Err(InvalidNomtProof::NonCanonicalTerminator { index: 1 })
        );
    }

    /// A position decoded from its fields (the constructors only build canonical ones).
    fn raw_position(path: [u8; 32], depth: u16, node_index: u64) -> TriePosition {
        borsh::from_slice(&[&path[..], &depth.to_le_bytes(), &node_index.to_le_bytes()].concat())
            .unwrap()
    }

    #[test]
    fn from_path_proofs_sorts_and_canonicalizes() {
        let proof = three_terminal_proof();
        let root = implied_root(&proof);
        let node = |i: usize| proof.paths[i].terminal.node::<Hasher>();
        let right = Hasher::hash_internal(&InternalData {
            left: TERMINATOR,
            right: node(2),
        });
        // As a NOMT witness could give them: unsorted, a terminator with stray bits.
        let path_proofs = vec![
            PathProof {
                terminal: proof.paths[2].terminal.clone(),
                siblings: vec![node(0), TERMINATOR],
            },
            PathProof {
                terminal: PathProofTerminal::Terminator(raw_position(
                    path_with(&[true, false], 0x3f),
                    2,
                    99,
                )),
                siblings: vec![node(0), node(2)],
            },
            PathProof {
                terminal: proof.paths[0].terminal.clone(),
                siblings: vec![right],
            },
        ];
        let built = NomtProof::from_path_proofs(path_proofs).unwrap();
        assert_eq!(bytes(built.inner()), bytes(&proof));
        assert!(verify_multi_proof::<Hasher>(built.inner(), root).is_ok());
        // Over-deep positions are an error, not a panic.
        let deep = PathProof {
            terminal: PathProofTerminal::Terminator(raw_position([0; 32], 300, 0)),
            siblings: vec![],
        };
        assert_eq!(
            NomtProof::from_path_proofs(vec![deep]),
            Err(InvalidNomtProof::TerminatorTooDeep {
                index: 0,
                depth: 300
            })
        );
    }

    /// Regression: nomt-core's `from_path_proofs` indexes a path proof's siblings by the bits
    /// it shares with its successor, unchecked, and panicked on a too-short sibling vector.
    #[test]
    fn from_path_proofs_rejects_bad_path_proofs_without_panicking() {
        let path_proof = |terminal: PathProofTerminal, siblings: usize| PathProof {
            terminal,
            siblings: vec![[4; 32]; siblings],
        };
        let leaf_000 = || leaf(path_with(&[false, false, false], 0), [1; 32]);
        let leaf_001 = || leaf(path_with(&[false, false, true], 0), [2; 32]);
        // `000…` and `001…` share 2 bits: each needs at least 3 siblings.
        assert_eq!(
            NomtProof::from_path_proofs(vec![path_proof(leaf_000(), 0), path_proof(leaf_001(), 3)]),
            Err(InvalidNomtProof::PathProofSiblings {
                index: 0,
                siblings: 0,
                min: 3,
                max: 256
            })
        );
        assert_eq!(
            NomtProof::from_path_proofs(vec![path_proof(leaf_001(), 3), path_proof(leaf_000(), 2)]),
            Err(InvalidNomtProof::PathProofSiblings {
                index: 0,
                siblings: 2,
                min: 3,
                max: 256
            })
        );
        assert_eq!(
            NomtProof::from_path_proofs(vec![path_proof(leaf_000(), 3), path_proof(leaf_001(), 1)]),
            Err(InvalidNomtProof::PathProofSiblings {
                index: 1,
                siblings: 1,
                min: 3,
                max: 256
            })
        );
        // Enough siblings: the proofs merge (the 2 shared, none unique: the bisection at bit 2
        // leaves each terminal at depth 3).
        let merged =
            NomtProof::from_path_proofs(vec![path_proof(leaf_000(), 3), path_proof(leaf_001(), 3)])
                .unwrap();
        assert_eq!(merged.inner().siblings.len(), 2);
        assert_eq!(merged.inner().paths[1].depth, 3);
        // More than 256 siblings.
        assert_eq!(
            NomtProof::from_path_proofs(vec![path_proof(leaf_000(), 257)]),
            Err(InvalidNomtProof::PathProofSiblings {
                index: 0,
                siblings: 257,
                min: 0,
                max: 256
            })
        );
        // A terminator with a sibling count other than its depth.
        for siblings in [1, 3] {
            assert_eq!(
                NomtProof::from_path_proofs(vec![path_proof(terminator(&[true, false]), siblings)]),
                Err(InvalidNomtProof::PathProofSiblings {
                    index: 0,
                    siblings,
                    min: 2,
                    max: 2
                })
            );
        }
        // Duplicate and prefix terminals (nomt-core panics on them) are errors too.
        assert_eq!(
            NomtProof::from_path_proofs(vec![path_proof(leaf_000(), 3), path_proof(leaf_000(), 3)]),
            Err(InvalidNomtProof::PathsNotAscending { index: 1 })
        );
        assert_eq!(
            NomtProof::from_path_proofs(vec![
                path_proof(leaf(path_with(&[true, true], 0), [1; 32]), 2),
                path_proof(terminator(&[true]), 1),
            ]),
            Err(InvalidNomtProof::PathIsPrefix { index: 1 })
        );
    }

    /// Arbitrary path proofs (random terminals, random sibling counts) never panic
    /// `from_path_proofs`, and whatever it builds is well-formed.
    #[test_strategy::proptest]
    fn from_path_proofs_never_panics(
        #[strategy(proptest::collection::vec((arbitrary_terminal(), 0usize..260), 0..6))]
        path_proofs: Vec<(PathProofTerminal, usize)>,
        #[strategy(proptest::collection::vec(any::<[u8; 32]>(), 0..4))] prefixes: Vec<[u8; 32]>,
    ) {
        // Leaves on a few shared prefixes, so that the paths share many bits.
        let path_proofs: Vec<PathProof> = path_proofs
            .into_iter()
            .enumerate()
            .map(|(i, (terminal, siblings))| {
                let terminal = match (terminal, prefixes.get(i % 4)) {
                    (PathProofTerminal::Leaf(mut leaf), Some(prefix)) => {
                        let keep = i * 61 % 256 / 8;
                        leaf.key_path[..keep].copy_from_slice(&prefix[..keep]);
                        PathProofTerminal::Leaf(leaf)
                    }
                    (terminal, _) => terminal,
                };
                PathProof {
                    terminal,
                    siblings: vec![[7; 32]; siblings],
                }
            })
            .collect();
        if let Ok(proof) = NomtProof::from_path_proofs(path_proofs) {
            prop_assert_eq!(decode(&bytes(proof.inner())).ok(), Some(proof.clone()));
            let _ = verify_multi_proof::<Hasher>(proof.inner(), implied_root(proof.inner()));
        }
    }

    #[test]
    fn a_too_deep_terminator_is_rejected() {
        let mut encoded = bytes(&three_terminal_proof());
        encoded[TERMINATOR_AT + 32..TERMINATOR_AT + 34].copy_from_slice(&257u16.to_le_bytes());
        // nomt-core decodes it, and would panic in `path()`.
        let decoded: MultiProof = borsh::from_slice(&encoded).unwrap();
        assert_eq!(
            NomtProof::new(decoded),
            Err(InvalidNomtProof::TerminatorTooDeep {
                index: 1,
                depth: 257
            })
        );
        assert!(decode(&encoded).is_err());
        let mut max = encoded;
        max[TERMINATOR_AT + 32..TERMINATOR_AT + 34].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(decode(&max).is_err());
    }

    #[test]
    fn depths_out_of_range_are_rejected() {
        // A leaf deeper than 256 bits.
        let proof = MultiProof {
            paths: vec![multi(leaf([7; 32], [1; 32]), 257)],
            siblings: vec![[1; 32]; 257],
        };
        assert_eq!(
            NomtProof::new(proof),
            Err(InvalidNomtProof::DepthOutOfRange {
                index: 0,
                depth: 257
            })
        );
        // A depth above the bisection it is in (`verify_range` would underflow).
        let mut proof = three_terminal_proof();
        proof.paths[2].depth = 1;
        assert_eq!(
            NomtProof::new(proof),
            Err(InvalidNomtProof::DepthOutOfRange { index: 2, depth: 1 })
        );
        let mut proof = three_terminal_proof();
        proof.paths[0].depth = 0;
        assert!(NomtProof::new(proof).is_err());
    }

    #[test]
    fn unsorted_duplicate_and_prefix_paths_are_rejected() {
        let mut proof = three_terminal_proof();
        proof.paths.swap(0, 2);
        assert_eq!(
            NomtProof::new(proof),
            Err(InvalidNomtProof::PathsNotAscending { index: 1 })
        );
        let mut proof = three_terminal_proof();
        proof.paths[0] = proof.paths[2].clone();
        proof.paths.remove(1);
        assert!(matches!(
            NomtProof::new(proof),
            Err(InvalidNomtProof::PathsNotAscending { .. })
        ));
        // A terminator at `1` before a leaf under `11`: `verify_range` would index past the
        // terminator's one-bit path.
        let proof = MultiProof {
            paths: vec![
                multi(terminator(&[true]), 1),
                multi(leaf(path_with(&[true, true], 0), [1; 32]), 2),
            ],
            siblings: vec![],
        };
        assert_eq!(
            NomtProof::new(proof.clone()),
            Err(InvalidNomtProof::PathIsPrefix { index: 1 })
        );
        assert!(decode(&bytes(&proof)).is_err());
    }

    #[test]
    fn the_sibling_count_must_match() {
        // A single leaf at depth 3 needs 3 siblings.
        let mut proof = MultiProof {
            paths: vec![multi(leaf([0; 32], [1; 32]), 3)],
            siblings: vec![[5; 32]; 3],
        };
        NomtProof::new(proof.clone()).unwrap();
        assert!(verify_multi_proof::<Hasher>(&proof, implied_root(&proof)).is_ok());
        for count in [0, 2, 4] {
            proof.siblings = vec![[5; 32]; count];
            assert_eq!(
                NomtProof::new(proof.clone()),
                Err(InvalidNomtProof::SiblingCount {
                    expected: 3,
                    actual: count
                })
            );
            assert!(decode(&bytes(&proof)).is_err());
        }
        // Two leaves under a common `00` prefix, bisected at bit 2, each one bit deeper.
        let proof = MultiProof {
            paths: vec![
                multi(leaf(path_with(&[false, false, false], 0), [1; 32]), 4),
                multi(leaf(path_with(&[false, false, true], 0), [2; 32]), 3),
            ],
            siblings: vec![[9; 32]; 2 + 1],
        };
        NomtProof::new(proof.clone()).unwrap();
        assert!(verify_multi_proof::<Hasher>(&proof, implied_root(&proof)).is_ok());
    }

    fn arbitrary_terminal() -> impl Strategy<Value = PathProofTerminal> {
        prop_oneof![
            (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(k, v)| leaf(k, v)),
            (any::<[u8; 32]>(), 0u16..=256).prop_map(|(path, depth)| {
                PathProofTerminal::Terminator(canonical_position(path, depth))
            }),
        ]
    }

    /// Well-formed proofs of random shapes: random terminals, sorted and made prefix-free,
    /// with random (in-range) depths and the right number of random siblings.
    fn well_formed_proof() -> impl Strategy<Value = MultiProof> {
        (
            proptest::collection::vec(arbitrary_terminal(), 0..8),
            any::<u64>(),
        )
            .prop_map(|(mut terminals, seed)| {
                terminals.sort_by(|a, b| a.path().cmp(b.path()));
                let mut kept: Vec<PathProofTerminal> = Vec::new();
                for terminal in terminals {
                    if kept.last().is_none_or(|prev| {
                        !terminal.path().starts_with(prev.path()) && terminal.path() != prev.path()
                    }) {
                        kept.push(terminal);
                    }
                }
                // Depths: the minimum each terminal needs (one past where it splits from its
                // neighbours), plus a seeded extra for leaves (terminators sit at their depth).
                let bits: Vec<Vec<bool>> = kept
                    .iter()
                    .map(|t| t.path().iter().by_vals().collect())
                    .collect();
                let shared =
                    |a: &[bool], b: &[bool]| a.iter().zip(b).take_while(|(x, y)| x == y).count();
                let mut rng = seed;
                let paths: Vec<MultiPathProof> = kept
                    .iter()
                    .enumerate()
                    .filter_map(|(i, terminal)| {
                        let mut min = 0;
                        if i > 0 {
                            min = min.max(shared(&bits[i - 1], &bits[i]) + 1);
                        }
                        if i + 1 < bits.len() {
                            min = min.max(shared(&bits[i], &bits[i + 1]) + 1);
                        }
                        let depth = match terminal {
                            PathProofTerminal::Terminator(position) => {
                                usize::from(position.depth())
                            }
                            PathProofTerminal::Leaf(_) => {
                                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                                (min + usize::try_from(rng >> 61).unwrap()).min(256)
                            }
                        };
                        (depth >= min).then(|| multi(terminal.clone(), depth))
                    })
                    .collect();
                let mut proof = MultiProof {
                    paths,
                    siblings: vec![],
                };
                // Dropping a too-shallow terminator may have made a neighbour too shallow:
                // keep the longest well-formed prefix.
                while !proof.paths.is_empty() && siblings_needed(0, 0, &proof.paths).is_err() {
                    proof.paths.pop();
                }
                let needed = if proof.paths.is_empty() {
                    0
                } else {
                    siblings_needed(0, 0, &proof.paths).unwrap()
                };
                proof.siblings = (0..needed)
                    .map(|i| {
                        let mut node = [0u8; 32];
                        node[..8]
                            .copy_from_slice(&(seed ^ u64::try_from(i).unwrap()).to_le_bytes());
                        node
                    })
                    .collect();
                proof
            })
    }

    /// Arbitrary bytes never panic the decoder, and whatever decodes is its own canonical
    /// encoding and never panics nomt-core's verification.
    #[test_strategy::proptest]
    fn arbitrary_bytes_never_panic(
        #[strategy(proptest::collection::vec(any::<u8>(), 0..512))] data: Vec<u8>,
    ) {
        if let Ok(proof) = borsh::from_slice::<NomtProof>(&data) {
            prop_assert_eq!(borsh::to_vec(&proof).unwrap(), data);
            let _ = verify_multi_proof::<Hasher>(proof.inner(), [0; 32]);
        }
    }

    /// Mutations of well-formed proofs (more likely to decode than random bytes): never a
    /// panic, and anything accepted is canonical and verifies against its implied root
    /// without panicking, and so do updates.
    #[test_strategy::proptest]
    fn mutated_proofs_never_panic(
        #[strategy(well_formed_proof())] proof: MultiProof,
        position: usize,
        #[strategy(1u8..)] flip: u8,
        #[strategy(proptest::collection::btree_map(any::<[u8; 32]>(), any::<Option<[u8; 32]>>(), 0..4))]
        ops: std::collections::BTreeMap<[u8; 32], Option<[u8; 32]>>,
    ) {
        let encoded = bytes(&proof);
        let nomt = decode(&encoded).unwrap();
        check_verification(&nomt, &ops);
        let mut mutated = encoded.clone();
        let at = position % mutated.len();
        mutated[at] ^= flip;
        if let Ok(nomt) = decode(&mutated) {
            prop_assert_eq!(borsh::to_vec(&nomt).unwrap(), mutated);
            check_verification(&nomt, &ops);
        }
    }

    /// Verifies `proof` against its implied root, then applies updates: in scope (the
    /// terminals' own keys) and the random `ops` (likely out of scope). Must not panic.
    fn check_verification(
        proof: &NomtProof,
        ops: &std::collections::BTreeMap<[u8; 32], Option<[u8; 32]>>,
    ) {
        use nomt_core::proof::verify_multi_proof_update;
        let root = implied_root(proof.inner());
        let verified = verify_multi_proof::<Hasher>(proof.inner(), root).unwrap();
        let _ = verify_multi_proof_update::<Hasher>(
            &verified,
            ops.iter().map(|(k, v)| (*k, *v)).collect(),
        );
        // Per terminal: its own key path, and a key path that leaves it one bit below its depth
        // (a new leaf next to it, so the update builds a deeper sub-trie).
        let mut in_scope = std::collections::BTreeMap::new();
        for path in &proof.inner().paths {
            let (mut key_path, value) = match &path.terminal {
                PathProofTerminal::Leaf(leaf) => (leaf.key_path, None),
                PathProofTerminal::Terminator(position) => (position.raw_path(), Some([3; 32])),
            };
            in_scope.insert(key_path, value);
            if path.depth < MAX_DEPTH {
                key_path[path.depth / 8] ^= 0x80 >> (path.depth % 8);
                in_scope.insert(key_path, Some([4; 32]));
            }
        }
        let _ = verify_multi_proof_update::<Hasher>(&verified, in_scope.into_iter().collect());
        for path in &proof.inner().paths {
            if let PathProofTerminal::Leaf(leaf) = &path.terminal {
                assert_eq!(verified.confirm_value(leaf).ok(), Some(true));
            }
        }
    }
}

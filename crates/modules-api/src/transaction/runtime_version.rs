//! What a signature binds a transaction to: the network and the runtime version
//! ([`RuntimeCommitment`]), and the versions the runtime accepts at each height
//! ([`VersionTable`] of [`VersionWindow`]s).
//!
//! A transaction names the runtime version it was signed for (`TxDetails::runtime_version`, a
//! spec version). The runtime's version table maps the spec version to the schema hash of that
//! version's types and to the heights at which it is accepted; the signing payload carries
//! `SHA-256("SELENDRA/runtime/v1" ‖ chain_id ‖ spec_version ‖ schema_hash)`, so a signature is
//! valid only for that network and that version's encoding of the call. After an upgrade a
//! held-back transaction cannot be decoded as a different call: its version is either no longer
//! accepted, or accepted with its own schema hash.
//!
//! Upstream committed to a 32-byte `chain_hash` and selected it by a 64-bit fragment of itself,
//! with compile-time overrides per height range (`CHAIN_HASH_OVERRIDES`): two hashes sharing a
//! fragment could not both be valid at a height, and that had to be checked separately (P5-39).
//! Here the version is selected by its number, and the commitment covers the whole schema hash.

use selendra_interface::common::{HexHash, RollupHeight};
use selendra_interface::reexports::digest::Digest;
use selendra_state::StateHasher;

use crate::ConsensusType;

/// A runtime version's schema hash: the hash of its transaction types' encodings. Opaque in
/// Phase 5; Phase 8 computes it in a golden test from borsh's schema.
pub type SchemaHash = [u8; 32];

/// What a transaction's signature commits to besides the transaction: the chain ID, the runtime
/// version and that version's schema hash.
///
/// `SHA-256("SELENDRA/runtime/v1" ‖ chain_id (u64 LE) ‖ spec_version (u32 LE) ‖ schema_hash)`,
/// hashed with the state hasher. borsh: the 32 bytes. JSON: `0x` + 64 lowercase hex digits.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
    ConsensusType,
)]
#[serde(transparent)]
pub struct RuntimeCommitment(HexHash);

impl RuntimeCommitment {
    /// The domain tag of the commitment.
    pub const DOMAIN: &'static [u8] = b"SELENDRA/runtime/v1";

    /// The commitment to `spec_version` with `schema_hash` on the chain `chain_id`.
    pub fn new(chain_id: u64, spec_version: u32, schema_hash: &SchemaHash) -> Self {
        let mut hasher = StateHasher::new();
        hasher.update(Self::DOMAIN);
        hasher.update(chain_id.to_le_bytes());
        hasher.update(spec_version.to_le_bytes());
        hasher.update(schema_hash);
        Self(HexHash::new(hasher.finalize().into()))
    }

    /// The 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0.0
    }
}

/// One runtime version and the heights at which transactions signed for it are accepted:
/// `from_height` (inclusive) to `until_height` (exclusive; `None`: no end).
///
/// In a [`VersionTable`], the part of a window that overlaps the next one is its **grace
/// period**: both versions are accepted there, so transactions signed just before an upgrade
/// still land. A grace period is for additive schema changes only (a new call or module: every
/// call of the old version decodes to the same call under the new one); a change of an existing
/// call's encoding must not have one. Phase 8 adds a compatibility test per grace period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VersionWindow {
    /// The spec version (`TxDetails::runtime_version` of the transactions signed for it).
    pub spec_version: u32,
    /// The version's schema hash.
    pub schema_hash: SchemaHash,
    /// The first height at which the version is accepted.
    pub from_height: RollupHeight,
    /// The first height at which it no longer is (`None`: the current version, no end).
    pub until_height: Option<RollupHeight>,
}

impl VersionWindow {
    /// The window of `spec_version` from `from_height` on, with no end.
    pub const fn open(spec_version: u32, schema_hash: SchemaHash, from_height: u64) -> Self {
        Self {
            spec_version,
            schema_hash,
            from_height: RollupHeight::new(from_height),
            until_height: None,
        }
    }

    /// The window of `spec_version` from `from_height` until `until_height` (exclusive).
    pub const fn closed(
        spec_version: u32,
        schema_hash: SchemaHash,
        from_height: u64,
        until_height: u64,
    ) -> Self {
        Self {
            spec_version,
            schema_hash,
            from_height: RollupHeight::new(from_height),
            until_height: Some(RollupHeight::new(until_height)),
        }
    }

    /// Whether the version is accepted at `height`.
    pub const fn contains(&self, height: RollupHeight) -> bool {
        height.get() >= self.from_height.get()
            && match self.until_height {
                Some(until) => height.get() < until.get(),
                None => true,
            }
    }

    /// The commitment a transaction signed for this version on `chain_id` carries.
    pub fn commitment(&self, chain_id: u64) -> RuntimeCommitment {
        RuntimeCommitment::new(chain_id, self.spec_version, &self.schema_hash)
    }
}

/// Why a list of [`VersionWindow`]s is not a valid [`VersionTable`]. `index` is the position
/// of the window that breaks the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VersionTableError {
    /// No window: no transaction would ever be accepted.
    #[error("the version table is empty")]
    Empty,
    /// The first window does not start at genesis (height 0): transactions before it would have
    /// no version.
    #[error("the first version window does not start at genesis")]
    FirstNotAtGenesis,
    /// A window ends at or before its start.
    #[error("version window {index} is empty (it ends at or before its start)")]
    EmptyWindow {
        /// The window.
        index: usize,
    },
    /// A window other than the last has no end.
    #[error("version window {index} has no end but is not the last")]
    OpenBeforeLast {
        /// The window.
        index: usize,
    },
    /// The last window ends: above it no version would be accepted.
    #[error("the last version window (index {index}) ends")]
    LastWindowEnds {
        /// The window.
        index: usize,
    },
    /// A window does not start after the previous one starts.
    #[error("version window {index} does not start after the previous window starts")]
    NotOrdered {
        /// The window.
        index: usize,
    },
    /// A window starts after the previous one ends: heights in between have no version.
    #[error("version window {index} starts after the previous window ends (a gap)")]
    Gap {
        /// The window.
        index: usize,
    },
    /// A window does not end after the previous one ends: the previous version would be
    /// accepted again after it (or for as long as it).
    #[error("version window {index} does not end after the previous window ends")]
    EndsBeforePrevious {
        /// The window.
        index: usize,
    },
    /// A window overlaps a window other than the next one: more than two versions accepted at
    /// once, an overlap outside a grace period.
    #[error("version window {first} overlaps window {second}, which does not follow it")]
    OverlapOutsideGrace {
        /// The earlier window.
        first: usize,
        /// The later window it overlaps.
        second: usize,
    },
    /// A window's spec version is not greater than the previous one's (versions are distinct
    /// and increase with height).
    #[error("version window {index} has a spec version not above the previous window's")]
    VersionNotIncreasing {
        /// The window.
        index: usize,
    },
}

impl VersionTableError {
    /// A message without the index, for the compile-time check (const evaluation cannot format
    /// numbers).
    const fn rule(&self) -> &'static str {
        match self {
            Self::Empty => "invalid version table: it is empty",
            Self::FirstNotAtGenesis => {
                "invalid version table: the first window does not start at genesis"
            }
            Self::EmptyWindow { .. } => {
                "invalid version table: a window ends at or before its start"
            }
            Self::OpenBeforeLast { .. } => {
                "invalid version table: a window other than the last has no end"
            }
            Self::LastWindowEnds { .. } => "invalid version table: the last window ends",
            Self::NotOrdered { .. } => {
                "invalid version table: a window does not start after the previous one starts"
            }
            Self::Gap { .. } => {
                "invalid version table: a window starts after the previous one ends (a gap)"
            }
            Self::EndsBeforePrevious { .. } => {
                "invalid version table: a window does not end after the previous one ends"
            }
            Self::OverlapOutsideGrace { .. } => {
                "invalid version table: a window overlaps a window that does not follow it"
            }
            Self::VersionNotIncreasing { .. } => {
                "invalid version table: a spec version is not above the previous one"
            }
        }
    }
}

/// The end of a window, `u64::MAX + 1` standing for "no end" (`u128`, so comparisons need no
/// special case).
const fn end(window: &VersionWindow) -> u128 {
    match window.until_height {
        Some(until) => until.get() as u128,
        None => u64::MAX as u128 + 1,
    }
}

/// Checks the rules of a [`VersionTable`] on `windows`, in a `const fn`:
/// - at least one window; the first starts at genesis (height 0); the last has no end, every
///   other one ends after it starts;
/// - each window starts after the previous one starts, and no later than it ends (no gap);
///   where they overlap is the previous window's grace period;
/// - each window ends after the previous one ends;
/// - a window overlaps only the next one: at most two versions are accepted at any height, the
///   newer one and (in its grace period) the one before it;
/// - spec versions increase strictly (so they are distinct).
///
/// So every height has exactly one newest version (the primary one) and at most one other.
///
/// # Errors
/// The first rule broken, window by window.
pub const fn check_version_table(windows: &[VersionWindow]) -> Result<(), VersionTableError> {
    if windows.is_empty() {
        return Err(VersionTableError::Empty);
    }
    if windows[0].from_height.get() != RollupHeight::GENESIS.get() {
        return Err(VersionTableError::FirstNotAtGenesis);
    }
    let last = windows.len() - 1;
    let mut index = 0;
    while index < windows.len() {
        let window = &windows[index];
        match window.until_height {
            Some(until) => {
                if index == last {
                    return Err(VersionTableError::LastWindowEnds { index });
                }
                if until.get() <= window.from_height.get() {
                    return Err(VersionTableError::EmptyWindow { index });
                }
            }
            None => {
                if index != last {
                    return Err(VersionTableError::OpenBeforeLast { index });
                }
            }
        }
        if index > 0 {
            let previous = &windows[index - 1];
            if window.from_height.get() <= previous.from_height.get() {
                return Err(VersionTableError::NotOrdered { index });
            }
            if window.from_height.get() as u128 > end(previous) {
                return Err(VersionTableError::Gap { index });
            }
            if end(window) <= end(previous) {
                return Err(VersionTableError::EndsBeforePrevious { index });
            }
            if window.spec_version <= previous.spec_version {
                return Err(VersionTableError::VersionNotIncreasing { index });
            }
        }
        if index > 1 {
            let earlier = &windows[index - 2];
            if (window.from_height.get() as u128) < end(earlier) {
                return Err(VersionTableError::OverlapOutsideGrace {
                    first: index - 2,
                    second: index,
                });
            }
        }
        index += 1;
    }
    Ok(())
}

/// The runtime versions a runtime accepts, by height: a list of [`VersionWindow`]s that passed
/// [`check_version_table`] (the only way to build one).
///
/// The runtime supplies its table as a constant (Phase 8's runtime), built with
/// [`VersionTable::new_or_panic`] so an invalid table does not compile:
///
/// ```
/// use selendra_modules_api::transaction::{VersionTable, VersionWindow};
///
/// const VERSIONS: VersionTable<'static> = VersionTable::new_or_panic(&[
///     VersionWindow::closed(1, [0x11; 32], 0, 1_100),
///     // Version 1 has a grace period from 1_000 to 1_100.
///     VersionWindow::open(2, [0x22; 32], 1_000),
/// ]);
/// assert_eq!(VERSIONS.windows().len(), 2);
/// ```
///
/// ```compile_fail,E0080
/// use selendra_modules_api::transaction::{VersionTable, VersionWindow};
///
/// // Three versions accepted from 1_050 to 1_100: version 1 overlaps version 3.
/// const VERSIONS: VersionTable<'static> = VersionTable::new_or_panic(&[
///     VersionWindow::closed(1, [0x11; 32], 0, 1_100),
///     VersionWindow::closed(2, [0x22; 32], 1_000, 1_200),
///     VersionWindow::open(3, [0x33; 32], 1_050),
/// ]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionTable<'a> {
    windows: &'a [VersionWindow],
}

impl<'a> VersionTable<'a> {
    /// The table of `windows`.
    ///
    /// # Errors
    /// If `windows` break a rule of [`check_version_table`].
    pub const fn new(windows: &'a [VersionWindow]) -> Result<Self, VersionTableError> {
        match check_version_table(windows) {
            Ok(()) => Ok(Self { windows }),
            Err(error) => Err(error),
        }
    }

    /// The table of `windows`, for a constant: panics if they break a rule of
    /// [`check_version_table`], which in a constant is a compile error (E0080) naming the
    /// rule.
    pub const fn new_or_panic(windows: &'a [VersionWindow]) -> Self {
        match check_version_table(windows) {
            Ok(()) => Self { windows },
            Err(error) => panic!("{}", error.rule()),
        }
    }

    /// The windows, oldest first.
    pub const fn windows(&self) -> &'a [VersionWindow] {
        self.windows
    }

    /// The window of `spec_version`, if transactions signed for it are accepted at `height`.
    pub fn resolve(&self, height: RollupHeight, spec_version: u32) -> Option<&'a VersionWindow> {
        self.windows
            .iter()
            .find(|window| window.spec_version == spec_version)
            .filter(|window| window.contains(height))
    }

    /// The newest version accepted at `height`: the one to sign new transactions for.
    pub fn primary_at(&self, height: RollupHeight) -> &'a VersionWindow {
        // The windows start in increasing order and the first at genesis: the last window
        // starting at or below `height` contains it (no gaps, the last has no end).
        let mut primary = &self.windows[0];
        for window in self.windows {
            if window.from_height <= height {
                primary = window;
            }
        }
        primary
    }

    /// The version accepted at `height` because it is in its grace period, if any: the one
    /// before [`primary_at`](Self::primary_at), still accepted.
    pub fn grace_at(&self, height: RollupHeight) -> Option<&'a VersionWindow> {
        let primary = self.primary_at(height);
        self.windows
            .iter()
            .filter(|window| window.spec_version != primary.spec_version)
            .find(|window| window.contains(height))
    }
}

#[cfg(test)]
mod tests;

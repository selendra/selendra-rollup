//! Pruning of old versions ([`PrunerConfig`], [`DbGroup::prune`](crate::DbGroup::prune)), and the
//! versions pinned by live readers, which pruning keeps.
//!
//! **What is pruned.** The flat store's archival rows of the user and kernel values (through
//! rockbound's `collect_pruning_batch`) and the accessory store's rows. Each keeps an index of
//! the keys written at each version (rockbound's pruning column family, the accessory DB's
//! `AccessoryKeysByVersion`); a pass walks that index from its oldest entry up to the *cutoff*
//! version, consumes the entries, and for each written key `K` at version `V` deletes `K`'s row
//! before `V` (its predecessor) and, if `K`'s newest row at or before the cutoff is a delete
//! marker, that marker too (every older row of `K` is gone by then, so reads find `K` absent
//! either way). The ledger DB and the per-version roots (`StateRootHashes`) are not pruned
//! (TODO.md: Phase 10/13 ledger policy, Phase 11 roots).
//!
//! **The cutoff.** With the newest committed version `L`, `versions_to_keep = k` and the oldest
//! version a live reader pins, `p`: `cutoff = min(L - k, p)`. A read at any version `v >= cutoff`
//! is unchanged by a pass: the newest row at or below `v` of a key is never the predecessor of a
//! consumed entry (a predecessor lies below a version `<= cutoff` that also has a row), and a
//! deleted marker reads as absent like the marker. So `[L - k, L]` stays readable (`k + 1`
//! versions), and so does every pinned version. Reads at or below the *watermark* (the newest
//! `V - 1` whose predecessor row a pass deleted, `< cutoff`) fail with
//! [`HistoricalValueError::PrunedVersion`](crate::HistoricalValueError), never with a wrong value:
//! rockbound keeps the flat store's watermark, the accessory DB keeps its own
//! ([`MetadataKey::AccessoryPrunedVersion`]; upstream had none, so an accessory read below the
//! pruned rows returned `None`).
//!
//! **Pins.** Every reader [`DbGroup::readers`](crate::DbGroup::readers) and the storage manager
//! build pins its base version (the newest committed version when it was built: a storage reads
//! a key that its own uncommitted blocks do not write there) until it and all its clones are
//! dropped. Upstream had no pins: a storage older than the pruning window panicked on its next
//! read. A storage held for long holds pruning back (a warning is logged once it is more than
//! `10 k` versions old).
//!
//! **Budget.** A pass consumes at most `max_keys_per_run` index entries of each store (user
//! values, kernel values, accessory), with a budget each: upstream shared one between user and
//! kernel values, so a user backlog starved kernel pruning. A store with entries left reports a
//! backlog ([`PruneStats::has_backlog`]); every pass consumes the entries it inspects, so passes
//! always progress.
//!
//! **Crashes.** Each store's pass is one RocksDB write batch (the archival DB: user and kernel
//! values together; the accessory DB: rows, index entries and watermark together), so a crash
//! leaves each store's pass written or not, and the next pass goes on from there. Pruning writes
//! only rows at or below the cutoff, so it never meets crash recovery's rollback of the newest
//! version, and nothing it writes is kept in an uncommitted snapshot (its range deletes would be
//! invisible there).

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::Context;
use rockbound::SchemaBatch;
use rockbound::cache::delta_reader::DeltaReader;
use rockbound::schema::KeyEncoder;
use rockbound::versioned_db::PruningBatchOutput;
use rockbound::{CodecError, Schema};
use selendra_interface::common::SlotNumber;

use crate::flat::FlatStateDb;
use crate::schema::{AccessoryKeysByVersion, DbMetadata, MetadataKey, ModuleAccessoryState};

#[cfg(test)]
mod tests;

/// When the storage manager prunes
/// ([`StorageManagerConfig::pruning`](crate::StorageManagerConfig)).
///
/// `versions_to_keep = k` keeps the newest `k + 1` versions readable (`[L - k, L]`, `L` the newest
/// committed version), plus every version a live storage is based on (see the
/// [module docs](self)). `max_keys_per_run` bounds the work of one pass: at most that many index
/// entries (keys written at some version) of each of the user values, the kernel values and
/// the accessory store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PrunerConfig {
    /// Never prune: every version stays readable.
    #[default]
    Off,
    /// Prune once, when the manager is opened (before any storage exists), until nothing is left
    /// to prune; never during finalizations.
    OnceAtStartup {
        /// See the type docs.
        versions_to_keep: NonZeroU64,
        /// See the type docs.
        max_keys_per_run: NonZeroU64,
    },
    /// Prune one pass at the end of a finalization, once `every_versions` versions were
    /// committed since the last pass that left nothing behind (a pass that hit its budget runs
    /// again at the next finalization). Synchronous: the finalization returns once its pass is
    /// written (bounded by `max_keys_per_run`).
    Periodic {
        /// Versions committed between two passes (1: every finalization). Upstream ran its
        /// pruner every `interval + 1` blocks.
        every_versions: NonZeroU64,
        /// See the type docs.
        versions_to_keep: NonZeroU64,
        /// See the type docs.
        max_keys_per_run: NonZeroU64,
    },
}

impl PrunerConfig {
    /// `(versions_to_keep, max_keys_per_run)`, unless pruning is off.
    pub fn settings(&self) -> Option<(NonZeroU64, NonZeroU64)> {
        match *self {
            Self::Off => None,
            Self::OnceAtStartup {
                versions_to_keep,
                max_keys_per_run,
            }
            | Self::Periodic {
                versions_to_keep,
                max_keys_per_run,
                ..
            } => Some((versions_to_keep, max_keys_per_run)),
        }
    }
}

/// What one pass did to one store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StorePruneStats {
    /// Index entries consumed (keys written at a version at or below the cutoff).
    pub entries: u64,
    /// Rows deleted (predecessors and delete markers).
    pub rows_deleted: u64,
    /// Whether the pass stopped at its budget with entries left up to the cutoff.
    pub backlog: bool,
}

/// What one pruning pass did ([`DbGroup::prune`](crate::DbGroup::prune)).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PruneStats {
    /// The cutoff of the pass (see the [module docs](self)); `None`: nothing was prunable (fewer
    /// than `versions_to_keep + 1` versions committed).
    pub cutoff: Option<SlotNumber>,
    /// The flat store's user values.
    pub flat_user: StorePruneStats,
    /// The flat store's kernel values.
    pub flat_kernel: StorePruneStats,
    /// The accessory store.
    pub accessory: StorePruneStats,
}

impl PruneStats {
    /// Whether a store has entries left up to the cutoff (another pass would prune more). Every
    /// pass consumes the entries it inspects, so passes run while this holds always end
    /// (critique: "until a pass deletes nothing" stopped early behind a batch of first writes,
    /// which consume entries but delete no row).
    pub fn has_backlog(&self) -> bool {
        [self.flat_user, self.flat_kernel, self.accessory]
            .iter()
            .any(|store| store.backlog && store.entries > 0)
    }

    /// Rows deleted by the pass, in every store.
    pub fn rows_deleted(&self) -> u64 {
        self.flat_user
            .rows_deleted
            .saturating_add(self.flat_kernel.rows_deleted)
            .saturating_add(self.accessory.rows_deleted)
    }
}

/// The cutoff of a pass (see the [module docs](self)): `min(latest - versions_to_keep,
/// oldest_pin)`, `None` if nothing is committed or fewer than `versions_to_keep + 1` versions
/// are.
pub(crate) fn cutoff(
    latest: Option<SlotNumber>,
    versions_to_keep: NonZeroU64,
    oldest_pin: Option<SlotNumber>,
) -> Option<SlotNumber> {
    let by_distance = latest?.checked_sub(versions_to_keep.get())?;
    Some(oldest_pin.map_or(by_distance, |pin| by_distance.min(pin)))
}

/// `budget` as rockbound's `usize` batch size (saturating: at most that many).
fn budget_usize(budget: NonZeroU64) -> usize {
    usize::try_from(budget.get()).unwrap_or(usize::MAX)
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn store_stats(output: &PruningBatchOutput) -> StorePruneStats {
    StorePruneStats {
        entries: to_u64(output.keys_inspected),
        rows_deleted: to_u64(output.keys_to_prune),
        backlog: output.hit_size_limit,
    }
}

/// One pass over the flat store's user and kernel values up to `cutoff` (each with `budget`):
/// one batch for the archival DB, and the stats of each namespace. `latest` is the newest
/// committed version, which rockbound must agree with (it computes the cutoff itself from
/// `latest - keep`).
pub(crate) fn collect_flat(
    flat: &FlatStateDb,
    latest: SlotNumber,
    cutoff: SlotNumber,
    budget: NonZeroU64,
) -> anyhow::Result<(SchemaBatch, StorePruneStats, StorePruneStats)> {
    for (name, committed) in [
        ("user", flat.user_db().get_committed_version_live_db()?),
        ("kernel", flat.kernel_db().get_committed_version_live_db()?),
    ] {
        anyhow::ensure!(
            committed == Some(latest.get()),
            "the flat store's {name} values are at version {committed:?}, not at the committed \
             version {latest}"
        );
    }
    let keep = latest
        .get()
        .checked_sub(cutoff.get())
        .filter(|keep| *keep > 0)
        .ok_or_else(|| anyhow::anyhow!("bug: cutoff {cutoff} is not below version {latest}"))?;
    let user = flat
        .user_db()
        .collect_pruning_batch(keep, Some(budget_usize(budget)))
        .context("collecting the user values to prune")?;
    let kernel = flat
        .kernel_db()
        .collect_pruning_batch(keep, Some(budget_usize(budget)))
        .context("collecting the kernel values to prune")?;
    let (user_stats, kernel_stats) = (store_stats(&user), store_stats(&kernel));
    let mut batch = user.batch;
    batch.merge(kernel.batch);
    Ok((batch, user_stats, kernel_stats))
}

/// The accessory store's pruning watermark ([`MetadataKey::AccessoryPrunedVersion`]): reads at
/// or below it are pruned.
pub(crate) fn accessory_pruned_version(db: &DeltaReader) -> anyhow::Result<Option<SlotNumber>> {
    db.get::<DbMetadata>(&MetadataKey::AccessoryPrunedVersion)?
        .map(|bytes| {
            let bytes: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!(
                    "DB corruption: the accessory pruning watermark must be 8 bytes, got {}",
                    bytes.len()
                )
            })?;
            Ok(SlotNumber::new(u64::from_be_bytes(bytes)))
        })
        .transpose()
}

/// Whether the accessory row `(key, version)` is a delete marker (`None`; `false` if absent),
/// without decoding a value.
fn is_accessory_delete_marker(
    db: &rockbound::DB,
    key: &[u8],
    version: SlotNumber,
) -> anyhow::Result<bool> {
    let row =
        <(&[u8], SlotNumber) as KeyEncoder<ModuleAccessoryState>>::encode_key(&(key, version))?;
    let is_marker = db.get_raw_with_cf_and_decoder(
        ModuleAccessoryState::COLUMN_FAMILY_NAME,
        &row,
        // Borsh `Option`: `0` is `None`, `1 ‖ value` is `Some`.
        &|data| match data {
            [0] => Ok(true),
            [1, ..] => Ok(false),
            _ => Err(CodecError::Wrapped(anyhow::anyhow!(
                "DB corruption: an accessory value is neither borsh `None` nor `Some` ({} bytes)",
                data.len()
            ))),
        },
    )?;
    Ok(is_marker == Some(true))
}

/// One pass over the accessory store up to `cutoff`, with `budget` (D14; upstream scanned every
/// key of the store per pass, counted keys rather than rows, never pruned the index, kept no
/// watermark and `expect`ed): the batch for the accessory DB and its stats.
///
/// Like rockbound's pass: the first `budget` index entries `(V, K)` with `V <= cutoff` are
/// consumed (deleted from the index); for each key, the row before each of its consumed
/// versions is deleted, and its newest consumed row too if it is a delete marker. The watermark
/// moves to the newest `V - 1` whose predecessor was deleted.
pub(crate) fn collect_accessory(
    db: &Arc<rockbound::DB>,
    cutoff: SlotNumber,
    budget: NonZeroU64,
) -> anyhow::Result<(SchemaBatch, StorePruneStats)> {
    let end = cutoff
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("slot number overflow"))?;
    let start: (SlotNumber, &[u8]) = (SlotNumber::GENESIS, &[]);
    let end: (SlotNumber, &[u8]) = (end, &[]);
    let mut iter = db.iter_range::<AccessoryKeysByVersion>(&start, &end)?;
    iter.seek_to_first();
    let mut collected: Vec<(SlotNumber, Vec<u8>)> = Vec::new();
    let mut stats = StorePruneStats::default();
    for entry in iter {
        let (version, key) = entry?.key;
        anyhow::ensure!(
            version <= cutoff,
            "DB corruption: the accessory index range up to version {cutoff} returned version \
             {version}"
        );
        if to_u64(collected.len()) >= budget.get() {
            stats.backlog = true;
            break;
        }
        collected.push((version, key));
    }
    stats.entries = to_u64(collected.len());
    let mut batch = SchemaBatch::new();
    // The consumed entries are a prefix of the index (it is ordered by version, then key).
    match (stats.backlog, collected.last()) {
        (_, None) => return Ok((batch, stats)),
        (false, Some(_)) => batch.delete_range::<AccessoryKeysByVersion>(&start, &end)?,
        (true, Some((version, key))) => {
            let last: (SlotNumber, &[u8]) = (*version, key);
            batch.delete_range::<AccessoryKeysByVersion>(&start, &last)?;
            batch.delete::<AccessoryKeysByVersion>(&last)?;
        }
    }

    collected.sort_unstable_by(|(va, ka), (vb, kb)| ka.cmp(kb).then(va.cmp(vb)));
    let reader = DeltaReader::new(db.clone(), Vec::new());
    let mut watermark: Option<SlotNumber> = None;
    let mut prev_in_group: Option<(&[u8], SlotNumber)> = None;
    for (index, (version, key)) in collected.iter().enumerate() {
        if let Some(query_version) = version.checked_sub(1) {
            let prev_version = match prev_in_group {
                Some((prev_key, prev_version)) if prev_key == key.as_slice() => Some(prev_version),
                _ => reader
                    .get_prev::<ModuleAccessoryState>(&(key.as_slice(), query_version))?
                    .and_then(|((found_key, found_version), _)| {
                        (found_key == *key).then_some(found_version)
                    }),
            };
            if let Some(prev_version) = prev_version {
                batch.delete::<ModuleAccessoryState>(&(key.as_slice(), prev_version))?;
                stats.rows_deleted = stats.rows_deleted.saturating_add(1);
                watermark = watermark.max(Some(query_version));
            }
        }
        prev_in_group = Some((key.as_slice(), *version));
        let last_of_group = collected
            .get(index.saturating_add(1))
            .is_none_or(|(_, next_key)| next_key != key);
        if last_of_group && is_accessory_delete_marker(db, key, *version)? {
            batch.delete::<ModuleAccessoryState>(&(key.as_slice(), *version))?;
            stats.rows_deleted = stats.rows_deleted.saturating_add(1);
        }
    }
    if let Some(watermark) = watermark
        && accessory_pruned_version(&reader)?.is_none_or(|old| watermark > old)
    {
        batch.put::<DbMetadata>(
            &MetadataKey::AccessoryPrunedVersion,
            &watermark.get().to_be_bytes().to_vec(),
        )?;
    }
    Ok((batch, stats))
}

/// The versions live readers are based on, each with its number of pins, shared by a
/// [`DbGroup`](crate::DbGroup) and the pins it hands out.
#[derive(Clone, Debug, Default)]
pub(crate) struct VersionPins {
    pins: Arc<Mutex<BTreeMap<SlotNumber, u64>>>,
}

impl VersionPins {
    /// Pins `version` until the returned pin and all its clones are dropped.
    pub(crate) fn pin(&self, version: SlotNumber) -> VersionPin {
        let mut pins = self.pins.lock().unwrap_or_else(PoisonError::into_inner);
        let count = pins.entry(version).or_insert(0);
        *count = count.saturating_add(1);
        drop(pins);
        VersionPin {
            _guard: Arc::new(PinGuard {
                pins: self.pins.clone(),
                version,
            }),
        }
    }

    /// The oldest pinned version.
    pub(crate) fn oldest(&self) -> Option<SlotNumber> {
        self.pins
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .next()
            .copied()
    }
}

/// A pin of one version (see [`VersionPins`]); clones share it.
#[derive(Clone, Debug)]
pub(crate) struct VersionPin {
    /// Held for its `Drop`.
    _guard: Arc<PinGuard>,
}

impl VersionPin {
    /// The pinned version.
    #[cfg(test)]
    pub(crate) fn version(&self) -> SlotNumber {
        self._guard.version
    }
}

#[derive(Debug)]
struct PinGuard {
    pins: Arc<Mutex<BTreeMap<SlotNumber, u64>>>,
    version: SlotNumber,
}

impl Drop for PinGuard {
    fn drop(&mut self) {
        // Poison-tolerant: a drop must neither panic nor leak the pin.
        let mut pins = self.pins.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = pins.get_mut(&self.version) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                pins.remove(&self.version);
            }
        }
    }
}

//! Startup crash recovery of the state databases ([`recover`], run by
//! [`DbGroup::open`](crate::DbGroup::open)).
//!
//! A commit writes the NOMT kernel tree, the NOMT user tree, the ledger DB, the accessory DB, the
//! flat archival DB and the flat live DB, in this order, each write synced to disk. The live DB is
//! written last and says which version is committed (`L`, with roots `R_L`; nothing committed:
//! the pre-genesis roots). After a crash in the middle of a commit, the databases written before
//! the live DB hold version `L + 1` (genesis if nothing is committed) and recovery rolls them
//! back:
//!
//! - **Versioned databases** (ledger, accessory, archival; the ledger's version is its newest
//!   slot, which records the roots): decided by version, never by root. One at
//!   `L` with root `R_L` is left alone. One at exactly `L + 1` whose root at `L` is `R_L` is
//!   rolled back by one version (at genesis there is no root at `L` to compare). Anything else
//!   cannot be the result of an interrupted commit and is an `Err`, with nothing written.
//!   (Upstream compared roots only, so a block that left the roots unchanged left its rows
//!   behind; and it refused to recover from a crash during the genesis commit.)
//! - **NOMT trees** have no version, only a root. A tree whose root is `R_L` is left alone.
//!   Otherwise its newest logged commit is rolled back (NOMT's rollback log, `rollback(1)`),
//!   and its root must then be `R_L`. If a versioned database holds `L + 1`, the tree's root
//!   must first be that version's (the trees are committed first): a root that is neither is an
//!   `Err` before anything is rolled back, so no rollback log is spent on a state recovery
//!   cannot repair. If no versioned database holds `L + 1` (the crash came before the ledger DB
//!   was written), nothing records the roots the trees were committed to: the tree is rolled
//!   back unchecked, whatever its root, and checked only afterwards. Versioned databases that
//!   hold `L + 1` must agree on its roots.
//!
//! Everything that can be checked before a rollback is checked before the first one; then the
//! databases are rolled back in commit order. Each rollback is synced, and recovery is
//! idempotent across crashes (also during recovery itself): a database already rolled back is
//! at `L`, and a database at `L` is never rolled back.
//!
//! That rule, not the length of NOMT's rollback log, keeps a NOMT tree from being rolled back
//! past `L`: `rollback(1)` undoes the newest logged commit and removes it from the log (and
//! records nothing for itself), but the log holds more than the one commit
//! `max_rollback_log_len(1)` suggests after a restart. NOMT prunes the log's on-disk range one
//! sync late, so a reopened tree can undo its last two commits, and one more for every restart
//! between commits (measured with NOMT 1.0.5: `open_irreconcilable_dbs_is_error_not_panic`).
//!
//! **The unchecked rollback, on states no interrupted commit leaves.** With no versioned
//! database at `L + 1`, a tree not at `R_L` is rolled back by one logged commit on every open
//! attempt, whatever its root: one commit ahead (the interrupted commit: the open succeeds),
//! but also several commits ahead, behind `L`, or diverged. Such an open fails the check after
//! the rollback, and the next attempt (a restart loop) rolls the tree back once more: a tree
//! `n` commits ahead of `L` is back at `R_L` at the `n`th attempt if its log reaches that far
//! (all databases then agree, and that open succeeds), while one behind `L` or diverged loses
//! one logged commit per attempt until its log runs out. Recording
//! the commit's roots before the first NOMT write would make every NOMT rollback checked
//! (TODO.md, Phase 10).

use std::sync::Arc;

use anyhow::Context;
use selendra_interface::common::{HexString, SlotNumber};
use selendra_interface::reexports::digest::Digest;
use selendra_interface::reexports::digest::typenum::U32;
use selendra_state::namespaces::ProvableNamespace;

use crate::accessory::AccessoryDb;
use crate::faults::{CommitPoint, Faults};
use crate::flat::FlatStateDb;
use crate::historical::next_version_after;
use crate::nomt_state::{NomtRoots, NomtStateDb};

#[cfg(test)]
mod tests;

/// One step of startup crash recovery: the rollback of one database by one version (and, after
/// the rollbacks, growing the NOMT hash tables).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecoveryStep {
    /// Rolls the NOMT kernel tree back.
    KernelNomt,
    /// Rolls the NOMT user tree back.
    UserNomt,
    /// Rolls the ledger DB back (its newest slot).
    Ledger,
    /// Rolls the accessory DB back.
    Accessory,
    /// Rolls the flat archival DB back.
    Archival,
    /// Grows the NOMT hash tables to the configured bucket count, after recovery and the
    /// consistency check (a fault point only: never in [`RecoveryReport::rolled_back`]).
    Grow,
}

/// What startup crash recovery did ([`DbGroup::last_recovery`](crate::DbGroup::last_recovery)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// The databases rolled back by one version, in the order they were rolled back (commit
    /// order). Empty if the last commit was not interrupted.
    pub rolled_back: Vec<RecoveryStep>,
    /// The committed version (the live DB's) the databases are at (`None`: nothing committed).
    pub live: Option<SlotNumber>,
}

/// The version and roots a database holds (`None`: empty, at the pre-genesis roots).
pub(crate) type Head = Option<(SlotNumber, NomtRoots)>;

/// The roots of `head` (the pre-genesis roots if empty).
pub(crate) fn root_of(head: Head) -> NomtRoots {
    head.map_or(NomtRoots::PRE_GENESIS, |(_, root)| root)
}

fn namespace_root(roots: NomtRoots, namespace: ProvableNamespace) -> [u8; 32] {
    match namespace {
        ProvableNamespace::User => roots.user,
        ProvableNamespace::Kernel => roots.kernel,
    }
}

/// Whether a versioned database at `head` must be rolled back, given the live DB at `live`: the
/// version to roll back and its roots, `None` if it is at the live DB's version and roots.
/// `root_at(L)` reads the database's root of exactly version `L`.
///
/// # Errors
/// Unless the database is at the live DB's version and roots, or exactly one version after it
/// with the live DB's roots at the live DB's version (see the [module docs](self)).
pub(crate) fn one_ahead(
    name: &str,
    head: Head,
    live: Head,
    root_at: impl FnOnce(SlotNumber) -> anyhow::Result<Option<NomtRoots>>,
) -> anyhow::Result<Option<(SlotNumber, NomtRoots)>> {
    if head == live {
        return Ok(None);
    }
    let live_version = live.map(|(version, _)| version);
    let next = next_version_after(live_version)?;
    let Some((version, roots)) = head.filter(|(version, _)| *version == next) else {
        anyhow::bail!(
            "the {name} (version {:?}, roots {}) cannot be reconciled with the flat live DB \
             (version {live_version:?}, roots {}): only a database exactly one version ahead of \
             the live DB (an interrupted commit) is rolled back. The state databases cannot be \
             recovered",
            head.map(|(version, _)| version),
            root_of(head),
            root_of(live),
        );
    };
    if let Some((live_version, live_roots)) = live {
        let stored = root_at(live_version)?;
        anyhow::ensure!(
            stored == Some(live_roots),
            "the {name} is at version {version}, one after the flat live DB's {live_version}, \
             but its roots at {live_version} ({}) are not the live DB's ({live_roots}). The state \
             databases cannot be recovered",
            stored.map_or_else(|| "none".to_owned(), |roots| roots.to_string()),
        );
    }
    Ok(Some((version, roots)))
}

/// Startup crash recovery (see the [module docs](self)): rolls back what an interrupted commit
/// wrote, and reports it. `faults` is called before each rollback
/// ([`CommitPoint::Recovery`]).
///
/// # Errors
/// If the databases are not in a state an interrupted commit leaves (nothing is rolled back
/// then, except a NOMT tree rolled back unchecked because no database records the next version:
/// it fails the check after its rollback, see the [module docs](self)), if a rollback fails or
/// does not restore the live DB's roots, or on read or write errors.
pub(crate) fn recover<H: Digest<OutputSize = U32> + Send + Sync>(
    nomt: &NomtStateDb<H>,
    flat: &mut FlatStateDb,
    ledger: &Arc<rockbound::DB>,
    accessory: &Arc<rockbound::DB>,
    faults: &Faults,
) -> anyhow::Result<RecoveryReport> {
    recover_inner(nomt, flat, ledger, accessory, faults).inspect_err(|error| {
        tracing::error!(
            error = format!("{error:#}"),
            "Startup crash recovery of the state databases failed"
        );
    })
}

fn recover_inner<H: Digest<OutputSize = U32> + Send + Sync>(
    nomt: &NomtStateDb<H>,
    flat: &mut FlatStateDb,
    ledger: &Arc<rockbound::DB>,
    accessory: &Arc<rockbound::DB>,
    faults: &Faults,
) -> anyhow::Result<RecoveryReport> {
    let live = flat.latest_version_and_root_live()?;
    let live_roots = root_of(live);

    // 1. Decide, writing nothing.
    let ledger_ahead = one_ahead(
        "ledger DB",
        crate::ledger::latest_version_and_root(ledger)?,
        live,
        |version| crate::ledger::root_at(ledger, version),
    )?;
    let accessory_ahead = one_ahead(
        "accessory DB",
        AccessoryDb::latest_version_and_root(accessory)?,
        live,
        |version| AccessoryDb::root_at(accessory, version),
    )?;
    let archival_ahead = flat.archival_ahead()?;
    // The roots of the interrupted commit, if a versioned database recorded them (all that did
    // must agree).
    let mut next_roots: Option<(&str, NomtRoots)> = None;
    for (name, ahead) in [
        ("ledger DB", ledger_ahead),
        ("accessory DB", accessory_ahead),
        ("flat archival DB", archival_ahead),
    ] {
        let Some((_, roots)) = ahead else {
            continue;
        };
        match next_roots {
            Some((first, first_roots)) => anyhow::ensure!(
                first_roots == roots,
                "the {first} and the {name} are both one version ahead of the flat live DB, \
                 with different roots ({first_roots} and {roots}). The state databases cannot \
                 be recovered"
            ),
            None => next_roots = Some((name, roots)),
        }
    }
    let next_roots = next_roots.map(|(_, roots)| roots);
    let mut nomt_rollbacks = Vec::new();
    for (namespace, step) in [
        (ProvableNamespace::Kernel, RecoveryStep::KernelNomt),
        (ProvableNamespace::User, RecoveryStep::UserNomt),
    ] {
        let current = namespace_root(nomt.root_hashes(), namespace);
        let expected = namespace_root(live_roots, namespace);
        if current == expected {
            continue;
        }
        if let Some(next_roots) = next_roots {
            let ahead = namespace_root(next_roots, namespace);
            anyhow::ensure!(
                current == ahead,
                "the NOMT {namespace:?} tree's root ({}) is neither the flat live DB's ({}, \
                 version {:?}) nor that of the interrupted commit's next version ({}). The state \
                 databases cannot be recovered (the tree is left as it is)",
                hex(current),
                hex(expected),
                live.map(|(version, _)| version),
                hex(ahead),
            );
        }
        nomt_rollbacks.push((namespace, step));
    }

    // 2. Roll back, in commit order.
    let mut rolled_back = Vec::new();
    for (namespace, step) in nomt_rollbacks {
        faults.hit(CommitPoint::Recovery(step))?;
        nomt.rollback_one(namespace)?;
        let root = namespace_root(nomt.root_hashes(), namespace);
        let expected = namespace_root(live_roots, namespace);
        anyhow::ensure!(
            root == expected,
            "after rolling back the last commit of the NOMT {namespace:?} tree, its root is {} \
             instead of the flat live DB's {} (version {:?}). The state databases cannot be \
             recovered",
            hex(root),
            hex(expected),
            live.map(|(version, _)| version),
        );
        rolled_back.push(step);
    }
    if let Some((version, _)) = ledger_ahead {
        faults.hit(CommitPoint::Recovery(RecoveryStep::Ledger))?;
        crate::ledger::rollback_version(ledger, version).context("rolling back the ledger DB")?;
        rolled_back.push(RecoveryStep::Ledger);
    }
    if let Some((version, _)) = accessory_ahead {
        faults.hit(CommitPoint::Recovery(RecoveryStep::Accessory))?;
        AccessoryDb::rollback_version(accessory, version)
            .context("rolling back the accessory DB")?;
        rolled_back.push(RecoveryStep::Accessory);
    }
    if let Some((version, _)) = archival_ahead {
        faults.hit(CommitPoint::Recovery(RecoveryStep::Archival))?;
        flat.rollback_archival(version)
            .context("rolling back the flat archival DB")?;
        rolled_back.push(RecoveryStep::Archival);
    }
    Ok(RecoveryReport {
        rolled_back,
        live: live.map(|(version, _)| version),
    })
}

fn hex(root: [u8; 32]) -> HexString<[u8; 32]> {
    HexString(root)
}

//! Nested scopes of a metered phase: writes that can be committed into the enclosing scope or
//! reverted (upstream `RevertableTxState`, `to_revertable`).
//!
//! [`MeteredRef::open_scope`] opens a scope inside the accessor's own (charging `scope_open`)
//! and returns its [`ScopeToken`]; [`MeteredRef::scoped`] narrows an accessor to it (the
//! scope's accessor lends that), and [`MeteredRef::close_scope`], called on the accessor that
//! opened it, commits or reverts it. A token is not `Clone`/`Copy`, has private fields and is
//! consumed by closing.
//!
//! A token is valid only in the metered phase that issued it: see [`ScopeToken`].
//!
//! # Misuse
//! Misuse never panics and never keeps writes it should not:
//! - closing a token that is not the innermost scope directly inside the accessor's (out of
//!   order, stale, or from another phase) fails with [`StateAccessError::ScopeMisuse`] and
//!   poisons the phase;
//! - a scope left open (its guard leaked: `ManuallyDrop`, `Box::leak`, which the `mem_forget`
//!   lint does not catch) is **reverted** by the next access through an enclosing accessor, and
//!   by [`MeteredTx::finalize`](super::MeteredTx::finalize): fail-closed, like dropping the
//!   guard;
//! - an accessor whose scope was closed or reverted that way, or narrowed to a token of another
//!   phase, fails with `ScopeMisuse`.
//!
//! The phase's poison is shared by all its scopes: reverting a scope does not clear it.

use std::marker::PhantomData;

use super::costs::StateGasMeter;
use super::error::StateAccessError;
use super::journal::Level;
use super::rights::AccessRights;
use super::tx::{Error, MeteredRef};
use crate::Storage;

/// The shared allocation behind a [`PhaseId`]: `Arc` where the target has pointer-sized
/// atomics (so a phase stays `Send`), `Rc` where it has none (such targets are
/// single-threaded).
#[cfg(target_has_atomic = "ptr")]
type Shared = std::sync::Arc<()>;
#[cfg(not(target_has_atomic = "ptr"))]
type Shared = std::rc::Rc<()>;

/// The identity of a metered phase: a heap allocation the phase and each of its scope tokens
/// hold a reference to, compared by address ([`is`](Self::is)). Two identities are the same
/// only if they come from the same [`new`](Self::new): an allocation's address is not reused
/// while any reference to it exists. Its address is never read as a value: it is not printed
/// (`Debug` shows `PhaseId(())`), ordered or hashed, and never reaches state, the witness or
/// gas.
#[derive(Debug, Clone)]
pub(crate) struct PhaseId(Shared);

impl PhaseId {
    /// A new identity, distinct from every other live one.
    pub(crate) fn new() -> Self {
        Self(Shared::new(()))
    }

    /// Whether `self` and `other` are the same identity.
    pub(crate) fn is(&self, other: &Self) -> bool {
        Shared::ptr_eq(&self.0, &other.0)
    }
}

/// The level of a token that names no scope (opening failed): depth `0` is never open.
const DEAD: Level = Level {
    depth: 0,
    serial: 0,
};

/// A nested scope opened by [`MeteredRef::open_scope`]. Close it with
/// [`MeteredRef::close_scope`] on the accessor that opened it; a token that is dropped instead
/// leaves the scope open until the next access through that accessor reverts it.
///
/// # Only in the phase that issued it
/// - **At run time**, a token carries the identity of the [`MeteredTx`](super::MeteredTx) that
///   issued it and a serial number unique within that phase. The identity is a shared heap
///   allocation of the phase that every token holds a reference to, compared by address, so it
///   cannot be reused while a token exists: a token never matches a scope of another phase,
///   whether that phase runs later on the same checkpoint, on another block's checkpoint, or on
///   another checkpoint alive at the same time (where depths and serials can be equal). The
///   identity is only ever compared: it never reaches state, the witness, gas or any other
///   consensus value, so the prover and the verifier behave the same.
/// - **At compile time**, a token is neither `Send` nor `Sync`, so safe code cannot keep it in
///   a `static` (a `static` must be `Sync`, and `Mutex`/`OnceLock` are `Sync` only over a
///   `Send` value; only a `static mut` is exempt, and it needs `unsafe`, which the workspace
///   forbids) or hand it to another thread:
///
/// ```compile_fail,E0277
/// use std::sync::Mutex;
///
/// use selendra_state::metered::ScopeToken;
///
/// static STASH: Mutex<Option<ScopeToken>> = Mutex::new(None);
/// ```
///
/// ```
/// use std::sync::Mutex;
///
/// use selendra_state::metered::ScopeEnd;
///
/// static STASH: Mutex<Option<ScopeEnd>> = Mutex::new(None);
/// ```
///
/// A lifetime tying the token to the phase's borrow is not used: the token would keep the
/// phase mutably borrowed for as long as it lives, so the scope it names could not be accessed
/// or closed (and a scope guard holding its parent could not be built). A token stashed in a
/// `thread_local!`, a `static mut` or a leaked box is still caught by the run-time identity.
#[must_use = "a scope that is never closed is reverted"]
#[derive(Debug)]
pub struct ScopeToken {
    /// The phase that issued it.
    phase: PhaseId,
    /// Depth `0` (never open): opening failed.
    level: Level,
    /// Neither `Send` nor `Sync`.
    local: PhantomData<*const ()>,
}

impl ScopeToken {
    /// The token's level, for the tests.
    #[cfg(test)]
    pub(super) fn level(&self) -> Level {
        self.level
    }
}

/// How [`MeteredRef::close_scope`] ends a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeEnd {
    /// Keep the scope's writes in the enclosing scope (which can still revert them).
    Commit,
    /// Drop the scope's writes.
    Revert,
}

impl<'a, St: Storage, M: StateGasMeter, R: AccessRights> MeteredRef<'a, St, M, R> {
    /// Opens a scope inside this accessor's (reverting deeper scopes left open first), charging
    /// `scope_open` before the scope is pushed, and returns its token.
    ///
    /// On a poisoned phase, through an accessor whose scope is no longer open, or if the
    /// charge is refused (out of gas), nothing is opened, the phase is poisoned (the failure
    /// is recorded as its first, if it is), and the token matches no scope: every later access
    /// fails with [`StateAccessError::Poisoned`] and the phase is reverted.
    ///
    /// Infallible, so that a scope guard (`selendra-modules-api`'s `RevertableTxState`) is
    /// built infallibly like upstream's `to_revertable`, and ported module code keeps its
    /// shape: the failure is never lost (it is the phase's recorded failure, reported by
    /// [`MeteredTx::finalize`](super::MeteredTx::finalize)), and the guard's first access
    /// fails.
    pub fn open_scope(&mut self) -> ScopeToken {
        let level = self.tx.open_scope(self.level).unwrap_or(DEAD);
        ScopeToken {
            phase: self.tx.id.clone(),
            level,
            local: PhantomData,
        }
    }

    /// Closes the scope of `token`, which must be open and directly inside this accessor's
    /// scope; scopes left open inside it are reverted first. [`ScopeEnd::Commit`] keeps its
    /// writes in this accessor's scope, [`ScopeEnd::Revert`] drops them. Not charged.
    ///
    /// # Errors
    /// - [`StateAccessError::Poisoned`] on a poisoned phase (the scope stays open; the whole
    ///   phase is reverted anyway).
    /// - [`StateAccessError::ScopeMisuse`], poisoning the phase, if this accessor's scope is no
    ///   longer open, or if `token`'s scope is not open directly inside it (closed out of
    ///   order, already closed, or another phase's).
    pub fn close_scope(&mut self, token: ScopeToken, end: ScopeEnd) -> Result<(), Error<M>> {
        if self.tx.failure.is_some() {
            return Err(StateAccessError::Poisoned);
        }
        let ours = token.phase.is(&self.tx.id);
        let journal = self.tx.scratchpad.journal_mut();
        let valid =
            ours && self.level.is_some_and(|level| {
                journal.is_open(level) && level.depth.checked_add(1) == Some(token.level.depth)
            }) && journal.is_open(token.level);
        if !valid {
            return Err(self.tx.fail(StateAccessError::ScopeMisuse));
        }
        journal.revert_above(token.level.depth);
        match end {
            ScopeEnd::Commit => journal.commit_top(),
            ScopeEnd::Revert => journal.revert_top(),
        }
        Ok(())
    }

    /// Narrows this accessor to the scope of `token`, which must be inside this accessor's:
    /// accesses through the result go into that scope (what a scope's accessor lends). If it
    /// is not (or this accessor's scope is no longer open, or `token` is another phase's),
    /// every access through the result fails with `ScopeMisuse`.
    pub fn scoped(self, token: &ScopeToken) -> Self {
        let inside = token.phase.is(&self.tx.id)
            && self.level.is_some_and(|level| {
                token.level.depth > level.depth && self.tx.scratchpad.journal().is_open(level)
            });
        Self {
            level: inside.then_some(token.level),
            ..self
        }
    }
}

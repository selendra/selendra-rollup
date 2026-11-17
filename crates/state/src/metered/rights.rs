//! Access rights of a metered phase, at the type level.
//!
//! The state transition function picks the rights when it builds a
//! [`MeteredTx`](super::MeteredTx) (its `R` parameter); every [`MeteredRef`](super::MeteredRef)
//! lent from it carries the same `R`, with no conversion to another one. The blanket
//! [`StateReader`](crate::StateReader)/[`StateWriter`](crate::StateWriter) impls over
//! [`Metered`](super::Metered) exist only for the namespaces the rights grant, so an accessor
//! cannot widen its rights, even by wrapping another one.
//!
//! | Rights | User | Kernel | Accessory |
//! |---|---|---|---|
//! | [`TxRights`] (transactions: the call, hooks) | read, write | read, write | write |
//! | [`PreExecRights`] (pre-execution: authentication, gas reservation) | read, write | – | – |
//!
//! No rights grant Accessory reads: accessory state is not provable, so the zk guest could not
//! answer them. Upstream's `test-utils` feature added them to the transaction accessors
//! (feature unification put them into every test build).
//!
//! The traits are sealed: only this module's markers implement them.

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::TxRights {}
    impl Sealed for super::PreExecRights {}
}

/// A set of access rights (a type-level marker). Sealed.
pub trait AccessRights: sealed::Sealed + std::fmt::Debug + Send + Sync + 'static {}

/// The rights grant [`User`](crate::User) reads.
pub trait ReadsUser: AccessRights {}
/// The rights grant [`Kernel`](crate::Kernel) reads.
pub trait ReadsKernel: AccessRights {}
/// The rights grant [`User`](crate::User) writes and deletes.
pub trait WritesUser: AccessRights {}
/// The rights grant [`Kernel`](crate::Kernel) writes and deletes.
pub trait WritesKernel: AccessRights {}
/// The rights grant [`Accessory`](crate::Accessory) writes and deletes (never reads).
pub trait WritesAccessory: AccessRights {}

/// The rights of a transaction's call and its hooks: User and Kernel read and write, Accessory
/// write (upstream `WorkingSet`).
#[derive(Debug)]
pub enum TxRights {}

impl AccessRights for TxRights {}
impl ReadsUser for TxRights {}
impl ReadsKernel for TxRights {}
impl WritesUser for TxRights {}
impl WritesKernel for TxRights {}
impl WritesAccessory for TxRights {}

/// The rights of pre-execution (authentication, the gas reservation): User read and write only
/// (upstream `PreExecWorkingSet`).
#[derive(Debug)]
pub enum PreExecRights {}

impl AccessRights for PreExecRights {}
impl ReadsUser for PreExecRights {}
impl WritesUser for PreExecRights {}

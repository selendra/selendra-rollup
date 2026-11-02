//! Types, traits and utilities used by the full node but not part of the rollup's state machine.
//!
//! This code is **never** compiled into the zk guest, so it can be non-deterministic,
//! access system resources or the network, write to disk, etc.

pub mod da;

//! Test helpers.

use std::path::Path;
use std::sync::{Condvar, Mutex, PoisonError};

/// How many tests may have databases open at once.
///
/// A test opens up to three RocksDB instances and two NOMT databases, and RocksDB preallocates
/// its write-ahead logs. With every test of the crate in parallel, the temporary directory
/// peaked at about 1 GB (measured), which fails when it is a small tmpfs; 4 at a time peaked at
/// about 0.5 GB.
const MAX_CONCURRENT: usize = 4;

static RUNNING: Mutex<usize> = Mutex::new(0);
static FREED: Condvar = Condvar::new();

/// A temporary directory for a test's databases; holds one of the [`MAX_CONCURRENT`] slots
/// until dropped.
pub(crate) struct TestDir {
    // Dropped (deleted) before the slot is freed.
    dir: tempfile::TempDir,
    _slot: Slot,
}

impl TestDir {
    pub(crate) fn path(&self) -> &Path {
        self.dir.path()
    }
}

struct Slot;

impl Drop for Slot {
    fn drop(&mut self) {
        let mut running = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
        *running = running.saturating_sub(1);
        FREED.notify_one();
    }
}

/// A new [`TestDir`], once a slot is free.
pub(crate) fn tempdir() -> TestDir {
    let mut running = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
    while *running >= MAX_CONCURRENT {
        running = FREED.wait(running).unwrap_or_else(PoisonError::into_inner);
    }
    *running += 1;
    drop(running);
    let slot = Slot;
    TestDir {
        dir: tempfile::tempdir().expect("create a temporary directory"),
        _slot: slot,
    }
}

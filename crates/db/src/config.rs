//! Configuration of the state databases ([`StateDbConfig`]).

use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};

/// Configuration of the state databases. Every field is required: there are no hidden defaults
/// and nothing to `expect` when the databases are opened (upstream's `RollupDbConfig` had
/// optional fields that panicked when missing).
///
/// Layout under [`path`](Self::path):
/// - `user_nomt/`, `kernel_nomt/`: the NOMT state trees (one per provable namespace);
/// - `state-db/`, `archival-state-db/`: the flat value store (live and archival RocksDB);
/// - `ledger/`: the ledger DB (RocksDB);
/// - `accessory/`: the accessory store (RocksDB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDbConfig {
    /// The parent directory of all the state databases.
    pub path: PathBuf,
    /// NOMT options of the user state tree.
    pub user: NomtNamespaceConfig,
    /// NOMT options of the kernel state tree.
    pub kernel: NomtNamespaceConfig,
    /// Size in bytes of the cache of hot user values in the flat store.
    pub user_state_cache_size: usize,
    /// Size in bytes of the cache of hot kernel values in the flat store (upstream hard-coded
    /// 100 000 bytes, about 186 entries).
    pub kernel_state_cache_size: usize,
}

/// NOMT options of one state tree. See [`nomt::Options`] for each option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NomtNamespaceConfig {
    /// Number of concurrent commit workers (at most 64 are used).
    pub commit_concurrency: NonZeroUsize,
    /// Number of hash-table buckets. A database is created with this many. An existing database
    /// with fewer is grown to this many when it is opened; one with more fails to open
    /// (shrinking is not supported).
    pub hashtable_buckets: NonZeroU32,
    /// Whether to allocate the hash-table file up front.
    pub preallocate_ht: bool,
    /// Page cache size in MiB.
    pub page_cache_size: usize,
    /// Leaf cache size in MiB.
    pub leaf_cache_size: usize,
    /// Number of upper page-tree levels kept in memory permanently (level 2 is about 16 MiB,
    /// level 3 about 1 GiB).
    pub page_cache_upper_levels: usize,
}

impl NomtNamespaceConfig {
    /// Small settings for tests: 500 buckets, no preallocation, 16 MiB caches, 2 commit
    /// workers.
    pub fn for_tests() -> Self {
        Self {
            commit_concurrency: NonZeroUsize::new(2).expect("2 is not zero"),
            hashtable_buckets: NonZeroU32::new(500).expect("500 is not zero"),
            preallocate_ht: false,
            page_cache_size: 16,
            leaf_cache_size: 16,
            page_cache_upper_levels: 2,
        }
    }

    /// The NOMT options of this tree, stored at `path`. Rollback of the last commit is enabled
    /// (crash recovery of the two trees, which are committed one after the other).
    pub(crate) fn nomt_options(&self, path: &Path) -> nomt::Options {
        let mut options = nomt::Options::new();
        options.path(path);
        options.rollback(true);
        options.max_rollback_log_len(1);
        options.metrics(false);
        options.commit_concurrency(self.commit_concurrency.get());
        options.hashtable_buckets(self.hashtable_buckets.get());
        options.preallocate_ht(self.preallocate_ht);
        options.page_cache_size(self.page_cache_size);
        options.leaf_cache_size(self.leaf_cache_size);
        options.page_cache_upper_levels(self.page_cache_upper_levels);
        options
    }
}

impl StateDbConfig {
    /// Settings for tests in `path`: [`NomtNamespaceConfig::for_tests`] for both trees and
    /// 1 MB value caches.
    pub fn for_tests(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            user: NomtNamespaceConfig::for_tests(),
            kernel: NomtNamespaceConfig::for_tests(),
            user_state_cache_size: 1_000_000,
            kernel_state_cache_size: 1_000_000,
        }
    }

    /// The directory of the user state tree.
    pub fn user_nomt_path(&self) -> PathBuf {
        self.path.join("user_nomt")
    }

    /// The directory of the kernel state tree.
    pub fn kernel_nomt_path(&self) -> PathBuf {
        self.path.join("kernel_nomt")
    }
}

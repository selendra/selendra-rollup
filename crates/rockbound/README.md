# Rockbound

A copy of [Sovereign Labs' rockbound](https://github.com/sovereign-labs/rockbound) at rev
`0aa43d4e581e047ba8d8e7a662ec6ade32b2cae3` (crate version 0.1.0), with fixes. It is
Apache-2.0 licensed (see `LICENSE`, `NOTICE`), and parts of it are derived from Aptos'
`schemadb`. The selendra node uses it as the flat (value) store under NOMT.

## Changes from upstream

Fixes (regression tests in `tests/versioned_db_inner/fixes.rs`):
- **Historical reads next to longer or shorter keys.** A historical read of `K` seeks backward
  from `K ‖ version` and could land on a row of a longer key `K ‖ s` or of a shorter key whose
  row starts with `K`. Upstream then returned `None`, so, for example, a `StateVec` length read
  as absent once element 0 had been written. Those rows are now skipped
  (`VersionedDB::get_versioned_internal`).
- **Empty values versus deletes.** Upstream archived a delete as the empty value, so an empty
  value (such as the encoding of `()`) read back from the archive as deleted. Archival values are
  now tagged: `0x01 ‖ value` for a put and `0x00` for a delete. Any other archival value is
  reported as corruption. The on-disk format is in the module docs of `versioned_db`. **It is not
  compatible with databases written by upstream rockbound.**
- **Read errors.** Upstream ended an iteration when RocksDB reported an error (I/O, corruption),
  so failed reads looked like absent data: historical reads returned `Ok(None)`, pruning saw no
  keys, and prefix iteration stopped early. These iterators now yield the error, once, and then
  end. The iterators are `RawDbIter`, the `DeltaReader` iterators, `VersionedDbIterator`,
  the pruning-key iterators and `SchemaIterator`. `SchemaIterator` also ends after a row that
  does not decode (a seek resumes it): upstream did not advance past the row, so `next` returned
  the same `Err` forever.
- **Corrupt data is an error, not a panic.** An undecodable key or value in `VersionedDbIterator`,
  an undecodable pruning key, and an undecodable entry in `DeltaReader::get_n_from_first_match`
  / `collect_in_range` now produce an `Err`. Upstream panicked, or silently skipped the entry.
- **Stale readers of the empty DB.** A prefix iterator errors when a version newer than the
  reader's is committed. Upstream compared `committed > reader_version.unwrap_or(0)`, so a reader
  taken before version 0 was committed iterated version 0's rows, while its point reads still
  saw the empty DB. It now compares the versions as options, so the empty reader (`None`) is
  older than any committed version (`VersionedDeltaReader::iter_with_prefix_and_cursor`).
- **Rollback.** `update_versioned_db_batch` without `is_commit` now removes the version's
  archival rows for puts too. Upstream wrote the puts again, live table and cache included.

API and scope:
- Iterator items are `anyhow::Result<..>`. `VersionedDbIterator` yields `(key, value)`; upstream
  yielded `(key, Option<value>)`, and the option was always `Some`.
- Removed: the async APIs (`*_async`, tokio); the prometheus metrics (`VersionedDbMetrics`,
  `update_metrics`); the `arbitrary` feature (proptest impls are now test-only);
  `DB::write_versioned_schemas`; and the `bindgen-runtime` feature (the workspace sets it on
  `rocksdb`).
- New: `DeltaReader::collect_keys_in_range(range, limit)`, the keys of the first `limit` rows
  of a range without their values (none is decoded or copied, from the DB or the snapshots),
  for scans of tables with large values. An inverted range is an `Err` (the snapshots'
  `BTreeMap::range` would panic).
- Removed the panic on a zero-length versioned key. With tagged archival values, a zero-length
  key cannot be confused with a delete.
- Tests: upstream's `DeltaReader` proptests discarded the result of their checks, so a failing
  check never failed a test. The checks now count, and two wrong expectations they hid are fixed.
  The async tests are now sync. `tests/cache_test.rs`, all commented out upstream, is not copied.
- Edition 2024, the workspace lints, and the workspace's dependency versions (`rocksdb` 0.25,
  `quick_cache` 0.7).

## Upstream README

This package is a low-level wrapper transforming [RocksDB](https://rocksdb.org/) from a byte-oriented key value store into a
type-oriented store. It's adapted from a similar package in Aptos-Core.

The most important concept exposed by Rockbound is a `Schema`, which maps a column-family name
codec's for the key and value.

```rust
pub trait Schema  {
    /// The column family name associated with this struct.
    /// Note: all schemas within the same DB must have distinct column family names.
    const COLUMN_FAMILY_NAME: &'static str;

    /// Type of the key.
    type Key: KeyCodec<Self>;

    /// Type of the value.
    type Value: ValueCodec<Self>;
}
```

Using this schema, we can write generic functions for storing and fetching typed data, and ensure that
it's always encoded/decoded in the way we expect.

```rust
impl SchemaDB {
	pub fn put<S: Schema>(&self, key: &impl KeyCodec<S>, value: &impl ValueCodec<S>) -> Result<()> {
		let key_bytes = key.encode_key()?;
        let value_bytes = value.encode_value()?;
		self.rocks_db_handle.put(S::COLUMN_FAMILY_NAME, key_bytes, value_bytes)
	}
}
```

To actually store and retrieve data, all we need to do is to implement a Schema:

```rust
pub struct AccountBalanceSchema;

impl Schema for AccountBalanceSchema {
	const COLUMN_FAMILY_NAME: &str = "account_balances";
	type Key = Account;
	type Value = u64;
}

impl KeyCodec<AccountBalanceSchema> for Account {
	fn encode_key(&self) -> Vec<u8> {
		bincode::to_vec(self)
	}

	fn decode_key(key: Vec<u8>) -> Self {
		// elided
	}
}

impl ValueCode<AccountBlanceSchema> for u64 {
	// elided
}
```

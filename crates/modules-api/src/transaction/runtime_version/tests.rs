//! The version table and the runtime commitment. The resolution tests are upstream's chain-hash
//! override tests (`src/tests.rs`), on version windows: upstream's `[start, end)` override
//! with a `grace_period` is a window ending at `end + grace_period`, overlapping the next one.

use super::*;

const HASH_1: SchemaHash = [0x11; 32];
const HASH_2: SchemaHash = [0x22; 32];
const HASH_3: SchemaHash = [0x33; 32];
const DEFAULT_HASH: SchemaHash = [0xDD; 32];

fn h(height: u64) -> RollupHeight {
    RollupHeight::new(height)
}

fn table(windows: &[VersionWindow]) -> VersionTable<'_> {
    VersionTable::new(windows).unwrap()
}

/// The primary version at `height` and the one in its grace period.
fn resolved(table: &VersionTable<'_>, height: u64) -> (u32, Option<u32>) {
    (
        table.primary_at(h(height)).spec_version,
        table.grace_at(h(height)).map(|window| window.spec_version),
    )
}

/// Known answers computed independently (`python3 -I`: `hashlib.sha256(b"SELENDRA/runtime/v1"
/// + struct.pack("<Q", chain_id) + struct.pack("<I", spec_version) + schema_hash)`).
#[test]
fn runtime_commitment_known_answers() {
    let schema: SchemaHash = std::array::from_fn(|i| u8::try_from(i).unwrap());
    let cases = [
        (
            1961,
            1,
            schema,
            "898b8a52faf3f07978fb7a4aed043add96ab4678ee2c021e1abe29b0b4898346",
        ),
        (
            1961,
            1,
            HASH_1,
            "e3fecf3f20cbff65f09446dbccabc194a5314e7754e4a1b6261cdbca984e4d1d",
        ),
        (
            1962,
            1,
            HASH_1,
            "6eddff9fe4d6b56a6dbbcac636c231b6ece2be3947c30d68acb448aaf98eaf05",
        ),
        (
            1961,
            2,
            HASH_1,
            "9c2c2cb78f2cdb10eadfbae934eee53f91f605e9cfaab10d0b1ffc8cb6f38166",
        ),
    ];
    for (chain_id, spec_version, schema_hash, expected) in cases {
        let commitment = RuntimeCommitment::new(chain_id, spec_version, &schema_hash);
        assert_eq!(hex::encode(commitment.as_bytes()), expected);
        assert_eq!(
            VersionWindow::open(spec_version, schema_hash, 0).commitment(chain_id),
            commitment
        );
        // borsh: the 32 bytes; JSON: `0x` + hex.
        assert_eq!(borsh::to_vec(&commitment).unwrap(), commitment.as_bytes());
        let json = serde_json::to_string(&commitment).unwrap();
        assert_eq!(json, format!("\"0x{expected}\""));
        assert_eq!(
            serde_json::from_str::<RuntimeCommitment>(&json).unwrap(),
            commitment
        );
        assert!(
            serde_json::from_str::<RuntimeCommitment>(&json.to_uppercase().replace("0X", "0x"))
                .is_err()
        );
    }
}

#[test]
fn the_table_is_built_in_a_const() {
    const VERSIONS: VersionTable<'static> = VersionTable::new_or_panic(&[
        VersionWindow::closed(1, HASH_1, 0, 150),
        VersionWindow::open(2, HASH_2, 100),
    ]);
    const CHECKED: Result<(), VersionTableError> = check_version_table(VERSIONS.windows());
    const REJECTED: Result<VersionTable<'static>, VersionTableError> = VersionTable::new(&[]);
    assert_eq!(CHECKED, Ok(()));
    assert_eq!(REJECTED, Err(VersionTableError::Empty));
    assert_eq!(resolved(&VERSIONS, 120), (2, Some(1)));
}

/// Upstream: `test_empty_overrides_returns_default`. There is no default chain hash: a table
/// with no window is rejected, and one open window from genesis accepts its version at every
/// height.
#[test]
fn empty_table_is_rejected_and_one_window_covers_every_height() {
    assert_eq!(VersionTable::new(&[]), Err(VersionTableError::Empty));
    let windows = [VersionWindow::open(1, DEFAULT_HASH, 0)];
    let table = table(&windows);
    for height in [0, 1000, u64::MAX] {
        assert_eq!(resolved(&table, height), (1, None));
        assert_eq!(table.resolve(h(height), 1), Some(&windows[0]));
        assert_eq!(table.resolve(h(height), 2), None);
    }
}

/// Upstream: `test_single_override_starting_at_zero`.
#[test]
fn single_window_before_the_current_one() {
    let windows = [
        VersionWindow::closed(1, HASH_1, 0, 1000),
        VersionWindow::open(2, DEFAULT_HASH, 1000),
    ];
    let table = table(&windows);
    // At the start (inclusive), within, and at the end - 1: version 1.
    for height in [0, 500, 999] {
        assert_eq!(resolved(&table, height), (1, None));
        assert_eq!(table.resolve(h(height), 1), Some(&windows[0]));
        assert_eq!(table.resolve(h(height), 2), None);
    }
    // At the end (exclusive) and after: version 2 only.
    for height in [1000, 2000] {
        assert_eq!(resolved(&table, height), (2, None));
        assert_eq!(table.resolve(h(height), 1), None);
        assert_eq!(table.resolve(h(height), 2), Some(&windows[1]));
    }
}

/// Upstream: `test_multiple_contiguous_overrides`.
#[test]
fn contiguous_windows() {
    let windows = [
        VersionWindow::closed(1, HASH_1, 0, 100),
        VersionWindow::closed(2, HASH_2, 100, 200),
        VersionWindow::closed(3, HASH_3, 200, 300),
        VersionWindow::open(4, DEFAULT_HASH, 300),
    ];
    let table = table(&windows);
    for (height, version) in [(50, 1), (100, 2), (150, 2), (250, 3), (300, 4), (5000, 4)] {
        assert_eq!(resolved(&table, height), (version, None), "{height}");
    }
    // The boundary belongs to the newer window only.
    assert_eq!(table.resolve(h(100), 1), None);
    assert_eq!(table.resolve(h(99), 1), Some(&windows[0]));
}

/// Upstream: `test_override_contains_method`.
#[test]
fn window_contains() {
    let window = VersionWindow::closed(1, HASH_1, 100, 200);
    assert!(!window.contains(h(99)));
    assert!(window.contains(h(100)));
    assert!(window.contains(h(150)));
    assert!(window.contains(h(199)));
    assert!(!window.contains(h(200)));
    assert!(!window.contains(h(201)));
    let open = VersionWindow::open(1, HASH_1, 100);
    assert!(!open.contains(h(99)));
    assert!(open.contains(h(u64::MAX)));
}

/// Upstream: `test_grace_period_single_override` (`[0, 100)` with a 50-block grace period).
#[test]
fn grace_period_of_one_window() {
    let windows = [
        VersionWindow::closed(1, HASH_1, 0, 150),
        VersionWindow::open(2, DEFAULT_HASH, 100),
    ];
    let table = table(&windows);
    // Within the primary range: version 1 only.
    assert_eq!(resolved(&table, 50), (1, None));
    // From the upgrade height to the end of the grace period: version 2, and version 1 too.
    assert_eq!(resolved(&table, 100), (2, Some(1)));
    assert_eq!(resolved(&table, 125), (2, Some(1)));
    assert_eq!(resolved(&table, 149), (2, Some(1)));
    assert_eq!(table.resolve(h(149), 1), Some(&windows[0]));
    assert_eq!(table.resolve(h(149), 2), Some(&windows[1]));
    // At the end of the grace period (exclusive): version 2 only.
    assert_eq!(resolved(&table, 150), (2, None));
    assert_eq!(table.resolve(h(150), 1), None);
}

/// Upstream: `test_grace_period_with_multiple_overrides`.
#[test]
fn grace_periods_of_several_windows() {
    let windows = [
        VersionWindow::closed(1, HASH_1, 0, 150),
        VersionWindow::closed(2, HASH_2, 100, 225),
        VersionWindow::open(3, DEFAULT_HASH, 200),
    ];
    let table = table(&windows);
    assert_eq!(resolved(&table, 50), (1, None));
    assert_eq!(resolved(&table, 100), (2, Some(1)));
    assert_eq!(resolved(&table, 125), (2, Some(1)));
    assert_eq!(resolved(&table, 150), (2, None));
    assert_eq!(resolved(&table, 200), (3, Some(2)));
    assert_eq!(resolved(&table, 225), (3, None));
}

/// Upstream: `test_in_grace_period_method` and `test_zero_grace_period_means_no_grace`. A grace
/// period is where a window overlaps the next one; windows that only touch have none.
#[test]
fn grace_period_is_the_overlap_with_the_next_window() {
    let windows = [
        VersionWindow::closed(1, HASH_1, 0, 250),
        VersionWindow::open(2, HASH_2, 200),
    ];
    let table = table(&windows);
    assert_eq!(table.grace_at(h(199)), None);
    for height in [200, 225, 249] {
        assert_eq!(table.grace_at(h(height)), Some(&windows[0]));
    }
    assert_eq!(table.grace_at(h(250)), None);
    assert_eq!(table.grace_at(h(300)), None);

    let touching = [
        VersionWindow::closed(1, HASH_1, 0, 200),
        VersionWindow::open(2, HASH_2, 200),
    ];
    let table = self::table(&touching);
    for height in [0, 199, 200, 250] {
        assert_eq!(table.grace_at(h(height)), None);
    }
}

/// Upstream: `allows_identical_hashes_during_overlapping_validity`. Two versions may share a
/// schema hash (an upgrade that changed no type); they are still selected by number, and their
/// commitments differ.
#[test]
fn identical_schema_hashes_may_overlap() {
    let windows = [
        VersionWindow::closed(1, HASH_1, 0, 150),
        VersionWindow::open(2, HASH_1, 100),
    ];
    let table = table(&windows);
    assert_eq!(table.resolve(h(120), 1), Some(&windows[0]));
    assert_eq!(table.resolve(h(120), 2), Some(&windows[1]));
    assert_ne!(windows[0].commitment(1961), windows[1].commitment(1961));
}

// Regressions of upstream's chain-hash override bugs

/// P5-39 (regression): upstream selected a transaction's chain hash by a 64-bit fragment of it,
/// so two hashes valid at once and sharing the fragment were indistinguishable (rejected by a
/// separate check, `rejects_colliding_fragments_*`, which had to be kept in step with every
/// override). Versions are selected by number and the commitment covers the whole schema hash:
/// schema hashes differing only after their first 8 bytes give distinct versions and distinct
/// commitments.
#[test]
fn colliding_fragments_resolve_by_version() {
    let first = [0xAA; 32];
    let mut second = first;
    second[31] ^= 1;
    let windows = [
        VersionWindow::closed(1, first, 0, 150),
        VersionWindow::open(2, second, 100),
    ];
    let table = table(&windows);
    assert_eq!(table.resolve(h(120), 1).unwrap().schema_hash, first);
    assert_eq!(table.resolve(h(120), 2).unwrap().schema_hash, second);
    assert_ne!(
        windows[0].commitment(1961),
        RuntimeCommitment::new(1961, 1, &second)
    );
    assert_ne!(
        RuntimeCommitment::new(1961, 1, &first),
        RuntimeCommitment::new(1961, 1, &second)
    );
}

/// P5-39 (regression): upstream's grace period could run past the next override into the one
/// after it (`rejects_colliding_fragments_across_long_grace_period` only rejected that when the
/// fragments collided), so three chain hashes were valid at once and an old schema was accepted
/// long after two upgrades. A window may overlap only the next one.
#[test]
fn overlap_outside_grace_rejected() {
    // Upstream's case: `[0, 100)` with a 250-block grace period, then `[100, 200)` and
    // `[200, 300)`; the second window is extended to 400 here, so only this rule is broken (as
    // upstream wrote it, it would also end before the first one does).
    assert_eq!(
        VersionTable::new(&[
            VersionWindow::closed(1, HASH_1, 0, 350),
            VersionWindow::closed(2, HASH_2, 100, 400),
            VersionWindow::open(3, HASH_3, 200),
        ]),
        Err(VersionTableError::OverlapOutsideGrace {
            first: 0,
            second: 2
        })
    );
    // The smallest such overlap: one height with three versions.
    assert_eq!(
        VersionTable::new(&[
            VersionWindow::closed(1, HASH_1, 0, 201),
            VersionWindow::closed(2, HASH_2, 100, 300),
            VersionWindow::open(3, HASH_3, 200),
        ]),
        Err(VersionTableError::OverlapOutsideGrace {
            first: 0,
            second: 2
        })
    );
    // Its accepted twin: window 1 ends where window 3 starts.
    let windows = [
        VersionWindow::closed(1, HASH_1, 0, 200),
        VersionWindow::closed(2, HASH_2, 100, 300),
        VersionWindow::open(3, HASH_3, 200),
    ];
    let table = table(&windows);
    assert_eq!(resolved(&table, 199), (2, Some(1)));
    assert_eq!(resolved(&table, 200), (3, Some(2)));
    // A window inside the previous one (the old version accepted again after the new one).
    assert_eq!(
        VersionTable::new(&[
            VersionWindow::closed(1, HASH_1, 0, 300),
            VersionWindow::closed(2, HASH_2, 100, 200),
            VersionWindow::open(3, HASH_3, 300),
        ]),
        Err(VersionTableError::EndsBeforePrevious { index: 1 })
    );
}

/// Every other rule of the table.
#[test]
fn table_rules() {
    let cases: [(&[VersionWindow], VersionTableError); 8] = [
        (
            &[VersionWindow::open(1, HASH_1, 1)],
            VersionTableError::FirstNotAtGenesis,
        ),
        (
            &[VersionWindow::closed(1, HASH_1, 0, 10)],
            VersionTableError::LastWindowEnds { index: 0 },
        ),
        (
            &[
                VersionWindow::open(1, HASH_1, 0),
                VersionWindow::open(2, HASH_2, 10),
            ],
            VersionTableError::OpenBeforeLast { index: 0 },
        ),
        (
            &[
                VersionWindow::closed(1, HASH_1, 0, 0),
                VersionWindow::open(2, HASH_2, 0),
            ],
            VersionTableError::EmptyWindow { index: 0 },
        ),
        (
            &[
                VersionWindow::closed(1, HASH_1, 0, 10),
                VersionWindow::open(2, HASH_2, 0),
            ],
            VersionTableError::NotOrdered { index: 1 },
        ),
        (
            &[
                VersionWindow::closed(1, HASH_1, 0, 10),
                VersionWindow::open(2, HASH_2, 11),
            ],
            VersionTableError::Gap { index: 1 },
        ),
        // Versions are distinct and increase.
        (
            &[
                VersionWindow::closed(1, HASH_1, 0, 10),
                VersionWindow::open(1, HASH_2, 10),
            ],
            VersionTableError::VersionNotIncreasing { index: 1 },
        ),
        (
            &[
                VersionWindow::closed(2, HASH_1, 0, 10),
                VersionWindow::open(1, HASH_2, 10),
            ],
            VersionTableError::VersionNotIncreasing { index: 1 },
        ),
    ];
    for (windows, error) in cases {
        assert_eq!(check_version_table(windows), Err(error), "{windows:?}");
        assert_eq!(VersionTable::new(windows), Err(error));
        assert!(!error.to_string().is_empty());
        assert!(error.rule().starts_with("invalid version table: "));
    }
}

/// Valid tables built from arbitrary steps, window by window: the first starts at genesis; each
/// later one starts after the previous one starts and no earlier than the one two back ends,
/// up to the end of the previous one (so it overlaps it, its grace period, or follows it), and
/// ends after the previous one ends; versions increase; the last is open.
fn valid_windows(raw: &[(u64, u64, u32)]) -> Vec<VersionWindow> {
    let mut windows: Vec<VersionWindow> = Vec::new();
    let mut version = 0;
    for (index, &(start_step, length, version_step)) in raw.iter().enumerate() {
        let from = match index {
            0 => 0,
            _ => {
                let previous = &windows[index - 1];
                let earliest = previous.from_height.get() + 1;
                let earliest = match index {
                    1 => earliest,
                    _ => earliest.max(windows[index - 2].until_height.unwrap().get()),
                };
                let latest = previous.until_height.unwrap().get();
                earliest + start_step % (latest - earliest + 1)
            }
        };
        let after = windows
            .last()
            .map_or(from, |previous| previous.until_height.unwrap().get());
        version += version_step + u32::from(index > 0);
        windows.push(VersionWindow::closed(
            version,
            HASH_1,
            from,
            after + 1 + length,
        ));
    }
    if let Some(last) = windows.last_mut() {
        last.until_height = None;
    }
    windows
}

/// The generator covers what the property is about: tables with several windows, with and
/// without a grace period between two of them.
#[test]
fn generated_tables_have_grace_periods() {
    let overlapping = valid_windows(&[(0, 9, 0), (3, 0, 0), (0, 0, 0)]);
    assert_eq!(
        overlapping,
        [
            VersionWindow::closed(0, HASH_1, 0, 10),
            VersionWindow::closed(1, HASH_1, 4, 11),
            VersionWindow::open(2, HASH_1, 10),
        ]
    );
    assert_eq!(resolved(&table(&overlapping), 5), (1, Some(0)));
    let following = valid_windows(&[(0, 4, 1), (4, 2, 2)]);
    assert_eq!(
        following,
        [
            VersionWindow::closed(1, HASH_1, 0, 5),
            VersionWindow::open(4, HASH_1, 5),
        ]
    );
    assert_eq!(resolved(&table(&following), 4), (1, None));
}

/// Generated valid tables (every one accepted: a generator that drifts fails here): every
/// height (around each boundary) has exactly one primary version and at most one other, and
/// `resolve` agrees with `contains` (an independent oracle).
#[test_strategy::proptest]
fn valid_tables_resolve_consistently(
    #[strategy(proptest::collection::vec((0u64..40, 0u64..40, 0u32..4), 1..6))] raw: Vec<(
        u64,
        u64,
        u32,
    )>,
) {
    let windows = valid_windows(&raw);
    let table = VersionTable::new(&windows).unwrap_or_else(|error| panic!("{error}: {windows:?}"));
    check_resolution(&table, &windows);
}

/// Arbitrary tables (mostly rejected): building one never panics, and any accepted one
/// resolves consistently.
#[test_strategy::proptest]
fn arbitrary_tables_resolve_consistently(
    #[strategy(proptest::collection::vec((0u64..40, 0u64..40, 0u32..4), 1..5))] raw: Vec<(
        u64,
        u64,
        u32,
    )>,
) {
    let mut windows = Vec::new();
    let mut from = 0;
    let mut version = 0;
    for (start_step, length, version_step) in &raw {
        from += start_step;
        version += version_step;
        windows.push(VersionWindow::closed(version, HASH_1, from, from + length));
    }
    if let Some(last) = windows.last_mut() {
        last.until_height = None;
    }
    if let Ok(table) = VersionTable::new(&windows) {
        check_resolution(&table, &windows);
    }
}

fn check_resolution(table: &VersionTable<'_>, windows: &[VersionWindow]) {
    let mut heights: Vec<u64> = windows
        .iter()
        .flat_map(|window| {
            let from = window.from_height.get();
            let until = window.until_height.map_or(from + 1, |until| until.get());
            [from.saturating_sub(1), from, until.saturating_sub(1), until]
        })
        .collect();
    heights.push(u64::MAX);
    for height in heights {
        let accepted: Vec<&VersionWindow> = windows
            .iter()
            .filter(|window| window.contains(h(height)))
            .collect();
        assert!((1..=2).contains(&accepted.len()), "{height}: {accepted:?}");
        assert_eq!(table.primary_at(h(height)), *accepted.last().unwrap());
        assert_eq!(
            table.grace_at(h(height)),
            (accepted.len() == 2).then(|| accepted[0])
        );
        for window in windows {
            assert_eq!(
                table.resolve(h(height), window.spec_version),
                window.contains(h(height)).then_some(window)
            );
        }
    }
}

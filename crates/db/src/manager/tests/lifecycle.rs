//! Upstream's generic storage manager tests (`storage_manager/tests/generic_tests.rs`) on one
//! fork, and regression tests of upstream's manager bugs (B1–B5).

use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use selendra_interface::node::storage::FinalizedBlock;

use super::*;
use crate::harness::{block_hash, header_slot_info};
use crate::ledger::{SlotContents, SlotInfo};
use crate::{CommitPoint, NomtRoots, RecoveryStep, WitnessMode, fail_at};

/// Upstream `linear_progression`: one block per height, finalized `finality` blocks later. At
/// every height, the finalized state, the state for the next block and the state after it see
/// exactly their blocks' values, ledger slots and root (upstream checked the values only).
fn linear_progression(to_height: u64, finality: u64) {
    let mut m = Manager::new();
    let mut chain: Vec<TestHeader> = Vec::new();
    let mut roots: Vec<Root> = Vec::new();
    let root_at = |roots: &[Root], len: usize| {
        len.checked_sub(1)
            .map_or(Root::PRE_GENESIS, |last| roots[last])
    };
    let finality_len = usize::try_from(finality).unwrap();
    for height in 1..=to_height {
        // The finalized state ("bootstrap" upstream).
        let finalized = chain.len().saturating_sub(finality_len);
        verify_finalized(&mut m, &chain[..finalized], root_at(&roots, finalized));
        if let Some(last) = finalized.checked_sub(1) {
            verify_after(
                &mut m,
                &chain[last].clone(),
                &chain[..finalized],
                roots[last],
            );
        }

        // The state for the block, then its changes.
        let hdr = TestHeader::linear(height);
        let (storage, ledger) = m.create_state_for(&hdr).unwrap();
        verify(&storage, &ledger, &chain, root_at(&roots, chain.len()));
        let (change_set, ledger_change_set, root) = changes(storage, &ledger, &hdr);
        m.save_change_set(&hdr, change_set, ledger_change_set)
            .unwrap();
        chain.push(hdr.clone());
        roots.push(root);

        // The state after it ("API storage" upstream).
        verify_after(&mut m, &hdr, &chain, root);

        if let Some(final_height) = height.checked_sub(finality)
            && final_height > 0
        {
            m.finalize(&TestHeader::linear(final_height)).unwrap();
            assert_eq!(
                m.latest_version(),
                Some(version_of(&TestHeader::linear(final_height)))
            );
        }
        assert_eq!(m.check_invariants(), m.unfinalized_count());
    }
    assert_eq!(finality == 0, m.unfinalized_count() == 0);
    assert_eq!(
        m.unfinalized_count(),
        usize::try_from(finality.min(to_height)).unwrap()
    );
}

#[test]
fn linear_progression_finality_0() {
    linear_progression(8, 0);
}

#[test]
fn linear_progression_finality_1() {
    linear_progression(8, 1);
}

#[test]
fn linear_progression_finality_4() {
    linear_progression(9, 4);
}

#[test]
fn linear_progression_finality_5() {
    linear_progression(10, 5);
}

#[test]
fn linear_progression_finality_6() {
    linear_progression(10, 6);
}

#[test]
fn linear_progression_finality_10() {
    linear_progression(10, 10);
}

/// Upstream `calls_on_empty`: saving or finalizing an unknown block on an empty manager is an
/// error, and nothing changes; the empty state is the finalized state.
#[test]
fn calls_on_empty() {
    let mut m = Manager::new();
    assert_eq!(m.finalized(), None);
    let hdr = TestHeader::linear(1);
    let (storage, ledger) = m.create_finalized_state().unwrap();
    verify(&storage, &ledger, &[], Root::PRE_GENESIS);
    let (change_set, ledger_change_set, _) = changes(storage, &ledger, &hdr);
    let err = err_string(m.save_change_set(&hdr, change_set, ledger_change_set));
    assert!(err.contains("was not registered"), "{err}");
    let err = err_string(m.finalize(&hdr));
    assert!(err.contains("not an uncommitted block"), "{err}");
    let err = err_string(m.create_state_after(&hdr));
    assert!(
        err.contains("neither a saved block nor the finalized"),
        "{err}"
    );
    assert_eq!(m.unfinalized_count(), 0);
    assert_eq!(m.check_invariants(), 0);
    assert_eq!(m.latest_version(), None);
}

/// Upstream `double_create_storage`, with checks: the same state each time (version and root),
/// no new block registered; storages for execution record a witness as configured, the others
/// never do (critique #9: upstream turned it off for them too, the plan had not).
#[test]
fn double_create_storage() {
    let mut m = Manager::with_config(|config| config.witness = WitnessMode::On);
    let h1 = TestHeader::linear(1);
    let h2 = TestHeader::linear(2);
    let (first, _) = m.create_finalized_state().unwrap();
    let (second, _) = m.create_finalized_state().unwrap();
    assert_eq!(first.witness_mode(), WitnessMode::Off);
    assert!(first.is_empty() && second.is_empty());

    let root = write(&mut m, &h1);
    let (first, _) = m.create_state_for(&h2).unwrap();
    let (second, _) = m.create_state_for(&h2).unwrap();
    assert_eq!(m.unfinalized_count(), 2);
    for storage in [&first, &second] {
        assert_eq!(storage.witness_mode(), WitnessMode::On);
        assert_eq!(storage.latest_version(), SlotNumber::GENESIS);
        assert_eq!(storage.root().unwrap(), root);
    }
    let (change_set, ledger_change_set, root2) = {
        let (storage, ledger) = m.create_state_for(&h2).unwrap();
        changes(storage, &ledger, &h2)
    };
    m.save_change_set(&h2, change_set, ledger_change_set)
        .unwrap();
    for _ in 0..2 {
        let (after, _) = m.create_state_after(&h2).unwrap();
        assert_eq!(after.witness_mode(), WitnessMode::Off);
        assert_eq!(after.latest_version(), SlotNumber::new(1));
        assert_eq!(after.root().unwrap(), root2);
    }
    m.finalize(&h1).unwrap();
    let (finalized, _) = m.create_state_after(&h1).unwrap();
    assert_eq!(finalized.witness_mode(), WitnessMode::Off);
    let (finalized, _) = m.create_finalized_state().unwrap();
    assert_eq!(finalized.witness_mode(), WitnessMode::Off);
    assert_eq!(m.unfinalized_count(), 1);
    assert_eq!(m.check_invariants(), 1);
}

/// Upstream `unknown_block_cannot_be_saved`, strengthened: a block's changes are saved only once
/// `create_state_for` registered it (B2), with the same parent.
#[test]
fn unknown_block_cannot_be_saved() {
    let mut m = Manager::new();
    let h1 = TestHeader::linear(1);
    let h2 = TestHeader::linear(2);
    let (storage, ledger) = m.create_finalized_state().unwrap();
    let (change_set, ledger_change_set, _) = changes(storage, &ledger, &h1);
    let err = err_string(m.save_change_set(&h1, change_set, ledger_change_set));
    assert!(err.contains("was not registered"), "{err}");

    write(&mut m, &h1);
    let (storage, ledger) = m.create_state_after(&h1).unwrap();
    let (change_set, ledger_change_set, _) = changes(storage, &ledger, &h2);
    // A header with the hash of a registered block but another parent.
    let (storage, ledger) = m.create_state_for(&h2).unwrap();
    let (other_change_set, other_ledger, _) = changes(storage, &ledger, &h2);
    let forged = TestHeader {
        prev: block_hash(9, 1),
        ..h2.clone()
    };
    let err = err_string(m.save_change_set(&forged, other_change_set, other_ledger));
    assert!(err.contains("was registered with parent"), "{err}");
    // The unregistered block 3.
    let h3 = TestHeader::linear(3);
    let err = err_string(m.save_change_set(&h3, change_set, ledger_change_set));
    assert!(err.contains("was not registered"), "{err}");
    assert_eq!(m.check_invariants(), 1);
}

/// Upstream `double_save_changes`.
#[test]
fn double_save_changes() {
    let mut m = Manager::new();
    let h1 = TestHeader::linear(1);
    let (storage, ledger) = m.create_state_for(&h1).unwrap();
    let (again, again_ledger) = m.create_state_for(&h1).unwrap();
    let (change_set, ledger_change_set, _) = changes(storage, &ledger, &h1);
    m.save_change_set(&h1, change_set, ledger_change_set)
        .unwrap();
    let (change_set, ledger_change_set, _) = changes(again, &again_ledger, &h1);
    let err = err_string(m.save_change_set(&h1, change_set, ledger_change_set));
    assert!(err.contains("saved already"), "{err}");
    assert_eq!(m.check_invariants(), 1);
}

/// Upstream `create_state_after_not_saved_block`: now an error until the block is saved (B5;
/// upstream returned the finalized state), then its state; once it is finalized, the finalized
/// state; once a later block is finalized, an error again (it is committed history).
#[test]
fn create_state_after_not_saved_block() {
    let mut m = Manager::new();
    let h1 = TestHeader::linear(1);
    let h2 = TestHeader::linear(2);
    let (storage, ledger) = m.create_state_for(&h1).unwrap();
    let err = err_string(m.create_state_after(&h1));
    assert!(err.contains("is not saved"), "{err}");
    let (change_set, ledger_change_set, root) = changes(storage, &ledger, &h1);
    m.save_change_set(&h1, change_set, ledger_change_set)
        .unwrap();
    let (after, after_ledger) = m.create_state_after(&h1).unwrap();
    verify(&after, &after_ledger, std::slice::from_ref(&h1), root);
    m.finalize(&h1).unwrap();
    // The storage from before the finalization reads the same.
    verify(&after, &after_ledger, std::slice::from_ref(&h1), root);
    verify_after(&mut m, &h1, std::slice::from_ref(&h1), root);

    let root2 = write(&mut m, &h2);
    m.finalize(&h2).unwrap();
    verify_after(&mut m, &h2, &[h1.clone(), h2.clone()], root2);
    let err = err_string(m.create_state_after(&h1));
    assert!(
        err.contains("neither a saved block nor the finalized"),
        "{err}"
    );
}

/// Upstream `finalize_only_last_block`: finalizing the newest of five blocks commits all of
/// them, in order: every version reads its own values and root.
#[test]
fn finalize_only_last_block() {
    let mut m = Manager::new();
    let chain = linear(5);
    let roots = write_all(&mut m, &chain);
    m.finalize(&chain[4]).unwrap();
    assert_eq!(m.unfinalized_count(), 0);
    assert_eq!(m.check_invariants(), 0);
    assert_eq!(m.latest_version(), Some(SlotNumber::new(4)));
    verify_finalized(&mut m, &chain, roots[4]);

    let (storage, _) = m.create_finalized_state().unwrap();
    let witness = Default::default();
    for (version, root) in (0u64..).zip(&roots) {
        let version = SlotNumber::new(version);
        assert_eq!(storage.get_root_hash(version), Some(*root));
        for hdr in &chain {
            let expected = (version_of(hdr) <= version).then(|| values(hdr).user);
            assert_eq!(
                storage
                    .get_historical::<User>(&key(hdr.height), Some(version), &witness)
                    .unwrap(),
                expected,
                "block {} at version {version}",
                hdr.height
            );
            let expected = (version_of(hdr) <= version).then(|| values(hdr).accessory);
            assert_eq!(
                storage
                    .get_accessory_historical(&key(hdr.height), Some(version))
                    .unwrap(),
                expected
            );
        }
    }
}

/// Upstream `check_snapshots_ordering`, rewritten: block `h` of `n` writes its hash to the keys
/// `1..=n-h+1`, so key `k` was last written by block `n-k+1`: a reader with its snapshots out of
/// order would see an older block's value. And the NOMT overlays give the same root as the
/// saved tip.
#[test]
fn snapshots_ordering() {
    let mut m = Manager::new();
    let n = 5u64;
    let chain = linear(n);
    let mut tip_root = Root::PRE_GENESIS;
    for hdr in &chain {
        let last_key = n.checked_sub(hdr.height).unwrap().checked_add(1).unwrap();
        let value = Some(values(hdr).user);
        let user: Vec<_> = (1..=last_key).map(|k| (key(k), value.clone())).collect();
        tip_root = write_block(&mut m, hdr, &user, &user, &user);
    }
    let (storage, _) = m.create_state_after(&chain[4]).unwrap();
    let witness = Default::default();
    for k in 1..=n {
        let writer = &chain[usize::try_from(n - k).unwrap()];
        assert_eq!(
            storage.get::<User>(&key(k), &witness),
            Some(values(writer).user),
            "key {k}"
        );
        assert_eq!(storage.get_accessory(&key(k)), Some(values(writer).user));
    }
    assert_eq!(storage.root().unwrap(), tip_root);
    let (value, root) = prove(&storage, 1).unwrap();
    assert_eq!((value, root), (Some(values(&chain[4]).user), tip_root));
}

/// Finalizing the finalized block is a no-op, also after a restart.
#[test]
fn finalize_is_idempotent_for_finalized_block() {
    let mut m = Manager::new();
    let chain = linear(3);
    write_all(&mut m, &chain);
    m.finalize(&chain[1]).unwrap();
    let finalized = m.finalized();
    m.finalize(&chain[1]).unwrap();
    assert_eq!(m.finalized(), finalized);
    assert_eq!(m.unfinalized_count(), 1);
    let mut m = m.reopen();
    m.finalize(&chain[1]).unwrap();
    assert_eq!(m.finalized(), finalized);
    // With another height, the same hash is an error.
    let wrong = TestHeader {
        height: 9,
        ..chain[1].clone()
    };
    assert!(err_string(m.finalize(&wrong)).contains("not its height"));
}

/// Critique #12: finalizing a committed ancestor of the finalized block (a runner retrying
/// after a restart) is a no-op, not an error; an unknown block is still an error.
#[test]
fn finalize_committed_ancestor_is_noop() {
    let mut m = Manager::new();
    let chain = linear(4);
    write_all(&mut m, &chain);
    m.finalize(&chain[2]).unwrap();
    let finalized = m.finalized();
    m.finalize(&chain[0]).unwrap();
    m.finalize(&chain[1]).unwrap();
    assert_eq!(m.finalized(), finalized);
    assert_eq!(m.unfinalized_count(), 1);
    let mut m = m.reopen();
    m.finalize(&chain[0]).unwrap();
    assert_eq!(m.finalized(), finalized);
    let wrong_height = TestHeader {
        height: 7,
        ..chain[0].clone()
    };
    assert!(err_string(m.finalize(&wrong_height)).contains("committed as slot 0"));
    let unknown = TestHeader::new(7, 2, 1);
    assert!(err_string(m.finalize(&unknown)).contains("not an uncommitted block"));
}

/// D5: after a restart, the finalized block (hash, DA height, slot) comes from the ledger's
/// newest slot; unfinalized blocks are gone, and the next block builds on the finalized one.
#[test]
fn restart_restores_finalized_block_from_ledger() {
    let mut m = Manager::new();
    let chain = linear(3);
    let roots = write_all(&mut m, &chain);
    m.finalize(&chain[1]).unwrap();
    let expected = Some(FinalizedBlock {
        hash: chain[1].hash,
        da_height: 2,
        slot: SlotNumber::new(1),
    });
    assert_eq!(m.finalized(), expected);
    let mut m = m.reopen();
    assert_eq!(m.finalized(), expected);
    assert_eq!(m.last_recovery().rolled_back, []);
    assert_eq!(m.unfinalized_count(), 0);
    verify_finalized(&mut m, &chain[..2], roots[1]);
    // Block 3 was lost: it is executed again, on the finalized block.
    let err = err_string(m.create_state_after(&chain[2]));
    assert!(err.contains("neither a saved block"), "{err}");
    assert_eq!(write(&mut m, &chain[2]), roots[2]);
    m.finalize(&chain[2]).unwrap();
    verify_finalized(&mut m, &chain, roots[2]);
    // Restarting an empty manager: nothing finalized.
    let mut empty = Manager::new().reopen();
    assert_eq!(empty.finalized(), None);
    verify_finalized(&mut empty, &[], Root::PRE_GENESIS);
}

/// D5 on a chain whose DA heights are not its slots plus one, on a fork other than the main
/// one: the restored DA height is the ledger slot's. (On [`linear`] chains, a height derived from
/// the slot is the same number; here it would refuse the next block and accept one at the
/// wrong height.)
#[test]
fn restart_restores_offset_da_height_from_ledger() {
    let mut m = Manager::new();
    let genesis = TestHeader::genesis(3, 100);
    let second = genesis.child(3);
    let mut chain = vec![genesis, second.clone()];
    let roots = write_all(&mut m, &chain);
    m.finalize(&second).unwrap();
    let expected = Some(FinalizedBlock {
        hash: second.hash,
        da_height: 101,
        slot: SlotNumber::new(1),
    });
    assert_eq!(m.finalized(), expected);
    let mut m = m.reopen();
    assert_eq!(m.finalized(), expected);
    verify_finalized(&mut m, &chain, roots[1]);
    // A child at the slot's height plus one is refused; the next DA height builds on it.
    let wrong = TestHeader {
        height: 2,
        ..second.child(4)
    };
    let err = err_string(m.create_state_for(&wrong));
    assert!(
        err.contains("cannot be a child of the finalized block"),
        "{err}"
    );
    let next = second.child(3);
    let root = write(&mut m, &next);
    m.finalize(&next).unwrap();
    assert_eq!(
        m.finalized(),
        Some(FinalizedBlock {
            hash: next.hash,
            da_height: 102,
            slot: SlotNumber::new(2),
        })
    );
    chain.push(next);
    verify_finalized(&mut m, &chain, root);
}

/// A7: at most `max_unfinalized_blocks` uncommitted blocks (upstream had no bound).
#[test]
fn unfinalized_depth_cap() {
    let mut m = Manager::with_config(|config| {
        config.max_unfinalized_blocks = NonZeroU64::new(3).unwrap();
    });
    let chain = linear(4);
    write_all(&mut m, &chain[..3]);
    let err = err_string(m.create_state_for(&chain[3]));
    assert!(err.contains("3 blocks are not finalized"), "{err}");
    // A block already registered is fine.
    m.create_state_for(&chain[2]).unwrap();
    assert_eq!(m.unfinalized_count(), 3);
    m.finalize(&chain[0]).unwrap();
    write(&mut m, &chain[3]);
    assert_eq!(m.unfinalized_count(), 3);
}

/// A11: finalizing a deep block commits each uncommitted ancestor in order, one commit each,
/// releasing the overlays lock between them.
#[test]
fn finalize_deep_block_commits_all_segments_in_order() {
    let mut m = Manager::new();
    let chain = linear(4);
    let roots = write_all(&mut m, &chain);
    let points = Arc::new(Mutex::new(Vec::new()));
    let recorded = points.clone();
    m.set_commit_hook(Some(Arc::new(move |point| {
        recorded.lock().unwrap().push(point);
        Ok(())
    })));
    m.finalize(&chain[3]).unwrap();
    let points = points.lock().unwrap().clone();
    let per_block = CommitPoint::COMMIT.to_vec();
    let mut expected = Vec::new();
    for index in 0..4 {
        expected.extend(per_block.iter().copied());
        if index < 3 {
            expected.push(CommitPoint::BetweenSegments);
        }
    }
    assert_eq!(points, expected);
    // Each version holds its own block.
    let (storage, ledger) = m.create_finalized_state().unwrap();
    verify(&storage, &ledger, &chain, roots[3]);
    for (version, root) in (0u64..).zip(&roots) {
        assert_eq!(storage.get_root_hash(SlotNumber::new(version)), Some(*root));
    }
}

/// Critique #3: blocks on empty databases start at version 0 (the snapshots' versions are not
/// `base + 1` when nothing is committed): genesis and two more, all unfinalized, read and
/// finalize.
#[test]
fn unfinalized_genesis_and_two_blocks() {
    let mut m = Manager::new();
    let chain = vec![
        TestHeader::linear(0),
        TestHeader::linear(1),
        TestHeader::linear(2),
    ];
    let roots = write_all(&mut m, &chain);
    let (storage, ledger) = m.create_state_after(&chain[2]).unwrap();
    verify(&storage, &ledger, &chain, roots[2]);
    assert_eq!(storage.latest_version(), SlotNumber::new(2));
    assert_eq!(
        prove(&storage, 0).unwrap(),
        (Some(values(&chain[0]).user), roots[2])
    );
    m.finalize(&chain[2]).unwrap();
    verify_finalized(&mut m, &chain, roots[2]);
}

// ---------------------------------------------------------------------------------------------
// Regressions of upstream's manager bugs.

/// B1: a block whose parent is unknown is refused (upstream executed it on the finalized
/// state and registered it anyway), and nothing is registered.
#[test]
fn create_state_for_rejects_unknown_parent() {
    let mut m = Manager::new();
    let chain = linear(2);
    write(&mut m, &chain[0]);
    m.finalize(&chain[0]).unwrap();
    let orphan = TestHeader::new(5, 2, 4);
    let err = err_string(m.create_state_for(&orphan));
    assert!(err.contains("unknown parent"), "{err}");
    assert_eq!(m.unfinalized_count(), 0);
    // Nor can it be saved with changes built on the finalized state.
    let (storage, ledger) = m.create_finalized_state().unwrap();
    let (change_set, ledger_change_set, _) = changes(storage, &ledger, &orphan);
    assert!(
        err_string(m.save_change_set(&orphan, change_set, ledger_change_set))
            .contains("was not registered")
    );
}

/// B1: a block whose parent is older than the finalized block is refused.
#[test]
fn create_state_for_rejects_parent_below_finalized() {
    let mut m = Manager::new();
    let chain = linear(3);
    write_all(&mut m, &chain);
    m.finalize(&chain[1]).unwrap();
    // A child of block 1, which is committed history now.
    let late = chain[0].child(7);
    let err = err_string(m.create_state_for(&late));
    assert!(err.contains("unknown parent"), "{err}");
    assert_eq!(m.unfinalized_count(), 1);
}

/// B1: a sibling of the finalized block arriving after its finalization is refused.
#[test]
fn create_state_for_rejects_late_sibling_of_finalized() {
    let mut m = Manager::new();
    let chain = linear(2);
    write_all(&mut m, &chain);
    m.finalize(&chain[1]).unwrap();
    let sibling = chain[0].child(8);
    assert_eq!(sibling.prev, chain[1].prev);
    let err = err_string(m.create_state_for(&sibling));
    assert!(err.contains("unknown parent"), "{err}");
    assert_eq!(m.unfinalized_count(), 0);
}

/// B4: a block cannot be its own parent, and must be one height above its parent (upstream's
/// walks looped forever on a cycle of headers).
#[test]
fn create_state_for_rejects_self_parent_and_height_gap() {
    let mut m = Manager::new();
    let chain = linear(2);
    write_all(&mut m, &chain);
    let own_parent = TestHeader {
        hash: block_hash(3, 3),
        prev: block_hash(3, 3),
        height: 3,
    };
    assert!(err_string(m.create_state_for(&own_parent)).contains("its own parent"));
    let gap = TestHeader {
        height: 4,
        ..chain[1].child(3)
    };
    assert!(err_string(m.create_state_for(&gap)).contains("cannot be a child of block"));
    // A block re-registered on another parent (a cycle through block 1).
    let cycle = TestHeader {
        prev: chain[1].hash,
        ..chain[0].clone()
    };
    assert!(err_string(m.create_state_for(&cycle)).contains("registered with parent"));
    // The finalized block itself.
    m.finalize(&chain[0]).unwrap();
    assert!(err_string(m.create_state_for(&chain[0])).contains("is the finalized block"));
    assert_eq!(m.unfinalized_count(), 1);
    assert_eq!(m.check_invariants(), 1);
}

/// B2: saved changes must have been executed on the block's parent: the right version, its
/// roots, its ledger slot's numbering, and a ledger slot for the block and these changes
/// (critique #5). Nothing is saved otherwise.
#[test]
fn save_rejects_change_set_not_built_on_parent() {
    let mut m = Manager::new();
    let h1 = TestHeader::linear(1);
    write(&mut m, &h1);
    m.finalize(&h1).unwrap();
    // Two forks on h1: a2 with ledger contents (a batch, a blob, ...), b2 without.
    let a2 = h1.child(2);
    let b2 = h1.child(3);
    let (storage, ledger) = m.create_state_for(&a2).unwrap();
    let (change_set, _, _) = changes(storage, &ledger, &a2);
    let ledger_a2 = ledger
        .materialize_slot(
            change_set.version(),
            change_set.roots(),
            header_slot_info(&a2),
            crate::test_utils::blocks::slot_contents(7, &[]),
        )
        .unwrap();
    m.save_change_set(&a2, change_set, ledger_a2).unwrap();
    write(&mut m, &b2);
    let a3 = a2.child(2);
    let b3 = b2.child(3);
    m.create_state_for(&b3).unwrap();

    // The version: changes executed on the finalized block (h1), saved for b3 (on b2).
    let (storage, ledger) = m.create_finalized_state().unwrap();
    let (stale, stale_ledger, _) = changes(storage, &ledger, &b3);
    let err = err_string(m.save_change_set(&b3, stale, stale_ledger));
    assert!(err.contains("its parent's next version is 2"), "{err}");

    // The roots: executed on a2, saved for b3.
    let (storage, ledger) = m.create_state_for(&a3).unwrap();
    let (on_a2, on_a2_ledger, _) = changes(storage, &ledger, &a3);
    let err = err_string(m.save_change_set(&b3, on_a2, on_a2_ledger));
    assert!(err.contains("other than its parent's"), "{err}");

    // The ledger numbering: state executed on b2, ledger slot built on a2 (which has items).
    let (storage, _) = m.create_state_for(&b3).unwrap();
    let (on_b2, _, _) = changes(storage, &ledger, &b3);
    let (_, ledger_on_a2) = m.create_state_for(&a3).unwrap();
    let mixed = ledger_on_a2
        .materialize_slot(
            on_b2.version(),
            on_b2.roots(),
            header_slot_info(&b3),
            SlotContents::default(),
        )
        .unwrap();
    let err = err_string(m.save_change_set(&b3, on_b2, mixed));
    assert!(
        err.contains("was not built on its parent block's ledger slot"),
        "{err}"
    );

    // A ledger slot for another DA block, or for other roots.
    let (storage, ledger) = m.create_state_for(&b3).unwrap();
    let (on_b2, _, _) = changes(storage, &ledger, &b3);
    let other_block = ledger
        .materialize_slot(
            on_b2.version(),
            on_b2.roots(),
            header_slot_info(&a3),
            SlotContents::default(),
        )
        .unwrap();
    let err = err_string(m.save_change_set(&b3, on_b2, other_block));
    assert!(err.contains("not block"), "{err}");
    // b3's DA hash at another height (a3 above is at b3's height: only the hash differs).
    let (storage, ledger) = m.create_state_for(&b3).unwrap();
    let (on_b2, _, _) = changes(storage, &ledger, &b3);
    let other_height = ledger
        .materialize_slot(
            on_b2.version(),
            on_b2.roots(),
            SlotInfo {
                da_height: 9,
                ..header_slot_info(&b3)
            },
            SlotContents::default(),
        )
        .unwrap();
    let err = err_string(m.save_change_set(&b3, on_b2, other_height));
    assert!(err.contains("at height 9, not block"), "{err}");
    let (storage, ledger) = m.create_state_for(&b3).unwrap();
    let (on_b2, _, _) = changes(storage, &ledger, &b3);
    let other_roots = ledger
        .materialize_slot(
            on_b2.version(),
            NomtRoots::PRE_GENESIS,
            header_slot_info(&b3),
            SlotContents::default(),
        )
        .unwrap();
    let err = err_string(m.save_change_set(&b3, on_b2, other_roots));
    assert!(
        err.contains("its changes for version 2 with roots"),
        "{err}"
    );

    // Nothing was saved; the right changes are.
    assert_eq!(m.check_invariants(), 2);
    let root = write(&mut m, &b3);
    verify_after(&mut m, &b3, &[h1.clone(), b2.clone(), b3.clone()], root);
}

/// B3: a finalization checks its whole chain before it writes: a chain that does not follow
/// (here a block's snapshot replaced by its parent's) is refused with nothing written, and the
/// manager is usable (upstream committed the chain block by block and stopped in the middle).
#[test]
fn finalize_validates_whole_chain_before_writing() {
    let mut m = Manager::new();
    let chain = linear(3);
    let roots = write_all(&mut m, &chain);
    let good = m.snapshots[&chain[2].hash].clone();
    let wrong = m.snapshots[&chain[1].hash].clone();
    m.snapshots.insert(chain[2].hash, wrong);
    let err = err_string(m.finalize(&chain[2]));
    assert!(err.contains("block"), "{err}");
    assert!(err.contains("not version 2"), "{err}");
    assert!(!m.is_poisoned());
    assert_eq!(m.latest_version(), None);
    assert_eq!(m.group().latest_version().unwrap(), None);
    assert_eq!(m.group().roots(), NomtRoots::PRE_GENESIS);
    m.snapshots.insert(chain[2].hash, good);
    m.finalize(&chain[2]).unwrap();
    verify_finalized(&mut m, &chain, roots[2]);
}

/// Critique #4: a commit refused by its checks, before anything is written, keeps the block
/// (its overlay and snapshot) and does not poison the manager: once the cause is gone, the
/// same finalization goes through.
#[test]
fn refused_commit_keeps_block_and_does_not_poison() {
    let mut m = Manager::new();
    let chain = linear(2);
    let roots = write_all(&mut m, &chain);
    // A slot written to the ledger DB past the commits (as a bug would): the commit's check of
    // the ledger DB refuses it.
    let stray = m
        .group()
        .ledger_reader()
        .unwrap()
        .materialize_slot(
            SlotNumber::GENESIS,
            NomtRoots::PRE_GENESIS,
            header_slot_info(&TestHeader::new(9, 1, 0)),
            SlotContents::default(),
        )
        .unwrap();
    crate::ledger::commit(m.group().ledger_db(), &stray).unwrap();
    let err = err_string(m.finalize(&chain[1]));
    assert!(err.contains("the ledger DB is at version Some(0)"), "{err}");
    assert!(!m.is_poisoned());
    assert_eq!(m.check_invariants(), 2);
    let (storage, ledger) = m.create_state_after(&chain[1]).unwrap();
    // The ledger reader sees the stray slot under the snapshots; the state is unchanged.
    drop(ledger);
    assert_eq!(storage.root().unwrap(), roots[1]);
    assert_eq!(prove(&storage, 2).unwrap().1, roots[1]);
    drop(storage);

    crate::ledger::rollback_head(m.group().ledger_db()).unwrap();
    m.finalize(&chain[1]).unwrap();
    verify_finalized(&mut m, &chain, roots[1]);
}

/// B3, D4: a commit that fails once it started writing poisons the manager: every method fails
/// until it is reopened, and reopening repairs the databases; the finalized block is then the
/// last one committed, and the lost blocks are executed again.
#[test]
fn manager_poisoned_after_commit_error() {
    let mut m = Manager::new();
    let chain = linear(3);
    let roots = write_all(&mut m, &chain);
    let next = chain[2].child(1);
    let (storage, ledger) = m.create_state_for(&next).unwrap();
    let (change_set, ledger_change_set, _) = changes(storage, &ledger, &next);
    // The first block's commit fails after the NOMT trees are written.
    m.set_commit_hook(Some(fail_at(CommitPoint::BeforeLedger)));
    let err = err_string(m.finalize(&chain[2]));
    assert!(err.contains("injected fault"), "{err}");
    assert!(m.is_poisoned());
    m.set_commit_hook(None);
    for err in [
        err_string(m.save_change_set(&next, change_set, ledger_change_set)),
        err_string(m.create_state_for(&next.child(1))),
        err_string(m.create_state_after(&chain[2])),
        err_string(m.create_finalized_state()),
        err_string(m.finalize(&chain[2])),
    ] {
        assert!(err.contains("poisoned"), "{err}");
    }

    // Reopened once every reader of the databases is dropped (they keep them open).
    drop(ledger);
    let mut m = m.reopen();
    assert!(!m.is_poisoned());
    assert_eq!(
        m.last_recovery().rolled_back,
        [RecoveryStep::KernelNomt, RecoveryStep::UserNomt]
    );
    assert_eq!(m.finalized(), None);
    assert_eq!(write_all(&mut m, &chain), roots);
    m.finalize(&chain[2]).unwrap();
    verify_finalized(&mut m, &chain, roots[2]);
}

/// B5: the state after a block exists only for a saved block or the finalized one: an unknown,
/// unsaved, committed (older than the finalized) or discarded block is an error (upstream
/// returned the finalized state for each).
#[test]
fn create_state_after_unknown_or_old_block_is_error() {
    let mut m = Manager::new();
    let chain = linear(3);
    write_all(&mut m, &chain);
    let sibling = chain[0].child(5);
    write(&mut m, &sibling);
    m.create_state_for(&chain[2].child(1)).unwrap();
    m.finalize(&chain[1]).unwrap();
    for (hdr, what) in [
        (
            TestHeader::new(9, 3, 9),
            "neither a saved block nor the finalized",
        ),
        (chain[2].child(1), "is not saved"),
        (chain[0].clone(), "neither a saved block nor the finalized"),
        (sibling, "neither a saved block nor the finalized"),
    ] {
        let err = err_string(m.create_state_after(&hdr));
        assert!(err.contains(what), "{}: {err}", hdr.hash);
    }
    m.create_state_after(&chain[1]).unwrap();
    m.create_state_after(&chain[2]).unwrap();
}

/// D5: the finalized block's DA hash must be a valid `Hdr::Hash`; the ledger slot of a block is
/// for that block (checked when its changes are saved), so a reopened manager restores it.
#[test]
fn ledger_slot_is_for_the_block() {
    let mut m = Manager::new();
    let h1 = TestHeader::linear(1);
    let root = write(&mut m, &h1);
    m.finalize(&h1).unwrap();
    let (_, ledger) = m.create_finalized_state().unwrap();
    let (_, slot) = ledger.committed_head().unwrap().unwrap();
    assert_eq!((slot.da_hash, slot.da_height), (da_hash(&h1), 1));
    assert_eq!(slot.timestamp, h1.time());
    assert_eq!(slot.roots, root.into());
}

/// Finalizing an unknown block, or a registered block that is not saved, is an error, and
/// nothing is committed.
#[test]
fn finalize_unknown_or_unsaved_block_is_error() {
    let mut m = Manager::new();
    let chain = linear(2);
    write_all(&mut m, &chain);
    let err = err_string(m.finalize(&TestHeader::new(4, 3, 1)));
    assert!(err.contains("not an uncommitted block"), "{err}");
    m.create_state_for(&chain[1].child(1)).unwrap();
    let err = err_string(m.finalize(&chain[1].child(1)));
    assert!(err.contains("is not saved"), "{err}");
    assert_eq!(m.latest_version(), None);
}

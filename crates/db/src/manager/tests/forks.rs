//! Upstream's generic storage manager tests with forks (`minimal_fork_bfs`,
//! `several_jumping_forks`, `removed_fork_data_view`, the parallel readers), with assertions
//! where upstream had none, and storages on discarded forks (B6, critique #1).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use selendra_state::StateAccesses;

use super::*;
use crate::harness::{block_changes, block_hash};
use crate::prover::GetWithProofError;

/// A fork of `length` blocks starting `start_height` blocks after its parent fork's first block
/// (the root fork: at height `start_height`), with child forks (upstream `ForkDescription`).
#[derive(Clone, Debug)]
struct ForkDescription {
    start_height: u64,
    length: u64,
    child_forks: Vec<ForkDescription>,
}

/// The blocks of a [`ForkDescription`], each with its children (upstream `ForkMap`).
#[derive(Default)]
struct ForkMap {
    blocks: HashMap<HexHash, (TestHeader, Vec<HexHash>)>,
    start: Option<HexHash>,
}

impl From<ForkDescription> for ForkMap {
    fn from(root: ForkDescription) -> Self {
        let mut map = Self::default();
        // (the parent fork's first height, the parent fork's id, the fork); the root fork's
        // parent is fork 0, never executed.
        let mut queue = VecDeque::from([(0u64, 0u64, root)]);
        let mut next_fork_id = 0u64;
        while let Some((base, parent_fork, fork)) = queue.pop_front() {
            next_fork_id = next_fork_id.checked_add(1).unwrap();
            let start = base.checked_add(fork.start_height).unwrap();
            let mut prev = block_hash(parent_fork, start.checked_sub(1).unwrap());
            for height in start..start.checked_add(fork.length).unwrap() {
                let hdr = TestHeader {
                    hash: block_hash(next_fork_id, height),
                    prev,
                    height,
                };
                if let Some((_, children)) = map.blocks.get_mut(&prev) {
                    children.push(hdr.hash);
                }
                map.start.get_or_insert(hdr.hash);
                prev = hdr.hash;
                assert!(map.blocks.insert(hdr.hash, (hdr, Vec::new())).is_none());
            }
            for child in fork.child_forks {
                queue.push_back((start, next_fork_id, child));
            }
        }
        map
    }
}

impl ForkMap {
    fn header(&self, hash: &HexHash) -> &TestHeader {
        &self.blocks[hash].0
    }

    fn children(&self, hash: &HexHash) -> Vec<HexHash> {
        self.blocks[hash].1.clone()
    }

    /// The blocks from the first one to `hash` (inclusive).
    fn chain_up_to(&self, hash: &HexHash) -> Vec<TestHeader> {
        let mut chain = Vec::new();
        let mut current = Some(*hash);
        while let Some(hash) = current {
            let Some((hdr, _)) = self.blocks.get(&hash) else {
                break;
            };
            chain.push(hdr.clone());
            current = Some(hdr.prev);
        }
        chain.reverse();
        chain
    }
}

#[derive(Clone, Copy)]
enum Exploration {
    BreadthFirst,
    DepthFirst,
}

/// Upstream `test_exploration`: executes and saves every block of `fork`, in breadth-first or
/// depth-first order; each state sees exactly its chain (values, ledger, root), before and after
/// the block. Then finalizes the longest chain block by block: the manager is empty after.
fn explore(fork: ForkDescription, mode: Exploration) {
    let map = ForkMap::from(fork);
    let mut m = Manager::new();
    let mut roots: HashMap<HexHash, Root> = HashMap::new();
    let mut queue = VecDeque::from([map.start.unwrap()]);
    let mut highest = map.header(&map.start.unwrap()).clone();
    while let Some(hash) = match mode {
        Exploration::BreadthFirst => queue.pop_front(),
        Exploration::DepthFirst => queue.pop_back(),
    } {
        queue.extend(map.children(&hash));
        let hdr = map.header(&hash).clone();
        if hdr.height > highest.height {
            highest = hdr.clone();
        }
        let chain = map.chain_up_to(&hash);
        let parent_root = roots.get(&hdr.prev).copied().unwrap_or(Root::PRE_GENESIS);
        let (storage, ledger) = m.create_state_for(&hdr).unwrap();
        verify(&storage, &ledger, &chain[..chain.len() - 1], parent_root);
        let (change_set, ledger_change_set, root) = changes(storage, &ledger, &hdr);
        m.save_change_set(&hdr, change_set, ledger_change_set)
            .unwrap();
        roots.insert(hash, root);
        verify_after(&mut m, &hdr, &chain, root);
        assert_eq!(m.check_invariants(), roots.len());
    }
    let longest = map.chain_up_to(&highest.hash);
    for hdr in &longest {
        m.finalize(hdr).unwrap();
        m.check_invariants();
    }
    assert_eq!(m.unfinalized_count(), 0);
    verify_finalized(&mut m, &longest, roots[&highest.hash]);
}

/// Upstream `minimal_fork_bfs` (both orders): a fork of 3 blocks with two forks of 5 blocks from
/// its first block.
#[test]
fn minimal_fork_bfs() {
    let leaf = ForkDescription {
        start_height: 1,
        length: 5,
        child_forks: Vec::new(),
    };
    let fork = ForkDescription {
        start_height: 1,
        length: 3,
        child_forks: vec![leaf.clone(), leaf],
    };
    explore(fork.clone(), Exploration::BreadthFirst);
    explore(fork, Exploration::DepthFirst);
}

/// Upstream `several_jumping_forks`, with assertions (upstream had none): at each height, 5
/// forks' blocks on the main fork's previous block, all saved; the main fork is finalized 3
/// blocks behind. Each finalization discards the other forks' blocks at its height (and their
/// children); the finalized state is the main fork's; a discarded block can be neither
/// finalized nor saved.
#[test]
fn several_jumping_forks() {
    const MAIN: u64 = TestHeader::MAIN_FORK;
    let (to_height, finality, forks) = (10u64, 3u64, 5u64);
    let mut m = Manager::new();
    let mut main_chain = Vec::new();
    let mut main_roots = Vec::new();
    for height in 1..=to_height {
        // At height 1 the forks' blocks are genesis candidates with the same parent.
        for fork in 1..=forks {
            let hdr = TestHeader::new(fork, height, MAIN);
            let root = write(&mut m, &hdr);
            if fork == MAIN {
                main_chain.push(hdr);
                main_roots.push(root);
            }
        }
        if let Some(final_height) = height.checked_sub(finality)
            && final_height > 0
        {
            let index = usize::try_from(final_height - 1).unwrap();
            m.finalize(&main_chain[index].clone()).unwrap();
            m.check_invariants();
            // Left: the blocks of each height after the finalized one.
            let left = usize::try_from((height - final_height) * forks).unwrap();
            assert_eq!(m.unfinalized_count(), left);
            verify_finalized(&mut m, &main_chain[..=index], main_roots[index]);
            // A discarded sibling of the finalized block.
            let discarded = TestHeader::new(2, final_height, MAIN);
            let err = err_string(m.finalize(&discarded));
            assert!(err.contains("not an uncommitted block"), "{err}");
            let (storage, ledger) = m.create_finalized_state().unwrap();
            let (change_set, ledger_change_set, _) = changes(storage, &ledger, &discarded);
            let err = err_string(m.save_change_set(&discarded, change_set, ledger_change_set));
            assert!(err.contains("was not registered"), "{err}");
            assert!(err_string(m.create_state_after(&discarded)).contains("neither"));
        } else {
            assert_eq!(
                m.unfinalized_count(),
                usize::try_from(height * forks).unwrap()
            );
        }
    }
}

/// Upstream `removed_fork_data_view`: A is finalized, B and C are its children; B is finalized.
/// Upstream showed that C's storage then read B's value. Here a storage before C (on A) and a
/// storage after C keep reading their own state (bound reads), and both are stale: computing a
/// state update fails with `StaleStorage` (on a discarded fork for the one after C); a proof
/// from the one after C fails at once, and the one on A proves the newest committed state (B).
#[test]
fn removed_fork_view() {
    let mut m = Manager::new();
    let a = TestHeader::linear(1);
    let root_a = write(&mut m, &a);
    m.finalize(&a).unwrap();
    let b = a.child(TestHeader::MAIN_FORK);
    let c = a.child(2);
    let (for_b, ledger_b) = m.create_state_for(&b).unwrap();
    let (for_c, ledger_c) = m.create_state_for(&c).unwrap();
    verify_state(&for_b, std::slice::from_ref(&a), root_a);
    verify_state(&for_c, std::slice::from_ref(&a), root_a);
    // B also writes a key C does not write, and changes one A wrote.
    let only_b = key(99);
    let [mut user, mut kernel, mut accessory] = writes(&b);
    for writes in [&mut user, &mut kernel, &mut accessory] {
        writes.push((only_b.clone(), Some(SlotValue::from(b"only B".to_vec()))));
        writes.push((key(1), None));
    }
    let (change_set, ledger_change_set, root_b) =
        block_changes(for_b, &ledger_b, &b, &user, &kernel, &accessory);
    m.save_change_set(&b, change_set, ledger_change_set)
        .unwrap();
    let (change_set, ledger_change_set, root_c) = changes(for_c.clone(), &ledger_c, &c);
    m.save_change_set(&c, change_set, ledger_change_set)
        .unwrap();
    let (after_c, _) = m.create_state_after(&c).unwrap();
    verify_state(&after_c, &[a.clone(), c.clone()], root_c);

    m.finalize(&b).unwrap();
    assert_eq!(m.check_invariants(), 0);
    // Bound reads unchanged, also of the keys B wrote and C did not (upstream read B's).
    verify_state(&after_c, &[a.clone(), c.clone()], root_c);
    verify_state(&for_c, std::slice::from_ref(&a), root_a);
    let witness = Default::default();
    for storage in [&after_c, &for_c] {
        assert_eq!(storage.get::<User>(&only_b, &witness), None);
        assert_eq!(storage.get::<Kernel>(&only_b, &witness), None);
        assert_eq!(storage.get_accessory(&only_b), None);
        let version = Some(storage.latest_version());
        assert_eq!(
            storage
                .get_historical::<User>(&only_b, version, &witness)
                .unwrap(),
            None
        );
    }
    // Iterating is refused: the live table holds B's rows.
    let prefix = SlotKey::try_from_bytes(&[0, 0]).unwrap();
    assert_stale(
        &after_c
            .maybe_iter_user_values_with_prefix(prefix.clone(), None)
            .err()
            .unwrap(),
        true,
    );
    assert!(
        for_c
            .maybe_iter_user_values_with_prefix(prefix, None)
            .is_err()
    );

    let empty = || StateAccesses::default();
    let err = after_c
        .compute_state_update(empty(), &Default::default(), root_c)
        .unwrap_err();
    assert_stale(&err, true);
    let err = for_c
        .compute_state_update(empty(), &Default::default(), root_a)
        .unwrap_err();
    assert_stale(&err, false);
    let err = prove(&after_c, 2).unwrap_err();
    assert_stale(&err, true);
    assert_eq!(prove(&for_c, 2).unwrap(), (Some(values(&b).user), root_b));
}

/// The state `storage` sees is `chain` with root `root` (no ledger: a ledger reader without
/// snapshots sees later commits).
fn verify_state(storage: &TestStorage, chain: &[TestHeader], root: Root) {
    let witness = Default::default();
    for hdr in chain {
        let k = key(hdr.height);
        assert_eq!(storage.get::<User>(&k, &witness), Some(values(hdr).user));
        assert_eq!(
            storage.get::<Kernel>(&k, &witness),
            Some(values(hdr).kernel)
        );
        assert_eq!(storage.get_accessory(&k), Some(values(hdr).accessory));
    }
    let next = chain.last().map_or(1, |hdr| hdr.height.saturating_add(1));
    assert_eq!(storage.get::<User>(&key(next), &witness), None);
    assert_eq!(storage.root().unwrap(), root);
}

/// B6, critique #1: storages on a losing fork two blocks deep (after a 1-block winner is
/// finalized) fail at once with `StaleStorage { discarded_fork: true }`, in one attempt: their
/// overlays are gone and not committed. (Upstream assumed every missing overlay committed, so
/// their sessions opened on the winner's trees: `get_with_proof` retried until its deadline,
/// and a session could mix the winner's trees with the loser's flat values.) Their bound reads
/// still see their own state.
#[test]
fn discarded_fork_storage_fails_fast() {
    let mut m = Manager::new();
    let f = TestHeader::linear(1);
    write(&mut m, &f);
    m.finalize(&f).unwrap();
    let b1 = f.child(TestHeader::MAIN_FORK);
    let c1 = f.child(2);
    let c2 = c1.child(2);
    let root_b1 = write(&mut m, &b1);
    let root_c1 = write(&mut m, &c1);
    let root_c2 = write(&mut m, &c2);
    let (after_c1, _) = m.create_state_after(&c1).unwrap();
    let (after_c2, _) = m.create_state_after(&c2).unwrap();
    let (for_c3, _) = m.create_state_for(&c2.child(2)).unwrap();
    m.finalize(&b1).unwrap();
    assert_eq!(m.unfinalized_count(), 0);

    for (storage, version) in [(&after_c2, 2), (&after_c1, 1), (&for_c3, 2)] {
        let err = match storage.get_with_proof_once::<User>(key(2)) {
            Err(GetWithProofError::Other(err)) => err,
            Err(GetWithProofError::StateRootMismatch) => panic!("a root mismatch: it would retry"),
            Ok(_) => panic!("a proof from a discarded fork"),
        };
        assert_stale(&err, true);
        assert_eq!(
            err.downcast_ref::<StaleStorage>(),
            Some(&StaleStorage {
                storage_version: Some(SlotNumber::new(version)),
                committed_version: Some(SlotNumber::new(1)),
                discarded_fork: true,
            })
        );
        assert_stale(&prove(storage, 2).unwrap_err(), true);
    }
    let err = for_c3
        .compute_state_update(StateAccesses::default(), &Default::default(), root_c2)
        .unwrap_err();
    assert_stale(&err, true);
    verify_state(&after_c2, &[f.clone(), c1.clone(), c2.clone()], root_c2);
    verify_state(&after_c1, &[f.clone(), c1.clone()], root_c1);
    // The winner proves.
    let (after_b1, _) = m.create_state_after(&b1).unwrap();
    assert_eq!(
        prove(&after_b1, 2).unwrap(),
        (Some(values(&b1).user), root_b1)
    );
}

/// Upstream `parallel_forks_reading_while_finalization_is_happening`, for correctness only (no
/// timing assertions; a deadlock fails the test after a timeout): 7 threads read the state
/// after the tips of 7 forks (bound reads and proofs) while the main fork is finalized block by
/// block under them.
#[test]
fn parallel_readers_during_finalization() {
    const MAIN: u64 = TestHeader::MAIN_FORK;
    within(Duration::from_secs(300), || {
        let main_len = 30u64;
        let mut m = Manager::new();
        let main = linear(main_len);
        let roots = write_all(&mut m, &main);
        // 6 more tips on the main fork's second to last block.
        let mut tips = vec![(main.clone(), roots[roots.len() - 1])];
        for fork in 2..=7 {
            let tip = TestHeader::new(fork, main_len, MAIN);
            let root = write(&mut m, &tip);
            let mut chain = main[..main.len() - 1].to_vec();
            chain.push(tip);
            tips.push((chain, root));
        }
        let readers: Vec<_> = tips
            .into_iter()
            .map(|(chain, root)| {
                let (storage, _) = m.create_state_after(chain.last().unwrap()).unwrap();
                (storage, chain, root)
            })
            .collect();

        let done = Arc::new(AtomicBool::new(false));
        let rounds = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for (storage, chain, root) in &readers {
                let (done, rounds) = (done.clone(), rounds.clone());
                scope.spawn(move || {
                    let tip = chain.last().unwrap();
                    loop {
                        let finished = done.load(Ordering::SeqCst);
                        verify_state(storage, chain, *root);
                        assert_eq!(
                            prove(storage, tip.height).unwrap(),
                            (Some(values(tip).user), *root)
                        );
                        rounds.fetch_add(1, Ordering::SeqCst);
                        if finished {
                            break;
                        }
                    }
                });
            }
            for hdr in &main[..main.len() - 1] {
                m.finalize(hdr).unwrap();
            }
            done.store(true, Ordering::SeqCst);
        });
        assert!(rounds.load(Ordering::SeqCst) >= readers.len());
        assert_eq!(m.unfinalized_count(), 7);
        m.check_invariants();
    });
}

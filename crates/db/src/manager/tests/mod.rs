//! Tests of the storage manager on real databases ([`TestManager`]): upstream's generic storage
//! manager tests (`lifecycle`, `forks`), proofs of unfinalized state (`proofs`),
//! `get_with_proof` while a finalization is paused at each commit point (`paused`), pruning
//! (`pruning`), and property tests against models (`proptests`).
//!
//! Every block writes values derived from its hash ([`Values`]) at the key of its height, in
//! the user, kernel and accessory namespaces, so a storage's reads show which blocks it sees.

mod forks;
mod lifecycle;
mod paused;
mod proofs;
mod proptests;
mod pruning;

use std::sync::mpsc;
use std::time::{Duration, Instant};

use selendra_interface::common::{HexHash, SlotNumber};
use selendra_interface::da::BlockHeaderTrait;
use selendra_interface::node::storage::HierarchicalStorageManager;
use selendra_state::namespaces::{Kernel, User};
use selendra_state::{NativeStorage, SlotKey, SlotValue, StateStorageSpec, Storage, StorageRoot};

use crate::harness::{TestHeader, TestManager, block_changes, write_block};
use crate::{LedgerChangeSet, LedgerReader, NomtChangeSet, NomtProverStorage, StaleStorage};

type Spec = StateStorageSpec;
type Manager = TestManager<Spec>;
type TestStorage = NomtProverStorage<Spec, HexHash>;
type Root = StorageRoot<Spec>;

/// The key block headers at `height` write to.
fn key(height: u64) -> SlotKey {
    SlotKey::try_from_bytes(&height.to_be_bytes()).expect("a valid key")
}

/// The values a block writes at [`key`]`(height)`: its hash and a namespace byte, so they differ
/// per block and per namespace.
struct Values {
    user: SlotValue,
    kernel: SlotValue,
    accessory: SlotValue,
}

fn values(hdr: &TestHeader) -> Values {
    let hash: [u8; 32] = hdr.hash.into();
    let with = |byte: u8| SlotValue::from([&hash[..], &[byte]].concat());
    Values {
        user: with(b'u'),
        kernel: with(b'k'),
        accessory: with(b'a'),
    }
}

/// The writes of block `hdr`: its [`values`] at [`key`]`(height)`.
fn writes(hdr: &TestHeader) -> [Vec<(SlotKey, Option<SlotValue>)>; 3] {
    let Values {
        user,
        kernel,
        accessory,
    } = values(hdr);
    let k = key(hdr.height);
    [
        vec![(k.clone(), Some(user))],
        vec![(k.clone(), Some(kernel))],
        vec![(k, Some(accessory))],
    ]
}

/// Executes and saves block `hdr` with its [`writes`]; returns the root after it.
fn write(m: &mut Manager, hdr: &TestHeader) -> Root {
    let [user, kernel, accessory] = writes(hdr);
    write_block(m, hdr, &user, &kernel, &accessory)
}

/// The changes of block `hdr` (its [`writes`]) on `storage` and `ledger`, not saved.
fn changes(
    storage: TestStorage,
    ledger: &LedgerReader,
    hdr: &TestHeader,
) -> (NomtChangeSet, LedgerChangeSet, Root) {
    let [user, kernel, accessory] = writes(hdr);
    block_changes(storage, ledger, hdr, &user, &kernel, &accessory)
}

/// Executes and saves the blocks of `chain` in order; returns their roots.
fn write_all(m: &mut Manager, chain: &[TestHeader]) -> Vec<Root> {
    chain.iter().map(|hdr| write(m, hdr)).collect()
}

/// The main fork from height 1 to `to` (inclusive).
fn linear(to: u64) -> Vec<TestHeader> {
    (1..=to).map(TestHeader::linear).collect()
}

/// `storage` and `ledger` see exactly the blocks of `chain` (oldest first, from genesis: block
/// `i` is version `i`), and `root` is the root after the last one: their values at their
/// heights, nothing at the next height, their ledger slots.
fn verify(storage: &TestStorage, ledger: &LedgerReader, chain: &[TestHeader], root: Root) {
    let witness = Default::default();
    for hdr in chain {
        let Values {
            user,
            kernel,
            accessory,
        } = values(hdr);
        let k = key(hdr.height);
        assert_eq!(
            storage.get::<User>(&k, &witness),
            Some(user),
            "user value of {}",
            hdr.hash
        );
        assert_eq!(storage.get::<Kernel>(&k, &witness), Some(kernel));
        assert_eq!(storage.get_accessory(&k), Some(accessory));
    }
    let next = chain.last().map_or(1, |hdr| hdr.height.saturating_add(1));
    assert_eq!(storage.get::<User>(&key(next), &witness), None);
    assert_eq!(storage.get_accessory(&key(next)), None);
    assert_eq!(storage.root().unwrap(), root, "the storage's root");
    let expected_version = chain.len().checked_sub(1).map(|v| v as u64);
    assert_eq!(
        (!storage.is_empty()).then(|| storage.latest_version().get()),
        expected_version,
        "the storage's version"
    );

    for (version, hdr) in (0u64..).zip(chain) {
        let slot = ledger
            .slot(SlotNumber::new(version))
            .unwrap()
            .expect("a slot per block");
        let hash: [u8; 32] = hdr.hash.into();
        assert_eq!((slot.da_hash, slot.da_height), (hash, hdr.height));
        assert_eq!(
            ledger.slot_by_hash(&hash).unwrap(),
            Some(SlotNumber::new(version))
        );
    }
    assert_eq!(
        ledger.head().unwrap().map(|(slot, _)| slot.get()),
        expected_version,
        "the ledger's newest slot"
    );
    assert_eq!(
        ledger.head().unwrap().map(|(_, slot)| slot.roots),
        expected_version.map(|_| root.into())
    );
}

/// The state and ledger after `hdr` ([`create_state_after`]) see `chain` up to it.
///
/// [`create_state_after`]: HierarchicalStorageManager::create_state_after
fn verify_after(m: &mut Manager, hdr: &TestHeader, chain: &[TestHeader], root: Root) {
    let (storage, ledger) = m.create_state_after(hdr).unwrap();
    verify(&storage, &ledger, chain, root);
}

/// The finalized state sees `chain`.
fn verify_finalized(m: &mut Manager, chain: &[TestHeader], root: Root) {
    let (storage, ledger) = m.create_finalized_state().unwrap();
    verify(&storage, &ledger, chain, root);
}

fn err_string<T>(result: anyhow::Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(err) => format!("{err:#}"),
    }
}

/// `err` is a [`StaleStorage`] error with `discarded_fork`.
fn assert_stale(err: &anyhow::Error, discarded_fork: bool) {
    let stale = err
        .downcast_ref::<StaleStorage>()
        .unwrap_or_else(|| panic!("not a StaleStorage error: {err:#}"));
    assert_eq!(stale.discarded_fork, discarded_fork, "{stale}");
}

/// The proof of the user value at `key(height)` from `storage`, through the retrying
/// `get_with_proof`.
fn prove(storage: &TestStorage, height: u64) -> anyhow::Result<(Option<SlotValue>, Root)> {
    let (proof, _, root) = storage.get_with_proof::<User>(key(height))?;
    Ok((proof.value, root))
}

/// Runs `f` on another thread and waits at most `timeout` for it (a deadlock fails the test
/// instead of hanging it; the thread is then left behind). A panic in `f` is resumed here.
fn within<R: Send + 'static>(timeout: Duration, f: impl FnOnce() -> R + Send + 'static) -> R {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)));
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(result)) => result,
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("did not finish within {timeout:?} (deadlock?)"),
    }
}

/// Waits for `thread` to finish, at most `timeout`, then panics. A scope resumes that panic only
/// once all its threads have finished, so it fails a thread that is slow but not one that is
/// deadlocked: run the scope in [`within`] (as `paused::paused_test` does) for that.
fn join_within<R>(thread: std::thread::ScopedJoinHandle<'_, R>, timeout: Duration) -> R {
    let start = Instant::now();
    while !thread.is_finished() {
        assert!(
            start.elapsed() < timeout,
            "the thread did not finish within {timeout:?} (deadlock?)"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    thread.join().expect("the thread panicked")
}

/// `hdr`'s height as a version on the main fork from height 1 (genesis).
fn version_of(hdr: &TestHeader) -> SlotNumber {
    SlotNumber::new(hdr.height.checked_sub(1).expect("heights start at 1"))
}

/// The DA hash of `hdr` as the ledger stores it.
fn da_hash(hdr: &impl BlockHeaderTrait<Hash = HexHash>) -> [u8; 32] {
    hdr.hash().into()
}

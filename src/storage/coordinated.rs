//! Crash-recoverable coordination between local transactional state and a
//! rollback-resistant external anchor.
//!
//! The engine historically calls `MonotonicCounter::increment()` before it
//! starts the storage transaction. A production counter that immediately
//! advances a remote/hardware anchor would therefore create an availability
//! dead-end if the local commit subsequently failed. This adapter preserves the
//! engine contract while changing the *durable* ordering:
//!
//! 1. `PreparedMonotonicCounter::increment` reserves `N + 1` in process only.
//! 2. the engine atomically commits state containing epoch `N + 1` locally.
//! 3. `AnchoredStorage::commit` advances the non-restorable anchor `N -> N + 1`.
//! 4. only then does the storage commit report success to the engine.
//!
//! A crash between steps 2 and 3 leaves one authenticated local epoch ahead of
//! the anchor. `coordinated_backends_for_restore` recognizes *only* that exact
//! one-step condition and advances the anchor forward. Older local state is a
//! rollback and larger gaps are corruption; both fail closed.

use std::sync::{Arc, Mutex};

use crate::primitives::error::PrimitiveError;
use crate::storage::monotonic::MonotonicCounter;
use crate::storage::trusted_anchor::RollbackAnchor;
use crate::storage::{StateBlob, StorageEpoch, TransactionId, TransactionalStorage};

const STORAGE_EPOCH_KEY: &[u8] = b"storage-epoch-v1";

struct Coordination {
    anchor: Arc<dyn RollbackAnchor>,
    pending_epoch: Mutex<Option<u64>>,
}

impl Coordination {
    fn new(anchor: Arc<dyn RollbackAnchor>) -> Self {
        Self {
            anchor,
            pending_epoch: Mutex::new(None),
        }
    }

    fn pending(&self) -> Result<Option<u64>, PrimitiveError> {
        Ok(*self
            .pending_epoch
            .lock()
            .map_err(|_| PrimitiveError::Internal)?)
    }

    fn prepare_next(&self) -> Result<u64, PrimitiveError> {
        let mut pending = self
            .pending_epoch
            .lock()
            .map_err(|_| PrimitiveError::Internal)?;
        if pending.is_some() {
            return Err(PrimitiveError::Internal);
        }
        let current = self.anchor.current()?;
        let next = current
            .checked_add(1)
            .ok_or(PrimitiveError::LimitExceeded)?;
        *pending = Some(next);
        Ok(next)
    }

    fn cancel_pending(&self) -> Result<(), PrimitiveError> {
        *self
            .pending_epoch
            .lock()
            .map_err(|_| PrimitiveError::Internal)? = None;
        Ok(())
    }

    fn finalize(&self, target: u64) -> Result<(), PrimitiveError> {
        let pending = self.pending()?;
        if pending != Some(target) {
            return Err(PrimitiveError::Internal);
        }
        let previous = target
            .checked_sub(1)
            .ok_or(PrimitiveError::Internal)?;

        let current = self.anchor.current()?;
        if current == target {
            self.cancel_pending()?;
            return Ok(());
        }
        if current != previous {
            return Err(PrimitiveError::Internal);
        }

        match self.anchor.compare_and_increment(previous) {
            Ok(observed) if observed == target => {
                self.cancel_pending()?;
                Ok(())
            }
            Ok(_) => Err(PrimitiveError::Internal),
            Err(_) => {
                // Resolve a potentially ambiguous transport/hardware response by
                // re-reading. If the anchor reached the target, the operation
                // did commit and is safe to acknowledge.
                if self.anchor.current()? == target {
                    self.cancel_pending()?;
                    Ok(())
                } else {
                    Err(PrimitiveError::Internal)
                }
            }
        }
    }
}

/// Counter half of the coordinated production backend pair.
///
/// `increment()` deliberately does not touch the durable anchor. It reserves the
/// epoch which `AnchoredStorage` must atomically embed in the next local commit.
pub struct PreparedMonotonicCounter {
    coordination: Arc<Coordination>,
}

impl MonotonicCounter for PreparedMonotonicCounter {
    fn current(&self) -> Result<u64, PrimitiveError> {
        self.coordination.anchor.current()
    }

    fn increment(&mut self) -> Result<u64, PrimitiveError> {
        self.coordination.prepare_next()
    }
}

/// Transactional storage wrapper which finalizes the external rollback anchor
/// only after the corresponding local state transaction is durably committed.
pub struct AnchoredStorage<S: TransactionalStorage> {
    inner: S,
    coordination: Arc<Coordination>,
    active_tx: Option<TransactionId>,
    staged_epoch: Option<u64>,
}

impl<S: TransactionalStorage> AnchoredStorage<S> {
    fn new(inner: S, coordination: Arc<Coordination>) -> Self {
        Self {
            inner,
            coordination,
            active_tx: None,
            staged_epoch: None,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: TransactionalStorage> TransactionalStorage for AnchoredStorage<S> {
    fn begin(&mut self) -> Result<TransactionId, PrimitiveError> {
        if self.active_tx.is_some() || self.staged_epoch.is_some() {
            return Err(PrimitiveError::Internal);
        }
        if self.coordination.pending()?.is_none() {
            return Err(PrimitiveError::Internal);
        }
        let tx = self.inner.begin()?;
        self.active_tx = Some(tx);
        Ok(tx)
    }

    fn put(
        &mut self,
        tx: TransactionId,
        key: &[u8],
        value: &StateBlob,
    ) -> Result<(), PrimitiveError> {
        if self.active_tx != Some(tx) {
            return Err(PrimitiveError::Internal);
        }
        if key == STORAGE_EPOCH_KEY {
            if value.0.len() != 8 || self.staged_epoch.is_some() {
                return Err(PrimitiveError::InvalidLength);
            }
            let epoch = u64::from_le_bytes(
                value
                    .0
                    .as_slice()
                    .try_into()
                    .map_err(|_| PrimitiveError::InvalidLength)?,
            );
            if self.coordination.pending()? != Some(epoch) {
                return Err(PrimitiveError::Internal);
            }
            self.staged_epoch = Some(epoch);
        }
        self.inner.put(tx, key, value)
    }

    fn delete(&mut self, tx: TransactionId, key: &[u8]) -> Result<(), PrimitiveError> {
        if self.active_tx != Some(tx) || key == STORAGE_EPOCH_KEY {
            return Err(PrimitiveError::Internal);
        }
        self.inner.delete(tx, key)
    }

    fn commit(&mut self, tx: TransactionId) -> Result<(), PrimitiveError> {
        if self.active_tx != Some(tx) {
            return Err(PrimitiveError::Internal);
        }
        let target = self.staged_epoch.ok_or(PrimitiveError::Internal)?;

        // Commit local authenticated state first. If this fails, the durable
        // anchor remains at N and the old local state remains authoritative.
        if let Err(error) = self.inner.commit(tx) {
            self.active_tx = None;
            self.staged_epoch = None;
            let _ = self.coordination.cancel_pending();
            return Err(error);
        }

        self.active_tx = None;
        self.staged_epoch = None;

        // Local N+1 is now durable. Failure here is fail-closed; a fresh process
        // may reconcile exactly one local-ahead epoch during restore.
        self.coordination.finalize(target)
    }

    fn abort(&mut self, tx: TransactionId) -> Result<(), PrimitiveError> {
        if self.active_tx != Some(tx) {
            return Err(PrimitiveError::Internal);
        }
        let result = self.inner.abort(tx);
        self.active_tx = None;
        self.staged_epoch = None;
        if result.is_ok() {
            self.coordination.cancel_pending()?;
        }
        result
    }

    fn get(&self, key: &[u8]) -> Result<Option<StateBlob>, PrimitiveError> {
        self.inner.get(key)
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>, PrimitiveError> {
        self.inner.keys()
    }

    fn epoch(&self) -> Result<StorageEpoch, PrimitiveError> {
        self.inner.epoch()
    }

    fn advance_epoch(&mut self) -> Result<StorageEpoch, PrimitiveError> {
        // Local implementation-specific epochs are not the trusted anchor and
        // remain available only for compatibility with TransactionalStorage.
        self.inner.advance_epoch()
    }
}

/// Build a coordinated backend pair for first-time device initialization.
///
/// The external anchor must be pristine and the local storage must not already
/// contain an engine epoch. This prevents accidentally initializing over an
/// existing or rolled-back identity database.
pub fn coordinated_backends_for_initialize<S>(
    storage: S,
    anchor: Arc<dyn RollbackAnchor>,
) -> Result<
    (
        Box<dyn TransactionalStorage>,
        Box<dyn MonotonicCounter>,
    ),
    PrimitiveError,
>
where
    S: TransactionalStorage + 'static,
{
    if anchor.current()? != 0 || storage.get(STORAGE_EPOCH_KEY)?.is_some() {
        return Err(PrimitiveError::Internal);
    }
    build_pair(storage, anchor)
}

/// Build a coordinated backend pair for restoring an existing device.
///
/// Accepted states are deliberately narrow:
/// - `local == anchor`: normal clean shutdown/commit;
/// - `local == anchor + 1`: local commit completed but anchor finalization was
///   interrupted, so the anchor is advanced forward exactly once;
/// - every other relationship fails closed.
pub fn coordinated_backends_for_restore<S>(
    storage: S,
    anchor: Arc<dyn RollbackAnchor>,
) -> Result<
    (
        Box<dyn TransactionalStorage>,
        Box<dyn MonotonicCounter>,
    ),
    PrimitiveError,
>
where
    S: TransactionalStorage + 'static,
{
    let blob = storage
        .get(STORAGE_EPOCH_KEY)?
        .ok_or(PrimitiveError::InvalidLength)?;
    if blob.0.len() != 8 {
        return Err(PrimitiveError::InvalidLength);
    }
    let local = u64::from_le_bytes(
        blob.0
            .as_slice()
            .try_into()
            .map_err(|_| PrimitiveError::InvalidLength)?,
    );
    let anchored = anchor.current()?;

    if local == anchored {
        return build_pair(storage, anchor);
    }

    if local == anchored.checked_add(1).ok_or(PrimitiveError::LimitExceeded)? {
        match anchor.compare_and_increment(anchored) {
            Ok(value) if value == local => return build_pair(storage, anchor),
            Ok(_) => return Err(PrimitiveError::Internal),
            Err(_) => {
                if anchor.current()? == local {
                    return build_pair(storage, anchor);
                }
                return Err(PrimitiveError::Internal);
            }
        }
    }

    // `local < anchored` is an older authentic snapshot (rollback).
    // `local > anchored + 1` cannot be produced by one interrupted commit.
    Err(PrimitiveError::Internal)
}

fn build_pair<S>(
    storage: S,
    anchor: Arc<dyn RollbackAnchor>,
) -> Result<
    (
        Box<dyn TransactionalStorage>,
        Box<dyn MonotonicCounter>,
    ),
    PrimitiveError,
>
where
    S: TransactionalStorage + 'static,
{
    let coordination = Arc::new(Coordination::new(anchor));
    let wrapped_storage = AnchoredStorage::new(storage, coordination.clone());
    let counter = PreparedMonotonicCounter { coordination };
    Ok((Box::new(wrapped_storage), Box::new(counter)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    struct TestAnchor {
        value: AtomicU64,
        fail_once_after_increment: AtomicBool,
    }

    impl TestAnchor {
        fn new(value: u64) -> Self {
            Self {
                value: AtomicU64::new(value),
                fail_once_after_increment: AtomicBool::new(false),
            }
        }

        fn fail_after_next_increment(&self) {
            self.fail_once_after_increment.store(true, Ordering::Release);
        }
    }

    impl RollbackAnchor for TestAnchor {
        fn current(&self) -> Result<u64, PrimitiveError> {
            Ok(self.value.load(Ordering::Acquire))
        }

        fn compare_and_increment(&self, expected: u64) -> Result<u64, PrimitiveError> {
            let target = expected
                .checked_add(1)
                .ok_or(PrimitiveError::LimitExceeded)?;
            self.value
                .compare_exchange(expected, target, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| PrimitiveError::Internal)?;
            if self
                .fail_once_after_increment
                .swap(false, Ordering::AcqRel)
            {
                return Err(PrimitiveError::Internal);
            }
            Ok(target)
        }
    }

    fn commit_epoch(
        storage: &mut dyn TransactionalStorage,
        counter: &mut dyn MonotonicCounter,
        value: &[u8],
    ) -> Result<u64, PrimitiveError> {
        let epoch = counter.increment()?;
        let tx = storage.begin()?;
        storage.put(tx, b"state", &StateBlob(value.to_vec()))?;
        storage.put(
            tx,
            STORAGE_EPOCH_KEY,
            &StateBlob(epoch.to_le_bytes().to_vec()),
        )?;
        storage.commit(tx)?;
        Ok(epoch)
    }

    #[test]
    fn anchor_advances_only_after_local_commit() {
        let anchor = Arc::new(TestAnchor::new(0));
        let (mut storage, mut counter) =
            coordinated_backends_for_initialize(MemoryStorage::default(), anchor.clone()).unwrap();
        assert_eq!(counter.increment().unwrap(), 1);
        assert_eq!(anchor.current().unwrap(), 0);
        let tx = storage.begin().unwrap();
        storage
            .put(tx, b"state", &StateBlob(b"one".to_vec()))
            .unwrap();
        storage
            .put(tx, STORAGE_EPOCH_KEY, &StateBlob(1u64.to_le_bytes().to_vec()))
            .unwrap();
        storage.commit(tx).unwrap();
        assert_eq!(anchor.current().unwrap(), 1);
    }

    #[test]
    fn abort_does_not_advance_anchor() {
        let anchor = Arc::new(TestAnchor::new(0));
        let (mut storage, mut counter) =
            coordinated_backends_for_initialize(MemoryStorage::default(), anchor.clone()).unwrap();
        assert_eq!(counter.increment().unwrap(), 1);
        let tx = storage.begin().unwrap();
        storage
            .put(tx, STORAGE_EPOCH_KEY, &StateBlob(1u64.to_le_bytes().to_vec()))
            .unwrap();
        storage.abort(tx).unwrap();
        assert_eq!(anchor.current().unwrap(), 0);
        assert_eq!(counter.increment().unwrap(), 1);
    }

    #[test]
    fn ambiguous_anchor_response_is_resolved_by_reread() {
        let anchor = Arc::new(TestAnchor::new(0));
        anchor.fail_after_next_increment();
        let (mut storage, mut counter) =
            coordinated_backends_for_initialize(MemoryStorage::default(), anchor.clone()).unwrap();
        assert_eq!(commit_epoch(&mut *storage, &mut *counter, b"one").unwrap(), 1);
        assert_eq!(anchor.current().unwrap(), 1);
    }

    #[test]
    fn restore_rejects_anchor_ahead_of_local_snapshot() {
        let anchor = Arc::new(TestAnchor::new(2));
        let mut storage = MemoryStorage::default();
        let tx = storage.begin().unwrap();
        storage
            .put(tx, STORAGE_EPOCH_KEY, &StateBlob(1u64.to_le_bytes().to_vec()))
            .unwrap();
        storage.commit(tx).unwrap();
        assert!(coordinated_backends_for_restore(storage, anchor).is_err());
    }

    #[test]
    fn restore_reconciles_exactly_one_local_epoch_ahead() {
        let anchor = Arc::new(TestAnchor::new(4));
        let mut storage = MemoryStorage::default();
        let tx = storage.begin().unwrap();
        storage
            .put(tx, STORAGE_EPOCH_KEY, &StateBlob(5u64.to_le_bytes().to_vec()))
            .unwrap();
        storage.commit(tx).unwrap();
        let _ = coordinated_backends_for_restore(storage, anchor.clone()).unwrap();
        assert_eq!(anchor.current().unwrap(), 5);
    }

    #[test]
    fn restore_rejects_multi_epoch_gap() {
        let anchor = Arc::new(TestAnchor::new(4));
        let mut storage = MemoryStorage::default();
        let tx = storage.begin().unwrap();
        storage
            .put(tx, STORAGE_EPOCH_KEY, &StateBlob(6u64.to_le_bytes().to_vec()))
            .unwrap();
        storage.commit(tx).unwrap();
        assert!(coordinated_backends_for_restore(storage, anchor).is_err());
    }
}

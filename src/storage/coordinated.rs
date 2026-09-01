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

pub type CoordinatedBackendPair = (Box<dyn TransactionalStorage>, Box<dyn MonotonicCounter>);

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
        let previous = target.checked_sub(1).ok_or(PrimitiveError::Internal)?;

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

/// Why a critical-state restore was refused.
///
/// **Every variant is terminal for the state that produced it.** None can be
/// retried into success, and none can be worked around by calling
/// [`coordinated_backends_for_initialize`] instead: that function independently
/// refuses whenever the anchor is non-pristine or local state already carries an
/// epoch. The variants exist so the application can tell a *security event*
/// apart from an *operational* one, which an opaque `PrimitiveError::Internal`
/// made impossible.
///
/// # What the application must do next
///
/// This library deliberately does not choose the recovery policy, because the
/// choice trades a bricked account against silent history loss and that is a
/// product decision:
///
/// * **Refuse to start.** Safest. A genuinely corrupted anchor permanently
///   locks the user out with no path back.
/// * **Re-initialize from scratch and force re-keying.** Recoverable, but drops
///   message history and *must* be surfaced to the user. If it happens silently
///   it becomes a downgrade an attacker can trigger on purpose.
///
/// Whichever is chosen, [`RestoreRejection::is_security_event`] marks the
/// variants that must never be resolved without telling the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreRejection {
    /// `local < anchor`: an older authentic snapshot was presented for a device
    /// whose anchor has since advanced. This is the rollback signature — the
    /// encrypted snapshot is valid and correctly authenticated, it is simply
    /// *stale*. Reusing it would replay message keys and nonces.
    RollbackDetected { local_epoch: u64, anchor_epoch: u64 },

    /// `local > anchor + 1`: a gap no single interrupted commit can produce.
    /// Indicates a forked or substituted anchor, or a state file from a
    /// different device.
    EpochGap { local_epoch: u64, anchor_epoch: u64 },

    /// No local epoch record, but the anchor has already advanced. The local
    /// crypto database was destroyed or withheld while the anchor survived.
    LocalStateMissing { anchor_epoch: u64 },

    /// Neither local state nor a used anchor: this device was never
    /// initialized. The only non-security variant — the correct response is to
    /// call [`coordinated_backends_for_initialize`].
    NotInitialized,

    /// The epoch record exists but is not a well-formed little-endian `u64`.
    EpochRecordCorrupt,

    /// The anchor could not be read at all.
    AnchorUnavailable,

    /// Reconciling a single interrupted commit did not land on the expected
    /// value, meaning the anchor moved underneath us (concurrent use of one
    /// identity from two processes).
    AnchorReconciliationFailed {
        expected_epoch: u64,
        observed_epoch: u64,
    },
}

impl RestoreRejection {
    /// True when the refusal indicates tampering, rollback, or state loss
    /// rather than an ordinary un-provisioned device.
    ///
    /// Only [`RestoreRejection::NotInitialized`] is non-security. Everything
    /// else must be surfaced, never silently recovered from.
    pub fn is_security_event(self) -> bool {
        !matches!(self, Self::NotInitialized)
    }
}

impl core::fmt::Display for RestoreRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RollbackDetected { .. } => f.write_str("state rollback detected"),
            Self::EpochGap { .. } => f.write_str("impossible epoch gap"),
            Self::LocalStateMissing { .. } => f.write_str("local crypto state missing"),
            Self::NotInitialized => f.write_str("device not initialized"),
            Self::EpochRecordCorrupt => f.write_str("epoch record corrupt"),
            Self::AnchorUnavailable => f.write_str("rollback anchor unavailable"),
            Self::AnchorReconciliationFailed { .. } => f.write_str("anchor reconciliation failed"),
        }
    }
}

impl std::error::Error for RestoreRejection {}

impl From<RestoreRejection> for PrimitiveError {
    /// Collapses to the previous opaque errors so existing call sites keep
    /// compiling. Prefer matching on [`RestoreRejection`] directly.
    fn from(value: RestoreRejection) -> Self {
        match value {
            RestoreRejection::EpochRecordCorrupt
            | RestoreRejection::LocalStateMissing { .. }
            | RestoreRejection::NotInitialized => PrimitiveError::InvalidLength,
            _ => PrimitiveError::Internal,
        }
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
) -> Result<CoordinatedBackendPair, PrimitiveError>
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
/// - every other relationship fails closed with a typed [`RestoreRejection`].
///
/// A refusal here cannot be bypassed by calling
/// [`coordinated_backends_for_initialize`] instead — see the invariant tests in
/// this module.
pub fn coordinated_backends_for_restore<S>(
    storage: S,
    anchor: Arc<dyn RollbackAnchor>,
) -> Result<CoordinatedBackendPair, RestoreRejection>
where
    S: TransactionalStorage + 'static,
{
    let anchored = anchor
        .current()
        .map_err(|_| RestoreRejection::AnchorUnavailable)?;

    let record = storage
        .get(STORAGE_EPOCH_KEY)
        .map_err(|_| RestoreRejection::EpochRecordCorrupt)?;

    let Some(blob) = record else {
        // Distinguishing these two is the point of the type. A pristine anchor
        // with no local state is a device that was never set up; an advanced
        // anchor with no local state means the crypto database was destroyed or
        // withheld while the anchor survived, which is a security event.
        return Err(if anchored == 0 {
            RestoreRejection::NotInitialized
        } else {
            RestoreRejection::LocalStateMissing {
                anchor_epoch: anchored,
            }
        });
    };

    if blob.0.len() != 8 {
        return Err(RestoreRejection::EpochRecordCorrupt);
    }
    let local = u64::from_le_bytes(
        blob.0
            .as_slice()
            .try_into()
            .map_err(|_| RestoreRejection::EpochRecordCorrupt)?,
    );

    if local == anchored {
        return build_pair(storage, anchor).map_err(|_| RestoreRejection::AnchorUnavailable);
    }

    if local == anchored.saturating_add(1) {
        return match anchor.compare_and_increment(anchored) {
            Ok(value) if value == local => {
                build_pair(storage, anchor).map_err(|_| RestoreRejection::AnchorUnavailable)
            }
            Ok(observed) => Err(RestoreRejection::AnchorReconciliationFailed {
                expected_epoch: local,
                observed_epoch: observed,
            }),
            Err(_) => {
                // The CAS may have applied before the error surfaced. Re-read
                // rather than assume either way.
                let observed = anchor
                    .current()
                    .map_err(|_| RestoreRejection::AnchorUnavailable)?;
                if observed == local {
                    build_pair(storage, anchor).map_err(|_| RestoreRejection::AnchorUnavailable)
                } else {
                    Err(RestoreRejection::AnchorReconciliationFailed {
                        expected_epoch: local,
                        observed_epoch: observed,
                    })
                }
            }
        };
    }

    if local < anchored {
        // Authentic but stale snapshot. Accepting it would replay message keys.
        return Err(RestoreRejection::RollbackDetected {
            local_epoch: local,
            anchor_epoch: anchored,
        });
    }

    Err(RestoreRejection::EpochGap {
        local_epoch: local,
        anchor_epoch: anchored,
    })
}

fn build_pair<S>(
    storage: S,
    anchor: Arc<dyn RollbackAnchor>,
) -> Result<CoordinatedBackendPair, PrimitiveError>
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
            self.fail_once_after_increment
                .store(true, Ordering::Release);
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
            if self.fail_once_after_increment.swap(false, Ordering::AcqRel) {
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
            .put(
                tx,
                STORAGE_EPOCH_KEY,
                &StateBlob(1u64.to_le_bytes().to_vec()),
            )
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
            .put(
                tx,
                STORAGE_EPOCH_KEY,
                &StateBlob(1u64.to_le_bytes().to_vec()),
            )
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
        assert_eq!(
            commit_epoch(&mut *storage, &mut *counter, b"one").unwrap(),
            1
        );
        assert_eq!(anchor.current().unwrap(), 1);
    }

    #[test]
    fn restore_rejects_anchor_ahead_of_local_snapshot() {
        let anchor = Arc::new(TestAnchor::new(2));
        let mut storage = MemoryStorage::default();
        let tx = storage.begin().unwrap();
        storage
            .put(
                tx,
                STORAGE_EPOCH_KEY,
                &StateBlob(1u64.to_le_bytes().to_vec()),
            )
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
            .put(
                tx,
                STORAGE_EPOCH_KEY,
                &StateBlob(5u64.to_le_bytes().to_vec()),
            )
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
            .put(
                tx,
                STORAGE_EPOCH_KEY,
                &StateBlob(6u64.to_le_bytes().to_vec()),
            )
            .unwrap();
        storage.commit(tx).unwrap();
        assert!(coordinated_backends_for_restore(storage, anchor).is_err());
    }
}

/// Critical-state restore invariants (item 1, review 2026-08-28).
///
/// These tests exist to pin one property: **a refused restore has no path back
/// into a usable engine except an explicit, deliberate re-initialization by the
/// application.** Regression here is a rollback vulnerability, not a test
/// failure.
#[cfg(test)]
mod restore_fail_closed_tests {
    use super::*;
    use crate::storage::{MemoryStorage, StateBlob};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Anchor(AtomicU64);

    impl Anchor {
        fn at(n: u64) -> Arc<Self> {
            Arc::new(Self(AtomicU64::new(n)))
        }
    }

    impl RollbackAnchor for Anchor {
        fn current(&self) -> Result<u64, PrimitiveError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
        fn compare_and_increment(&self, expected: u64) -> Result<u64, PrimitiveError> {
            self.0
                .compare_exchange(expected, expected + 1, Ordering::SeqCst, Ordering::SeqCst)
                .map(|_| expected + 1)
                .map_err(|_| PrimitiveError::Internal)
        }
    }

    fn storage_at(epoch: u64) -> MemoryStorage {
        let mut s = MemoryStorage::default();
        let tx = s.begin().unwrap();
        s.put(
            tx,
            STORAGE_EPOCH_KEY,
            &StateBlob(epoch.to_le_bytes().to_vec()),
        )
        .unwrap();
        s.commit(tx).unwrap();
        s
    }

    #[test]
    fn stale_snapshot_is_named_as_rollback_not_opaque_internal() {
        let err = coordinated_backends_for_restore(storage_at(3), Anchor::at(7))
            .map(|_| ())
            .unwrap_err();
        assert_eq!(
            err,
            RestoreRejection::RollbackDetected {
                local_epoch: 3,
                anchor_epoch: 7
            }
        );
        assert!(err.is_security_event());
    }

    #[test]
    fn rollback_cannot_be_escaped_by_initializing_instead() {
        // The whole point of failing closed: the application must not be able to
        // route around a detected rollback by taking the other entry point.
        let anchor = Anchor::at(7);
        assert!(coordinated_backends_for_restore(storage_at(3), anchor.clone()).is_err());
        assert!(coordinated_backends_for_initialize(storage_at(3), anchor.clone()).is_err());
        // Nor by wiping local state first and initializing over a used anchor.
        assert!(coordinated_backends_for_initialize(MemoryStorage::default(), anchor).is_err());
    }

    #[test]
    fn wiped_local_state_with_used_anchor_is_a_security_event() {
        let err = coordinated_backends_for_restore(MemoryStorage::default(), Anchor::at(7))
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err, RestoreRejection::LocalStateMissing { anchor_epoch: 7 });
        assert!(err.is_security_event());
    }

    #[test]
    fn fresh_device_is_the_only_non_security_rejection() {
        let err = coordinated_backends_for_restore(MemoryStorage::default(), Anchor::at(0))
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err, RestoreRejection::NotInitialized);
        assert!(!err.is_security_event());
        // ...and it is genuinely recoverable via the documented entry point.
        assert!(
            coordinated_backends_for_initialize(MemoryStorage::default(), Anchor::at(0)).is_ok()
        );
    }

    #[test]
    fn impossible_epoch_gap_is_distinguished_from_rollback() {
        let err = coordinated_backends_for_restore(storage_at(20), Anchor::at(7))
            .map(|_| ())
            .unwrap_err();
        assert_eq!(
            err,
            RestoreRejection::EpochGap {
                local_epoch: 20,
                anchor_epoch: 7
            }
        );
    }

    #[test]
    fn corrupt_epoch_record_is_distinguished_from_missing_state() {
        let mut s = MemoryStorage::default();
        let tx = s.begin().unwrap();
        s.put(tx, STORAGE_EPOCH_KEY, &StateBlob(vec![1, 2, 3]))
            .unwrap();
        s.commit(tx).unwrap();
        assert_eq!(
            coordinated_backends_for_restore(s, Anchor::at(7))
                .map(|_| ())
                .unwrap_err(),
            RestoreRejection::EpochRecordCorrupt
        );
    }

    #[test]
    fn interrupted_commit_still_reconciles_exactly_once() {
        let anchor = Anchor::at(6);
        assert!(coordinated_backends_for_restore(storage_at(7), anchor.clone()).is_ok());
        assert_eq!(anchor.current().unwrap(), 7, "anchor advanced exactly once");
    }

    #[test]
    fn clean_restore_does_not_move_the_anchor() {
        let anchor = Anchor::at(7);
        assert!(coordinated_backends_for_restore(storage_at(7), anchor.clone()).is_ok());
        assert_eq!(anchor.current().unwrap(), 7);
    }

    #[test]
    fn every_rejection_except_not_initialized_is_a_security_event() {
        for r in [
            RestoreRejection::RollbackDetected {
                local_epoch: 1,
                anchor_epoch: 2,
            },
            RestoreRejection::EpochGap {
                local_epoch: 9,
                anchor_epoch: 2,
            },
            RestoreRejection::LocalStateMissing { anchor_epoch: 2 },
            RestoreRejection::EpochRecordCorrupt,
            RestoreRejection::AnchorUnavailable,
            RestoreRejection::AnchorReconciliationFailed {
                expected_epoch: 3,
                observed_epoch: 5,
            },
        ] {
            assert!(r.is_security_event(), "{r:?} must be a security event");
        }
        assert!(!RestoreRejection::NotInitialized.is_security_event());
    }
}

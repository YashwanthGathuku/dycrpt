//! Transactional storage abstraction for crash-safe ratchet persistence.
//!
//! Invariant: never produce externally sendable ciphertext unless the
//! corresponding ratchet-state transition can be committed safely.

pub mod monotonic;

use crate::primitives::error::PrimitiveError;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
pub struct StateBlob(pub Vec<u8>);

impl Drop for StateBlob {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StorageEpoch(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionId(pub u64);

pub trait TransactionalStorage: Send + Sync {
    fn begin(&mut self) -> Result<TransactionId, PrimitiveError>;
    fn put(
        &mut self,
        tx: TransactionId,
        key: &[u8],
        value: &StateBlob,
    ) -> Result<(), PrimitiveError>;
    fn delete(&mut self, tx: TransactionId, key: &[u8]) -> Result<(), PrimitiveError>;
    fn commit(&mut self, tx: TransactionId) -> Result<(), PrimitiveError>;
    fn abort(&mut self, tx: TransactionId) -> Result<(), PrimitiveError>;
    fn get(&self, key: &[u8]) -> Result<Option<StateBlob>, PrimitiveError>;
    fn epoch(&self) -> Result<StorageEpoch, PrimitiveError>;
    fn advance_epoch(&mut self) -> Result<StorageEpoch, PrimitiveError>;
}

#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct MemoryStorage {
    committed: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    staged: Option<(
        TransactionId,
        std::collections::HashMap<Vec<u8>, Option<Vec<u8>>>,
    )>,
    next_tx: u64,
    epoch: u64,
}

impl TransactionalStorage for MemoryStorage {
    fn begin(&mut self) -> Result<TransactionId, PrimitiveError> {
        if self.staged.is_some() {
            return Err(PrimitiveError::Internal);
        }
        let id = TransactionId(self.next_tx);
        self.next_tx += 1;
        self.staged = Some((id, std::collections::HashMap::new()));
        Ok(id)
    }

    fn put(
        &mut self,
        tx: TransactionId,
        key: &[u8],
        value: &StateBlob,
    ) -> Result<(), PrimitiveError> {
        let staged = self.staged.as_mut().ok_or(PrimitiveError::Internal)?;
        if staged.0 != tx {
            return Err(PrimitiveError::Internal);
        }
        staged.1.insert(key.to_vec(), Some(value.0.clone()));
        Ok(())
    }

    fn delete(&mut self, tx: TransactionId, key: &[u8]) -> Result<(), PrimitiveError> {
        let staged = self.staged.as_mut().ok_or(PrimitiveError::Internal)?;
        if staged.0 != tx {
            return Err(PrimitiveError::Internal);
        }
        staged.1.insert(key.to_vec(), None);
        Ok(())
    }

    fn commit(&mut self, tx: TransactionId) -> Result<(), PrimitiveError> {
        let staged = self.staged.take().ok_or(PrimitiveError::Internal)?;
        if staged.0 != tx {
            self.staged = Some(staged);
            return Err(PrimitiveError::Internal);
        }
        for (k, v) in staged.1 {
            match v {
                Some(val) => {
                    self.committed.insert(k, val);
                }
                None => {
                    self.committed.remove(&k);
                }
            }
        }
        Ok(())
    }

    fn abort(&mut self, tx: TransactionId) -> Result<(), PrimitiveError> {
        if let Some((id, _)) = &self.staged {
            if *id == tx {
                self.staged = None;
                return Ok(());
            }
        }
        Err(PrimitiveError::Internal)
    }

    fn get(&self, key: &[u8]) -> Result<Option<StateBlob>, PrimitiveError> {
        Ok(self.committed.get(key).map(|v| StateBlob(v.clone())))
    }

    fn epoch(&self) -> Result<StorageEpoch, PrimitiveError> {
        Ok(StorageEpoch(self.epoch))
    }

    fn advance_epoch(&mut self) -> Result<StorageEpoch, PrimitiveError> {
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or(PrimitiveError::LimitExceeded)?;
        Ok(StorageEpoch(self.epoch))
    }
}

/// Detects restoration of an older storage epoch (backup / rollback).
#[derive(Clone, Debug, Default)]
pub struct RollbackGuard {
    last_seen: u64,
}

impl RollbackGuard {
    /// Observe a loaded epoch. Fails if it is older than the last seen value.
    pub fn observe(&mut self, epoch: StorageEpoch) -> Result<(), PrimitiveError> {
        if epoch.0 < self.last_seen {
            return Err(PrimitiveError::Internal);
        }
        self.last_seen = epoch.0;
        Ok(())
    }

    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }
}

impl MemoryStorage {
    /// Committed keys (for crash-reload of all sessions).
    pub fn keys(&self) -> Vec<Vec<u8>> {
        self.committed.keys().cloned().collect()
    }

    /// Drop every committed blob (delete-all-sessions).
    pub fn clear(&mut self) {
        for v in self.committed.values_mut() {
            v.fill(0);
        }
        self.committed.clear();
        self.staged = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_before_commit_leaves_old_state() {
        let mut store = MemoryStorage::default();
        let key = b"session-1";
        let v1 = StateBlob(b"state-v1".to_vec());
        let tx = store.begin().unwrap();
        store.put(tx, key, &v1).unwrap();
        store.commit(tx).unwrap();

        let tx2 = store.begin().unwrap();
        let v2 = StateBlob(b"state-v2".to_vec());
        store.put(tx2, key, &v2).unwrap();
        store.abort(tx2).unwrap();

        let got = store.get(key).unwrap().unwrap();
        assert_eq!(got.0, b"state-v1");
    }

    #[test]
    fn epoch_advances_monotonically() {
        let mut store = MemoryStorage::default();
        let e0 = store.epoch().unwrap();
        store.advance_epoch().unwrap();
        let e1 = store.epoch().unwrap();
        assert!(e1 > e0);
    }

    #[test]
    fn rollback_guard_rejects_older_epoch() {
        let mut g = RollbackGuard::default();
        g.observe(StorageEpoch(3)).unwrap();
        g.observe(StorageEpoch(3)).unwrap();
        g.observe(StorageEpoch(5)).unwrap();
        assert!(g.observe(StorageEpoch(4)).is_err());
    }

    #[test]
    fn crash_during_put_before_commit() {
        let mut store = MemoryStorage::default();
        let tx = store.begin().unwrap();
        store
            .put(tx, b"k", &StateBlob(b"uncommitted".to_vec()))
            .unwrap();
        // Process crash ≈ drop staged transaction without commit.
        store.abort(tx).unwrap();
        assert!(store.get(b"k").unwrap().is_none());
    }
}

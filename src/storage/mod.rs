//! Transactional storage abstraction for crash-safe ratchet persistence.
//!
//! Invariant: never produce externally sendable ciphertext unless the
//! corresponding ratchet-state transition can be committed safely.
//!
//! Production hosts should combine [`encrypted_file::EncryptedFileStorage`]
//! with [`coordinated`] and a non-restorable [`trusted_anchor::RollbackAnchor`].
//! The coordinated adapter makes the durable ordering local-state-first then
//! anchor-finalization, and supports one-step forward recovery after a crash
//! between those two durable operations.

pub mod coordinated;
pub mod encrypted_file;
pub mod monotonic;
pub mod trusted_anchor;

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

/// Minimal durable-store contract required by the crypto engine.
///
/// Implementations must provide atomic transaction semantics: after a
/// successful `commit`, every staged put/delete is durable together; after a
/// successful `abort`, none of them are. If commit outcome is uncertain, return
/// an error — the engine will poison itself and refuse further crypto work.
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

    /// Enumerate committed keys so sessions can be restored/deleted without
    /// requiring an implementation-specific downcast.
    fn keys(&self) -> Result<Vec<Vec<u8>>, PrimitiveError>;

    /// Legacy/local epoch helpers retained for tests and adapters. The crypto
    /// engine does not treat these as a trusted anti-rollback primitive.
    fn epoch(&self) -> Result<StorageEpoch, PrimitiveError>;
    fn advance_epoch(&mut self) -> Result<StorageEpoch, PrimitiveError>;
}

/// Process-local transactional backend for tests and ephemeral development.
/// It is deliberately not encrypted and not rollback-resistant.
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

fn zeroize_staged(staged: &mut std::collections::HashMap<Vec<u8>, Option<Vec<u8>>>) {
    for value in staged.values_mut() {
        if let Some(bytes) = value.as_mut() {
            bytes.zeroize();
        }
    }
    staged.clear();
}

impl TransactionalStorage for MemoryStorage {
    fn begin(&mut self) -> Result<TransactionId, PrimitiveError> {
        if self.staged.is_some() {
            return Err(PrimitiveError::Internal);
        }
        let id = TransactionId(self.next_tx);
        self.next_tx = self
            .next_tx
            .checked_add(1)
            .ok_or(PrimitiveError::LimitExceeded)?;
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
        if let Some(Some(mut old)) = staged.1.insert(key.to_vec(), Some(value.0.clone())) {
            old.zeroize();
        }
        Ok(())
    }

    fn delete(&mut self, tx: TransactionId, key: &[u8]) -> Result<(), PrimitiveError> {
        let staged = self.staged.as_mut().ok_or(PrimitiveError::Internal)?;
        if staged.0 != tx {
            return Err(PrimitiveError::Internal);
        }
        if let Some(Some(mut old)) = staged.1.insert(key.to_vec(), None) {
            old.zeroize();
        }
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
                    if let Some(mut old) = self.committed.insert(k, val) {
                        old.zeroize();
                    }
                }
                None => {
                    if let Some(mut old) = self.committed.remove(&k) {
                        old.zeroize();
                    }
                }
            }
        }
        Ok(())
    }

    fn abort(&mut self, tx: TransactionId) -> Result<(), PrimitiveError> {
        match self.staged.take() {
            Some((id, mut staged)) if id == tx => {
                zeroize_staged(&mut staged);
                Ok(())
            }
            Some(other) => {
                self.staged = Some(other);
                Err(PrimitiveError::Internal)
            }
            None => Err(PrimitiveError::Internal),
        }
    }

    fn get(&self, key: &[u8]) -> Result<Option<StateBlob>, PrimitiveError> {
        Ok(self.committed.get(key).map(|v| StateBlob(v.clone())))
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>, PrimitiveError> {
        Ok(self.committed.keys().cloned().collect())
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

/// Detects restoration of an older storage epoch within a running process.
/// Production anti-rollback also requires an external anchor that cannot be
/// restored together with app data.
#[derive(Clone, Debug, Default)]
pub struct RollbackGuard {
    last_seen: u64,
}

impl RollbackGuard {
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
    pub fn keys(&self) -> Vec<Vec<u8>> {
        self.committed.keys().cloned().collect()
    }

    pub fn clear(&mut self) {
        for v in self.committed.values_mut() {
            v.zeroize();
        }
        self.committed.clear();
        if let Some((_, mut staged)) = self.staged.take() {
            zeroize_staged(&mut staged);
        }
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
        store.abort(tx).unwrap();
        assert!(store.get(b"k").unwrap().is_none());
    }

    #[test]
    fn trait_key_enumeration_matches_committed_state() {
        let mut store = MemoryStorage::default();
        let tx = store.begin().unwrap();
        store.put(tx, b"a", &StateBlob(vec![1])).unwrap();
        store.put(tx, b"b", &StateBlob(vec![2])).unwrap();
        store.commit(tx).unwrap();
        let mut keys = TransactionalStorage::keys(&store).unwrap();
        keys.sort();
        assert_eq!(keys, vec![b"a".to_vec(), b"b".to_vec()]);
    }
}

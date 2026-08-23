//! Encrypted durable transactional storage for mobile/desktop hosts.
//!
//! The host supplies a random 256-bit storage key. On Android that key should
//! be wrapped/protected by Android Keystore (StrongBox when available); on iOS
//! it should be protected by Keychain/Secure Enclave policy. The key is never
//! written by this backend.
//!
//! Each commit writes one AES-256-GCM authenticated snapshot to a temporary
//! file, `fsync`s it, atomically renames it over the live snapshot, and fsyncs
//! the parent directory. Rollback detection is deliberately NOT provided here:
//! use the independent `MonotonicCounter`/trusted-anchor contract for that.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::primitives::aead::{self, AeadKey, TAG_LEN};
use crate::primitives::error::PrimitiveError;
use crate::primitives::random::fill_random;
use crate::storage::{StateBlob, StorageEpoch, TransactionId, TransactionalStorage};

const FILE_MAGIC: &[u8; 8] = b"VCENCST1";
const MAP_MAGIC: &[u8; 8] = b"VCMAP001";
const STORAGE_AD: &[u8] = b"VoiceChat/EncryptedFileStorage/v1";
const NONCE_LEN: usize = 12;
const MAX_STORAGE_FILE: usize = 512 * 1024 * 1024;
const MAX_RECORDS: usize = 200_000;
const MAX_KEY_LEN: usize = 64 * 1024;
const MAX_VALUE_LEN: usize = 80 * 1024 * 1024;

type SnapshotMap = HashMap<Vec<u8>, Vec<u8>>;

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct StagedValue(Option<Vec<u8>>);

/// Atomic encrypted snapshot implementation of [`TransactionalStorage`].
pub struct EncryptedFileStorage {
    path: PathBuf,
    key: AeadKey,
    committed: HashMap<Vec<u8>, Vec<u8>>,
    staged: Option<(TransactionId, HashMap<Vec<u8>, StagedValue>)>,
    next_tx: u64,
    local_epoch: u64,
}

impl EncryptedFileStorage {
    /// Open an existing snapshot or create an empty store if the path does not
    /// yet exist. `key_bytes` must come from a host secure-key facility and must
    /// not be restored together with an attacker-controlled backup.
    pub fn open(path: impl Into<PathBuf>, key_bytes: [u8; 32]) -> Result<Self, PrimitiveError> {
        let path = path.into();
        let key = AeadKey::from_bytes(key_bytes);
        let (committed, local_epoch) = if path.exists() {
            Self::read_snapshot(&path, &key)?
        } else {
            (HashMap::new(), 0)
        };
        Ok(Self {
            path,
            key,
            committed,
            staged: None,
            next_tx: 1,
            local_epoch,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_snapshot(path: &Path, key: &AeadKey) -> Result<(SnapshotMap, u64), PrimitiveError> {
        let metadata = fs::metadata(path).map_err(|_| PrimitiveError::Internal)?;
        let file_len =
            usize::try_from(metadata.len()).map_err(|_| PrimitiveError::LimitExceeded)?;
        if file_len < FILE_MAGIC.len() + NONCE_LEN + TAG_LEN || file_len > MAX_STORAGE_FILE {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut bytes = Vec::with_capacity(file_len);
        File::open(path)
            .and_then(|mut f| f.read_to_end(&mut bytes))
            .map_err(|_| PrimitiveError::Internal)?;
        if bytes.len() != file_len || &bytes[..8] != FILE_MAGIC {
            bytes.zeroize();
            return Err(PrimitiveError::InvalidLength);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[8..8 + NONCE_LEN]);
        let mut plaintext = aead::open(key, &nonce, &bytes[8 + NONCE_LEN..], STORAGE_AD)?;
        bytes.zeroize();
        let parsed = Self::decode_map(&plaintext);
        plaintext.zeroize();
        parsed
    }

    fn decode_map(data: &[u8]) -> Result<(SnapshotMap, u64), PrimitiveError> {
        if data.len() < 8 + 8 + 4 || &data[..8] != MAP_MAGIC {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut i = 8usize;
        let epoch = read_u64(data, &mut i)?;
        let count = read_u32(data, &mut i)? as usize;
        if count > MAX_RECORDS {
            return Err(PrimitiveError::LimitExceeded);
        }
        let mut map = HashMap::with_capacity(count);
        for _ in 0..count {
            let key_len = read_u32(data, &mut i)? as usize;
            let value_len = read_u32(data, &mut i)? as usize;
            if key_len == 0 || key_len > MAX_KEY_LEN || value_len > MAX_VALUE_LEN {
                return Err(PrimitiveError::LimitExceeded);
            }
            let key = take(data, &mut i, key_len)?.to_vec();
            let value = take(data, &mut i, value_len)?.to_vec();
            if map.insert(key, value).is_some() {
                return Err(PrimitiveError::InvalidLength);
            }
        }
        if i != data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        Ok((map, epoch))
    }

    fn effective_record_count(
        &self,
        staged: &HashMap<Vec<u8>, StagedValue>,
    ) -> Result<usize, PrimitiveError> {
        let mut count = self.committed.len();
        for (key, value) in staged {
            let existed = self.committed.contains_key(key);
            match (&value.0, existed) {
                (Some(_), false) => {
                    count = count.checked_add(1).ok_or(PrimitiveError::LimitExceeded)?
                }
                (None, true) => count = count.checked_sub(1).ok_or(PrimitiveError::Internal)?,
                _ => {}
            }
        }
        if count > MAX_RECORDS {
            return Err(PrimitiveError::LimitExceeded);
        }
        Ok(count)
    }

    fn encode_effective_map(
        &self,
        staged: &HashMap<Vec<u8>, StagedValue>,
    ) -> Result<Vec<u8>, PrimitiveError> {
        let count = self.effective_record_count(staged)?;
        let mut out = Vec::new();
        out.extend_from_slice(MAP_MAGIC);
        out.extend_from_slice(&self.local_epoch.to_le_bytes());
        out.extend_from_slice(&(count as u32).to_le_bytes());

        let mut emitted = HashSet::with_capacity(count);
        let mut keys: Vec<&Vec<u8>> = self.committed.keys().collect();
        keys.sort();
        for key in keys {
            match staged.get(key).and_then(|v| v.0.as_ref()) {
                Some(value) => append_record(&mut out, key, value)?,
                None if staged.contains_key(key) => continue,
                None => append_record(
                    &mut out,
                    key,
                    self.committed.get(key).ok_or(PrimitiveError::Internal)?,
                )?,
            }
            emitted.insert(key.clone());
        }

        let mut new_keys: Vec<&Vec<u8>> = staged
            .iter()
            .filter_map(|(key, value)| {
                if !self.committed.contains_key(key) && value.0.is_some() {
                    Some(key)
                } else {
                    None
                }
            })
            .collect();
        new_keys.sort();
        for key in new_keys {
            let value = staged
                .get(key)
                .and_then(|v| v.0.as_ref())
                .ok_or(PrimitiveError::Internal)?;
            append_record(&mut out, key, value)?;
            emitted.insert(key.clone());
        }
        if emitted.len() != count || out.len() > MAX_STORAGE_FILE {
            out.zeroize();
            return Err(PrimitiveError::LimitExceeded);
        }
        Ok(out)
    }

    fn persist_staged(&self, staged: &HashMap<Vec<u8>, StagedValue>) -> Result<(), PrimitiveError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|_| PrimitiveError::Internal)?;

        let mut plaintext = self.encode_effective_map(staged)?;
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce)?;
        let encrypted = aead::seal(&self.key, &nonce, &plaintext, STORAGE_AD);
        plaintext.zeroize();
        let mut encrypted = encrypted?;

        let mut suffix = [0u8; 16];
        fill_random(&mut suffix)?;
        let suffix_hex = encode_lower_hex(&suffix);
        suffix.zeroize();
        let file_name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(PrimitiveError::InvalidLength)?;
        let temp_path = parent.join(format!(".{file_name}.{suffix_hex}.tmp"));

        let write_result = (|| {
            let mut temp = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|_| PrimitiveError::Internal)?;
            temp.write_all(FILE_MAGIC)
                .map_err(|_| PrimitiveError::Internal)?;
            temp.write_all(&nonce)
                .map_err(|_| PrimitiveError::Internal)?;
            temp.write_all(&encrypted)
                .map_err(|_| PrimitiveError::Internal)?;
            temp.sync_all().map_err(|_| PrimitiveError::Internal)?;
            drop(temp);
            fs::rename(&temp_path, &self.path).map_err(|_| PrimitiveError::Internal)?;
            File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| PrimitiveError::Internal)?;
            Ok(())
        })();
        encrypted.zeroize();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result
    }

    fn apply_staged(&mut self, mut staged: HashMap<Vec<u8>, StagedValue>) {
        for (key, mut staged_value) in staged.drain() {
            match staged_value.0.take() {
                Some(value) => {
                    if let Some(mut old) = self.committed.insert(key, value) {
                        old.zeroize();
                    }
                }
                None => {
                    if let Some(mut old) = self.committed.remove(&key) {
                        old.zeroize();
                    }
                }
            }
        }
    }
}

impl TransactionalStorage for EncryptedFileStorage {
    fn begin(&mut self) -> Result<TransactionId, PrimitiveError> {
        if self.staged.is_some() {
            return Err(PrimitiveError::Internal);
        }
        let tx = TransactionId(self.next_tx);
        self.next_tx = self
            .next_tx
            .checked_add(1)
            .ok_or(PrimitiveError::LimitExceeded)?;
        self.staged = Some((tx, HashMap::new()));
        Ok(tx)
    }

    fn put(
        &mut self,
        tx: TransactionId,
        key: &[u8],
        value: &StateBlob,
    ) -> Result<(), PrimitiveError> {
        if key.is_empty() || key.len() > MAX_KEY_LEN || value.0.len() > MAX_VALUE_LEN {
            return Err(PrimitiveError::LimitExceeded);
        }
        let staged = self.staged.as_mut().ok_or(PrimitiveError::Internal)?;
        if staged.0 != tx {
            return Err(PrimitiveError::Internal);
        }
        staged
            .1
            .insert(key.to_vec(), StagedValue(Some(value.0.clone())));
        Ok(())
    }

    fn delete(&mut self, tx: TransactionId, key: &[u8]) -> Result<(), PrimitiveError> {
        if key.is_empty() || key.len() > MAX_KEY_LEN {
            return Err(PrimitiveError::LimitExceeded);
        }
        let staged = self.staged.as_mut().ok_or(PrimitiveError::Internal)?;
        if staged.0 != tx {
            return Err(PrimitiveError::Internal);
        }
        staged.1.insert(key.to_vec(), StagedValue(None));
        Ok(())
    }

    fn commit(&mut self, tx: TransactionId) -> Result<(), PrimitiveError> {
        let (id, staged) = self.staged.take().ok_or(PrimitiveError::Internal)?;
        if id != tx {
            self.staged = Some((id, staged));
            return Err(PrimitiveError::Internal);
        }
        if let Err(e) = self.persist_staged(&staged) {
            self.staged = Some((id, staged));
            return Err(e);
        }
        self.apply_staged(staged);
        Ok(())
    }

    fn abort(&mut self, tx: TransactionId) -> Result<(), PrimitiveError> {
        let (id, mut staged) = self.staged.take().ok_or(PrimitiveError::Internal)?;
        if id != tx {
            self.staged = Some((id, staged));
            return Err(PrimitiveError::Internal);
        }
        for value in staged.values_mut() {
            value.zeroize();
        }
        staged.clear();
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<StateBlob>, PrimitiveError> {
        Ok(self.committed.get(key).map(|v| StateBlob(v.clone())))
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>, PrimitiveError> {
        Ok(self.committed.keys().cloned().collect())
    }

    fn epoch(&self) -> Result<StorageEpoch, PrimitiveError> {
        Ok(StorageEpoch(self.local_epoch))
    }

    fn advance_epoch(&mut self) -> Result<StorageEpoch, PrimitiveError> {
        self.local_epoch = self
            .local_epoch
            .checked_add(1)
            .ok_or(PrimitiveError::LimitExceeded)?;
        Ok(StorageEpoch(self.local_epoch))
    }
}

impl Drop for EncryptedFileStorage {
    fn drop(&mut self) {
        for value in self.committed.values_mut() {
            value.zeroize();
        }
        self.committed.clear();
        if let Some((_, staged)) = self.staged.as_mut() {
            for value in staged.values_mut() {
                value.zeroize();
            }
            staged.clear();
        }
    }
}

fn append_record(out: &mut Vec<u8>, key: &[u8], value: &[u8]) -> Result<(), PrimitiveError> {
    if key.is_empty() || key.len() > MAX_KEY_LEN || value.len() > MAX_VALUE_LEN {
        return Err(PrimitiveError::LimitExceeded);
    }
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(value);
    Ok(())
}

fn take<'a>(data: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8], PrimitiveError> {
    let end = i.checked_add(n).ok_or(PrimitiveError::LimitExceeded)?;
    if end > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let value = &data[*i..end];
    *i = end;
    Ok(value)
}

fn read_u32(data: &[u8], i: &mut usize) -> Result<u32, PrimitiveError> {
    Ok(u32::from_le_bytes(
        take(data, i, 4)?
            .try_into()
            .map_err(|_| PrimitiveError::InvalidLength)?,
    ))
}

fn read_u64(data: &[u8], i: &mut usize) -> Result<u64, PrimitiveError> {
    Ok(u64::from_le_bytes(
        take(data, i, 8)?
            .try_into()
            .map_err(|_| PrimitiveError::InvalidLength)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        let mut random = [0u8; 8];
        fill_random(&mut random).unwrap();
        let suffix = encode_lower_hex(&random);
        std::env::temp_dir().join(format!("voicechat-{label}-{suffix}.store"))
    }

    #[test]
    fn encrypted_store_roundtrip_and_wrong_key_fails() {
        let path = temp_path("roundtrip");
        let key = [7u8; 32];
        {
            let mut store = EncryptedFileStorage::open(&path, key).unwrap();
            let tx = store.begin().unwrap();
            store
                .put(tx, b"session", &StateBlob(b"secret-state".to_vec()))
                .unwrap();
            store.commit(tx).unwrap();
        }
        let store = EncryptedFileStorage::open(&path, key).unwrap();
        assert_eq!(store.get(b"session").unwrap().unwrap().0, b"secret-state");
        assert!(EncryptedFileStorage::open(&path, [8u8; 32]).is_err());
        let raw = fs::read(&path).unwrap();
        assert!(!raw
            .windows(b"secret-state".len())
            .any(|w| w == b"secret-state"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn abort_never_reaches_disk() {
        let path = temp_path("abort");
        let mut store = EncryptedFileStorage::open(&path, [3u8; 32]).unwrap();
        let tx = store.begin().unwrap();
        store.put(tx, b"k", &StateBlob(b"v".to_vec())).unwrap();
        store.abort(tx).unwrap();
        assert!(store.get(b"k").unwrap().is_none());
        assert!(!path.exists());
    }

    #[test]
    fn delete_is_durable() {
        let path = temp_path("delete");
        let key = [9u8; 32];
        let mut store = EncryptedFileStorage::open(&path, key).unwrap();
        let tx = store.begin().unwrap();
        store.put(tx, b"k", &StateBlob(b"v".to_vec())).unwrap();
        store.commit(tx).unwrap();
        let tx = store.begin().unwrap();
        store.delete(tx, b"k").unwrap();
        store.commit(tx).unwrap();
        drop(store);
        let restored = EncryptedFileStorage::open(&path, key).unwrap();
        assert!(restored.get(b"k").unwrap().is_none());
        let _ = fs::remove_file(path);
    }
}

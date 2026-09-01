//! Bounded replay cache.
//!
//! Prevents acceptance of previously processed protocol messages while
//! keeping memory usage strictly bounded. Persisted state is treated as
//! untrusted input: counts, capacities, field lengths, duplicate keys, and
//! trailing bytes are all validated before state is restored.

use crate::primitives::error::PrimitiveError;
use std::collections::{HashMap, VecDeque};

/// Maximum number of message identifiers retained per conversation.
pub const DEFAULT_REPLAY_CACHE_SIZE: usize = 4096;
/// Hard upper bound accepted from persisted state.
pub const MAX_REPLAY_CACHE_SIZE: usize = 65_536;
/// Persisted replay-key component bounds. These are deliberately much larger
/// than normal protocol values while preventing attacker-controlled allocation.
const MAX_CONVERSATION_ID_LEN: usize = 64 * 1024;
const MAX_SENDER_DEVICE_ID_LEN: usize = 4 * 1024;
const MAX_MESSAGE_ID_LEN: usize = 16 * 1024;

/// Key that uniquely identifies a message for replay detection.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ReplayKey {
    pub conversation_id: Vec<u8>,
    pub sender_device_id: Vec<u8>,
    pub message_id: Vec<u8>,
}

impl ReplayKey {
    fn validate(&self) -> Result<(), PrimitiveError> {
        if self.conversation_id.len() > MAX_CONVERSATION_ID_LEN
            || self.sender_device_id.len() > MAX_SENDER_DEVICE_ID_LEN
            || self.message_id.is_empty()
            || self.message_id.len() > MAX_MESSAGE_ID_LEN
        {
            return Err(PrimitiveError::LimitExceeded);
        }
        Ok(())
    }
}

/// Bounded, FIFO-evicting replay cache.
pub struct ReplayCache {
    capacity: usize,
    order: VecDeque<ReplayKey>,
    present: HashMap<ReplayKey, ()>,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0 && capacity <= MAX_REPLAY_CACHE_SIZE);
        Self {
            capacity,
            order: VecDeque::with_capacity(capacity),
            present: HashMap::with_capacity(capacity),
        }
    }

    /// True if this key is already recorded.
    pub fn contains(&self, key: &ReplayKey) -> bool {
        self.present.contains_key(key)
    }

    /// Returns true if the key was already seen (replay).
    /// Otherwise inserts it and returns false.
    pub fn check_and_insert(&mut self, key: ReplayKey) -> Result<bool, PrimitiveError> {
        key.validate()?;
        if self.present.contains_key(&key) {
            return Ok(true);
        }
        if self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.present.remove(&old);
            }
        }
        self.present.insert(key.clone(), ());
        self.order.push_back(key);
        Ok(false)
    }

    pub fn len(&self) -> usize {
        self.present.len()
    }

    pub fn is_empty(&self) -> bool {
        self.present.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut o = b"VCREPL01".to_vec();
        o.extend_from_slice(&(self.capacity as u32).to_le_bytes());
        o.extend_from_slice(&(self.order.len() as u32).to_le_bytes());
        for k in &self.order {
            put_vec(&mut o, &k.conversation_id);
            put_vec(&mut o, &k.sender_device_id);
            put_vec(&mut o, &k.message_id);
        }
        o
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, PrimitiveError> {
        if data.len() < 16 || &data[..8] != b"VCREPL01" {
            return Err(PrimitiveError::InvalidLength);
        }
        let capacity = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let n = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        if capacity == 0 || capacity > MAX_REPLAY_CACHE_SIZE || n > capacity {
            return Err(PrimitiveError::LimitExceeded);
        }

        let mut i = 16;
        let mut cache = Self::new(capacity);
        for _ in 0..n {
            let conversation_id = take_vec(data, &mut i, MAX_CONVERSATION_ID_LEN)?;
            let sender_device_id = take_vec(data, &mut i, MAX_SENDER_DEVICE_ID_LEN)?;
            let message_id = take_vec(data, &mut i, MAX_MESSAGE_ID_LEN)?;
            let key = ReplayKey {
                conversation_id,
                sender_device_id,
                message_id,
            };
            key.validate()?;
            // Duplicate serialized keys are non-canonical and would make the
            // FIFO order disagree with the set representation.
            if cache.present.contains_key(&key) {
                return Err(PrimitiveError::InvalidLength);
            }
            cache.present.insert(key.clone(), ());
            cache.order.push_back(key);
        }
        if i != data.len() || cache.order.len() != cache.present.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        Ok(cache)
    }
}

fn put_vec(o: &mut Vec<u8>, b: &[u8]) {
    o.extend_from_slice(&(b.len() as u32).to_le_bytes());
    o.extend_from_slice(b);
}

fn take_vec(data: &[u8], i: &mut usize, max: usize) -> Result<Vec<u8>, PrimitiveError> {
    if *i + 4 > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let n = u32::from_le_bytes(data[*i..*i + 4].try_into().unwrap()) as usize;
    *i += 4;
    if n > max {
        return Err(PrimitiveError::LimitExceeded);
    }
    if *i + n > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let v = data[*i..*i + n].to_vec();
    *i += n;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: u8) -> ReplayKey {
        ReplayKey {
            conversation_id: b"c".to_vec(),
            sender_device_id: b"d".to_vec(),
            message_id: vec![id],
        }
    }

    #[test]
    fn detects_replay() {
        let mut cache = ReplayCache::new(4);
        assert!(!cache.check_and_insert(key(1)).unwrap());
        assert!(cache.check_and_insert(key(1)).unwrap());
    }

    #[test]
    fn respects_capacity() {
        let mut cache = ReplayCache::new(3);
        for i in 0..5u8 {
            let _ = cache.check_and_insert(key(i)).unwrap();
        }
        assert!(cache.len() <= 3);
        assert!(!cache.check_and_insert(key(0)).unwrap());
    }

    #[test]
    fn serialize_reload_preserves_entries() {
        let mut cache = ReplayCache::new(8);
        assert!(!cache.check_and_insert(key(3)).unwrap());
        let mut cache2 = ReplayCache::deserialize(&cache.serialize()).unwrap();
        assert!(cache2.contains(&key(3)));
        assert!(cache2.check_and_insert(key(3)).unwrap());
    }

    #[test]
    fn deserialize_rejects_count_greater_than_capacity() {
        let mut blob = b"VCREPL01".to_vec();
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&2u32.to_le_bytes());
        assert!(ReplayCache::deserialize(&blob).is_err());
    }

    #[test]
    fn deserialize_rejects_oversized_capacity_before_allocating() {
        let mut blob = b"VCREPL01".to_vec();
        blob.extend_from_slice(&((MAX_REPLAY_CACHE_SIZE as u32) + 1).to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        assert!(ReplayCache::deserialize(&blob).is_err());
    }

    #[test]
    fn deserialize_rejects_duplicate_keys() {
        let mut cache = ReplayCache::new(4);
        cache.check_and_insert(key(7)).unwrap();
        let one = cache.serialize();

        // Rebuild a valid header claiming two entries, then append the same
        // serialized key payload twice.
        let payload = &one[16..];
        let mut blob = b"VCREPL01".to_vec();
        blob.extend_from_slice(&4u32.to_le_bytes());
        blob.extend_from_slice(&2u32.to_le_bytes());
        blob.extend_from_slice(payload);
        blob.extend_from_slice(payload);
        assert!(ReplayCache::deserialize(&blob).is_err());
    }

    #[test]
    fn check_and_insert_rejects_oversized_components() {
        let mut cache = ReplayCache::new(4);
        let oversized = ReplayKey {
            conversation_id: vec![0; MAX_CONVERSATION_ID_LEN + 1],
            sender_device_id: b"d".to_vec(),
            message_id: vec![1],
        };
        assert!(cache.check_and_insert(oversized).is_err());
    }
}

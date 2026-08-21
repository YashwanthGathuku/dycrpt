//! Bounded replay cache.
//!
//! Prevents acceptance of previously processed protocol messages while
//! keeping memory usage strictly bounded.

use crate::primitives::error::PrimitiveError;
use std::collections::{HashMap, VecDeque};

/// Maximum number of message identifiers retained per conversation.
pub const DEFAULT_REPLAY_CACHE_SIZE: usize = 4096;

/// Key that uniquely identifies a message for replay detection.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ReplayKey {
    pub conversation_id: Vec<u8>,
    pub sender_device_id: Vec<u8>,
    pub message_id: Vec<u8>,
}

/// Bounded, FIFO-evicting replay cache.
pub struct ReplayCache {
    capacity: usize,
    order: VecDeque<ReplayKey>,
    present: HashMap<ReplayKey, ()>,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
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
        if self.present.contains_key(&key) {
            return Ok(true); // replay
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
        if capacity == 0 {
            return Err(PrimitiveError::InvalidLength);
        }
        let mut i = 16;
        let mut cache = Self::new(capacity);
        for _ in 0..n {
            let conversation_id = take_vec(data, &mut i)?;
            let sender_device_id = take_vec(data, &mut i)?;
            let message_id = take_vec(data, &mut i)?;
            let key = ReplayKey {
                conversation_id,
                sender_device_id,
                message_id,
            };
            cache.present.insert(key.clone(), ());
            cache.order.push_back(key);
        }
        if i != data.len() {
            return Err(PrimitiveError::InvalidLength);
        }
        Ok(cache)
    }
}

fn put_vec(o: &mut Vec<u8>, b: &[u8]) {
    o.extend_from_slice(&(b.len() as u32).to_le_bytes());
    o.extend_from_slice(b);
}

fn take_vec(data: &[u8], i: &mut usize) -> Result<Vec<u8>, PrimitiveError> {
    if *i + 4 > data.len() {
        return Err(PrimitiveError::InvalidLength);
    }
    let n = u32::from_le_bytes(data[*i..*i + 4].try_into().unwrap()) as usize;
    *i += 4;
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
        assert_eq!(cache.check_and_insert(key(1)).unwrap(), false);
        assert_eq!(cache.check_and_insert(key(1)).unwrap(), true);
    }

    #[test]
    fn respects_capacity() {
        let mut cache = ReplayCache::new(3);
        for i in 0..5u8 {
            let _ = cache.check_and_insert(key(i)).unwrap();
        }
        assert!(cache.len() <= 3);
        // oldest (0) should have been evicted
        assert_eq!(cache.check_and_insert(key(0)).unwrap(), false);
    }

    #[test]
    fn serialize_reload_preserves_entries() {
        let mut cache = ReplayCache::new(8);
        assert!(!cache.check_and_insert(key(3)).unwrap());
        let mut cache2 = ReplayCache::deserialize(&cache.serialize()).unwrap();
        assert!(cache2.contains(&key(3)));
        assert!(cache2.check_and_insert(key(3)).unwrap());
    }
}

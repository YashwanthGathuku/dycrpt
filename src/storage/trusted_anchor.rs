//! Rollback-resistant monotonic anchor adapter.
//!
//! Encrypted storage prevents disclosure/tampering but cannot distinguish the
//! newest valid ciphertext from an older valid ciphertext restored from backup.
//! This module deliberately separates that problem behind an anchor that lives
//! outside the application's restorable data domain.

use crate::primitives::error::PrimitiveError;
use crate::storage::monotonic::MonotonicCounter;

/// Backend contract for a value that cannot be rolled back together with the
/// local encrypted crypto-state snapshot.
///
/// Implementations may be server-anchored, hardware-backed, or another reviewed
/// non-restorable platform primitive. A plain file/database row stored beside
/// the crypto database does NOT satisfy this contract.
pub trait RollbackAnchor: Send + Sync {
    /// Read the currently committed anchor value.
    fn current(&self) -> Result<u64, PrimitiveError>;

    /// Atomically change `expected` to `expected + 1` and return the new value.
    ///
    /// On `Err`, the implementation MUST resolve ambiguity before returning: it
    /// must know whether the value changed. If the remote/hardware outcome is
    /// unknown, the implementation must fail the application closed until it
    /// can re-read/reconcile the anchor.
    fn compare_and_increment(&self, expected: u64) -> Result<u64, PrimitiveError>;
}

/// Adapts a rollback-resistant compare-and-increment anchor to the engine's
/// `MonotonicCounter` contract.
pub struct AnchoredMonotonicCounter<A: RollbackAnchor> {
    anchor: A,
}

impl<A: RollbackAnchor> AnchoredMonotonicCounter<A> {
    pub fn new(anchor: A) -> Self {
        Self { anchor }
    }

    pub fn into_inner(self) -> A {
        self.anchor
    }
}

impl<A: RollbackAnchor> MonotonicCounter for AnchoredMonotonicCounter<A> {
    fn current(&self) -> Result<u64, PrimitiveError> {
        self.anchor.current()
    }

    fn increment(&mut self) -> Result<u64, PrimitiveError> {
        let before = self.anchor.current()?;
        let after = self.anchor.compare_and_increment(before)?;
        if after != before.checked_add(1).ok_or(PrimitiveError::LimitExceeded)? {
            return Err(PrimitiveError::Internal);
        }
        Ok(after)
    }
}

/// In-memory anchor useful only for deterministic tests. It intentionally does
/// not claim rollback resistance across process/device restore.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct TestAnchor(Mutex<u64>);

    impl RollbackAnchor for TestAnchor {
        fn current(&self) -> Result<u64, PrimitiveError> {
            Ok(*self.0.lock().map_err(|_| PrimitiveError::Internal)?)
        }

        fn compare_and_increment(&self, expected: u64) -> Result<u64, PrimitiveError> {
            let mut value = self.0.lock().map_err(|_| PrimitiveError::Internal)?;
            if *value != expected {
                return Err(PrimitiveError::Internal);
            }
            *value = value.checked_add(1).ok_or(PrimitiveError::LimitExceeded)?;
            Ok(*value)
        }
    }

    #[test]
    fn adapter_is_strictly_monotonic() {
        let anchor = TestAnchor(Mutex::new(4));
        let mut counter = AnchoredMonotonicCounter::new(anchor);
        assert_eq!(counter.current().unwrap(), 4);
        assert_eq!(counter.increment().unwrap(), 5);
        assert_eq!(counter.increment().unwrap(), 6);
    }

    struct BadAnchor;

    impl RollbackAnchor for BadAnchor {
        fn current(&self) -> Result<u64, PrimitiveError> {
            Ok(9)
        }

        fn compare_and_increment(&self, _expected: u64) -> Result<u64, PrimitiveError> {
            Ok(11)
        }
    }

    #[test]
    fn adapter_rejects_non_unit_jump() {
        let mut counter = AnchoredMonotonicCounter::new(BadAnchor);
        assert!(counter.increment().is_err());
    }
}

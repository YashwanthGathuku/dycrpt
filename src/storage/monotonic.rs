//! Monotonic counter abstraction for rollback resistance.
//!
//! The crypto engine binds every durable state commit to one strictly
//! increasing counter value. A restored snapshot is accepted only when the
//! counter value stored with the snapshot exactly matches the external
//! monotonic counter.
//!
//! Production implementations should bind this trait to a value that is not
//! restored together with application data (hardware/TEE backed where the
//! platform provides a suitable primitive). `MemoryCounter` is intentionally
//! test/dev only and does not survive process recreation.

use crate::primitives::error::PrimitiveError;

/// Strictly increasing counter. Implementations must not wrap or move backwards.
///
/// **Failure contract:** if `increment()` returns `Err`, the implementation must
/// guarantee that the durable counter value did not change. A backend whose
/// increment outcome can become "unknown" after an error is not compatible with
/// this trait; it needs an adapter/protocol that resolves the outcome before
/// returning control to the crypto engine. This prevents an unobserved counter
/// advance from desynchronizing the durable ratchet-state epoch.
///
/// The trait is `Send + Sync` because mobile FFI calls may arrive from multiple
/// threads even though the engine serializes a given state transition.
pub trait MonotonicCounter: Send + Sync {
    fn current(&self) -> Result<u64, PrimitiveError>;
    fn increment(&mut self) -> Result<u64, PrimitiveError>;
}

/// Process-local counter (tests / hosts without a trusted monotonic source).
#[derive(Default)]
pub struct MemoryCounter {
    n: u64,
}

impl MemoryCounter {
    pub fn with_value(n: u64) -> Self {
        Self { n }
    }
}

impl MonotonicCounter for MemoryCounter {
    fn current(&self) -> Result<u64, PrimitiveError> {
        Ok(self.n)
    }

    fn increment(&mut self) -> Result<u64, PrimitiveError> {
        self.n = self.n.checked_add(1).ok_or(PrimitiveError::LimitExceeded)?;
        Ok(self.n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_counter_increases() {
        let mut c = MemoryCounter::default();
        assert_eq!(c.increment().unwrap(), 1);
        assert_eq!(c.increment().unwrap(), 2);
        assert_eq!(c.current().unwrap(), 2);
    }

    #[test]
    fn seeded_counter_continues_monotonically() {
        let mut c = MemoryCounter::with_value(41);
        assert_eq!(c.current().unwrap(), 41);
        assert_eq!(c.increment().unwrap(), 42);
    }
}

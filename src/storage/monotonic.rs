//! Monotonic counter abstraction for rollback resistance.
//!
//! Commodity phones do not expose a trusted increment-only counter to
//! userspace. Implementations should bind this trait to:
//!   * Android StrongBox / Keystore hardware counters when present
//!   * iOS Secure Enclave monotonic values when present
//!   * otherwise a local counter that **cannot** survive backup restore
//!
//! Residual risk without hardware is documented in KNOWN_LIMITATIONS.

use crate::primitives::error::PrimitiveError;

/// Strictly increasing counter. Implementations must not wrap.
pub trait MonotonicCounter {
    fn current(&self) -> Result<u64, PrimitiveError>;
    fn increment(&mut self) -> Result<u64, PrimitiveError>;
}

/// Process-local counter (tests / hosts without TEE).
#[derive(Default)]
pub struct MemoryCounter {
    n: u64,
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
}

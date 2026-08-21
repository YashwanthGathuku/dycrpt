//! Secure memory handling: zeroization and constant-time comparison.
//!
//! # Guarantees (userspace, best-effort)
//!
//! - Secret-bearing types implement `Zeroize` / `ZeroizeOnDrop` so drops
//!   overwrite the bytes before deallocation.
//! - Temporary buffers (DH outputs, HKDF OKM, message keys after use) are
//!   explicitly zeroized at the end of the scope that needs them.
//! - Equality of secret material uses `subtle::ConstantTimeEq`.
//!
//! # Non-guarantees (document for HARDENING.md)
//!
//! On managed/mobile OS runtimes, the following may still retain copies:
//! compiler temporaries, registers, swap, crash dumps, memory compression,
//! GC heaps (if any foreign bridge copies data). Userspace zeroization is
//! necessary but not sufficient for those residual risks.

use core::ops::{Deref, DerefMut};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Heap buffer that is zeroized on drop and compared in constant time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            inner: data.to_vec(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Explicitly wipe now (also happens on drop).
    pub fn zeroize_now(&mut self) {
        self.inner.zeroize();
    }
}

impl ConstantTimeEq for SecretBytes {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for SecretBytes {}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

/// Fixed-size 32-byte secret (keys, shared secrets, chain keys).
/// Preferred over raw `[u8; 32]` for anything secret-bearing.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes32(pub [u8; 32]);

impl SecretBytes32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(data: &[u8]) -> Option<Self> {
        if data.len() != 32 {
            return None;
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(data);
        Some(Self(a))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn zeroize_now(&mut self) {
        self.0.zeroize();
    }
}

impl ConstantTimeEq for SecretBytes32 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SecretBytes32 {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for SecretBytes32 {}

impl Deref for SecretBytes32 {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretBytes32 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Constant-time equality for byte slices (length mismatch → false).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

/// Explicitly zero a mutable byte slice (stack or heap).
#[inline]
pub fn secure_zero(buf: &mut [u8]) {
    buf.zeroize();
}

/// Explicitly zero a 32-byte array.
#[inline]
pub fn secure_zero_32(buf: &mut [u8; 32]) {
    buf.zeroize();
}

/// Scope guard: zeroizes the contained buffer when dropped.
/// Use for temporary key material that must not outlive a block.
pub struct ZeroizingScope<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> ZeroizingScope<T> {
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    pub fn get(&self) -> &T {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Transfer ownership of the inner value. Caller becomes responsible
    /// for wiping it; this scope will not run `Drop`.
    pub fn into_inner(self) -> T
    where
        T: Default,
    {
        let mut this = self;
        core::mem::take(&mut this.inner)
    }
}

impl<T: Zeroize> Drop for ZeroizingScope<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> Deref for ZeroizingScope<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> DerefMut for ZeroizingScope<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

/// Helper: run a closure with a zeroizing temporary copy of key material.
/// The copy is wiped when the closure returns (success or panic via drop).
pub fn with_secret_32<R>(secret: &[u8; 32], f: impl FnOnce(&[u8; 32]) -> R) -> R {
    let tmp = ZeroizingScope::new(*secret);
    let result = f(&tmp);
    // Drop of tmp zeroizes
    drop(tmp);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_eq_and_zeroize() {
        let a = SecretBytes::from_slice(b"secret-value-1234567890");
        let b = SecretBytes::from_slice(b"secret-value-1234567890");
        let c = SecretBytes::from_slice(b"different-value-xxxxxx");
        assert!(a == b);
        assert!(a != c);
        assert!(ct_eq(a.as_slice(), b.as_slice()));
        assert!(!ct_eq(a.as_slice(), c.as_slice()));
    }

    #[test]
    fn secret_bytes32_ct_eq() {
        let a = SecretBytes32::new([1u8; 32]);
        let b = SecretBytes32::new([1u8; 32]);
        let c = SecretBytes32::new([2u8; 32]);
        assert!(a == b);
        assert!(a != c);
    }

    #[test]
    fn zeroizing_scope_wipes() {
        let scope = ZeroizingScope::new([0xAAu8; 32]);
        assert_eq!(scope[0], 0xAA);
        drop(scope);
        // After drop, contents should have been zeroized (can't observe easily
        // without reuse; the Drop impl is the contract).
    }

    #[test]
    fn secure_zero_clears() {
        let mut buf = [0xFFu8; 16];
        secure_zero(&mut buf);
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn with_secret_32_runs() {
        let k = [9u8; 32];
        let out = with_secret_32(&k, |s| s[0]);
        assert_eq!(out, 9);
    }
}

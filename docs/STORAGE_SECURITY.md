# STORAGE_SECURITY.md

**Status:** PARTIALLY VERIFIED (MemoryStorage tests); platform stores UNVERIFIED

## Requirements

- Transactional begin/put/commit/abort  
- Ciphertext not released until commit succeeds  
- Monotonic `StorageEpoch` for rollback detection  
- Zeroization of `StateBlob` on drop  

## Source

`src/storage/mod.rs` — `TransactionalStorage` trait, `MemoryStorage`, epoch API.

## Residual risk

Commodity Android/iOS without hardware monotonic counters: stale backup restore remains a residual risk (documented in `HARDENING.md`). Perfect rollback resistance is **not** claimed.

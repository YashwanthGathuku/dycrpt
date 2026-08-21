# ARCHITECTURE.md

**Project:** voicechat-crypto  
**Language:** Pure Rust  
**Date:** 2026-08-17  
**Status:** Design complete — no protocol implementation yet

## 1. Goals

- Provide a high-assurance, clean-room implementation of the current Signal Protocol family (PQXDH + Triple Ratchet / SPQR + Sesame-style session management) for VoiceChat.
- Expose a **protocol-independent public API** that never forces the application (Flutter / Android / iOS) to understand ratchet state, chain keys, epochs, or message numbers.
- Support native compilation for Android and iOS with clean Kotlin/Swift FFI.
- Enforce strict security invariants at every layer.
- Remain permissively licensed and free of any AGPL/GPL dependencies.

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                       │
│              (Flutter / Kotlin / Swift)                     │
└───────────────────────────┬─────────────────────────────────┘
                            │ FFI (uniffi / cbindgen)
┌───────────────────────────▼─────────────────────────────────┐
│                    Public CryptoEngine API                  │
│         (protocol-independent, session-oriented)            │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼──────┐   ┌────────▼────────┐   ┌──────▼──────┐
│   Session    │   │    Prekeys      │   │  Identity   │
│   Manager    │   │    Manager      │   │  Manager    │
└───────┬──────┘   └────────┬────────┘   └──────┬──────┘
        │                   │                   │
┌───────▼───────────────────▼───────────────────▼──────┐
│              Core Cryptographic Engine               │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌────────┐  │
│  │  PQXDH  │  │ Ratchet  │  │Fingerprint│ │ Replay│  │
│  └─────────┘  └──────────┘  └─────────┘  └────────┘  │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐             │
│  │Primitives│  │  Wire   │  │ Padding │             │
│  └─────────┘  └──────────┘  └─────────┘             │
└───────────────────────────┬──────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────┐
│              Storage Abstraction                      │
│         (pluggable, transaction-aware)                │
└──────────────────────────────────────────────────────┘
```

## 3. Public API Surface (CryptoEngine)

The application interacts **only** with a single entry point. Internal ratchet state, chain keys, epochs, skipped message keys, and protocol version details are never exposed.

### Conceptual Interface

```rust
/// Top-level engine. One instance per local device identity.
pub struct CryptoEngine { /* opaque */ }

impl CryptoEngine {
    /// Create or restore a device identity and long-term keys.
    /// Returns a stable DeviceId and the local identity public key.
    pub fn initialize_device(
        storage: impl Storage,
        config: DeviceConfig,
    ) -> Result<Self, CryptoError>;

    /// Generate a full public prekey bundle for the server.
    /// Contains identity key, signed prekey, one-time prekeys,
    /// and post-quantum prekeys as required by current protocol.
    pub fn generate_public_prekey_bundle(
        &mut self,
        count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;

    /// Replenish one-time and last-resort prekeys.
    pub fn replenish_prekeys(
        &mut self,
        one_time_count: usize,
    ) -> Result<PublicPrekeyBundle, CryptoError>;

    /// Start a new outbound session with a remote party
    /// using their published prekey bundle.
    /// Returns a SessionId. The application never sees ratchet state.
    pub fn establish_outbound_session(
        &mut self,
        remote_bundle: &PublicPrekeyBundle,
        conversation_context: &[u8],
    ) -> Result<SessionId, CryptoError>;

    /// Process an inbound prekey / session-establishment message.
    /// Creates or resumes a session. Returns SessionId.
    pub fn process_inbound_session(
        &mut self,
        message: &InboundSessionMessage,
        conversation_context: &[u8],
    ) -> Result<SessionId, CryptoError>;

    /// Encrypt an application payload for an existing session.
    /// Returns a sealed ciphertext suitable for network transport.
    pub fn encrypt(
        &mut self,
        session_id: &SessionId,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedMessage, CryptoError>;

    /// Decrypt a sealed message. Returns plaintext or a typed error
    /// (replay, identity change, unrecoverable, etc.).
    pub fn decrypt(
        &mut self,
        session_id: &SessionId,
        sealed: &SealedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Compute a human-verifiable safety fingerprint / number
    /// for the local and remote identities in a session.
    pub fn get_safety_fingerprint(
        &self,
        session_id: &SessionId,
    ) -> Result<SafetyFingerprint, CryptoError>;

    /// Explicitly acknowledge that the application has accepted
    /// an identity key change for a remote party.
    pub fn acknowledge_identity_change(
        &mut self,
        session_id: &SessionId,
    ) -> Result<(), CryptoError>;

    pub fn has_session(&self, session_id: &SessionId) -> bool;
    pub fn delete_session(&mut self, session_id: &SessionId) -> Result<(), CryptoError>;
    pub fn delete_all_sessions(&mut self) -> Result<(), CryptoError>;
}
```

All types (`SessionId`, `PublicPrekeyBundle`, `SealedMessage`, `SafetyFingerprint`, etc.) are opaque to the application or expose only the minimum necessary public information.

## 4. Internal Module Responsibilities

| Module | Responsibility |
|--------|----------------|
| **identity/** | Long-term identity key pairs, device identity, XEdDSA signatures, identity key rotation policy. |
| **primitives/** | Thin, audited wrappers around X25519, ML-KEM (FIPS 203), HKDF, AEAD, SHA-2/HMAC, constant-time comparison, zeroization. No protocol logic. |
| **pqxdh/** | Implementation of the PQXDH key agreement protocol (from public specification only). Produces initial root secrets and associated data. |
| **ratchet/** | Double Ratchet, Header Encryption variant, Sparse Post-Quantum Ratchet (SPQR), Triple Ratchet. State machines, chain advancement, skipped-message handling. |
| **session/** | Higher-level session lifecycle. Combines PQXDH establishment + continuous ratcheting + multi-device / Sesame-style session selection. Owns the mapping from SessionId to internal ratchet state. |
| **prekeys/** | Generation, signing, storage, and consumption of signed prekeys, one-time prekeys, and post-quantum prekeys. |
| **storage/** | Trait-based persistent storage with transactional semantics. Implementations must support atomic read-modify-write for ratchet state. |
| **wire/** | Canonical serialization / deserialization of all network-visible objects (bundles, sealed messages, headers). Versioned, extensible, authenticated where required. |
| **fingerprint/** | Safety number / fingerprint generation from identity keys (and optional conversation context). |
| **replay/** | Detection and rejection of previously accepted protocol messages. |
| **padding/** | Deterministic or random padding of plaintext before encryption to reduce traffic analysis. |
| **ffi/** | Uniffi / cbindgen / diplomat bindings for Kotlin, Swift, and Flutter. |
| **testing/** | Independent test vectors, property-based tests, fuzz targets, formal invariant checkers. |

## 5. State Ownership & Data Flow

- **CryptoEngine** owns the long-term identity and the collection of active sessions.
- Each **Session** owns its Triple Ratchet state (or classical Double Ratchet if explicitly negotiated) and associated metadata (remote identity, device identifiers, conversation context, protocol version).
- **Storage** is the only component allowed to persist secrets. All state transitions that consume keys or nonces must be performed inside a storage transaction.
- Application plaintext never touches the ratchet modules; it only enters at the `encrypt` / `decrypt` boundary after padding and associated-data binding.

## 6. Concurrency Model

- Pure Rust. No Go.
- Session state is protected by interior mutability or explicit locking only where necessary.
- Parallel prekey generation uses `rayon` or equivalent.
- Cross-session operations are independent; the engine never shares mutable ratchet state across sessions.

## 7. Error Model

All errors are typed and fail-closed:

- `CryptoError::Replay`
- `CryptoError::IdentityChanged` (requires explicit acknowledgement)
- `CryptoError::Unrecoverable` (session must be deleted)
- `CryptoError::ProtocolVersionMismatch`
- `CryptoError::Malformed`
- `CryptoError::Storage`
- etc.

No silent fallbacks.

## 8. Versioning & Extensibility

- Protocol version is explicitly negotiated and authenticated during session establishment.
- Wire formats carry a version field protected by the AEAD or signature.
- Future algorithm suites can be added without breaking existing sessions.

## 9. Next Steps

1. Freeze this architecture and the four companion documents.
2. Implement primitives and storage traits first.
3. Implement PQXDH (PROMPT 2+).
4. Implement ratchet state machines with full invariant enforcement.
5. Wire formats and public API last.

This architecture satisfies the requirement that the application never needs to understand internal ratchet state while still exposing every capability required for a production messaging system.
# WIRE_PROTOCOL.md

**Project:** voicechat-crypto  
**Date:** 2026-08-17  
**Status:** Design — independent wire formats derived from protocol requirements, not from any implementation

This document defines the network-visible objects that `voicechat-crypto` produces and consumes. Formats are designed for clarity, versioning, authenticatability, and minimal ambiguity. They intentionally do **not** copy any existing binary layout from other projects.

All multi-byte integers are little-endian unless otherwise stated. All variable-length fields are length-prefixed with a `u32` (or `u16` where size is known to be small).

## 1. Design Principles

- Explicit versioning on every top-level object.
- Cryptographic binding of version, suite, and identities.
- Fail-closed parsing (unknown versions / critical fields → error).
- Support for the full current protocol family (PQXDH + Triple Ratchet / SPQR).
- Extensibility via typed optional fields without breaking authentication.

## 2. Top-Level Objects

### 2.1 PublicPrekeyBundle

Published by a device to the server (or exchanged out-of-band). Contains everything needed for a remote party to perform PQXDH and start a session.

```
struct PublicPrekeyBundle {
    version: u8,                          // currently 1
    suite: CipherSuiteId,                 // authenticated identifier
    identity_key: IdentityPublicKey,      // X25519 + XEdDSA compatible
    device_id: DeviceId,                  // opaque 16–32 byte identifier
    signed_prekey: SignedPrekey,          // medium-term, signed by identity
    one_time_prekeys: Vec<OneTimePrekey>, // classical
    pq_last_resort_prekey: PqPrekey,      // ML-KEM
    pq_one_time_prekeys: Vec<PqPrekey>,   // ML-KEM one-time
    // optional future fields
}
```

`SignedPrekey` contains the public key and an XEdDSA signature over a domain-separated encoding of the key + version + suite.

### 2.2 InboundSessionMessage (Prekey / Initial Message)

The first message that establishes a session. Carries the PQXDH ciphertext material and the first ratchet header.

```
struct InboundSessionMessage {
    version: u8,
    suite: CipherSuiteId,
    sender_identity_key: IdentityPublicKey,
    sender_device_id: DeviceId,
    // PQXDH material
    ephemeral_key: X25519PublicKey,
    pq_ciphertext: MlKemCiphertext,       // from encapsulation to remote PQ prekey
    // first Triple Ratchet / SPQR header
    ratchet_header: RatchetHeader,
    // encrypted payload (may be empty or contain application data)
    sealed_payload: SealedPayload,
}
```

### 2.3 SealedMessage (Subsequent Messages)

All messages after session establishment.

```
struct SealedMessage {
    version: u8,
    session_id_hint: Option<SessionId>,   // optional, for routing only
    ratchet_header: RatchetHeader,        // contains classical + SPQR material
    sealed_payload: SealedPayload,
}
```

### 2.4 RatchetHeader

Opaque to the application. Contains everything the Triple Ratchet needs to advance.

```
struct RatchetHeader {
    // Classical Double Ratchet portion
    dh_public: X25519PublicKey,           // current sending ratchet key
    pn: u32,                              // previous chain length
    n: u32,                               // message number in current chain

    // Sparse Post-Quantum Ratchet / ML-KEM Braid portion
    scka_chunk: SckaChunk,                // erasure-coded chunk of KEM material
    epoch: u32,
    // ... additional SPQR fields as required by the public specification
}
```

Header encryption (when enabled) wraps the sensitive fields under a header key.

### 2.5 SealedPayload

```
struct SealedPayload {
    ciphertext: Vec<u8>,                  // AEAD ciphertext
    // nonce / IV is derived or included according to the chosen AEAD
}
```

Associated Data for the AEAD always includes:

- Protocol version
- Cipher suite
- Local and remote identity keys
- Device identifiers
- Conversation context
- Ratchet header (or its authenticated encoding)
- Message number / epoch

## 3. CipherSuiteId

An authenticated identifier for the combination of:

- Curve (X25519)
- PQ KEM (ML-KEM-768 recommended)
- Hash / HKDF
- AEAD
- Protocol version family (PQXDH + Triple Ratchet)

Negotiation is explicit and authenticated; silent downgrade is forbidden by the DOWNGRADE-RESISTANCE invariant.

## 4. SafetyFingerprint

Not a wire object in the normal sense, but a value that can be displayed or compared out-of-band.

Derived from the two identity keys (and optionally conversation context) using a domain-separated, iterated hash construction consistent with the public safety-number guidance in the broader Signal ecosystem literature, but independently specified.

## 5. Versioning Rules

- Every top-level object begins with a `version: u8`.
- Parsers must reject unknown versions (fail-closed).
- Critical security parameters (suite, identities) are bound into the cryptographic operations, not merely into the version byte.

## 6. Serialization Notes

- Prefer a simple, unambiguous binary format (length-prefixed fields, fixed-size keys).
- CBOR or a minimal protobuf-like encoding may be used internally if it improves clarity, but the security properties must not depend on the encoding being canonical beyond what is explicitly authenticated.
- All public keys and ciphertexts use the encodings defined in the respective standards (RFC 7748, FIPS 203).

## 7. Future Extensions

New optional fields may be added with typed tags. Unknown non-critical fields are ignored; unknown critical fields cause rejection. Any change that affects security properties requires a new `CipherSuiteId` or protocol version.

This wire design is intentionally independent. It carries exactly the information required by the public specifications while remaining clean and auditable.
# HEADER_ENCRYPTION.md — Evaluation, Tradeoff, and Implementation Complexity

**Date:** 2026-08-17  
**Specification:** Double Ratchet Algorithm, Revision 4 — Header Encryption variant (public)

## Decision

Header Encryption is implemented as an **optional authenticated profile**:

`VOICECHAT_CLASSICAL_HE_V1`

It is included in suite negotiation. It is **not** the default. It is **not** forced when it would conflict with unreviewed multi-device routing assumptions.

## Motivation (public specification)

Message headers contain the ratchet public key and counters (PN, N). Encrypting them prevents a passive observer from:

- linking messages to sessions by ratchet public key
- observing message ordering within a session

---

## Comparison Summary

| Dimension | Standard Double Ratchet headers | Header-encrypted variant |
|-----------|----------------------------------|---------------------------|
| **Metadata exposure** | Ratchet public key + PN + N visible | Opaque AEAD ciphertext only |
| **Implementation complexity** | Baseline | Significantly higher (see below) |
| **Out-of-order handling** | Skip by (DHr, N) | Skip by (header_key, N); try HKr then NHKr |
| **Key-management complexity** | One shared secret SK | SK + shared_hka + shared_nhkb |
| **Bandwidth** | 40-byte header | ~68-byte encrypted header |
| **Mobile performance** | 1 AEAD / message | 2 AEAD / message |
| **Session association** | Clear ratchet key aids demux | Outside spec scope; needs outer handle or trial decrypt |
| **Reliability risk** | Low | Higher with multi-device / Sesame demux |

---

## Implementation Complexity Details

### 1. Additional persistent state

| Variable | Size | Purpose |
|----------|------|---------|
| `HKs` | 32 bytes | Current sending header key |
| `HKr` | 32 bytes | Current receiving header key |
| `NHKs` | 32 bytes | Next sending header key |
| `NHKr` | 32 bytes | Next receiving header key |

**Delta vs classical:** +128 bytes of secret key material per session, plus the change that `MKSKIPPED` is indexed by `(header_key_bytes, n)` instead of `(ratchet_public_key, n)`.

Each skipped-key entry grows from ~36 bytes of index to ~36 bytes (32-byte HK + 4-byte n). Under `MAX_SKIP = 1000` this is a measurable but bounded increase.

Serialization / crash-recovery surface grows proportionally: four extra optional 32-byte fields and a different map key type must be written, versioned, and zeroized.

### 2. Additional cryptographic operations per message

| Operation | Classical | Header Encryption |
|-----------|-----------|-------------------|
| Message AEAD | 1 | 1 |
| Header AEAD (encrypt or decrypt attempts) | 0 | 1 (send) or 1–2 (receive: HKr then possibly NHKr) |
| Header nonce generation | 0 | 12 random bytes (send) |
| KDF_RK vs KDF_RK_HE | 64-byte OKM | 96-byte OKM (root + chain + next header key) |

Receive path is branchy: try skipped set → try `HKr` → try `NHKr` (and on success run full `DHRatchetHE`). Each failed header decrypt is a full AEAD verification.

### 3. Initialization complexity

Classical:

```
InitAlice(SK, bob_dh_public)
InitBob(SK, bob_dh_keypair)
```

Header Encryption:

```
InitAliceHE(SK, bob_dh_public, shared_hka, shared_nhkb)
InitBobHE(SK, bob_dh_keypair, shared_hka, shared_nhkb)
```

Two additional 32-byte secrets must be agreed during the handshake (domain-separated from the main PQXDH SK). They must be:

- derived with frozen labels (e.g. `VoiceChat/DR-HE/v1/HKa`, `…/NHKb`)
- zeroized after install into ratchet state
- never reused across sessions

Handshake transcript / AD binding must cover these values (or their derivation context) so a network attacker cannot substitute header-key material.

### 4. Control-flow and code-path complexity

| Path | Classical | Header Encryption |
|------|-----------|-------------------|
| Encrypt | Derive MK → HEADER → ENCRYPT body | Derive MK → HEADER → **HENCRYPT** → ENCRYPT body |
| Decrypt | TrySkipped → (maybe DHRatchet) → Skip → MK → DECRYPT | TrySkipped(by HK) → **HDECRYPT(HKr)** → or **HDECRYPT(NHKr)** + DHRatchetHE → Skip → MK → DECRYPT |
| DH ratchet | Update DHs/DHr, RK, CKs/CKr | Same **plus** shift HKs←NHKs, HKr←NHKr, derive new NHKs/NHKr via KDF_RK_HE |
| Skip storage | Keyed by (DHr, N) | Keyed by (HKr, N) |

Error handling must distinguish:

- malformed encrypted header (length / AEAD fail)
- authentic header under the wrong session’s key (demux miss)
- authentic header under NHKr (legitimate ratchet step)

Incorrectly treating a demux miss as a ratchet step is a serious state-desync risk.

### 5. Interaction with multi-device / Sesame

This is the dominant complexity and reliability cost for VoiceChat.

- With clear headers, the ratchet public key is a natural hint for “which session does this belong to?”
- With encrypted headers, that hint disappears. The public specification explicitly leaves session association out of scope.
- VoiceChat options:
  1. **Outer clear routing label** (conversation_id / session_id) — restores demux but re-introduces linkable metadata at the transport layer.
  2. **Bounded trial decrypt** across candidate sessions for that user — correct but O(candidates) AEAD cost and careful anti-DoS limits.
  3. **Device-level mailboxes** (Sesame-style) so the transport already names the device — still requires mapping device → active session without the ratchet key.

Until one of these is implemented and tested, enabling HE by default would weaken reliability under multi-device and delayed delivery.

### 6. Testing surface growth

| Area | Classical tests | Additional HE tests required |
|------|-----------------|------------------------------|
| Round-trip | Yes | Yes (first message via NHKr path) |
| Out-of-order / skip | Yes | Yes, keyed by header key |
| Tamper → state unchanged | Yes | Yes for both header and body AEAD |
| DH ratchet | Yes | Yes, including HK/NHK shift |
| Init key agreement | SK only | SK + shared_hka + shared_nhkb consistency Alice/Bob |
| Wrong-session header | N/A | Must not advance state |
| Serialization / reload | Yes | Yes, all four HK fields + new MKSKIPPED key type |
| Multi-device demux | Optional | **Required** before HE is default |

### 7. Bandwidth and mobile cost (concrete)

- Clear header: 32 (DH) + 4 (PN) + 4 (N) = **40 bytes**
- Encrypted header: 12 (nonce) + 40 (plaintext header) + 16 (AES-GCM tag) ≈ **68 bytes** (+70%)
- Extra CPU: one AES-GCM per header on send; up to two on receive before body decrypt
- Extra RAM: 128 bytes secrets + larger skipped map under load

Acceptable for many deployments; not free on low-end mobile or very high message rates.

### 8. Complexity verdict

| Question | Answer |
|----------|--------|
| Is the variant implementable from the public spec alone? | Yes |
| Does it fit the clean-room / transactional / bounded architecture? | Yes, as an optional profile |
| Does it increase state, code paths, and test surface materially? | **Yes** |
| Does it complicate multi-device demux? | **Yes — main reliability risk** |
| Should it be the default for VoiceChat MVP? | **No** |
| Should it be offered in authenticated negotiation? | **Yes** (`ClassicalHeV1`) |

---

## Negotiation

Preference order (strongest / most private first):

1. `HybridPqV1`
2. `ClassicalHeV1`
3. `ClassicalV1`

No network-controlled silent downgrade: after establishment, `enforce_profile` rejects any other profile.

## Residual risks

- Trial-decrypt cost and DoS surface if many candidate sessions exist
- Extra bandwidth and dual-AEAD CPU on mobile
- Larger serialized state and recovery surface
- Demux policy must be explicit before HE is enabled in production multi-device builds

## Module

`src/ratchet/header_encrypt/` — HE state machine from the public specification (InitAliceHE / InitBobHE, HENCRYPT / HDECRYPT, DHRatchetHE, SkipMessageKeysHE, transactional decrypt).

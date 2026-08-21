# PROTOCOL.md — Protocol Surface for Auditors

**Status:** PARTIALLY VERIFIED (internal design + unit tests; no external audit)

## Profiles

| Profile ID | Construction |
|------------|----------------|
| `VOICECHAT_CLASSICAL_V1` | PQXDH + classical Double Ratchet |
| `VOICECHAT_CLASSICAL_HE_V1` | PQXDH + Double Ratchet Header Encryption variant |
| `VOICECHAT_HYBRID_PQ_V1` | PQXDH + Triple Ratchet (classical DR ‖ SPQR / ML-KEM Braid concepts) |

Selection is preference-ordered and **authenticated after establishment** (`policy::enforce_profile`). Silent network downgrade is rejected by design.

## Handshake

- **PQXDH** (public Signal PQXDH Rev 3): X25519 identity/signed/one-time prekeys + ML-KEM (profile) last-resort/one-time PQ prekeys.
- Shared secret via specified DH combination + KEM SS + domain-separated HKDF.
- Associated data binds identities and PQ public key material per public re-encapsulation guidance.

## Continuous ratcheting

- Classical Double Ratchet (public Rev 4 algorithms).
- Optional Header Encryption variant (public HE section).
- Hybrid: SPQR epoch keys combined via `KDF_HYBRID` (Triple Ratchet composition).

## Application framing

- Versioned **authenticated envelope** binds conversation, users, devices, message ids, payload type; voice-profile identifiers forbidden on the wire.
- Padding buckets (random content) optional before AEAD.

## Session management

- Sesame-inspired multi-device data model with hard device/session/initiating limits.
- Identity change → `IDENTITY_CHANGED` until explicit acknowledge.

## Public documents used

Listed in `SOURCE_BOUNDARY.md`. No libsignal source was an input to implementation.

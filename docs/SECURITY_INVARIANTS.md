# SECURITY_INVARIANTS.md

**Status:** PARTIALLY VERIFIED (unit/property tests + TLA+ models); **not VERIFIED** externally

| ID | Invariant | Primary enforcement |
|----|-----------|---------------------|
| KEY-SEPARATION | Keys not reused across purposes | Domain-separated labels (`LABELS`) |
| UNIQUE-MESSAGE-KEY | Unique MK per message | DR / hybrid KDF_CK |
| FORWARD-SECRECY | Past MKs unrecoverable after deletion | Chain advance + zeroize |
| POST-COMPROMISE-RECOVERY | Fresh entropy restores confidentiality where protocol allows | DH ratchet / SPQR epoch |
| ATOMIC-STATE | Crash must not reuse consumed key/nonce | Transactional storage + trial decrypt |
| REPLAY-REJECTION | Accepted message ≠ second application event | ReplayCache |
| BOUNDED-SKIP | Skip cost/memory bounded | MAX_SKIP / SPQR bounds |
| IDENTITY-BINDING | Session bound to identities, devices, conversation, version | Envelope AD + fingerprint + policy |
| DOWNGRADE-RESISTANCE | No silent suite/profile downgrade | `select_profile` / `enforce_profile` |
| FAIL-CLOSED | Malformed/unauthenticated data does not commit state | Decrypt trial; parse rejects |

Voice-specific: **VOICE PROFILE NEVER LEAVES OWNER DEVICE** (`encrypt_voice_payload` guard).

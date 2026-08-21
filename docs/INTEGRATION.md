# INTEGRATION.md — VoiceChatCryptoEngine Adapter

**Date:** 2026-08-17

## Integration path

```
UI / Flutter domain
        ↓
  CryptoEngineApi   (application-defined abstraction)
        ↓
  VoiceChatCryptoEngine   (this crate)
        ↓
  voicechat-crypto modules (pqxdh, ratchet, envelope, …)
```

The rest of VoiceChat must not import libsignal or know which backend implements `CryptoEngineApi`.

## Application-visible API

| Method | Role |
|--------|------|
| `initialize_device` | Local identity + engine |
| `generate_public_prekey_bundle` / `replenish_prekeys` | Publish prekeys |
| `establish_outbound_session` | PQXDH Alice + DR |
| `process_inbound_session` | PQXDH Bob + DR |
| `encrypt` / `decrypt` | Session AEAD |
| `encrypt_voice_payload` | Voice messages with profile guard |
| `safety_fingerprint` | Safety numbers |
| `acknowledge_identity_change` | Clear IDENTITY_CHANGED |
| `has_session` / `delete_session` / `delete_all_sessions` | Lifecycle |

No root keys, chain keys, message keys, or private keys are returned.

## Privacy: voice profile

**VOICE PROFILE NEVER LEAVES OWNER DEVICE.**

- `encrypt_voice_payload` accepts only the sender-encoded audio payload.
- Associated data containing `voice_profile` / `voice-profile` markers is **rejected** (`CryptoError::VoiceProfileForbidden`).
- Envelope / wire metadata must not carry voice-profile identifiers (see envelope field set).
- Only the encrypted voice-message ciphertext is eligible to cross the network.

## Behavioral tests

Located in `src/engine/mod.rs` tests:

- Outbound session + encrypt path
- Voice profile forbidden in AD
- Voice payload allowed without profile metadata
- Symmetric safety fingerprint via engine
- Session delete
- Replay / decrypt failure paths

## No libsignal

This adapter was built solely against the public application `CryptoEngine` contract in `ARCHITECTURE.md` and voicechat-crypto modules. libsignal was not inspected.

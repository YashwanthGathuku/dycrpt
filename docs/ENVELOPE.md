# ENVELOPE.md — VoiceChat Authenticated Envelope

**Date:** 2026-08-17  
**Status:** Implemented

## Purpose

Application data is never encrypted as an unstructured blob. Every message is wrapped in a versioned envelope whose security-sensitive metadata is cryptographically bound (via AEAD associated data). Consequently:

- Ciphertext produced for conversation A cannot be moved into conversation B and still authenticate.
- Ciphertext intended for device A cannot validate as intended for device B.
- Protocol version, crypto suite, sender/recipient identities, message identifiers, sequence numbers and (for synthetic voice) codec/duration/length are all covered by the authentication tag.

## Bound Fields

| Field | Binding |
|-------|---------|
| protocol_version | AD |
| crypto_suite | AD |
| conversation_id | AD |
| sender_user_id / sender_device_id | AD |
| recipient_user_id / recipient_device_id | AD |
| message_id | AD |
| message_type / sequence / created_timestamp | AD |
| payload_type | AD |
| synthetic_voice metadata (codec, duration_ms, payload_length) | AD (when present) |
| payload body | AEAD plaintext |

## Canonical Serialization

Fixed field order, length-prefixed identifiers, little-endian integers, no optional free-form maps. Duplicate fields are impossible by construction. The parser rejects:

- unsupported protocol versions
- unknown critical suite / payload-type values
- integer / length overflows
- oversized identifiers or payloads
- invalid UTF-8 (codec names)
- truncated or trailing data
- synthetic-voice length mismatches

## Integration with the Ratchet

```
envelope = build_envelope(...)
ad       = envelope.associated_data()
(header, ciphertext) = ratchet.encrypt(envelope.payload, ad)
# transmit header || ciphertext
# on receive: decrypt with the same ad construction; any field change fails AEAD
```

## Fuzzing

The parser (`Envelope::parse`) is the primary untrusted-decoding boundary. Continuous fuzzing is required:

```bash
# once cargo-fuzz is available on a modern toolchain
cargo fuzz run envelope_parse
```

A minimal fuzz harness stub lives under `fuzz/`.

## Tests

- Canonical round-trip
- Conversation-ID change → different AD
- Recipient-device change → different AD
- Unsupported version rejected
- Oversized payload rejected
- Truncation / trailing garbage rejected
- Synthetic-voice round-trip and length-mismatch rejection

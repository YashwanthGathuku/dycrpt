# P02 Physical Device Interoperability Protocol

This is the required evidence protocol before dycrpt can be called production-ready.
It is intentionally stricter than "the demo chat worked". A run is valid only
when every assertion below is recorded on real devices using the same commit SHA.

## Required matrix

| Sender | Receiver | Required |
|---|---|---|
| Android physical device A | Android physical device B | yes |
| iPhone physical device A | iPhone physical device B | yes |
| Android physical device | iPhone physical device | yes, both directions |

Use at least one process-kill/restart in every matrix row. Simulators/emulators
are useful additional coverage but do not satisfy the physical-device gate.

## Build identity

Record before each run:

- dycrpt git commit SHA
- Rust toolchain version
- Android app version/build + OS/API level + device model
- iOS app version/build + iOS version + device model
- protocol version (`vc_protocol_version`)
- selected crypto profile
- SHA-256 of the compiled native library on each endpoint

The two endpoints must use the same protocol version and an explicitly supported
profile. Default production-gate runs use `ClassicalV1`. Header Encryption and
Hybrid are separate opt-in test rows and do not substitute for the classical gate.

## Test conversation

Use a fresh application conversation ID for the run and fresh device state unless
the case explicitly tests persistence. Never publish raw private state, storage
keys, prekey secrets, ratchet chain/root keys, or decrypted storage snapshots.

For every transmitted object, log only:

- direction
- logical sequence number
- byte length
- SHA-256(packet/sealed bytes)
- local monotonic storage epoch after durable commit
- result code

For plaintext, log expected/received SHA-256 and length, not sensitive real chat.
Use synthetic test strings/media only.

## Mandatory cases

### 1. PQXDH first message

1. Bob uploads/exports a prekey bundle containing EC and PQ one-time prekeys.
2. Alice establishes outbound and persists the initiation before transport.
3. Record hash of the exact initiation packet.
4. Bob processes it and must recover the expected first plaintext.
5. Bob processes the exact packet again; expected result: replay/state error and
   no second plaintext delivery.

Pass conditions:
- identities/fingerprint agree on both endpoints
- first plaintext hash matches
- replay produces no plaintext
- Bob's consumed one-time IDs are not reusable after restart

### 2. Bidirectional ratchet

Send this order without restarting:

A1, A2, A3, B1, B2, A4, B3

Pass conditions:
- every plaintext hash matches
- ordered messages remain ordered at the application layer
- no duplicate delivery
- all result codes are success

### 3. Network reordering

Generate A5, A6, A7 but deliver in order A7, A5, A6.

Pass conditions:
- all three decrypt exactly once
- skipped-key bounds remain respected
- later normal A8/B4 traffic still succeeds

### 4. Duplicate ciphertext

Deliver A8 twice.

Pass conditions:
- first decrypt succeeds
- second is rejected as replay
- following B5/A9 traffic still succeeds

### 5. Tamper and recovery

Flip one bit independently in:
- protocol/profile/tag metadata
- ratchet header
- ciphertext/tag

Pass conditions:
- each tampered object fails authentication/routing
- original untouched object still decrypts afterward
- ratchet state is not advanced by the failed attempt

### 6. Crash after durable send-state commit

1. Sender encrypts message C1 and receives success from dycrpt.
2. Kill the process before transport acknowledgement.
3. Restart using encrypted durable storage + trusted rollback anchor.
4. Transport the already-produced ciphertext.
5. Continue with C2.

Pass conditions:
- no key/nonce reuse
- C1 and C2 decrypt
- storage epoch is monotonic across restart

### 7. Crash before/failed durable commit

Inject a storage commit failure during encryption.

Pass conditions:
- dycrpt returns storage failure and emits no usable ciphertext to application
- engine is poisoned/fail-closed
- application must recreate/restore engine before continuing

### 8. Outbound initiation retry

1. Create initiation packet but drop it at transport.
2. Restart sender.
3. Obtain `pending_outbound_initiation` and compare SHA-256 to original.
4. Send retry.

Pass condition: exact bytes are identical.

### 9. Identity replacement

After establishing/acknowledging peer identity, reinstall/reset the remote endpoint
to create a new long-term identity while preserving the same application peer ID.

Pass conditions:
- peer-aware API returns `IdentityChanged`
- no new session is established until explicit user verification/acknowledgement

### 10. Prekey rotation/delayed initiation

Create an initiation using old signed EC + last-resort PQ keys, delay delivery,
rotate both keys while retaining one previous generation, then deliver.

Pass conditions:
- delayed packet succeeds while retained
- packet fails after explicit expiry/removal of that historical generation

### 11. One-time allocation concurrency

Against the same production-like server allocator, execute at least 10,000 unique
allocation tokens with >=100 concurrent clients.

Pass conditions:
- duplicate EC OPK allocations = 0
- duplicate one-time PQ allocations = 0
- replaying every request token returns byte-identical original allocation

### 12. Encrypted storage / backup rollback

- verify raw storage file does not contain known plaintext state markers
- copy the encrypted snapshot at epoch N
- advance to N+2
- replace local snapshot with old N copy while leaving trusted anchor current

Pass condition: restore is rejected before any message encryption/decryption.

## Evidence record

Create one JSON record per matrix run with this minimum shape:

```json
{
  "dycrpt_commit": "<sha>",
  "profile": "ClassicalV1",
  "endpoint_a": {"platform":"android","device":"...","os":"...","native_sha256":"..."},
  "endpoint_b": {"platform":"ios","device":"...","os":"...","native_sha256":"..."},
  "cases": [
    {"id":"pqxdh-first","pass":true,"artifacts":["sha256:..."]}
  ],
  "private_key_material_logged": false
}
```

Evidence may contain public identities and safety fingerprints if desired, but do
not commit phone numbers, access tokens, private keys, raw decrypted state, or
real user messages.

## Release gate

The physical-device gate is **OPEN** until all mandatory rows and cases have
recorded passing evidence on the exact candidate commit. Writing this harness or
passing desktop unit tests does not close the gate.

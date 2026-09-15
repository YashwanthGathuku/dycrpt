# P0 Hardening — 2026-08-22

This document records the P0 findings from the August 22 review and the exact
boundary between fixes completed inside this repository and platform/server work
that cannot be truthfully claimed as complete here.

## Completed in this branch

### 1. Durable state backend is injectable

`VoiceChatCryptoEngine` no longer hardcodes `MemoryStorage` as its only storage
shape. Production integrations can supply `Box<dyn TransactionalStorage>` and a
separate `Box<dyn MonotonicCounter>`.

`MemoryStorage` / `MemoryCounter` remain test-development defaults only.

### 2. Ratchet state is transaction-bound to an external monotonic epoch

Every engine commit now:

1. advances the external monotonic counter;
2. begins the durable transaction;
3. writes the complete state change and the new epoch in the same transaction;
4. commits;
5. updates the in-process rollback guard.

If any storage step after counter advancement fails or has an unknown outcome,
the engine becomes **poisoned** and refuses future crypto operations. Continuing
would risk reusing a message key / AES-GCM nonce after rollback.

Restore requires:

```text
persisted_epoch == external_counter.current()
```

before ratchet state is accepted.

### 3. Whole-initiation replay domain fixed

The PQXDH initiation replay id is now derived from stable packet/transcript
material and does **not** include the recipient's newly generated local session
id.

The replay entry is inserted only after the first ciphertext authenticates, so
unauthenticated packets cannot poison the cache.

Regression: `initiation_replay_without_one_time_prekeys_is_rejected`.

### 4. Session deletion is durable-first

`delete_session` no longer ignores storage errors. It commits deletion first and
only then removes the live session / reports success.

`delete_all_sessions` deletes only serialized session records. It preserves
identity, prekeys, trust state, peer bindings, replay state, and the rollback
epoch.

### 5. Stable peer identity lifecycle added and wired into the engine

`PeerIdentityStore` maps an application-defined stable peer/device identifier to
the cryptographic identity previously seen/acknowledged.

Production session establishment should use:

- `establish_outbound_session_for_peer`
- `process_inbound_session_from_peer`
- `peer_identity_state`
- `acknowledge_peer_identity`

A different key for an acknowledged stable peer returns `IdentityChanged`
before a new ratchet is created.

The old key-indexed trust API remains for compatibility but is not sufficient by
itself to answer "is this still the same account/device?".

### 6. Signed/LR-PQ prekey lifecycle implemented

`PrekeyStore` now supports:

- signed EC prekey rotation;
- last-resort PQ prekey rotation;
- bounded retention of previous private keys for delayed initiations;
- explicit expiry helpers;
- exact lookup by the packet's `used_spk_id` / `pq_prekey_id`;
- `VCPREK02` serialization with `VCPREK01` migration support.

The engine resolves the exact historical reusable key referenced by a delayed
packet instead of requiring only the newest key.

### 7. One-time prekey server contract made explicit

The library exports complete public EC/PQ OPK inventories. The production server
must atomically allocate/pop each one-time public key. See
`PREKEY_SERVER_CONTRACT.md`.

### 8. Safety-number numeric encoding fixed

The old numeric mapping produced only about 35 data-bearing digits and padded the
remaining 25 digits with zeroes. Numeric v2 derives all twelve five-digit groups
from a domain-separated SHA-512 expansion of the binary fingerprint.

## Added P0 regressions

- whole initiation replay with zero OPKs;
- delayed initiation after signed + LR-PQ rotation;
- stable peer identity replacement blocked;
- peer binding survives crash reload;
- session deletion survives reload;
- uncertain storage commit poisons engine;
- safety-number tail is data-bearing;
- strict serialized booleans / duplicate peer records;
- rotated prekey state roundtrip.

## External gates that remain

These cannot be closed by a pure Rust library alone:

### A. Real encrypted durable storage

Android/iOS adapters still need to implement `TransactionalStorage` using a
durable encrypted database/key hierarchy appropriate for each platform.

### B. Non-restorable monotonic source

Production must supply a counter/version source that cannot be rolled back by
restoring the same application backup. `MemoryCounter` is not sufficient.

If a target platform cannot provide a trustworthy local monotonic primitive,
the deployment needs a documented alternative design (for example server-
anchored state/versioning with explicit offline limitations) and external review.

### C. Atomic server OPK allocation

The actual prekey service must implement `PREKEY_SERVER_CONTRACT.md` and record
concurrency stress evidence. The mobile library cannot enforce the server's
database transaction.

### D. External cryptography review and physical-device testing

`PRODUCTION_READY` remains false until the existing audit and mobile interop
gates are satisfied.

## No claim change

This branch does **not** change the project rule:

```text
PRODUCTION_READY = false
```

until the external gates above and the repository's existing production gates
are cleared.

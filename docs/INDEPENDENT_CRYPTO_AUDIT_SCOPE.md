# Independent Cryptography Audit Scope — P02 Candidate

`PRODUCTION_READY` must remain false until an independent reviewer completes
this scope against a fixed candidate commit and all critical/high findings are
resolved or explicitly rejected with written technical rationale.

## Independence requirement

The reviewer must not be the author of the implementation under review and must
have practical experience reviewing modern messaging protocols and Rust crypto
state machines. Automated scanners/LLM reviews are useful supporting evidence
but do **not** satisfy the independent-audit gate by themselves.

## Clean-room boundary

The implementation is intended to be derived from public protocol specifications,
not libsignal source. Reviewers should audit correctness against public-domain
Signal protocol specifications and standard primitive specifications. Any direct
source-comparison work involving AGPL libsignal should be performed outside this
permissive clean-room repository and should not copy protected implementation
expression into this codebase.

## In-scope production candidate

Primary production path:
- `CryptoProfile::ClassicalV1`
- PQXDH handshake and prekey validation
- classical Double Ratchet
- AES-256-GCM message protection
- X25519 contributory checks
- XEdDSA/XEd25519 signature implementation used by prekeys
- ML-KEM-768 use inside PQXDH
- replay cache and initiation replay domain
- identity/safety-number lifecycle
- prekey rotation, retention and one-time consumption
- engine persistence/rollback/poisoning semantics
- encrypted file storage
- trusted rollback-anchor contract
- C FFI and Swift/Android integration boundary
- PostgreSQL one-time prekey allocator

Experimental features must still be reviewed for memory-safety/cross-profile
isolation if compiled, but they are not to be promoted by this audit:
- Header Encryption profile
- Hybrid/Triple Ratchet
- SPQR/Braid
- Sesame experimental transport/session manager

## Required questions

### Primitive correctness

- Are X25519 low-order/non-contributory inputs rejected at every protocol DH use?
- Are signatures canonical, domain-correct and resistant to malleability relevant
  to the protocol?
- Is ML-KEM validation/implicit rejection used correctly?
- Are HKDF/HMAC labels domain-separated and frozen appropriately?
- Is AES-GCM key/nonce uniqueness guaranteed by ratchet + durable-state semantics?
- Are secret intermediates and persisted plaintext state zeroized where practical?

### PQXDH

- Verify every DH/KEM term and ordering against the public PQXDH specification.
- Verify associated-data construction and identity/prekey signature binding.
- Verify one-time EC/PQ consumption only after first message authentication.
- Verify replay of a valid initiation cannot establish a second session when
  one-time prekeys are absent/last-resort is used.
- Verify delayed messages across signed/LR-PQ rotation use exact historical IDs.

### Double Ratchet

- Verify KDF_RK/KDF_CK/message-key derivation and nonce derivation.
- Verify DH ratchet update order and rollback on authentication failure.
- Verify skipped-key bounds, duplicate handling, counter overflow behavior and
  persistence serialization.
- Verify low-order header DH is rejected transactionally.
- Verify crash/restart cannot reuse a message key or AES-GCM nonce.

### Engine state machine

Model every mutating operation as:

`precondition -> trial mutation -> durable commit -> externally observable result`

Identify any path where:
- ciphertext/plaintext is returned before durable state is safe
- an error leaves uncommitted live state usable
- replay/identity/prekey state advances without the session transition
- a storage ambiguity is not converted into a terminal poisoned state
- deletion reports success before durable deletion
- crash reload mixes state from different snapshots

### Persistence / rollback

- Verify encrypted snapshot format, bounds, AEAD AD, nonce generation and atomic
  replacement behavior on Android/iOS filesystems.
- Verify the encryption key lifecycle does not silently generate a different key
  for an existing database.
- Verify the rollback anchor is genuinely outside the restorable app-data domain.
- Analyze the counter-first / storage-second crash window and the operational
  reconciliation procedure for an anchor value ahead of local storage.
- Verify backup/restore tests reject old but authentic encrypted snapshots.

### Identity lifecycle

- Verify cryptographic identity is keyed by stable application peer/device ID,
  not phone number/display name or key bytes alone.
- Verify changed keys are not silently overwritten before acknowledgement.
- Verify device IDs and peer IDs are bounded and canonical.
- Verify safety numbers are symmetric and every displayed digit is data-bearing.

### Server one-time prekeys

- Prove database constraints and transaction isolation make successful unique
  OPK allocation injective over `(device, kind, prekey_id)`.
- Verify request-token retries are idempotent even under simultaneous identical
  requests.
- Verify rotation cannot split one returned bundle across generations.
- Verify upload cannot overwrite/reuse a consumed one-time ID.
- Run the supplied >=10k allocation stress case against the target DB settings.

### FFI / concurrency

- No fabricated Rust lifetimes from foreign pointers.
- Every FFI panic is contained.
- Buffer-size queries must not mutate crypto state.
- Destroy must be terminal with respect to queued/in-flight operations.
- Same-session operations must serialize.
- Different-session parallelism must not permit ratchet races, stale persistence,
  replay races, or storage-epoch corruption.
- Global mutations (prekeys, identity trust, reload, delete-all) must exclude
  incompatible session operations.

## Required adversarial tests

At minimum:
- bit flips/truncation/trailing data for every wire/persistence parser
- protocol/profile/session-tag relabeling
- low-order X25519 inputs in PQXDH and ratchet headers
- huge counters and skipped-message distances
- duplicate/out-of-order messages
- whole initiation replay with and without OPKs
- identity replacement with stable peer ID
- prekey rotation/expiry race
- storage put/commit/rename/fsync failure injection
- rollback to older valid encrypted snapshot
- concurrent same-session encryption attempts
- concurrent different-session encryption/decryption
- FFI destroy race and panic injection
- 10k+ concurrent OPK allocation requests

## Deliverables

The external auditor must provide:
1. exact audited commit SHA and feature matrix
2. threat model/assumptions
3. finding list with severity + exploitability rationale
4. reproduction for every Critical/High/Medium finding
5. verification of remediations on a later exact SHA
6. residual-risk statement
7. explicit statement whether ClassicalV1 is suitable for the claimed deployment
   assumptions (not a generic guarantee of cryptographic security)

## Release rule

Any unresolved Critical or High keeps `PRODUCTION_READY=false`. Medium findings
require documented disposition. Experimental Hybrid/SPQR promotion requires its
own dedicated formal/cryptographic review and is not implied by ClassicalV1 audit.

# Formal State-Machine Models

**Date:** 2026-08-17  
**Technique:** TLA+ (finite-state model checking with TLC)

## What this is

Simplified, model-checkable representations of VoiceChat protocol **state machines** and **invariants**.  

We are **not** attempting to prove cryptographic primitives (X25519, ML-KEM, AEAD, signatures).  
We **are** modeling lifecycle and transition discipline so that tools can check properties such as:

| Property | Module |
|----------|--------|
| One-time keys cannot be legitimately consumed twice | `PrekeyConsumption.tla` |
| Invalid authentication cannot commit ratchet state | `RatchetState.tla` |
| Failed decryption does not commit state | `RatchetState.tla` |
| Replay does not yield a second accepted application event | `ReplayAndIdentity.tla` |
| Identity replacement is not a silent success | `ReplayAndIdentity.tla` |
| Protocol profile downgrade is impossible after binding | `ReplayAndIdentity.tla` |
| State machines do not take impossible transitions | all modules (type + next-state relation) |

## What this is not

**Do not describe the library as “formally verified.”**  

These models are specifications of intended invariants. A property is only considered checked after TLC (or another accepted checker) has been run on a concrete finite instance and reported success. Until that run is recorded, the status is **modeled, not proven**.

## Assumptions (explicit)

See also `VoiceChatInvariants.tla`.

1. **Primitive black boxes** — AEAD authenticity and signature unforgeability are assumed; discrete-log / lattice problems are not modeled.
2. **Network adversary** — can drop, reorder, duplicate, inject; cannot forge tags/signatures without keys.
3. **Transactional storage** — commit is atomic; crash aborts open transactions.
4. **Identifier uniqueness** — `message_id` uniqueness within a conversation is assumed for replay detection.
5. **Finite approximation** — counters, prekey sets, and message sets are bounded for model checking.
6. **Profile scope** — classical Double Ratchet transitions are the baseline; HE and Triple Ratchet are separate profiles.

## Files

```
formal/tla/
  PrekeyConsumption.tla    # OPK at-most-once
  RatchetState.tla         # encrypt / trial-decrypt / commit / abort / DH ratchet
  ReplayAndIdentity.tla    # replay, identity change, profile binding
  SesameMailbox.tla        # send / receive / receipt / retry loop bounds
  BraidEpoch.tla           # SCKA epoch closeness
  VoiceChatInvariants.tla  # composition notes + shared assumptions
```

## How to check (TLC)

1. Install [TLA+ Toolbox](https://lamport.azurewebsites.net/tla/toolbox.html) or `tla2tools.jar`.
2. Create a model for e.g. `PrekeyConsumption` with:
   - `PrekeyIds = {p1, p2, p3}`
   - `MaxConsumptions = 1`
3. Specify invariants: `TypeOK`, `AtMostOnce`, `ConsumedNotAvailable`, `AvailableUnconsumed`.
4. Run TLC; record the configuration and result.

Example TLC-oriented constants for `RatchetState`:

```
MaxNs = 5
MaxNr = 5
MaxSkip = 3
```

Invariants: `TypeOK`, `NoCommitOnFailure`, `NotBothTrialAndCommitted`, `CountersMonotonic`.

## Mapping to implementation

| Model construct | Implementation |
|-----------------|----------------|
| `Consume` / `DoubleConsumeAttempt` | `prekeys` one-time types + transactional storage |
| `BeginDecrypt` / `CommitDecrypt` / `AbortDecrypt` | `DoubleRatchetState::decrypt` trial state |
| `Accept` / `ReplayAttempt` | `ReplayCache::check_and_insert` |
| `ObserveIdentityChange` / `AcknowledgeIdentity` | `IdentityTracker` |
| `BindProfile` / `DowngradeAttempt` | `policy::select_profile` / `enforce_profile` |

## Future work

- PlusCal versions for readability
- TLC configs checked in CI with recorded results
- Optional ProVerif models for handshake correspondence assertions (still assuming idealized crypto)
- Explicit session↔conversation injectivity model once session IDs are fully wired

## Status

| Artifact | Status |
|----------|--------|
| Models written | Yes |
| Assumptions documented | Yes |
| TLC run recorded in-repo | **Yes (this session)** — TLC2 2026.08.11 on finite instances below |
| “Formally verified” claim | **Not authorized** for the cryptographic library as a whole. Finite-state *state-machine* invariants were checked. Primitives are still assumed. |

### This-session TLC transcripts

Tool: `formal/tools/tla2tools.jar` (TLC2 Version 2026.08.11.125311, OpenJDK 21).

| Model | Config | Result |
|-------|--------|--------|
| `PrekeyConsumption` | PrekeyIds={p1,p2,p3}, MaxConsumptions=1 | No error. 289 generated / 64 distinct / depth 4. Invariants TypeOK, AtMostOnce, ConsumedNotAvailable, AvailableUnconsumed. |
| `RatchetState` | MaxNs=5, MaxNr=5, MaxSkip=3 | No error. 1824 generated / 840 distinct / depth 29. Invariants TypeOK, NoCommitOnFailure, NotBothTrialAndCommitted, CountersMonotonic. |
| `ReplayAndIdentity` | MessageIds={m1,m2,m3}, Conversations={c1,c2}, Profiles={classical,hybrid} | No error. 4225 generated / 576 distinct / depth 10. Invariants NoDuplicateAccept, NoSilentIdentitySuccess. |
| `SesameMailbox` | Devices={a,b}, MaxLoop=4 | No error. 216 gen / 70 distinct / depth 9. Invariants TypeOK, ReceiptsBounded, LoopsBounded. |
| `BraidEpoch` | epochs bounded to 4 | No error. 33 gen / 20 distinct / depth 8. Invariant EpochsClose. |

These checks apply only to the finite models. They do **not** make VoiceChat Crypto “formally verified.”

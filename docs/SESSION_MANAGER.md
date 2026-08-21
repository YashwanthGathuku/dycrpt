# SESSION_MANAGER.md — Sesame-Style Multi-Device Session Management

**Date:** 2026-08-17  
**Basis:** Public-domain Sesame specification concepts only (no implementation code copied).

## Data Model

```
SessionManager
 └─ UserRecord (per remote user)
     ├─ IdentityTracker
     └─ DeviceRecord (per remote device)  [≤ MAX_DEVICES_PER_USER]
         ├─ active: Option<SessionRecord>
         └─ inactive: VecDeque<SessionRecord>  [total sessions ≤ MAX_SESSIONS_PER_DEVICE]
```

Supports:

```
User A ─ Device A1, A2, A3
User B ─ Device B1, B2
```

MVP may use one active device; structures do not prevent multi-device.

## Handled Cases

| Concern | Mechanism |
|---------|-----------|
| Active / inactive sessions | Active pointer + ordered inactive list; promote on receive |
| Replacing sessions | New active pushes previous to inactive head; tail eviction |
| Failed sessions | Explicit `SessionStatus::Failed` |
| Resend limits | `MAX_RESEND_ATTEMPTS` (application uses when retrying) |
| Device limits | `MAX_DEVICES_PER_USER` |
| Session limits | `MAX_SESSIONS_PER_DEVICE`, `MAX_INITIATING_SESSIONS` |
| Partial delivery | Per-device sessions; inactive retained for delayed messages |
| Identity changes | `IdentityTracker` gate; outbound blocked until `acknowledge_identity` |

## Anti-DoS

- Hard caps on users, devices per user, sessions per device, concurrent initiating sessions.
- No unbounded allocation paths in the manager.

## Transport Agnostic

No network, Firebase, or mailbox logic. The library only manages cryptographic session state. Delivery, device lists, and prekey fetch are application/transport responsibilities.

## Deterministic Simulations

Unit tests cover:

- Single-device initiating → confirm
- Device-limit enforcement
- Identity-change blocks outbound until acknowledgement
- Multi-device data model (three devices for one user)

## Relationship to Sesame

Concepts mapped from the public Sesame document (UserRecord, DeviceRecord, active/inactive sessions, stale markers, bounded storage, session promotion on receive). Algorithms adapted to VoiceChat’s PQXDH + Double Ratchet stack and identity-change policy; no source code was examined or copied.

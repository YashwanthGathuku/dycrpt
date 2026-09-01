# dycrpt vs libsignal — scope comparison, v1 definition, and exit criteria

**For:** Yashwanth (Ash) Gathuku
**Date:** 2026-08-28
**libsignal structure retrieved:** 2026-08-28, from `github.com/signalapp/libsignal` `main`
**dycrpt measured at:** `hardening/f1-f4-review-fixes-2026-08-28`, 18,958 lines of Rust in `src/`

---

## 1. The comparison is not what you think it is

libsignal ships **18 Rust crates**. Listing them matters, because most of them are not a
cryptography library at all:

| libsignal crate | What it is | Does dycrpt need it? |
|---|---|---|
| `protocol` | X3DH/PQXDH, Double Ratchet, Triple Ratchet, sessions, sender keys, sealed sender | **Yes — this is the comparison** |
| `crypto` | AES-CBC/CTR/GCM wrappers, HMAC | Yes (dycrpt = `primitives/`) |
| `core` | Service IDs, device IDs, primitive newtypes | Partly |
| `bridge` | Java/Swift/Node FFI generation | Yes (dycrpt = `ffi/`) |
| `zkgroup` | Anonymous group credentials for Signal's private groups | **No** — Signal-service specific |
| `zkcredential` | Generic ZK credential framework backing zkgroup | **No** |
| `poksho` | Proof-of-knowledge / Sigma protocol toolkit | **No** |
| `attest` | SGX / AMD-SEV / Nitro enclave attestation for CDSI + SVR | **No** |
| `svrb` | Secure Value Recovery (PIN-protected backup key escrow) | **No** |
| `account-keys` | PIN hashing, registration & backup key derivation | **No** |
| `keytrans` | Key transparency log verification | **No** |
| `net` | Chat websocket, CDSI client, proxying | **No** |
| `media` | MP4/WebP sanitizer against malicious media | **No** |
| `message-backup` | Signal's backup file format + validator | **No** |
| `usernames` | Username hashing and discovery | **No** |
| `device-transfer` | Device-to-device migration keys | **No** |
| `cli-utils`, `debug` | Tooling | No |

**Fourteen of eighteen crates are Signal's product infrastructure, not a crypto library.**
They exist because Signal runs a service with private groups, contact discovery, encrypted
backups, and key transparency. You do not run that service. Trying to "match libsignal" at the
repository level is a category error that would have you building enclave attestation clients.

The honest comparison is `rust/protocol` against dycrpt. That is the fight you are actually in.

---

## 2. Protocol layer: like for like

libsignal `rust/protocol/src` against dycrpt `src/`:

| Capability | libsignal | dycrpt | Status |
|---|---|---|---|
| PQXDH key agreement | `pqxdh.rs` | `pqxdh/` | ✅ Have |
| Double Ratchet | `double_ratchet.rs` | `ratchet/mod.rs` | ✅ Have |
| Triple Ratchet / PQ ratchet | `triple_ratchet.rs` | `ratchet/triple/`, `ratchet/spqr/` | ✅ Have |
| ML-KEM | `kem.rs`, `kem/` | `primitives/kem.rs`, `mlkem_inc.rs` | ✅ Have (gated) |
| Identity keys | `identity_key.rs` | `identity/` | ✅ Have |
| Safety numbers / fingerprint | `fingerprint.rs` | `fingerprint/` | ✅ Have |
| Session state & management | `session.rs`, `session_management.rs`, `state/` | `engine/`, `session/` | ✅ Have |
| Primitive wrappers | `crypto.rs` | `primitives/` | ✅ Have |
| Wire format | protobuf (`proto/`) | custom (`wire/`, `envelope/`) | ⚠️ Divergent — no Signal interop |
| **Group messaging** | `sender_keys.rs`, `group_cipher.rs` | — | ❌ **Absent** |
| **Sealed sender (metadata)** | `sealed_sender.rs` | — | ❌ **Absent** |
| **Attachment / streaming auth** | `incremental_mac.rs` | — | ❌ **Absent** |
| Multi-device (Sesame) | `session_management.rs` | `session/sesame.rs` | ⚠️ Prototype, feature-gated off |
| Language bindings | Java, Swift, Node (generated) | C ABI, Swift, JNI (new, **untested on device**) | ⚠️ Partial |

### What dycrpt has that libsignal's protocol crate does not

This list is short but it is real, and it is where your differentiation actually lives:

1. **Rollback-resistant persistence, in the library.** libsignal delegates storage to the
   application through store traits. dycrpt ships `EncryptedFileStorage`, a monotonic-epoch
   contract, a trusted anchor interface, typed fail-closed restore rejections, and an engine
   that poisons itself on an unknown write outcome. Signal solves rollback at the app layer;
   you solve it at the library layer. That is a genuine design contribution.
2. **A permissive licence on a PQXDH implementation.** I searched again and found no other
   permissively licensed PQXDH implementation. libsignal is AGPL-3.0-only. This is your one
   unambiguous market gap.
3. **TLA+ models, a parity harness, and a constant-time harness in-tree.**
4. **Header encryption profile** (`ratchet/header_encrypt/`) — beyond the Signal spec.

---

## 3. Scoring it honestly

**Protocol core (1:1 messaging): roughly at parity.** You have PQXDH, Double Ratchet, Triple
Ratchet, ML-KEM, identity, fingerprints, sessions. That is not a small achievement and it is
genuinely most of what a 1:1 secure messenger needs.

**Everything around the core: not close, and mostly shouldn't be.** Group messaging and sealed
sender are real gaps for a messenger. The other fourteen crates are gaps you should never close.

**Assurance: not comparable, and this is the only category that decides adoption.**

| | libsignal | dycrpt |
|---|---|---|
| Independent audits | Multiple, public | **Zero** |
| Formal analysis of PQXDH | Published ProVerif/CryptoVerif work | TLA+ state models only (different thing) |
| Production exposure | Billions of messages/day, ~15 years | Zero |
| Full-time cryptographers | Several | Zero |
| Bus factor | Team + foundation | **1** |
| Known-answer vectors | Extensive | RFC 7748 + RFC 5869 only |
| Device-tested platform bindings | Java, Swift, Node in production | **None tested on hardware** |

The three defects found in three review sessions — malleable signatures surviving every gate, a
fuzz gate producing 0 parses from 1,000,000 inputs, and a complete Kotlin facade over zero JNI
symbols — are all in this last category. None were code-quality failures. All were verification
failures.

---

## 4. Version 1: the definition

You are right that a project without an end never finishes. So v1 is defined here by what it
**refuses** to contain.

### In scope

- One-to-one messaging only
- `ClassicalV1` profile only (X25519 + Double Ratchet)
- Single device per identity
- Persistent encrypted storage with rollback-resistant restore
- One platform binding, working on real hardware — **pick Android or iOS, not both**
- C ABI + that one binding
- Apache-2.0 / MIT dual licence, with actual LICENSE files

### Explicitly out of scope for v1 — write this down and defend it

- Group messaging / sender keys
- Sealed sender / metadata protection
- Attachment or streaming encryption
- Multi-device (Sesame stays feature-gated off)
- Hybrid PQ profile (`hybrid` stays feature-gated; `mlkem_inc.rs` is the highest-risk code you own)
- Header encryption profile
- The second platform binding
- Signal wire interop

Every one of those is a legitimate v2 candidate. None belongs in the thing you audit first,
because **an audit is priced by surface area** and each of them enlarges the bill on code that
1:1 messaging does not need.

---

## 5. Exit criteria — how you know v1 is done

Not "it feels finished." Each gate is a command with a pass/fail output. v1 ships when all seven
are green **and not before**.

### Gate 1 — Scope frozen
`docs/V1_SCOPE.md` exists, lists the out-of-scope items above, and every one is either absent
from the build or behind a non-default feature flag. Verified by `cargo build` with default
features exposing none of them.

### Gate 2 — Known-answer vectors
Currently you assert two: RFC 7748 §6.1 and RFC 5869 Case 1. v1 requires:
- All RFC 7748 X25519 vectors, including the iterated ones
- All RFC 5869 HKDF-SHA256 cases
- Project Wycheproof X25519 and HMAC vectors wired into the suite
- If `hybrid` is ever un-gated: NIST ACVP ML-KEM-768 KATs (this is one of the reasons it stays gated for v1)

Pass condition: `cargo test kat` runs ≥ 100 external vectors and all pass.

### Gate 3 — Every gate can fail (mutation testing)

This is the one that addresses your actual weakness, and it produces a number.

`cargo-mutants` injects small faults into your source — flipping a comparison, replacing a
return value, deleting a statement — and reruns the test suite for each. If the tests still pass,
that fault is a hole your suite cannot see. The **mutation score** is caught ÷ viable.

This is the general form of the F1 problem. F1 was a real fault your entire gate stack could not
detect. A mutation run tells you how many *more* such faults are undetectable, as a number,
before an auditor charges you to find out.

Pass condition for v1: **≥ 85% mutation score on `src/primitives/`, `src/ratchet/`, `src/pqxdh/`,
`src/replay/`, and `src/storage/`.** Every surviving mutant is either killed with a new test or
recorded in `docs/KNOWN_LIMITATIONS.md` with a justification.

```bash
cargo install cargo-mutants --version 26.0.0 --locked   # 27.x needs rustc ≥ 1.88
cargo mutants --file 'src/primitives/**' --file 'src/ratchet/**' -- --lib
```

Budget real time for this: each mutant rebuilds the crate. Run it on a machine you can leave
alone overnight, not in a CI job with a timeout.

### Gate 4 — Differential testing against libsignal

You already have `backends/libsignal/PIN.md` and the parity harness reports
`libsignal backend: NOT_LINKED`. For v1, link it — **in a separate test-only binary that is never
distributed**, so the AGPL boundary holds. Then run both implementations over identical
transcripts and assert identical outputs where the specs say they must agree.

This is the strongest correctness evidence available to you that does not cost money, and it is
the one thing that converts "I implemented the spec" into "I match the reference."

Pass condition: ≥ 10,000 randomized transcripts, zero divergences, and the AGPL isolation
documented and verified by `cargo deny`.

### Gate 5 — Adversarial suite
- `host_runner` at ≥ 10M iterations, zero panics, corpus self-check passing
- The libfuzzer targets actually **run** under `cargo-fuzz` for ≥ 1 hour each, not merely built
- `ct_timing --samples 500000` passing, with at least three probes: X25519, AEAD tag comparison, and skipped-key lookup
- 10k randomized handshake gate passing in release

### Gate 6 — Real device, real app
Pick one platform. The engine runs on physical hardware, inside a real application, with:
- Two devices exchanging ≥ 1,000 messages including offline delivery and reordering
- A backup/restore cycle producing `VC_STATE_LOST` and the app handling it without crashing
- A `nativeLiveAnchorCount` create/destroy loop showing no `GlobalRef` growth
- Concurrent send/receive under load with no anchor desynchronization

### Gate 7 — External audit
One firm, scoped to the v1 surface only. Every finding either fixed or documented with an
accepted-risk rationale. **v1 does not ship before this.** Not because a rule says so, but
because you have now seen three times what your own gates fail to catch, and the whole argument
for the library is that it is trustworthy.

---

## 6. Sequence

| Phase | Work | Gate |
|---|---|---|
| **A** | Freeze scope; write `V1_SCOPE.md`; add LICENSE files | 1 |
| **B** | Wycheproof + full RFC vectors | 2 |
| **C** | Mutation testing to ≥ 85%; kill or document every survivor | 3 |
| **D** | Link libsignal in an isolated test binary; differential run | 4 |
| **E** | Adversarial suite at full scale, multi-probe timing | 5 |
| **F** | One platform on hardware, in a real app | 6 |
| **G** | Audit; fix; re-review the fixes | 7 |
| **→** | **Tag v1.0.0, publish under Apache-2.0 / MIT** | — |

Phases B, C and E can overlap. D depends on B. F depends on nothing else and can run in parallel
from now. G is last and is the only one with a bill attached.

Realistically: C and D are the long poles, and F depends on your hardware time, not mine.

---

## 7. My opinion

**Is dycrpt equal to libsignal? At the 1:1 protocol core, close. Everywhere else, no — and in
assurance, not remotely.** But the assurance gap is the only one that is both real and closeable
by you alone, and it is closeable, because the three defects found so far were all detectable by
techniques that cost time rather than money.

The one thing I would change about how you are thinking: **stop treating "what does libsignal
have that I don't" as the roadmap.** Answered literally, it points at enclave attestation and
zero-knowledge group credentials, which would be a waste of your life. Answered honestly, the
list is three protocol features and one enormous assurance gap — and the assurance gap is worth
more than all three features combined, because it is what makes the code you already have
believable.

Gate 3 is the recommendation I would push hardest. A mutation score is the first number you will
ever have that measures whether your tests can actually detect a fault. Everything else in this
document is scoping. That one is diagnosis.

Ship v1 small. A narrow, audited, permissively licensed PQXDH library that does 1:1 messaging
correctly on one platform is a real artifact that people can use and that stands up as evidence
of what you can do. A broad, unaudited one that does everything is a portfolio piece with a
signature-malleability bug in it.

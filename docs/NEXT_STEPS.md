# NEXT STEPS — ordered queue for Antigravity

Do these **in order**. Do not start VoiceChat integration or Hybrid-as-default until the gate in each section is met.

Policy: [`FINAL_SECURITY_RULE.md`](FINAL_SECURITY_RULE.md), [`SOURCE_BOUNDARY.md`](SOURCE_BOUNDARY.md).  
Context: [`HANDOFF.md`](HANDOFF.md).

---

## Do not do

- Inspect or vendor `libsignal` inside this repo.
- Claim production-ready / quantum-proof / formally verified / independently audited.
- Put `HybridPqV1` first in `PROFILE_PREFERENCE`.
- Enable `sesame` for the VoiceChat app.
- Require ciphertext or SK byte-equality with Signal.
- Invent Encaps1 “optimizations” that change Decaps or official-CT match.
- Rewrite the library. Hardening + evidence only unless a P0 bug appears.

---

## 1. Re-verify this tree (30–90 min)

**Why:** Handoff evidence is from 2026-08-19. Your checkout may have drifted.

```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features -- --skip ten_thousand
cargo run -p crypto-parity
```

**Done when:** all exit 0; P0 failures still 0; record output in `TEST_EVIDENCE.md` if anything changed.

---

## 2. Record the VoiceChat libsignal pin (external)

**Why:** Differential harness cannot name a moving target. Pin is currently **UNVERIFIED**.

1. Open the **parent VoiceChat** repo (not in this workspace).
2. Find the exact `libsignal` / `libsignal-client` commit or crate version.
3. Write it into `crypto-parity/backends/libsignal/PIN.md` (sha + date + how you found it).
4. Do **not** upgrade that pin during a parity campaign.

**Done when:** PIN.md has a real commit, not a guess.

---

## 3. Optional: live libsignal differential (separate AGPL repo)

**Why:** Current `crypto-parity` is VoiceChatCrypto **self-parity**. Reviewer asked for two backends on the same scenarios.

1. New repo, AGPL, **outside** this workspace.
2. Implement the same scenario IDs (`crypto-parity/scenarios/*.yaml` + `src/corpus.rs` ids).
3. Compare **outcomes** (ACCEPT / REJECT_* / state_advanced), never wire bytes.
4. Classify every divergence: `BUG_VOICECHAT_CRYPTO` | `BUG_REFERENCE_ASSUMPTION` | `INTENTIONAL_DIFFERENCE` | `SPEC_VARIANT` | `UNKNOWN`.
5. **`UNKNOWN` blocks promotion.**

**Done when:** a report exists with those classifications. Not required to ship ClassicalV1 behind a **dev** flag if P0s stay green here.

---

## 4. Heavy evidence (this repo)

Run and paste verbatim into `TEST_EVIDENCE.md`:

```
cargo test --lib ten_thousand
cargo run -p crypto-parity -- --full
cargo test --release --all-features -- --skip ten_thousand
```

On Linux (not this GNU Windows host): `cargo-fuzz` / `libfuzzer` on `fuzz/fuzz_targets/*`.

**Done when:** 10k PQXDH recorded this checkout; `--full` random violations = 0; fuzz run length recorded (hours or iters).

**Note:** `--full` is 200 sessions × 5000 DR events (1e6). Debug can take a long time. Prefer `--release` if you add a release profile run.

---

## 5. Prekey stress (reviewer item)

100 contacts × 100 initiations: concurrency, OPK exhaust, replenish, duplicate requests, delayed first message, `simulate_crash_reload`, storage abort.

Measure: `duplicate OPK consumption = 0`.

Add as `crypto-parity` scenarios or `tests/prekey_stress.rs`. Keep it deterministic with a seed.

**Done when:** a named test exists, is run, and records zero double-consumes.

---

## 6. Experimental VoiceChat integration — ClassicalV1 only

**Only after** steps 1 and (ideally) 4. **Not** Hybrid.

1. Feature-flag in the **parent app**: `VoiceChatCrypto` vs existing libsignal path.
2. Use `DeviceConfig::recommended` (ClassicalV1).
3. Wire `CryptoEngineApi` only. No private keys to Dart/Kotlin/Swift.
4. Same-platform VoiceChatCrypto ↔ VoiceChatCrypto first (one Android, then two).
5. Then Android ↔ iPhone.
6. Keep libsignal as rollback until an **external** audit.

**Done when:** a real device conversation works (text + voice payload) and crash-reload does not reuse OPKs. Record device models / OS versions.

---

## 7. Hybrid / Braid (later, not default)

Do **not** auto-select Hybrid until:

- Independent review of `src/primitives/mlkem_inc.rs` and `src/ratchet/braid/`
- Encaps1 side-channel story is honest (lab CT or documented residual)
- `crypto-parity` Hybrid scenarios exist (`--features hybrid`)
- Reviewer still wants Classical as default

**Done when:** a written external opinion exists. Code-complete is not enough.

---

## 8. Sesame (later)

Replace hardcoded SK in `src/session/sesame.rs` with real per-device PQXDH **before** exporting. Until then keep `feature = "sesame"` off.

VoiceChat V1 can use app-level device lists / Firebase. That is OK.

---

## 9. External cryptography audit

Packet: [`AUDIT_HANDOFF.md`](AUDIT_HANDOFF.md), [`SPEC_TRACE.md`](SPEC_TRACE.md), [`SOURCE_BOUNDARY.md`](SOURCE_BOUNDARY.md), [`TEST_EVIDENCE.md`](TEST_EVIDENCE.md), `crypto-parity/reports/`.

Ask for: ship / ship-with-fixes / do-not-ship, with spec citations.

**Only after this** may anyone discuss removing libsignal.

---

## Promotion checklist (copy into a PR)

```
[ ] Step 1 re-verify green on this checkout
[ ] 100% P0 in crypto-parity
[ ] ≥95% Signal-Core / ≥90% Operational / 100% VoiceChat axes
[ ] 10k PQXDH recorded
[ ] Randomized `--full` or equivalent ≥1e6 transitions, 0 violations (or documented subset)
[ ] Parser fuzz: 0 panics for defined run
[ ] libsignal pin recorded (if doing differential)
[ ] No UNKNOWN divergences (if doing differential)
[ ] ClassicalV1 device interop (if integrating)
[ ] External audit (if replacing libsignal)
```

---

## Suggested first Antigravity prompt

```
Read docs/HANDOFF.md and docs/NEXT_STEPS.md.
Obey docs/FINAL_SECURITY_RULE.md and docs/SOURCE_BOUNDARY.md.
Do NEXT_STEPS §1 (re-verify). If green, implement §5 prekey stress test with a seed.
Do not enable Hybrid as default. Do not add libsignal. Do not claim production-ready.
Paste verbatim cargo output into docs/TEST_EVIDENCE.md.
```

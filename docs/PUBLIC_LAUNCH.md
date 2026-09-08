# Public launch: who this is for, how we talk about it, what we do next

**Date:** 2026-09-08  
**Audience:** Yashwanth (project owner)  
**Rule:** This file is process and positioning. It does not make the crate production-ready.

The comparison with libsignal lives in `LIBSIGNAL_COMPARISON.md`. That document is for **us**. It is not the homepage, not the README, and not a press line.

---

## 1. The legal line (do not cross)

libsignal is AGPL-3.0. Signal’s **specifications** (PQXDH, Double Ratchet, XEdDSA, Sesame, ML-KEM Braid) are **public domain**. NIST FIPS 203 and the RFCs are freely implementable.

Allowed public sentence:

> Clean-room implementation of the **public-domain** PQXDH, Double Ratchet, and XEdDSA specifications, plus FIPS 203 ML-KEM, under MIT OR Apache-2.0. Not affiliated with Signal. Not a port of libsignal. Not compatible with the Signal network.

Forbidden public sentences:

- “We replicated / cloned / forked libsignal.”
- “Drop-in replacement for libsignal.”
- “Signal-compatible” / “works with Signal.”
- Using Signal’s name, logo, or “libsignal” as the product identity.

Why: a clean-room spec implementation is a normal, legal way to use a public-domain protocol. Claiming you copied an AGPL codebase (even if you did not) invites a copyright fight you cannot win on vibes. `SOURCE_BOUNDARY.md` is the engineering rule; this file is the **speech** rule.

Also missing today: `Cargo.toml` says MIT OR Apache-2.0 but **there are no LICENSE files in the repo**. Do not make the GitHub repo public until those files exist.

---

## 2. Do not compete with 2013 Signal. Compete with 2026 embedding.

libsignal was built for a **human messenger**: phone numbers, sealed sender, groups, attachments, a global relay, AGPL so a hosted fork cannot hide.

The world that showed up later:

| Shift | What it means for this crate |
|---|---|
| **Agents / tool-calling AIs** | Identities are keys, not phone numbers. Sessions are short. State is checkpointed and restored constantly. A library that **fail-closes on rollback** is more useful than a library that assumes a human phone. |
| **Everyone embeds models** | Closed-source copilots, enterprise agents, game NPCs, device runtimes cannot take AGPL into the binary. Permissive E2E is the product. |
| **Post-quantum is a NIST standard, not a blog post** | FIPS 203 exists. Hybrid can be an *optional* profile. Claiming “quantum-proof” is still a lie until KATs + audit. |
| **“ML” confusion** | ML-KEM is **Module-Lattice** cryptography, not machine-learning crypto. Never market it as “AI encryption.” |
| **Libsignal’s unsupported-outside-Signal stance** | Their README says use outside Signal is unsupported. That is the opening: a supported, permissively licensed engine for *other* products. |

**Differentiation that is already real (say these, not “we cloned Signal”):**

1. **Permissive license** — embed in an agent SDK, a game, a closed app.
2. **Rollback-resistant storage in the library** — agents and mobile apps restore backups every day. libsignal leaves that to the app. You made it a typed fail-closed contract (`RollbackDetected`, `StateLost`). That is the agent-era feature, not a Signal clone feature.
3. **Machine identities** — no phone-number or Signal-service assumption in the engine.
4. **PQ as an explicit, gated profile** — Classical default; hybrid opt-in when the KATs exist.
5. **Evidence culture** — mutation testing found real holes (malleable signatures, skip bounds, lying anchors). Publish the *method*, not a fake “more secure than Signal” claim.

**Do not invent a fake “AI crypto” algorithm.** The security rule still holds: only public, reviewed constructions. Agents need boring, audited, embeddable E2E — not a new ratchet named after transformers.

---

## 3. What “everyone can use” actually requires

A public GitHub repo is not proof. Proof is:

| Artifact | Status now |
|---|---|
| LICENSE + LICENSE-APACHE | **Missing** |
| README that does not sound like a libsignal port | Weak (“Signal-family”) |
| `cargo test` + mutation scores you can cite | Partial (3 files) |
| Known-answer vectors (Wycheproof / RFCs) | Almost none |
| One platform on a real device | Never run |
| Independent audit | Never |
| crates.io (or equivalent) package | `publish = false` |

Until LICENSE files, KATs, and one hardware loop exist, “open source so everyone can use it” is a git remote, not a product.

---

## 4. Next step (do this week, in order)

This is the only queue. Do not start groups, sealed sender, or “AI ratchet” work.

### Step 0 — Speech and license (1 day) — **do first, before public**

1. Add `LICENSE` (MIT) and `LICENSE-APACHE`.
2. Rewrite the **top of README**: public-domain specs, MIT/Apache, not affiliated with Signal, not a libsignal port, not Signal-network compatible.
3. Keep `LIBSIGNAL_COMPARISON.md` in `docs/` for maintainers. Do not link it from the README hero.
4. Write `docs/V1_SCOPE.md` (ClassicalV1 + storage + one FFI; everything else gated).
5. Then, and only then, make the GitHub repo public if you want. Public ≠ v1.0. Public is “here is the lab, here is what is not claimed.”

**Done when:** `ls LICENSE LICENSE-APACHE` works; README has the allowed sentence; no “replicated libsignal” anywhere in tracked files.

### Step 1 — Proof that tests can fail (ongoing)

Mutation on `src/pqxdh/`, `src/replay/`, `src/storage/encrypted_file.rs`, remaining primitives. Kill or document every survivor. Cite scores in README only as “measured on date X,” never as “fully verified.”

### Step 2 — Proof the math matches the spec (KATs)

Wycheproof X25519 + HMAC, full RFC 7748, full RFC 5869. `cargo test kat`. This is what a stranger clones and runs.

### Step 3 — Proof it runs in the world (hardware)

One OS. Two devices. 1,000 messages, reorder, kill-app, restore-old-backup → `VC_STATE_LOST` without crash. That is the demo you show, not a slide that says “like Signal.”

### Step 4 — Proof someone else looked (audit)

Pay for a v1-surface audit (Classical + storage + one binding). Ship 1.0.0 only after that. crates.io after that.

Differential vs libsignal stays in a **separate AGPL repo** if you ever do it. Never in this README.

---

## 5. Process (how the team works after public)

```
change → tests that can fail (especially rejection paths)
      → mutation on the touched module if it is primitives/ratchet/pqxdh/replay/storage
      → commit + push
      → no production / quantum-proof / “Signal compatible” language in the PR
```

Forbidden in PRs and issues:

- Pasting libsignal source, even “for comparison.”
- Byte-equality with Signal wire.
- New features that enlarge audit surface before v1 (groups, hybrid-default, second OS).

Public communications owner: one person. If a journalist asks “is this libsignal?” the answer is the allowed sentence in §1, then stop.

---

## 6. 90-day picture

| When | Public sees | You do not say |
|---|---|---|
| Day 0 (after Step 0) | Source, tests, limitations, Classical default | Production-ready |
| Day 30 | KAT numbers, more mutation scores | More secure than Signal |
| Day 60 | Phone video: two devices, backup fail-closed | Quantum-proof |
| Day 90+ | Audit letter → tag 1.0.0 → crates.io | Compatible with Signal |

If you skip to “public + viral ‘we rebuilt Signal’” you get legal heat and no users. If you skip to “AI-native quantum ML ratchet” you get a new unaudited construction. The boring path is the one that makes the crate **usable**: license, spec KATs, hardware, audit, permissive embed in agents.

# Clean-room verification (2026-09-08)

**Question:** Did this tree copy libsignal code, methods, or unique constants in a way that could taint months of work?

**Engineering verdict:** No copy of libsignal **source, APIs, HKDF labels, protobuf wire, or AGPL headers** was found in `src/`, `ffi/`, `tests/`, or `Cargo.lock`. Shared *words* that appear are names from **public-domain specifications** (PQXDH, Double Ratchet, XEdDSA) or generic English (`SessionRecord`, `Header`, `RootKey` as a concept).

This is **not a lawyer’s opinion**. It is a source-to-source identifier and structure check against `signalapp/libsignal` `main` (`rust/protocol`) retrieved 2026-09-08. A court cares about copying of *expression* (code, comments, unique strings), not about implementing the same public algorithm.

---

## How this was checked

1. `Cargo.lock` / `Cargo.toml` for any `libsignal` / AGPL crate — **none**.
2. Repo-wide search for libsignal-only identifiers (below) — **no matches in `.rs` except the word `SessionRecord`**, which is a different type.
3. Side-by-side of libsignal `rust/protocol/src/lib.rs` public API vs this `src/lib.rs`.
4. Side-by-side of libsignal `double_ratchet.rs` vs this `src/ratchet/mod.rs`.
5. HKDF info labels vs libsignal’s `WhisperText` / `WhisperRatchet` / `WhisperMessageKeys`.
6. SPDX/copyright grep for `AGPL` / `Copyright … Signal Messenger` in this tree — **none**.

Not done (and not claimed): hashing every file of all ~18 libsignal crates against every file here; Java/Swift/Node bridges; historical `libsignal-protocol-c`. Those are extra product code we do not implement.

---

## What would have been a red flag (and was not found)

| libsignal-only marker | In this crate? |
|---|---|
| `WhisperText`, `WhisperRatchet`, `WhisperMessageKeys` HKDF labels | **No** |
| `SignalProtocolError`, `SignalMessage`, `PreKeySignalMessage` | **No** |
| `process_prekey_bundle`, `AliceSignalProtocolParameters` | **No** |
| `SealedSender`, `SenderCertificate`, `UnidentifiedSenderMessage` | **No** |
| `InMemSignalProtocolStore`, `ProtocolAddress`, `KyberPreKeyRecord` | **No** |
| Protobuf `SessionStructure` / lazy protobuf receiver chains | **No** — we use a custom binary map (`VCENCST2`, `VCMAP001`, etc.) |
| `ensure_receiver_chain`, `consume_message_key`, `dh_ratchet_step` | **No** |
| `SPDX-License-Identifier: AGPL-3.0-only` | **No** |
| libsignal in `Cargo.lock` | **No** |

Our HKDF labels are **VoiceChat-prefixed** (`VoiceChat/DR/v1/Root`, `VoiceChat_CURVE25519_SHA-256_ML-KEM-768`). That is both domain separation and evidence of independent protocol definition. Ciphertexts will not match Signal’s even if the math is the same family.

PQXDH `F = 32 × 0xFF` prepended to IKM is **in the public PQXDH spec §2.2**, not a libsignal secret. XEdDSA `hash_i` 0xFF prefix is **in the public XEdDSA spec**. Those matches are required by the spec.

---

## Structure is different

| | libsignal protocol | this crate |
|---|---|---|
| Session type | Protobuf-backed `SessionRecord` / `SessionStructure` | `VoiceChatCryptoEngine` + small `SessionRecord { id, status, ratchet, timestamp }` |
| Ratchet state | `RatchetState` + `SenderChain` + protobuf receiver chains | `DoubleRatchetState` with `dhs/dhr/rk/cks/ckr/ns/nr/pn/mkskipped` |
| Encrypt API | `message_encrypt` / `CiphertextMessage` | `encrypt` → `SealedMessage` / custom envelope |
| Handshake | `process_prekey_bundle` | `alice_initiate` / `InitiationPacket` |
| Persistence | App-supplied store traits | `EncryptedFileStorage` + rollback anchor (our design) |

Same *algorithm family* (public spec). Different *expression* (types, names, wire, labels, storage). That is what a clean-room spec implementation looks like.

`SessionRecord` as a name appears in both. Ours is four fields wrapping `DoubleRatchetState`. libsignal’s is a large protobuf session object. The Sesame specification talks about session records in English. A shared English noun is not a copied class.

---

## What you must still not do

- Do not paste libsignal source into issues, PRs, or “comparison snippets” in this repo.
- Do not run `cargo add libsignal`.
- Do not claim “we replicated libsignal” in public. Say: public-domain specs, independent code, VoiceChat labels, not Signal-network compatible.
- Drop the crates.io keyword `"signal"` before a public crates.io publish (still in `Cargo.toml` keywords — marketing, not copied code, but it invites the wrong comparison).
- Add `LICENSE` / `LICENSE-APACHE` before making the GitHub repo public.

---

## Bottom line

**No source match was found that would indicate a libsignal copy.** Months of work are not jeopardized by a hidden Whisper-label or AGPL file in this tree.

Risk that remains is **speech and process**, not a smoking-gun file: saying “clone of libsignal,” linking AGPL later, or adding Signal wire protobufs. Keep `SOURCE_BOUNDARY.md` and `PUBLIC_LAUNCH.md`.

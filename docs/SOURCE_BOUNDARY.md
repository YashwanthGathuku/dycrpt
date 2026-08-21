# SOURCE_BOUNDARY.md

**Repository:** voicechat-crypto  
**Purpose:** Clean-room implementation of Signal Protocol cryptographic components for VoiceChat, based exclusively on public specifications.  
**Date of audit:** 2026-08-17 (spec URLs re-fetched this session; revisions unchanged)  
**Principal engineer notes:** This document establishes the strict source boundary for all future implementation work. No code, structure, naming, serialization formats, test vectors derived from, or behavioral assumptions based on any `libsignal` (or historical) implementation may be used.

## 1. Allowed Sources

The following sources are the *only* permitted inputs for protocol understanding, algorithm design, parameter selection, and test vector generation.

### 1.1 Official Signal Protocol Specifications (Public Domain)

All documents are published at https://signal.org/docs/ and explicitly placed in the public domain by Signal Technology Foundation / Signal Messenger.

| Specification | Revision / Date | Last Updated | Authors / Editors | Direct URL | IPR Statement |
|---------------|-----------------|--------------|-------------------|------------|---------------|
| The PQXDH Key Agreement Protocol | Revision 3, 2023-05-24 | 2024-01-23 | Ehren Kret, Rolfe Schmidt | https://signal.org/docs/specifications/pqxdh/ | "This document is hereby placed in the public domain." |
| The Double Ratchet Algorithm (includes Header Encryption variant, Sparse Post-Quantum Ratchet, and Triple Ratchet) | Revision 4, 2025-11-04 | 2025-11-04 | Trevor Perrin (editor), Moxie Marlinspike, Rolfe Schmidt (revision 3+) | https://signal.org/docs/specifications/doubleratchet/ | "This document is hereby placed in the public domain." |
| The ML-KEM Braid Protocol | Revision 1, 2025-02-21 | 2025-09-26 | Rolfe Schmidt (designed by Graeme Connell and Rolfe Schmidt) | https://signal.org/docs/specifications/mlkembraid/ | "This document is hereby placed in the public domain." |
| The XEdDSA and VXEdDSA Signature Schemes | Revision 1, 2016-10-20 | — | Trevor Perrin (editor) | https://signal.org/docs/specifications/xeddsa/ | "This document is hereby placed in the public domain." |
| The Sesame Algorithm: Session Management for Asynchronous Message Encryption | Revision 2, 2017-04-14 | — | Moxie Marlinspike, Trevor Perrin (editor) | https://signal.org/docs/specifications/sesame/ | "This document is hereby placed in the public domain." |
| X3DH (historical reference only; superseded by PQXDH for new sessions) | — | — | — | https://signal.org/docs/specifications/x3dh/ | Public domain |

**Notes on Double Ratchet Rev 4:**
- Section 4 describes the Header Encryption variant.
- Section 5 describes the Sparse Post-Quantum Ratchet (SPQR) built on a Sparse Continuous Key Agreement (SCKA) protocol.
- Section 6 describes the Triple Ratchet (hybrid of classical Double Ratchet + SPQR).

### 1.2 NIST Standards

| Document | Status | Publication Date | IPR / Licensing |
|----------|--------|------------------|-----------------|
| FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) | Final | 2024-08-13 | U.S. Government work (public domain). NIST has royalty-free patent licenses covering implementers of ML-KEM as published. See NIST PQC license summary. |

### 1.3 IETF RFCs

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| RFC 7748 | Elliptic Curves for Security (X25519 / X448) | Informational | Freely implementable; no known patents on Curve25519/X25519. |
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | Informational | Standard IETF copyright; free to implement. |
| RFC 2104 | HMAC | — | Supporting. |
| Other AEAD-related (e.g., RFC 5116, Rogaway papers referenced in Signal specs) | — | — | Use as referenced by Signal specs only. |

### 1.4 Academic / Supporting References Explicitly Cited by Official Specs

- Papers and analyses cited *inside* the Signal specifications themselves (e.g., formal verification papers referenced in PQXDH and Double Ratchet).
- NIST PQC submission materials for CRYSTALS-Kyber only to the extent needed to understand FIPS 203.

### 1.5 Independently Generated Materials

- Independently generated test vectors (from the mathematical definitions in the specs).
- Our own protocol/property requirements and threat model for VoiceChat.
- Documentation of permissively licensed cryptographic primitive libraries (crate docs, RFCs).

## 2. Prohibited Sources (Absolute)

The following are **strictly forbidden** under any circumstances:

- Any source code from `signalapp/libsignal` (current or historical).
- Any GitHub search, clone, browse, or inspection of `libsignal`, `libsignal-protocol-c`, `libsignal-protocol-java`, or derivative implementations.
- Translation, adaptation, or structural copying of any libsignal code, function names, class hierarchies, serialization formats, constant values beyond those explicitly stated in public specs, comments, or test suites.
- Any AGPL, GPL, LGPL, or other reciprocal/copyleft runtime dependency.
- Assumptions of protocol behavior derived from Signal application source code, mobile clients, or server implementations.
- Any closed-source or non-public Signal materials.
- Reverse-engineering of binary Signal clients for cryptographic details.

**Enforcement:** Any contribution that violates this boundary will be rejected. All implementers must attest they have not inspected prohibited sources.

## 3. Specification Retrieval Record (as of 2026-08-17)

- PQXDH: Revision 3 (2023-05-24, last updated 2024-01-23)
- Double Ratchet: Revision 4 (2025-11-04) — includes Header Encryption, SPQR, Triple Ratchet
- ML-KEM Braid: Revision 1 (2025-02-21, last updated 2025-09-26)
- XEdDSA: Revision 1 (2016-10-20)
- Sesame: Revision 2 (2017-04-14)
- FIPS 203: Final (2024-08-13)
- RFC 7748: January 2016
- RFC 5869: May 2010

All Signal specification documents contain the explicit statement:  
> “This document is hereby placed in the public domain.”

## 4. Dependency License Gate

No protocol implementation work may begin until:

1. Every candidate runtime dependency has been audited in `docs/LICENSE_AUDIT.md`.
2. The audit confirms zero AGPL/GPL/reciprocal licenses.
3. All dependencies are dual-licensed or licensed under MIT, Apache-2.0, BSD, ISC, or equivalent permissive terms that allow VoiceChat (and downstream) to remain under a permissive license.

## 5. Clean-Room Process Rules

- Protocol logic must be derived solely from the mathematical and procedural descriptions in the allowed specifications.
- Function and type names in the Rust library should be descriptive of the *specification concepts*, not mirror any known implementation naming.
- Test vectors must be either taken from the public specifications (where present) or generated independently from the equations.
- When in doubt about a detail not specified, raise it as an open question rather than inferring from external implementations.

---

**Document status:** Authoritative for the voicechat-crypto project.  
**Next step required before any code:** Complete and freeze `docs/LICENSE_AUDIT.md`.
# AMD_SEV_SNP_INTEGRITY.md — Investigation of SEV-SNP Integrity Checks

**Date:** 2026-08-17  
**Context:** Follow-on to `HARDWARE_MEMORY_ENCRYPTION.md`. Relevant if VoiceChat server-side components (or future confidential backends) ever run under AMD confidential VMs.

## Executive summary

**SEV-SNP** adds **hardware-enforced memory integrity** on top of SEV’s memory encryption. The core mechanism is the **Reverse Map Table (RMP)**: for each 4 KB physical page it records ownership (which VM / hypervisor / firmware), the intended guest physical address (GPA), and validation state. On relevant accesses the CPU checks the RMP inline with page-table walks.

**Intended integrity guarantee (software/hypervisor adversary):**  
If a guest reads a **private** page, it sees the value it last wrote, **or** it takes a fault — not silent stale data, not another page’s data, not hypervisor-written garbage.

**Not in the published threat model (AMD’s own statements):**  
Online physical DRAM integrity attacks such as **DDR bus interposition during VM runtime**. Offline cold-boot style attacks are mitigated by memory encryption when enabled; active bus attacks are out of scope.

---

## Evolution of integrity in the SEV family

| Generation | Confidentiality (HV can’t read guest RAM) | Register state | Memory integrity vs malicious HV |
|------------|---------------------------------------------|-----------------|----------------------------------|
| SME / SEV  | Yes (AES memory encryption) | No | **No** — remap, replay, alias, corrupt ciphertext possible |
| SEV-ES     | Yes | Encrypted on exit | Still **no** full memory integrity |
| **SEV-SNP**| Yes | Yes | **Yes** (RMP) against HV remap / alias / replay / corruption *in the software threat model* |

Classical attacks that motivated SNP: SEVered (remapping), SEVurity (ciphertext malleability), and related HV-controlled page-table abuse.

---

## How integrity checks work

### Reverse Map Table (RMP)

- System-wide structure in DRAM: **one 16-byte entry per 4 KB page** that can be assigned to guests.
- Indexed by **system physical address (SPA)**.
- Located via MSRs `RMP_BASE` / `RMP_END` (1 MB alignment in practice; contiguous or **segmented RMP** on newer multi-socket parts).
- Entries track (conceptually): assigned?, ASID (owner), GPA, validated?, immutable?, VMPL permissions, VMSA-related flags, etc.

**RMP updates** are not free-form OS writes. They go through controlled paths:

- `RMPUPDATE` (hypervisor-facing assignment transitions)
- `PVALIDATE` (guest accepts/validates a page into its private map)
- AMD-SP (PSP) firmware commands for certain ownership states

That finite-state discipline is what makes “only the owner may write” enforceable.

### When checks run

| Access | RMP check? | Rationale |
|--------|------------|-----------|
| Guest **private** read/write (C=1) | Yes | Ownership + GPA + validated |
| Hypervisor **write** to guest page | Yes | Blocks HV corruption of guest private memory |
| Hypervisor **read** of guest page | Typically no | Encryption already hides plaintext |
| Guest **shared** pages (C=0) | No | Intentionally shared with HV |
| Native (non-VM) access to HV-owned pages | Ownership check | Guest-owned pages fault if accessed incorrectly |

After GVA→GPA→SPA translation, hardware compares the walk’s GPA against the RMP entry’s recorded GPA (among other fields). Mismatch → fault. That comparison is the load-bearing check against **silent remapping**.

### Page validation (`PVALIDATE`)

Hypervisor assigns a page (`RMPUPDATE`); guest must **validate** it before treating it as trusted private memory. Until validated, the page is not a normal private working page for the guest. This prevents the HV from slipping unacknowledged backing pages under the guest.

### Bijective mapping property

SNP aims for a **1:1 GPA↔SPA** discipline for private pages:

- One SPA is not legitimately mapped as two different private GPAs (anti-aliasing).
- Changing SPA behind a GPA without proper invalidate/re-validate is detected (anti-remapping).

### VMPL (Virtual Machine Privilege Levels)

Optional intra-guest privilege rings (VMPL0 highest … VMPL3 lowest). RMP entries carry per-VMPL access rights. Used for:

- **SVSM** (Secure VM Service Module) at VMPL0 providing services to a less-privileged guest kernel
- Finer isolation inside one confidential VM (not a substitute for RMP’s HV isolation)

---

## What SNP integrity is good for

Against a **malicious or compromised hypervisor** (classic confidential-computing threat model):

| Attack class | Pre-SNP SEV/SEV-ES | SEV-SNP (design intent) |
|--------------|--------------------|-------------------------|
| HV reads guest plaintext | Blocked by encryption | Blocked |
| HV remaps GPA→different SPA | Possible | **Detected / fault** |
| HV aliases one SPA to two GPAs | Possible | **Blocked** |
| HV replays old encrypted page content | Possible | **Mitigated** by ownership + validation discipline |
| HV writes guest private page | Possible | **Blocked** (RMP write check) |

For a VoiceChat **server** component in an SNP guest: session state in guest private memory is protected from the HV under this model better than plain SEV.

---

## What SNP integrity does **not** guarantee

### 1. Physical bus / interposer attacks (out of scope)

AMD has stated that **online DRAM integrity attacks, including DDR bus interposition during VM runtime, fall outside the published SEV-SNP threat model**. Memory encryption helps offline cold-boot style extraction; it is **not** a full cryptographic integrity tree with freshness on every line (unlike older SGX MEE-style designs that paid a large performance cost).

Research (Battering RAM, Wiretap, TEE.Fail-class work on DDR4/DDR5) demonstrates practical physical attacks against confidential VMs when the adversary can interpose on the memory bus. Treat “SNP” as **not** equivalent to “safe against datacenter physical access.”

### 2. Implementation / initialization bugs

Public research (2025–2026) has shown serious issues around **RMP initialization and platform security processor (PSP) interactions**, including:

- **RMPocalypse** — gaps in RMP protection during SNP init allowing RMP corruption and full break of guarantees on evaluated Zen 3/4/5 parts (firmware mitigations expected; verify current microcode/firmware).
- **XCA-class attacks** (e.g. Fabricked, Staleus, BREAKFAST / Heracles-related lines) — hypervisor influence over interconnect / PSP memory routing leading to broken isolation or forged attestation in lab settings.

**Operational rule:** SNP is only as strong as **current** firmware + attested TCB. Always verify `REPORTED_TCB`, policy flags, and vendor advisories; do not assume “SNP enabled” means “immune.”

### 3. Shared pages and explicit trust

Anything marked shared with the hypervisor is outside RMP private-page integrity. Guest–HV communication buffers must be designed accordingly (GHCB protocol, careful data minimization).

### 4. Side channels

Encryption + RMP do not eliminate classical side channels (cache, timing, ciphertext-metadata leakage). Newer platforms add **ciphertext hiding** and related mitigations; enable and attest them where available.

---

## Implications for VoiceChat

| Deployment | SNP integrity relevance |
|------------|-------------------------|
| Mobile clients (Android/iOS) | **None directly** — not AMD SNP guests |
| Desktop Linux clients | Unrelated unless running inside an SNP VM |
| Backend / relay in AMD confidential cloud VM | **Relevant** — prefer SNP over plain SEV; attest launch; keep secrets in guest private memory; still assume physical datacenter adversary is out of SNP’s published scope |
| Long-term identity keys | Still prefer HSM/KMS or platform SE; SNP is VM isolation, not a substitute for key custody |

**Library stance (unchanged):**

- Cryptographic correctness does not depend on SNP.
- Zeroization, transactional storage, and Keystore/Keychain remain the primary app-level controls.
- If a VoiceChat service is marketed as “running in confidential VMs,” documentation must state: **SNP integrity targets a malicious hypervisor, not a physical bus adversary**, and must require up-to-date attested firmware.

---

## Practical checklist (if using SNP)

1. Require **SEV-SNP** (not SEV-ES alone).  
2. Guest policy: `DEBUG=0` in production; consider `PAGE_SWAP_DISABLE` and **ciphertext hiding** where offered.  
3. Verify attestation: measurement, policy, `REPORTED_TCB`, platform info, `REPORT_DATA` binding.  
4. Track AMD firmware advisories for RMP/PSP issues (RMPocalypse-class and XCA-class).  
5. Do not treat SNP as protection against a skilled physical attacker in the rack.

---

## Relation to prior docs

| Doc | Relationship |
|-----|----------------|
| `HARDWARE_MEMORY_ENCRYPTION.md` | SNP = encryption **plus** RMP integrity (HV threat model) |
| `SECURE_MEMORY.md` / `HARDENING.md` | Userspace zeroize still required inside the guest |
| `FORMAL_MODEL.md` | SNP is an environment assumption, not a protocol invariant |

## References (public)

- AMD SEV-SNP whitepapers and APM (Reverse Map Table, PVALIDATE, RMPUPDATE)  
- Linux kernel documentation: AMD memory encryption / SNP RMP  
- AMD SEV-SNP Firmware ABI  
- Academic/industry analyses: SEV→SNP integrity gap; RMPocalypse; XCA/Fabricked/Staleus/BREAKFAST lines; physical interposer work and AMD threat-model statements  

**Status:** Investigation complete. No change to the VoiceChat Crypto protocol core is required; SNP is an optional hosting environment with explicit threat-model boundaries.

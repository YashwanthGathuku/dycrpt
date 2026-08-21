# HARDWARE_MEMORY_ENCRYPTION.md — Investigation

**Date:** 2026-08-17  
**Scope:** What hardware memory encryption exists, what it actually protects, and what VoiceChat Crypto can (and cannot) rely on from userspace Rust.

## Why this matters

Userspace zeroization (`Zeroize` / `ZeroizeOnDrop`) reduces residual secret lifetime in process memory but **cannot** defend against:

- Physical DRAM readout (cold boot, DIMM removal)
- Memory-bus interposition / probing
- Privileged software that dumps process memory
- DMA from malicious devices (without IOMMU)

Hardware memory encryption and TEEs address *some* of these threats. They do not make a messaging crypto library “quantum-proof” or immune to all physical attacks.

---

## Landscape (2025–2026)

### 1. Full-DRAM / transparent encryption (host OS / firmware)

| Technology | Vendor | Granularity | Key model | Typical enablement |
|------------|--------|-------------|-----------|--------------------|
| **Intel TME** | Intel | Entire physical memory | Single ephemeral key | BIOS early boot |
| **Intel TME-MK** (formerly MKTME) | Intel | Page-granular, multi-key | Software-selected KeyIDs + HW keys | BIOS + OS / TDX |
| **AMD SME** | AMD | Page (PTE bit) | HW key | BIOS and/or `mem_encrypt=on` |
| **AMD TSME** | AMD | Transparent full memory | Single key at boot | BIOS; **consumer Ryzen: largely PRO-only as of 2026 firmware policy** |
| **AMD SEV / SEV-SNP** | AMD | Per-VM | Per-guest keys (AMD-SP) | Hypervisor + guest |
| **Intel TDX** | Intel | Confidential VM | Uses TME-MK under the hood | Cloud / server |
| **Arm CCA + MEC** | Arm | Realm / encrypted contexts | Realm-associated keys | Emerging server / mobile SoCs |

**What it helps:** Confidentiality of DRAM contents against a passive physical attacker who reads DIMMs or probes the bus *if* encryption is active and the attacker lacks the hardware key.

**What it does not fully solve:**

- Recent research (e.g. DDR5 bus interposition / TEE.Fail-class work, 2025–2026) shows that **deterministic memory encryption without integrity/freshness** can still leak secrets to a physical interposer adversary on some server TEE deployments.
- Firmware can disable transparent encryption (AMD TSME restricted on consumer Ryzen via firmware updates).
- Userspace applications **cannot** turn TME/TSME on by themselves; it is a platform/BIOS/kernel decision.

### 2. TEE / enclave memory encryption (isolate from OS)

| Platform | Mechanism | Memory protection notes |
|----------|-----------|-------------------------|
| **Apple Secure Enclave** | Dedicated core + Memory Protection Engine | SEP DRAM region encrypted+authenticated (AES-XEX + CMAC); ephemeral key per boot; opaque to application processor |
| **Android Keystore / StrongBox** | TEE (TrustZone) or discrete SE (e.g. Titan M2) | Key material ideally never enters app RAM; ops run inside TEE/SE |
| **Intel SGX (legacy client)** | Enclave Page Cache + MEE | Stronger integrity/replay historically; limited EPC size; physical attacks still researched |
| **Arm TrustZone** | Secure world isolation | Often used for Keymaster/KeyMint; not full DRAM encryption for the Normal World app |

**What it helps:** Long-term **private keys** (identity, device wrapping keys) can stay inside hardware-backed storage so VoiceChat’s app process never holds the raw private key for signing / unwrap.

**What it does not help alone:** Live **ratchet state** (root/chain/message keys) lives in the app process for performance. Encrypting that state at rest is still the app’s job; hardware memory encryption of *all* RAM is platform-dependent.

---

## Relevance to VoiceChat Crypto

| Secret class | Best practical protection | Hardware angle |
|--------------|---------------------------|----------------|
| Long-term identity private keys | Generate/store in Android Keystore (StrongBox if available) or iOS Keychain/Secure Enclave; export only public keys to Rust | **Yes — preferred** |
| Session ratchet state (RK, CK, MK, DHs) | Zeroize on drop; transactional storage; minimize lifetime | Full-DRAM encryption if platform enables it (not under library control) |
| PQXDH ephemeral / OPK secrets | Zeroize immediately after use | Same |
| Safety number / public fingerprints | Public — no HW encryption needed | N/A |

### What the Rust library can do

1. **Continue aggressive zeroization** (already implemented).
2. **Keep secrets out of Dart** (FFI opaque handles — already designed).
3. **Optional hooks** for the host to wrap long-term keys with platform Keystore/Keychain (library stores only handles or wrapped blobs).
4. **Document** that enabling OS/firmware memory encryption (TME/SME where available) improves physical-attack resistance for *all* process memory, including ours — but is outside the crate’s control.

### What the library must not claim

- “Hardware-encrypted memory” for ratchet state on arbitrary Android/iOS devices.
- Protection against sophisticated physical bus interposers on servers solely because TME/SEV exists.
- That StrongBox/Secure Enclave encrypts in-app ratchet chains (they do not, unless the entire crypto engine is redesigned to run inside the TEE — usually impractical for Double Ratchet throughput).

---

## Platform-specific notes for VoiceChat

### Android

- Use **hardware-backed Keystore / StrongBox** for device identity private keys when `KeyInfo.isInsideSecureHardware` / StrongBox is true.
- File-based encryption protects data at rest; it does **not** encrypt RAM while the app runs.
- TrustZone TEE holds keys; app RAM still holds session keys during chats.

### iOS

- **Secure Enclave** + Keychain for long-term keys; SEP memory is encrypted/authenticated by the Memory Protection Engine.
- Application processor RAM for the Flutter/native crypto process is normal DRAM unless the whole device has additional SoC protections not exposed as an app API.

### Desktop (Linux)

- AMD: `mem_encrypt=on` / BIOS SME or TSME when hardware and firmware allow.
- Intel: TME enabled in BIOS where supported.
- Detect capability via CPUID / sysfs; do not depend on it for correctness.

---

## Residual risk (update to HARDENING.md §7 / SECURE_MEMORY.md)

| Threat | Userspace zeroize | Full-DRAM encryption (TME/SME) | TEE/SE key storage |
|--------|-------------------|--------------------------------|--------------------|
| Cold-boot DRAM readout | Weak | Strong if enabled | Strong for keys never in RAM |
| Compromised OS dumps process | Weak | Weak (OS sees plaintext in CPU) | Strong for keys in TEE |
| DMA attacker | Weak without IOMMU | Depends on platform | Strong for TEE-only keys |
| Physical bus interposer | Weak | Partial; integrity often weak on modern TEEs | Stronger inside discrete SE / SEP |
| App bug leaks key to logs | Mitigated by not logging secrets | N/A | N/A |

---

## Recommendations for VoiceChat

1. **Treat hardware memory encryption as defense-in-depth**, not a substitute for zeroization, transactional storage, or Keystore/Keychain for long-term keys.
2. **Bind long-term identity keys to platform secure hardware** via the host app; pass only public keys and opaque session handles into Rust.
3. **Do not redesign the Double Ratchet to run entirely in a TEE** for the MVP — latency and API limits make this unrealistic on mobile.
4. **Optional future:** detect `mem_encrypt` / TEE availability and surface a “hardware memory protection: available / unavailable” status to the UI for transparency.
5. **Keep residual-risk language honest** in security docs: physical attackers with bus access and compromised OS remain out of the library’s full control.

## References (public)

- Intel TME / TME-MK specifications  
- AMD SME / TSME / SEV-SNP documentation; Linux `amd-memory-encryption`  
- Apple Platform Security (Secure Enclave Memory Protection Engine)  
- Android Keystore / StrongBox / KeyMint  
- Academic/industry analysis of DDR5 interposition and TEE memory-encryption limits (2025–2026)

**Status:** Investigation complete. No code change required in the crypto core beyond existing zeroization; host integration should prefer hardware-backed key storage for long-term secrets.

# THREAT_MODEL.md

**Status:** PARTIALLY VERIFIED (design); UNVERIFIED (external)

## Assets

- Long-term identity private keys  
- Session ratchet secrets (root/chain/message keys)  
- One-time prekey secrets  
- Message confidentiality and authenticity  
- Conversation/device binding integrity  
- Safety fingerprint accuracy  

## Adversaries

| Adversary | Capabilities |
|-----------|----------------|
| Network | Drop, reorder, inject, replay, modify packets |
| Malicious peer | Craft bundles, messages, identity keys |
| Compromised server | Prekey distribution, metadata, offline message store |
| Local malware (app-level) | Read process memory if OS compromised |
| Physical (device) | Cold boot, bus probing — partially mitigated only if platform HW encryption/TEE used |
| Future quantum (record-now-decrypt-later) | Targeted by HYBRID_PQ profile design intent — not “quantum proof” |

## Out of scope

- Compromised Secure Enclave / StrongBox firmware  
- Perfect security under full OS compromise with live memory access  
- Traffic analysis beyond padding buckets  
- Social engineering of safety-number verification  

## High-level mitigations

PQXDH + ratchet FS/PCS, AEAD, envelope AD binding, replay cache, MAX_SKIP, transactional storage, identity tracker, authenticated profiles, zeroization, FFI opacity, optional HE/hybrid profiles.

See `HARDENING.md` for residual risks.

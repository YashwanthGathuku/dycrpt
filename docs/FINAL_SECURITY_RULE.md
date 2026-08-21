# FINAL_SECURITY_RULE.md

**Status:** Binding project policy. Not optional. Not waived by schedule pressure.

## Rule

At no point is anyone authorized to weaken a protocol because implementation is difficult.

If:

```text
security requirement
       conflicts with
implementation convenience
```

**security wins.**

## Explicitly forbidden

| Prohibition | Rationale |
|-------------|-----------|
| Invent cryptographic algorithms | Only public, reviewed constructions |
| Silently replace PQXDH | Handshake is the specified PQXDH (public spec) |
| Silently downgrade post-quantum protection | Hybrid profile must not become classical-only without authenticated negotiation failure or explicit user-visible policy |
| Reuse keys across purposes | KEY-SEPARATION invariant |
| Create custom encryption primitives | Use audited, permissively licensed libraries only |
| Disable authentication | AEAD / signatures / binding remain mandatory |
| Accept unauthenticated state transitions | FAIL-CLOSED; trial decrypt; no commit on auth failure |
| Expose private keys through FFI | Opaque handles only; no root/chain/message/identity/ML-KEM private keys to Dart |
| Adopt copyleft runtime dependencies to finish faster | LICENSE_AUDIT gate; reciprocal licenses require explicit approval |

## When uncertain

1. **Stop** that feature.  
2. **Document** the blocker (e.g. in `KNOWN_LIMITATIONS.md`).  
3. **Preserve** the security invariant.  
4. Do **not** ship a weaker substitute under the same profile name.

## Relationship to other docs

This rule overrides convenience-driven changes to:

- `SECURITY_INVARIANTS.md`
- `SOURCE_BOUNDARY.md`
- `PROTOCOL.md` / profile negotiation
- `POST_QUANTUM_PROFILE.md` non-claims
- `FFI.md` secret boundary
- `LICENSE_AUDIT.md`
- `AUDIT_SCOPE.md` (production readiness remains BLOCKED without external review)

## Audit note

Any PR or patch that violates this rule is a **security defect**, regardless of test greenness or compile success.

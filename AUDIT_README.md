# Security Audit Package — voicechat-crypto

**Start here:** [`docs/AUDIT_SCOPE.md`](docs/AUDIT_SCOPE.md) → [`docs/AUDIT_MAP.md`](docs/AUDIT_MAP.md)

This repository is prepared for **independent** cryptography review.

- We do **not** claim production readiness.
- We do **not** mark findings VERIFIED without external review.
- Compilation success does not upgrade evidence.

Clean-room rule summary: implementation follows **public** protocol specifications only; libsignal source was not used (`docs/SOURCE_BOUNDARY.md`).

## Binding policy

See [`docs/FINAL_SECURITY_RULE.md`](docs/FINAL_SECURITY_RULE.md) — security requirements always win over implementation convenience.

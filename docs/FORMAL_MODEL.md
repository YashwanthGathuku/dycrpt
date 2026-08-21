# FORMAL_MODEL.md

Formal state-machine models live under `formal/`.

- **Technique:** TLA+ (TLC model checking)
- **Scope:** Protocol/state invariants only — not cryptographic primitive proofs
- **Claim level:** Finite-state TLC checks recorded in `formal/README.md`. The library is **not** “formally verified.”

See `formal/README.md` for assumptions, modules, how to run TLC, and the mapping to implementation.

### Invariants targeted

1. One-time prekeys consumed at most once  
2. Failed authentication does not commit ratchet state  
3. No impossible state transitions  
4. Replay does not produce a second accepted application event  
5. Identity replacement is not a silent success  
6. Profile downgrade impossible after binding  
7. Session identifiers do not cross conversations (design invariant; model sketch)

### Related implementation tests

Adversarial and property tests in `src/testing/adversarial.rs` exercise the same invariants dynamically. The TLA+ models are the static counterpart.

#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text()
    if new in text:
        print(f"already fixed: {label}")
        return
    if old not in text:
        raise SystemExit(f"expected pattern missing for {label} in {path}")
    path.write_text(text.replace(old, new, 1))
    print(f"fixed: {label}")


# Preserve zeroizing Drop semantics without cloning the PQXDH associated-data buffer.
replace_once(
    Path("src/engine/mod.rs"),
    """            let shared = bob_process(\n                &bob_mat,\n                &alice_ik,\n                &alice_ek,\n                &message.kem_ciphertext,\n                message.used_ec_opk_id,\n            )\n            .map_err(CryptoError::from)?;\n            let bob_dh = X25519Secret::from_bytes(signed.secret.to_bytes());\n            let ratchet = init_bob_ratchet(self.profile, &shared.sk, bob_dh)?;\n            (ratchet, shared.ad, last_resort)\n""",
    """            let mut shared = bob_process(\n                &bob_mat,\n                &alice_ik,\n                &alice_ek,\n                &message.kem_ciphertext,\n                message.used_ec_opk_id,\n            )\n            .map_err(CryptoError::from)?;\n            let bob_dh = X25519Secret::from_bytes(signed.secret.to_bytes());\n            let ratchet = init_bob_ratchet(self.profile, &shared.sk, bob_dh)?;\n            let handshake_ad = std::mem::take(&mut shared.ad);\n            (ratchet, handshake_ad, last_resort)\n""",
    "PQXDH shared.ad ownership",
)

# Move the staged Vec via Option::take so the zeroizing wrapper still drops safely.
replace_once(
    Path("src/storage/encrypted_file.rs"),
    """        for (key, staged_value) in staged.drain() {\n            match staged_value.0 {\n""",
    """        for (key, mut staged_value) in staged.drain() {\n            match staged_value.0.take() {\n""",
    "encrypted staged-value ownership",
)

# Test helper: transfer the StateBlob Vec without cloning, leaving an empty Vec for Drop.
replace_once(
    Path("tests/storage_hardening.rs"),
    """        TransactionalStorage::get(&*storage, key)\n            .unwrap()\n            .unwrap()\n            .0\n""",
    """        let mut blob = TransactionalStorage::get(&*storage, key)\n            .unwrap()\n            .unwrap();\n        std::mem::take(&mut blob.0)\n""",
    "StateBlob test ownership",
)

# Rustc reported these exact five scenarios as having unnecessary mut bindings.
# Patch function-specific prefixes only; other corpus scenarios genuinely pass engines as &mut.
corpus = Path("crypto-parity/src/corpus.rs")
text = corpus.read_text()
function_specific = [
    (
        'fn wrong_prekey_id() -> Result<(), String> {\n    let mut alice = engine_named(b"a")?;\n    let mut bob = engine_named(b"b")?;',
        'fn wrong_prekey_id() -> Result<(), String> {\n    let alice = engine_named(b"a")?;\n    let bob = engine_named(b"b")?;',
        'wrong_prekey_id unused mut',
    ),
    (
        'fn stale_bundle() -> Result<(), String> {\n    let mut alice = engine_named(b"a")?;\n    let mut bob = engine_named(b"b")?;',
        'fn stale_bundle() -> Result<(), String> {\n    let alice = engine_named(b"a")?;\n    let bob = engine_named(b"b")?;',
        'stale_bundle unused mut',
    ),
    (
        'fn p0_crash_no_opk_resurrect() -> Result<(), String> {\n    let mut a = engine_named(b"a")?;\n    let mut b = engine_named(b"b")?;',
        'fn p0_crash_no_opk_resurrect() -> Result<(), String> {\n    let a = engine_named(b"a")?;\n    let b = engine_named(b"b")?;',
        'p0_crash_no_opk_resurrect unused mut',
    ),
    (
        'fn prekey_replenish() -> Result<(), String> {\n    let mut e = engine()?;',
        'fn prekey_replenish() -> Result<(), String> {\n    let e = engine()?;',
        'prekey_replenish unused mut',
    ),
    (
        'fn prekey_exhaust_then_last_resort() -> Result<(), String> {\n    let mut a = engine_named(b"a")?;\n    let mut b = engine_named(b"b")?;',
        'fn prekey_exhaust_then_last_resort() -> Result<(), String> {\n    let a = engine_named(b"a")?;\n    let b = engine_named(b"b")?;',
        'prekey_exhaust_then_last_resort unused mut',
    ),
]
for old, new, label in function_specific:
    if new in text:
        print(f"already fixed: {label}")
        continue
    if old not in text:
        raise SystemExit(f"expected function-specific pattern missing: {label}")
    text = text.replace(old, new, 1)
    print(f"fixed: {label}")
corpus.write_text(text)

print("Layer-2 compile/clippy fixes applied.")

#!/usr/bin/env python3
"""Apply the two Rust 1.85 E0509 ownership fixes found by Codespace verification.

This deliberately transfers sensitive buffers with mem::take / Option::take
instead of cloning them. The zeroizing Drop implementations remain intact.
"""
from pathlib import Path


def replace_exact(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}")
    p.write_text(text.replace(old, new, 1))


replace_exact(
    "src/engine/mod.rs",
    """            let shared = bob_process(\n                &bob_mat,\n                &alice_ik,\n                &alice_ek,\n                &message.kem_ciphertext,\n                message.used_ec_opk_id,\n            )\n            .map_err(CryptoError::from)?;\n            let bob_dh = X25519Secret::from_bytes(signed.secret.to_bytes());\n            let ratchet = init_bob_ratchet(self.profile, &shared.sk, bob_dh)?;\n            (ratchet, shared.ad, last_resort)\n""",
    """            let mut shared = bob_process(\n                &bob_mat,\n                &alice_ik,\n                &alice_ek,\n                &message.kem_ciphertext,\n                message.used_ec_opk_id,\n            )\n            .map_err(CryptoError::from)?;\n            let bob_dh = X25519Secret::from_bytes(signed.secret.to_bytes());\n            let ratchet = init_bob_ratchet(self.profile, &shared.sk, bob_dh)?;\n            let handshake_ad = std::mem::take(&mut shared.ad);\n            (ratchet, handshake_ad, last_resort)\n""",
)

replace_exact(
    "src/storage/encrypted_file.rs",
    """        for (key, staged_value) in staged.drain() {\n            match staged_value.0 {\n                Some(value) => {\n                    if let Some(mut old) = self.committed.insert(key, value) {\n                        old.zeroize();\n                    }\n                }\n                None => {\n                    if let Some(mut old) = self.committed.remove(&key) {\n                        old.zeroize();\n                    }\n                }\n            }\n        }\n""",
    """        for (key, mut staged_value) in staged.drain() {\n            match staged_value.0.take() {\n                Some(value) => {\n                    if let Some(mut old) = self.committed.insert(key, value) {\n                        old.zeroize();\n                    }\n                }\n                None => {\n                    if let Some(mut old) = self.committed.remove(&key) {\n                        old.zeroize();\n                    }\n                }\n            }\n        }\n""",
)

print("Applied E0509 fixes without cloning sensitive buffers.")

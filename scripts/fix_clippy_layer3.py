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


def replace_all_exact(path: Path, old: str, new: str, expected: int, label: str) -> None:
    text = path.read_text()
    if old not in text:
        if new in text:
            print(f"already fixed: {label}")
            return
        raise SystemExit(f"expected pattern missing for {label} in {path}")
    count = text.count(old)
    if count != expected:
        raise SystemExit(
            f"refusing {label}: expected {expected} occurrences, found {count} in {path}"
        )
    path.write_text(text.replace(old, new))
    print(f"fixed: {label} ({count} occurrence(s))")


# 1) Fingerprint canonical ordering: express the three-way comparison directly.
replace_once(
    Path("src/fingerprint/mod.rs"),
    """    if a_bytes < b_bytes {\n        (a, b)\n    } else if b_bytes < a_bytes {\n        (b, a)\n    } else {\n        let a_dev = a.device_id.as_deref().unwrap_or(&[]);\n        let b_dev = b.device_id.as_deref().unwrap_or(&[]);\n        if a_dev <= b_dev {\n            (a, b)\n        } else {\n            (b, a)\n        }\n    }\n""",
    """    match a_bytes.cmp(&b_bytes) {\n        std::cmp::Ordering::Less => (a, b),\n        std::cmp::Ordering::Greater => (b, a),\n        std::cmp::Ordering::Equal => {\n            let a_dev = a.device_id.as_deref().unwrap_or(&[]);\n            let b_dev = b.device_id.as_deref().unwrap_or(&[]);\n            if a_dev <= b_dev {\n                (a, b)\n            } else {\n                (b, a)\n            }\n        }\n    }\n""",
    "fingerprint comparison chain",
)

# 2) ML-KEM fixed-size polynomial loops. These iterator forms still execute exactly N
# operations and introduce no secret-dependent early exit/branching.
replace_once(
    Path("src/primitives/mlkem_inc.rs"),
    """            for t in 0..N {\n                acc[t] = fq_add(acc[t], prod[t]);\n            }\n""",
    """            for (acc_t, prod_t) in acc.iter_mut().zip(prod.iter()) {\n                *acc_t = fq_add(*acc_t, *prod_t);\n            }\n""",
    "ML-KEM accumulator loop",
)
replace_once(
    Path("src/primitives/mlkem_inc.rs"),
    """        for t in 0..N {\n            u[i][t] = fq_add(acc[t], e1[i][t]);\n        }\n""",
    """        for (u_t, (acc_t, e_t)) in u[i].iter_mut().zip(acc.iter().zip(e1[i].iter())) {\n            *u_t = fq_add(*acc_t, *e_t);\n        }\n""",
    "ML-KEM u/e1 loop",
)
replace_once(
    Path("src/primitives/mlkem_inc.rs"),
    """        for t in 0..N {\n            c[t] = compress(u[i][t], DU);\n        }\n""",
    """        for (c_t, u_t) in c.iter_mut().zip(u[i].iter()) {\n            *c_t = compress(*u_t, DU);\n        }\n""",
    "ML-KEM compression loop",
)

# 3) Give the coordinated storage pair a public semantic name instead of repeating
# a large trait-object tuple in three public signatures.
coordinated = Path("src/storage/coordinated.rs")
text = coordinated.read_text()
alias = "pub type CoordinatedBackendPair = (Box<dyn TransactionalStorage>, Box<dyn MonotonicCounter>);\n"
if alias not in text:
    needle = 'const STORAGE_EPOCH_KEY: &[u8] = b"storage-epoch-v1";\n'
    if needle not in text:
        raise SystemExit("expected STORAGE_EPOCH_KEY insertion point missing")
    text = text.replace(needle, needle + "\n" + alias, 1)
    print("fixed: coordinated backend type alias")
else:
    print("already fixed: coordinated backend type alias")
old_sig = "Result<(Box<dyn TransactionalStorage>, Box<dyn MonotonicCounter>), PrimitiveError>"
if old_sig in text:
    count = text.count(old_sig)
    if count != 3:
        raise SystemExit(f"refusing coordinated signatures: expected 3, found {count}")
    text = text.replace(old_sig, "Result<CoordinatedBackendPair, PrimitiveError>")
    print("fixed: coordinated backend signatures (3 occurrences)")
elif "Result<CoordinatedBackendPair, PrimitiveError>" in text:
    print("already fixed: coordinated backend signatures")
else:
    raise SystemExit("expected coordinated backend signature patterns missing")
coordinated.write_text(text)

# 4) Name the encrypted snapshot map and replace format!-per-byte hex collection
# with a fixed two-nibble encoder (one output allocation, no per-byte allocation).
encrypted = Path("src/storage/encrypted_file.rs")
text = encrypted.read_text()
map_alias = "type SnapshotMap = HashMap<Vec<u8>, Vec<u8>>;\n"
hex_helper = '''\nfn encode_lower_hex(bytes: &[u8]) -> String {\n    const HEX: &[u8; 16] = b"0123456789abcdef";\n    let mut out = String::with_capacity(bytes.len() * 2);\n    for &byte in bytes {\n        out.push(HEX[(byte >> 4) as usize] as char);\n        out.push(HEX[(byte & 0x0f) as usize] as char);\n    }\n    out\n}\n'''
if map_alias not in text:
    needle = "const MAX_VALUE_LEN: usize = 80 * 1024 * 1024;\n"
    if needle not in text:
        raise SystemExit("expected encrypted-file alias insertion point missing")
    text = text.replace(needle, needle + "\n" + map_alias + hex_helper, 1)
    print("fixed: encrypted snapshot type alias + hex encoder")
else:
    print("already fixed: encrypted snapshot type alias")
    if "fn encode_lower_hex(bytes: &[u8]) -> String" not in text:
        raise SystemExit("SnapshotMap alias exists but encode_lower_hex helper is missing")
old_ret = "Result<(HashMap<Vec<u8>, Vec<u8>>, u64), PrimitiveError>"
if old_ret in text:
    count = text.count(old_ret)
    if count != 2:
        raise SystemExit(f"refusing snapshot return signatures: expected 2, found {count}")
    text = text.replace(old_ret, "Result<(SnapshotMap, u64), PrimitiveError>")
    print("fixed: encrypted snapshot signatures (2 occurrences)")
elif "Result<(SnapshotMap, u64), PrimitiveError>" in text:
    print("already fixed: encrypted snapshot signatures")
else:
    raise SystemExit("expected encrypted snapshot return patterns missing")
old_hex_prod = 'let suffix_hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();'
if old_hex_prod in text:
    text = text.replace(old_hex_prod, "let suffix_hex = encode_lower_hex(&suffix);", 1)
    print("fixed: production temp-file suffix encoding")
elif "let suffix_hex = encode_lower_hex(&suffix);" in text:
    print("already fixed: production temp-file suffix encoding")
else:
    raise SystemExit("expected production suffix encoding pattern missing")
old_hex_test = 'let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();'
if old_hex_test in text:
    text = text.replace(old_hex_test, "let suffix = encode_lower_hex(&random);", 1)
    print("fixed: test temp-file suffix encoding")
elif "let suffix = encode_lower_hex(&random);" in text:
    print("already fixed: test temp-file suffix encoding")
else:
    raise SystemExit("expected test suffix encoding pattern missing")
encrypted.write_text(text)

# 5) The two internal helpers intentionally mirror wide C ABI calls. Grouping them
# into Rust structs solely for Clippy would obscure pointer/length pairing and add
# conversion code at a security boundary, so keep a narrow, documented exemption.
ffi = Path("src/ffi/mod.rs")
text = ffi.read_text()
for name in ("establish_outbound_inner", "process_inbound_inner"):
    target = f"fn {name}("
    attr_target = f"#[allow(clippy::too_many_arguments)]\nfn {name}("
    if attr_target in text:
        print(f"already fixed: FFI {name} argument lint")
        continue
    if target not in text:
        raise SystemExit(f"expected FFI helper missing: {name}")
    text = text.replace(
        target,
        "// This helper mirrors a C ABI pointer/length surface; keeping the pairs explicit\n"
        "// makes validation auditable and avoids a second representation at the FFI boundary.\n"
        "#[allow(clippy::too_many_arguments)]\n"
        + target,
        1,
    )
    print(f"fixed: FFI {name} argument lint")
ffi.write_text(text)

print("Layer-3 Clippy fixes applied.")

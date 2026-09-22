# Vendored known-answer vectors

Downloaded 2026-09-08 from `C2SP/wycheproof` branch `main`, directory `testvectors_v1`:

- `x25519_test.json` (518 tests, curve25519)
- `hmac_sha256_test.json` (174 tests)
- `hmac_sha512_test.json` (174 tests)

Source: <https://github.com/C2SP/wycheproof>. License: Apache-2.0. These files are unmodified.

RFC 7748 and RFC 5869 vectors are written into `tests/kat.rs` from the published RFC text. They are not in these JSON files.

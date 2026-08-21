# FUZZING.md

**Status:** PARTIALLY VERIFIED (host runner + in-crate walks); cargo-fuzz/libfuzzer **FAILED** on Windows GNU; continuous corpus **UNVERIFIED** until CI on a libfuzzer host

## Host runner (this Windows GNU host)

```
cargo run --manifest-path fuzz/Cargo.toml --bin host_runner -- 20000
```

No `libfuzzer-sys`. Walks envelope, headers, KEM encodings, public bundle, initiation packet, sealed message.

## libfuzzer targets (Linux / MSVC hosts)

| Target | Parser |
|--------|--------|
| `envelope_parse` | `Envelope::parse` |
| `header_decode` | `Header::decode` |
| `triple_header_decode` | `TripleHeader::decode` |

Enable with `--features libfuzzer`. Location: `fuzz/fuzz_targets/`

On `stable-x86_64-pc-windows-gnu`, `libfuzzer-sys` fails to compile `FuzzerExtFunctionsWindows.cpp` (`__pragma(comment(linker,…))`).

## Policy

- Parser must not panic  
- Fail-closed on malformed input  
- Every fuzz-found crypto/state bug → permanent regression + seed in `KNOWN_FAILURE_SEEDS`

## Sanitizers

`#![deny(unsafe_code)]` (except FFI feature), Miri, ASan/LSan (nightly), cargo-fuzz.

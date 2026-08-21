# iOS build (no device in this workspace)

Physical iOS interop is **not** executed here.

```
rustup target add aarch64-apple-ios
cargo build --release --target aarch64-apple-ios --features ffi
```

Link `libvoicechat_crypto.a` and `ffi/include/voicechat_crypto.h` as the
bridging header. Swift API: `ffi/swift/VoiceChatCrypto.swift`.

# Android build (no device in this workspace)

Physical Android interop is **not** executed here.

```
# NDK + rustup target
rustup target add aarch64-linux-android
cargo build --release --target aarch64-linux-android --features ffi
```

JNI should map Kotlin `VoiceChatCrypto.kt` `external` methods to
`vc_engine_create`, `vc_generate_bundle`, `vc_establish_outbound`,
`vc_process_inbound`, `vc_encrypt`, `vc_decrypt` only.

Never add JNI methods that take 32-byte shared secrets or DH secrets.

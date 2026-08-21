//! Fuzz target: Double Ratchet Header::decode
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = voicechat_crypto::ratchet::Header::decode(data);
});

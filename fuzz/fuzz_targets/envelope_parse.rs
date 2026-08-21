//! Fuzz target: Envelope::parse (untrusted decoding boundary).
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = voicechat_crypto::envelope::Envelope::parse(data);
});

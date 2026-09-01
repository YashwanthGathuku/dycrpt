#![no_main]

use libfuzzer_sys::fuzz_target;
use voicechat_crypto::prekeys::PublicPrekeyBundle;

fuzz_target!(|data: &[u8]| {
    let _ = PublicPrekeyBundle::decode(data);
});

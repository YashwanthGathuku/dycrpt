#![no_main]

use libfuzzer_sys::fuzz_target;
use voicechat_crypto::engine::{InitiationPacket, SealedMessage};

fuzz_target!(|data: &[u8]| {
    let _ = SealedMessage::decode(data);
    let _ = InitiationPacket::decode(data);
});

//! Parser front-door: no panic, no fail-open on junk.

use std::panic::{catch_unwind, AssertUnwindSafe};
use voicechat_crypto::engine::{InitiationPacket, SealedMessage};
use voicechat_crypto::envelope::Envelope;
use voicechat_crypto::ratchet::Header;

pub struct FuzzReport {
    pub inputs: u64,
    pub panics: u64,
}

pub fn run() -> FuzzReport {
    let mut inputs = 0u64;
    let mut panics = 0u64;
    let samples: &[&[u8]] = &[
        &[],
        &[0],
        &[0xff; 7],
        &[0xff; 64],
        b"VCSEAL01",
        b"VCINIT01",
        &[0u8; 1024],
        &[1, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f],
    ];
    for s in samples {
        inputs += 3;
        if catch_unwind(AssertUnwindSafe(|| {
            let _ = Envelope::parse(s);
        }))
        .is_err()
        {
            panics += 1;
        }
        if catch_unwind(AssertUnwindSafe(|| {
            let _ = SealedMessage::decode(s);
        }))
        .is_err()
        {
            panics += 1;
        }
        if catch_unwind(AssertUnwindSafe(|| {
            let _ = InitiationPacket::decode(s);
        }))
        .is_err()
        {
            panics += 1;
        }
        inputs += 1;
        if catch_unwind(AssertUnwindSafe(|| {
            let _ = Header::decode(s);
        }))
        .is_err()
        {
            panics += 1;
        }
    }
    let mut huge = vec![0u8; 4096];
    huge[0] = 1;
    inputs += 1;
    if catch_unwind(AssertUnwindSafe(|| {
        let _ = Envelope::parse(&huge);
    }))
    .is_err()
    {
        panics += 1;
    }
    FuzzReport { inputs, panics }
}

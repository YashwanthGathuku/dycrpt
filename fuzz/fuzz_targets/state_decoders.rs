#![no_main]

use libfuzzer_sys::fuzz_target;
use voicechat_crypto::fingerprint::TrustStore;
use voicechat_crypto::identity::PeerIdentityStore;
use voicechat_crypto::prekeys::PrekeyStore;
use voicechat_crypto::ratchet::header_encrypt::HeaderEncryptState;
use voicechat_crypto::ratchet::triple::TripleRatchetState;
use voicechat_crypto::ratchet::{DoubleRatchetState, DEFAULT_MAX_SKIP};
use voicechat_crypto::replay::ReplayCache;

fuzz_target!(|data: &[u8]| {
    let _ = DoubleRatchetState::deserialize(data, DEFAULT_MAX_SKIP);
    let _ = HeaderEncryptState::deserialize(data, DEFAULT_MAX_SKIP);
    let _ = TripleRatchetState::deserialize(data, DEFAULT_MAX_SKIP);
    let _ = ReplayCache::deserialize(data);
    let _ = TrustStore::deserialize(data);
    let _ = PeerIdentityStore::deserialize(data);
    let _ = PrekeyStore::deserialize(data);
});

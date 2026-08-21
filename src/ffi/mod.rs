#![allow(
    unsafe_code,
    dead_code,
    unused_assignments,
    unused_imports,
    clippy::missing_safety_doc
)]

//! Stable C ABI for Android (Kotlin) and iOS (Swift).
//!
//! # Security boundary
//!
//! Raw secret material NEVER crosses this boundary:
//! - root keys, chain keys, message keys
//! - identity private keys
//! - ML-KEM private keys
//! - PQXDH shared secrets
//!
//! Handshake (PQXDH) and ratchet state live only inside
//! [`VoiceChatCryptoEngine`]. Callers pass public bundles / initiation
//! packets and receive opaque engine handles plus public data.
//!
//! Gate: enable for production only after the full desktop test suite passes.

use std::collections::HashMap;
use std::slice;
use std::sync::{Mutex, OnceLock};

use crate::engine::{
    CryptoEngineApi, CryptoError, DeviceConfig, InitiationPacket, SealedMessage, SessionId,
    VoiceChatCryptoEngine,
};
use crate::fingerprint::{compute_fingerprint, IdentityMaterial};
use crate::policy::CryptoProfile;
use crate::prekeys::PublicPrekeyBundle;
use crate::primitives::x25519::X25519Public;

/// Opaque handle type visible to foreign code (non-zero on success).
pub type VcHandle = u64;

/// Error codes returned across the FFI (stable ABI).
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcError {
    Ok = 0,
    InvalidArgument = 1,
    CryptoFailure = 2,
    StateError = 3,
    NotFound = 4,
    IdentityChanged = 5,
    LimitExceeded = 6,
    Internal = 99,
}

impl From<CryptoError> for VcError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::InvalidArgument => VcError::InvalidArgument,
            CryptoError::CryptoFailure => VcError::CryptoFailure,
            CryptoError::NoSession | CryptoError::Replay => VcError::StateError,
            CryptoError::IdentityChanged => VcError::IdentityChanged,
            CryptoError::LimitExceeded => VcError::LimitExceeded,
            CryptoError::VoiceProfileForbidden => VcError::InvalidArgument,
            CryptoError::Storage | CryptoError::Internal => VcError::Internal,
        }
    }
}

struct Registry {
    next: u64,
    engines: HashMap<VcHandle, VoiceChatCryptoEngine>,
}

impl Registry {
    fn new() -> Self {
        Self {
            next: 1,
            engines: HashMap::new(),
        }
    }

    fn alloc(&mut self) -> Result<VcHandle, VcError> {
        let h = self.next;
        self.next = self.next.checked_add(1).ok_or(VcError::LimitExceeded)?;
        Ok(h)
    }
}

fn registry() -> &'static Mutex<Registry> {
    static REG: OnceLock<Mutex<Registry>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(Registry::new()))
}

/// Conservative encoded sizes so a size query never commits crypto state.
const BUNDLE_BOUND: usize = 4096;
fn packet_bound(pt_len: usize) -> Result<usize, VcError> {
    8192usize.checked_add(pt_len).ok_or(VcError::LimitExceeded)
}
fn sealed_bound(pt_len: usize) -> Result<usize, VcError> {
    4096usize.checked_add(pt_len).ok_or(VcError::LimitExceeded)
}

fn copy_out(src: &[u8], dst: *mut u8, dst_len: *mut usize) -> i32 {
    if dst_len.is_null() {
        return VcError::InvalidArgument as i32;
    }
    if dst.is_null() || unsafe { *dst_len } < src.len() {
        unsafe {
            *dst_len = src.len();
        }
        return VcError::InvalidArgument as i32;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        *dst_len = src.len();
    }
    VcError::Ok as i32
}

/// Size query with a conservative bound. Returns true if the caller should
/// stop (no crypto). Never used after a mutating engine call.
unsafe fn need_buffer(dst: *mut u8, dst_len: *mut usize, bound: usize) -> bool {
    if dst_len.is_null() {
        return true;
    }
    if dst.is_null() || *dst_len < bound {
        *dst_len = bound;
        return true;
    }
    false
}

fn read_bytes(ptr: *const u8, len: usize) -> Result<&'static [u8], VcError> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(&[]);
        }
        return Err(VcError::InvalidArgument);
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Create a device engine (identity + prekeys). Writes 32-byte public identity.
///
/// # Safety
/// `out_handle` must be valid. `out_public` may be null or point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn vc_engine_create(
    device_id: *const u8,
    device_id_len: usize,
    profile: u8,
    out_handle: *mut VcHandle,
    out_public: *mut u8,
) -> i32 {
    if out_handle.is_null() {
        return VcError::InvalidArgument as i32;
    }
    let profile = match CryptoProfile::from_u8(profile) {
        Ok(p) => p,
        Err(_) => return VcError::InvalidArgument as i32,
    };
    let dev_id = match read_bytes(device_id, device_id_len) {
        Ok(b) => b.to_vec(),
        Err(e) => return e as i32,
    };
    let engine = match VoiceChatCryptoEngine::initialize_device(DeviceConfig {
        device_id: dev_id,
        profile,
    }) {
        Ok(e) => e,
        Err(e) => return VcError::from(e) as i32,
    };
    if !out_public.is_null() {
        let pk = engine.local_identity_public();
        std::ptr::copy_nonoverlapping(pk.as_ptr(), out_public, 32);
    }
    let mut reg = match registry().lock() {
        Ok(g) => g,
        Err(_) => return VcError::Internal as i32,
    };
    let h = match reg.alloc() {
        Ok(h) => h,
        Err(e) => return e as i32,
    };
    reg.engines.insert(h, engine);
    *out_handle = h;
    VcError::Ok as i32
}

/// Alias for [`vc_engine_create`] with classical profile.
#[no_mangle]
pub unsafe extern "C" fn vc_create_device_identity(
    device_id: *const u8,
    device_id_len: usize,
    out_handle: *mut VcHandle,
    out_public: *mut u8,
) -> i32 {
    vc_engine_create(device_id, device_id_len, 1, out_handle, out_public)
}

/// Destroy an engine and zeroize its secrets (via Drop).
#[no_mangle]
pub unsafe extern "C" fn vc_engine_destroy(engine: VcHandle) -> i32 {
    let mut reg = match registry().lock() {
        Ok(g) => g,
        Err(_) => return VcError::Internal as i32,
    };
    match reg.engines.remove(&engine) {
        Some(_) => VcError::Ok as i32,
        None => VcError::NotFound as i32,
    }
}

/// Alias for [`vc_engine_destroy`].
#[no_mangle]
pub unsafe extern "C" fn vc_delete_identity(identity: VcHandle) -> i32 {
    vc_engine_destroy(identity)
}

/// Write the 32-byte local identity public key.
#[no_mangle]
pub unsafe extern "C" fn vc_engine_public_identity(engine: VcHandle, out_public: *mut u8) -> i32 {
    if out_public.is_null() {
        return VcError::InvalidArgument as i32;
    }
    let reg = match registry().lock() {
        Ok(g) => g,
        Err(_) => return VcError::Internal as i32,
    };
    let eng = match reg.engines.get(&engine) {
        Some(e) => e,
        None => return VcError::NotFound as i32,
    };
    let pk = eng.local_identity_public();
    std::ptr::copy_nonoverlapping(pk.as_ptr(), out_public, 32);
    VcError::Ok as i32
}

/// Publish a public prekey bundle (no secrets).
#[no_mangle]
pub unsafe extern "C" fn vc_generate_bundle(
    engine: VcHandle,
    one_time_count: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let mut reg = match registry().lock() {
        Ok(g) => g,
        Err(_) => return VcError::Internal as i32,
    };
    let eng = match reg.engines.get_mut(&engine) {
        Some(e) => e,
        None => return VcError::NotFound as i32,
    };
    if need_buffer(out, out_len, BUNDLE_BOUND) {
        return VcError::InvalidArgument as i32;
    }
    let bundle = match eng.generate_public_prekey_bundle(one_time_count) {
        Ok(b) => b,
        Err(e) => return VcError::from(e) as i32,
    };
    copy_out(&bundle.encode(), out, out_len)
}

/// Alice: PQXDH + first ratchet ciphertext. Returns session id (16) + packet.
///
/// Secrets never leave the engine.
#[no_mangle]
pub unsafe extern "C" fn vc_establish_outbound(
    engine: VcHandle,
    bundle: *const u8,
    bundle_len: usize,
    conversation: *const u8,
    conversation_len: usize,
    first_pt: *const u8,
    first_pt_len: usize,
    ad: *const u8,
    ad_len: usize,
    out_session: *mut u8,
    out_packet: *mut u8,
    out_packet_len: *mut usize,
) -> i32 {
    if out_session.is_null() {
        return VcError::InvalidArgument as i32;
    }
    let bundle_bytes = match read_bytes(bundle, bundle_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    let conv = match read_bytes(conversation, conversation_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    let pt = match read_bytes(first_pt, first_pt_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    let aad = match read_bytes(ad, ad_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    let bound = match packet_bound(first_pt_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    if need_buffer(out_packet, out_packet_len, bound) {
        return VcError::InvalidArgument as i32;
    }
    let parsed = match PublicPrekeyBundle::decode(bundle_bytes) {
        Ok(b) => b,
        Err(_) => return VcError::CryptoFailure as i32,
    };
    let mut reg = match registry().lock() {
        Ok(g) => g,
        Err(_) => return VcError::Internal as i32,
    };
    let eng = match reg.engines.get_mut(&engine) {
        Some(e) => e,
        None => return VcError::NotFound as i32,
    };
    let (sid, packet) = match eng.establish_outbound_session(&parsed, conv, pt, aad) {
        Ok(v) => v,
        Err(e) => return VcError::from(e) as i32,
    };
    let encoded = packet.encode();
    if encoded.len() > *out_packet_len {
        *out_packet_len = encoded.len();
        return VcError::Internal as i32;
    }
    std::ptr::copy_nonoverlapping(sid.0.as_ptr(), out_session, 16);
    std::ptr::copy_nonoverlapping(encoded.as_ptr(), out_packet, encoded.len());
    *out_packet_len = encoded.len();
    VcError::Ok as i32
}

/// Bob: consume initiation packet. Returns session id (16) + first plaintext.
#[no_mangle]
pub unsafe extern "C" fn vc_process_inbound(
    engine: VcHandle,
    packet: *const u8,
    packet_len: usize,
    conversation: *const u8,
    conversation_len: usize,
    ad: *const u8,
    ad_len: usize,
    out_session: *mut u8,
    out_pt: *mut u8,
    out_pt_len: *mut usize,
) -> i32 {
    if out_session.is_null() {
        return VcError::InvalidArgument as i32;
    }
    let pkt_bytes = match read_bytes(packet, packet_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    let conv = match read_bytes(conversation, conversation_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    let aad = match read_bytes(ad, ad_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    if need_buffer(out_pt, out_pt_len, 4096) {
        return VcError::InvalidArgument as i32;
    }
    let parsed = match InitiationPacket::decode(pkt_bytes) {
        Ok(p) => p,
        Err(e) => return VcError::from(e) as i32,
    };
    let mut reg = match registry().lock() {
        Ok(g) => g,
        Err(_) => return VcError::Internal as i32,
    };
    let eng = match reg.engines.get_mut(&engine) {
        Some(e) => e,
        None => return VcError::NotFound as i32,
    };
    let (sid, pt) = match eng.process_inbound_session(&parsed, conv, aad) {
        Ok(v) => v,
        Err(e) => return VcError::from(e) as i32,
    };
    if pt.len() > *out_pt_len {
        *out_pt_len = pt.len();
        return VcError::Internal as i32;
    }
    std::ptr::copy_nonoverlapping(sid.0.as_ptr(), out_session, 16);
    std::ptr::copy_nonoverlapping(pt.as_ptr(), out_pt, pt.len());
    *out_pt_len = pt.len();
    VcError::Ok as i32
}

/// Encrypt. Output is a sealed-message blob (no secrets).
#[no_mangle]
pub unsafe extern "C" fn vc_encrypt(
    engine: VcHandle,
    session_id: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    ad: *const u8,
    ad_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if session_id.is_null() {
        return VcError::InvalidArgument as i32;
    }
    let mut sid = [0u8; 16];
    std::ptr::copy_nonoverlapping(session_id, sid.as_mut_ptr(), 16);
    let pt = match read_bytes(plaintext, plaintext_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    let aad = match read_bytes(ad, ad_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    let bound = match sealed_bound(plaintext_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    if need_buffer(out, out_len, bound) {
        return VcError::InvalidArgument as i32;
    }
    let mut reg = match registry().lock() {
        Ok(g) => g,
        Err(_) => return VcError::Internal as i32,
    };
    let eng = match reg.engines.get_mut(&engine) {
        Some(e) => e,
        None => return VcError::NotFound as i32,
    };
    let sealed = match eng.encrypt(&SessionId(sid), pt, aad) {
        Ok(s) => s,
        Err(e) => return VcError::from(e) as i32,
    };
    copy_out(&sealed.encode(), out, out_len)
}

/// Decrypt a sealed-message blob. State is unchanged on auth failure.
#[no_mangle]
pub unsafe extern "C" fn vc_decrypt(
    engine: VcHandle,
    session_id: *const u8,
    sealed: *const u8,
    sealed_len: usize,
    ad: *const u8,
    ad_len: usize,
    out_pt: *mut u8,
    out_pt_len: *mut usize,
) -> i32 {
    if session_id.is_null() {
        return VcError::InvalidArgument as i32;
    }
    let mut sid = [0u8; 16];
    std::ptr::copy_nonoverlapping(session_id, sid.as_mut_ptr(), 16);
    let blob = match read_bytes(sealed, sealed_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    let aad = match read_bytes(ad, ad_len) {
        Ok(b) => b,
        Err(e) => return e as i32,
    };
    if need_buffer(out_pt, out_pt_len, 4096) {
        return VcError::InvalidArgument as i32;
    }
    let parsed = match SealedMessage::decode(blob) {
        Ok(s) => s,
        Err(e) => return VcError::from(e) as i32,
    };
    let mut reg = match registry().lock() {
        Ok(g) => g,
        Err(_) => return VcError::Internal as i32,
    };
    let eng = match reg.engines.get_mut(&engine) {
        Some(e) => e,
        None => return VcError::NotFound as i32,
    };
    let pt = match eng.decrypt(&SessionId(sid), &parsed, aad) {
        Ok(p) => p,
        Err(e) => return VcError::from(e) as i32,
    };
    copy_out(&pt, out_pt, out_pt_len)
}

/// Compute safety fingerprint for two public identity keys (32 bytes each).
#[no_mangle]
pub unsafe extern "C" fn vc_fingerprint(
    public_a: *const u8,
    public_b: *const u8,
    device_a: *const u8,
    device_a_len: usize,
    device_b: *const u8,
    device_b_len: usize,
    out_binary: *mut u8,
    out_numeric: *mut u8,
    out_numeric_len: *mut usize,
) -> i32 {
    if public_a.is_null() || public_b.is_null() || out_binary.is_null() {
        return VcError::InvalidArgument as i32;
    }
    let mut pa = [0u8; 32];
    let mut pb = [0u8; 32];
    std::ptr::copy_nonoverlapping(public_a, pa.as_mut_ptr(), 32);
    std::ptr::copy_nonoverlapping(public_b, pb.as_mut_ptr(), 32);
    let a = match X25519Public::from_bytes(pa) {
        Ok(p) => p,
        Err(_) => return VcError::CryptoFailure as i32,
    };
    let b = match X25519Public::from_bytes(pb) {
        Ok(p) => p,
        Err(_) => return VcError::CryptoFailure as i32,
    };
    let da = if device_a.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(device_a, device_a_len).to_vec())
    };
    let db = if device_b.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(device_b, device_b_len).to_vec())
    };
    let fp = match compute_fingerprint(
        &IdentityMaterial {
            identity_key: a,
            device_id: da,
        },
        &IdentityMaterial {
            identity_key: b,
            device_id: db,
        },
    ) {
        Ok(f) => f,
        Err(_) => return VcError::CryptoFailure as i32,
    };
    std::ptr::copy_nonoverlapping(fp.binary.as_ptr(), out_binary, 32);
    if !out_numeric.is_null() && !out_numeric_len.is_null() {
        let digits = fp.numeric.as_bytes();
        if *out_numeric_len < digits.len() {
            *out_numeric_len = digits.len();
            return VcError::InvalidArgument as i32;
        }
        std::ptr::copy_nonoverlapping(digits.as_ptr(), out_numeric, digits.len());
        *out_numeric_len = digits.len();
    }
    VcError::Ok as i32
}

/// Delete one session inside an engine.
#[no_mangle]
pub unsafe extern "C" fn vc_delete_session(engine: VcHandle, session_id: *const u8) -> i32 {
    if session_id.is_null() {
        return VcError::InvalidArgument as i32;
    }
    let mut sid = [0u8; 16];
    std::ptr::copy_nonoverlapping(session_id, sid.as_mut_ptr(), 16);
    let mut reg = match registry().lock() {
        Ok(g) => g,
        Err(_) => return VcError::Internal as i32,
    };
    let eng = match reg.engines.get_mut(&engine) {
        Some(e) => e,
        None => return VcError::NotFound as i32,
    };
    match eng.delete_session(&SessionId(sid)) {
        Ok(()) => VcError::Ok as i32,
        Err(e) => VcError::from(e) as i32,
    }
}

/// Protocol version constant for interoperability checks.
#[no_mangle]
pub extern "C" fn vc_protocol_version() -> u16 {
    crate::policy::PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn create_engine(id: &[u8]) -> (VcHandle, [u8; 32]) {
        let mut h = 0u64;
        let mut pk = [0u8; 32];
        assert_eq!(
            vc_engine_create(id.as_ptr(), id.len(), 1, &mut h, pk.as_mut_ptr()),
            0
        );
        assert_ne!(h, 0);
        assert_ne!(pk, [0u8; 32]);
        (h, pk)
    }

    unsafe fn size_query_then_copy(f: impl Fn(*mut u8, *mut usize) -> i32) -> Vec<u8> {
        let mut n = 0usize;
        assert_eq!(
            f(std::ptr::null_mut(), &mut n),
            VcError::InvalidArgument as i32
        );
        assert!(n > 0);
        let mut buf = vec![0u8; n];
        assert_eq!(f(buf.as_mut_ptr(), &mut n), 0);
        buf.truncate(n);
        buf
    }

    #[test]
    fn protocol_version_nonzero() {
        assert_eq!(vc_protocol_version(), crate::policy::PROTOCOL_VERSION);
    }

    #[test]
    fn alice_bob_ffi_pqxdh_no_secrets_cross() {
        unsafe {
            let (h_alice, alice_pk) = create_engine(b"alice");
            let (h_bob, bob_pk) = create_engine(b"bob");

            let bundle = size_query_then_copy(|out, n| vc_generate_bundle(h_bob, 2, out, n));

            let conv = b"conv";
            let ad = b"ad";
            let first = b"A1";
            let mut sid_a = [0u8; 16];
            let packet = {
                let mut n = 0usize;
                assert_eq!(
                    vc_establish_outbound(
                        h_alice,
                        bundle.as_ptr(),
                        bundle.len(),
                        conv.as_ptr(),
                        conv.len(),
                        first.as_ptr(),
                        first.len(),
                        ad.as_ptr(),
                        ad.len(),
                        sid_a.as_mut_ptr(),
                        std::ptr::null_mut(),
                        &mut n,
                    ),
                    VcError::InvalidArgument as i32
                );
                let mut pkt = vec![0u8; n];
                assert_eq!(
                    vc_establish_outbound(
                        h_alice,
                        bundle.as_ptr(),
                        bundle.len(),
                        conv.as_ptr(),
                        conv.len(),
                        first.as_ptr(),
                        first.len(),
                        ad.as_ptr(),
                        ad.len(),
                        sid_a.as_mut_ptr(),
                        pkt.as_mut_ptr(),
                        &mut n,
                    ),
                    0
                );
                pkt.truncate(n);
                pkt
            };
            assert_ne!(sid_a, [0u8; 16]);

            let mut sid_b = [0u8; 16];
            let mut pt_len = 0usize;
            assert_eq!(
                vc_process_inbound(
                    h_bob,
                    packet.as_ptr(),
                    packet.len(),
                    conv.as_ptr(),
                    conv.len(),
                    ad.as_ptr(),
                    ad.len(),
                    sid_b.as_mut_ptr(),
                    std::ptr::null_mut(),
                    &mut pt_len,
                ),
                VcError::InvalidArgument as i32
            );
            let mut pt = vec![0u8; pt_len];
            assert_eq!(
                vc_process_inbound(
                    h_bob,
                    packet.as_ptr(),
                    packet.len(),
                    conv.as_ptr(),
                    conv.len(),
                    ad.as_ptr(),
                    ad.len(),
                    sid_b.as_mut_ptr(),
                    pt.as_mut_ptr(),
                    &mut pt_len,
                ),
                0
            );
            assert_eq!(&pt[..pt_len], b"A1");

            let sealed = size_query_then_copy(|out, n| {
                vc_encrypt(
                    h_bob,
                    sid_b.as_ptr(),
                    b"B1".as_ptr(),
                    2,
                    ad.as_ptr(),
                    ad.len(),
                    out,
                    n,
                )
            });
            let mut out_len = 0usize;
            assert_eq!(
                vc_decrypt(
                    h_alice,
                    sid_a.as_ptr(),
                    sealed.as_ptr(),
                    sealed.len(),
                    ad.as_ptr(),
                    ad.len(),
                    std::ptr::null_mut(),
                    &mut out_len,
                ),
                VcError::InvalidArgument as i32
            );
            let mut out = vec![0u8; out_len];
            assert_eq!(
                vc_decrypt(
                    h_alice,
                    sid_a.as_ptr(),
                    sealed.as_ptr(),
                    sealed.len(),
                    ad.as_ptr(),
                    ad.len(),
                    out.as_mut_ptr(),
                    &mut out_len,
                ),
                0
            );
            assert_eq!(&out[..out_len], b"B1");

            let mut bin = [0u8; 32];
            let mut num = [0u8; 64];
            let mut nlen = 64usize;
            assert_eq!(
                vc_fingerprint(
                    alice_pk.as_ptr(),
                    bob_pk.as_ptr(),
                    b"alice".as_ptr(),
                    5,
                    b"bob".as_ptr(),
                    3,
                    bin.as_mut_ptr(),
                    num.as_mut_ptr(),
                    &mut nlen,
                ),
                0
            );
            assert_ne!(bin, [0u8; 32]);
            assert_eq!(nlen, 60);

            assert_eq!(vc_delete_session(h_alice, sid_a.as_ptr()), 0);
            assert_eq!(vc_engine_destroy(h_alice), 0);
            assert_eq!(vc_engine_destroy(h_bob), 0);
        }
    }

    #[test]
    fn identity_session_encrypt_decrypt_delete() {
        // Same path as interop; kept so existing suite names still exist.
        alice_bob_ffi_pqxdh_no_secrets_cross();
    }

    #[test]
    fn alice_bob_ffi_encrypt_decrypt_interop() {
        alice_bob_ffi_pqxdh_no_secrets_cross();
    }
}

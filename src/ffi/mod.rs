#![allow(unsafe_code, dead_code, clippy::missing_safety_doc)]

//! Stable C ABI for Android (Kotlin) and iOS (Swift).
//!
//! Foreign memory is copied into bounded owned Rust buffers before parsing;
//! no borrowed raw-pointer slice is ever assigned a fabricated `'static`
//! lifetime. Every fallible ABI entry point catches Rust panics.
//!
//! The engine itself is internally concurrent. The FFI registry therefore does
//! not wrap the entire engine in a mutex: a per-handle lifecycle RwLock only
//! coordinates terminal destroy against in-flight calls, while the Rust engine
//! serializes same-session work and permits different sessions to run in
//! parallel.
//!
//! `vc_engine_create` remains a **development** constructor using in-memory
//! storage: nothing it produces survives process exit. Production integration
//! must use [`vc_engine_open_persistent`], which binds `EncryptedFileStorage`
//! to a caller-supplied rollback-resistant anchor.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use crate::engine::{
    CryptoEngineApi, CryptoError, DeviceConfig, InitiationPacket, SealedMessage, SessionId,
    VoiceChatCryptoEngine,
};
use crate::fingerprint::{compute_fingerprint, IdentityMaterial};
use crate::policy::CryptoProfile;
use crate::prekeys::PublicPrekeyBundle;
use crate::primitives::error::PrimitiveError;
use crate::primitives::x25519::X25519Public;
use crate::storage::coordinated::{
    coordinated_backends_for_initialize, coordinated_backends_for_restore, RestoreRejection,
};
use crate::storage::encrypted_file::EncryptedFileStorage;
use crate::storage::trusted_anchor::RollbackAnchor;
use zeroize::Zeroize;

#[cfg(feature = "android")]
pub mod jni;

pub type VcHandle = u64;

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
    /// Persisted state is authentic but older than the rollback anchor. The
    /// local database was restored from a backup or otherwise reverted.
    ///
    /// **Terminal.** Never retry, never fall back to a fresh-device
    /// constructor, and never resolve this silently — see
    /// [`vc_engine_open_persistent`].
    RollbackDetected = 7,
    /// Persisted state is missing or unreadable while the anchor shows the
    /// device was previously provisioned. Also terminal.
    StateLost = 8,
    /// The supplied rollback anchor could not be read or advanced.
    AnchorUnavailable = 9,
    /// No persisted state and a pristine anchor: this device was never set up.
    /// The only non-terminal open failure. Call the initializing constructor.
    NotInitialized = 10,
    Internal = 99,
}

impl From<RestoreRejection> for VcError {
    fn from(value: RestoreRejection) -> Self {
        match value {
            RestoreRejection::RollbackDetected { .. } | RestoreRejection::EpochGap { .. } => {
                VcError::RollbackDetected
            }
            RestoreRejection::LocalStateMissing { .. } | RestoreRejection::EpochRecordCorrupt => {
                VcError::StateLost
            }
            RestoreRejection::NotInitialized => VcError::NotInitialized,
            RestoreRejection::AnchorUnavailable
            | RestoreRejection::AnchorReconciliationFailed { .. } => VcError::AnchorUnavailable,
        }
    }
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

struct EngineSlot {
    closed: AtomicBool,
    calls: RwLock<()>,
    engine: VoiceChatCryptoEngine,
}

impl EngineSlot {
    fn new(engine: VoiceChatCryptoEngine) -> Self {
        Self {
            closed: AtomicBool::new(false),
            calls: RwLock::new(()),
            engine,
        }
    }
}

type SharedEngine = Arc<EngineSlot>;

struct Registry {
    next: u64,
    engines: HashMap<VcHandle, SharedEngine>,
}

impl Registry {
    fn new() -> Self {
        Self {
            next: 1,
            engines: HashMap::new(),
        }
    }

    fn alloc(&mut self) -> Result<VcHandle, VcError> {
        let handle = self.next;
        self.next = self.next.checked_add(1).ok_or(VcError::LimitExceeded)?;
        Ok(handle)
    }
}

fn registry() -> &'static Mutex<Registry> {
    static REG: OnceLock<Mutex<Registry>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(Registry::new()))
}

fn engine_for(handle: VcHandle) -> Result<SharedEngine, VcError> {
    let reg = registry().lock().map_err(|_| VcError::Internal)?;
    reg.engines.get(&handle).cloned().ok_or(VcError::NotFound)
}

fn with_engine<R>(
    handle: VcHandle,
    f: impl FnOnce(&VoiceChatCryptoEngine) -> Result<R, VcError>,
) -> Result<R, VcError> {
    let slot = engine_for(handle)?;
    if slot.closed.load(Ordering::Acquire) {
        return Err(VcError::NotFound);
    }
    let _call = slot.calls.read().map_err(|_| VcError::Internal)?;
    if slot.closed.load(Ordering::Acquire) {
        return Err(VcError::NotFound);
    }
    f(&slot.engine)
}

fn ffi_guard(f: impl FnOnce() -> i32) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => VcError::Internal as i32,
    }
}

const BUNDLE_BOUND: usize = 4096;
const MAX_FFI_DEVICE_ID: usize = 4 * 1024;
const MAX_FFI_PEER_ID: usize = 4 * 1024;
const MAX_FFI_CONVERSATION: usize = 64 * 1024;
const MAX_FFI_AD: usize = 1024 * 1024;
const MAX_FFI_MESSAGE: usize = 64 * 1024 * 1024;
const MAX_FFI_PACKET: usize = MAX_FFI_MESSAGE + 128 * 1024;

fn packet_bound(pt_len: usize) -> Result<usize, VcError> {
    128usize
        .checked_mul(1024)
        .and_then(|n| n.checked_add(pt_len))
        .filter(|n| *n <= MAX_FFI_PACKET)
        .ok_or(VcError::LimitExceeded)
}

fn sealed_bound(pt_len: usize) -> Result<usize, VcError> {
    64usize
        .checked_mul(1024)
        .and_then(|n| n.checked_add(pt_len))
        .filter(|n| *n <= MAX_FFI_PACKET)
        .ok_or(VcError::LimitExceeded)
}

fn read_owned(ptr: *const u8, len: usize, max: usize) -> Result<Vec<u8>, VcError> {
    if len > max {
        return Err(VcError::LimitExceeded);
    }
    if ptr.is_null() {
        return if len == 0 {
            Ok(Vec::new())
        } else {
            Err(VcError::InvalidArgument)
        };
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) }.to_vec())
}

fn read_sid(ptr: *const u8) -> Result<SessionId, VcError> {
    if ptr.is_null() {
        return Err(VcError::InvalidArgument);
    }
    let mut sid = [0u8; 16];
    unsafe { std::ptr::copy_nonoverlapping(ptr, sid.as_mut_ptr(), 16) };
    if sid == [0u8; 16] {
        return Err(VcError::InvalidArgument);
    }
    Ok(SessionId(sid))
}

fn reserve_output(dst: *mut u8, dst_len: *mut usize, bound: usize) -> Result<bool, VcError> {
    if dst_len.is_null() {
        return Err(VcError::InvalidArgument);
    }
    if dst.is_null() || unsafe { *dst_len } < bound {
        unsafe { *dst_len = bound };
        return Ok(false);
    }
    Ok(true)
}

fn copy_out(src: &[u8], dst: *mut u8, dst_len: *mut usize) -> i32 {
    if dst_len.is_null() {
        return VcError::InvalidArgument as i32;
    }
    if dst.is_null() || unsafe { *dst_len } < src.len() {
        unsafe { *dst_len = src.len() };
        return VcError::InvalidArgument as i32;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        *dst_len = src.len();
    }
    VcError::Ok as i32
}

fn result_code(result: Result<(), VcError>) -> i32 {
    match result {
        Ok(()) => VcError::Ok as i32,
        Err(e) => e as i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn vc_engine_create(
    device_id: *const u8,
    device_id_len: usize,
    profile: u8,
    out_handle: *mut VcHandle,
    out_public: *mut u8,
) -> i32 {
    ffi_guard(|| {
        if out_handle.is_null() {
            return VcError::InvalidArgument as i32;
        }
        let profile = match CryptoProfile::from_u8(profile) {
            Ok(p) => p,
            Err(_) => return VcError::InvalidArgument as i32,
        };
        let dev_id = match read_owned(device_id, device_id_len, MAX_FFI_DEVICE_ID) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => return VcError::InvalidArgument as i32,
            Err(e) => return e as i32,
        };
        let engine = match VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: dev_id,
            profile,
        }) {
            Ok(v) => v,
            Err(e) => return VcError::from(e) as i32,
        };
        let pk = engine.local_identity_public();
        let shared = Arc::new(EngineSlot::new(engine));
        let handle = {
            let mut reg = match registry().lock() {
                Ok(v) => v,
                Err(_) => return VcError::Internal as i32,
            };
            let handle = match reg.alloc() {
                Ok(v) => v,
                Err(e) => return e as i32,
            };
            reg.engines.insert(handle, shared);
            handle
        };
        if !out_public.is_null() {
            unsafe { std::ptr::copy_nonoverlapping(pk.as_ptr(), out_public, 32) };
        }
        unsafe { *out_handle = handle };
        VcError::Ok as i32
    })
}

#[no_mangle]
pub unsafe extern "C" fn vc_create_device_identity(
    device_id: *const u8,
    device_id_len: usize,
    out_handle: *mut VcHandle,
    out_public: *mut u8,
) -> i32 {
    vc_engine_create(device_id, device_id_len, 1, out_handle, out_public)
}

#[no_mangle]
pub unsafe extern "C" fn vc_engine_destroy(engine: VcHandle) -> i32 {
    ffi_guard(|| {
        let slot = {
            let mut reg = match registry().lock() {
                Ok(v) => v,
                Err(_) => return VcError::Internal as i32,
            };
            let Some(slot) = reg.engines.remove(&engine) else {
                return VcError::NotFound as i32;
            };
            slot.closed.store(true, Ordering::Release);
            slot
        };

        // A write guard waits for all older read guards. Once acquired, every
        // call that entered before close has returned and no queued call can
        // start because it will observe `closed` on its second check.
        match slot.calls.write() {
            Ok(guard) => drop(guard),
            Err(_) => return VcError::Internal as i32,
        }
        VcError::Ok as i32
    })
}

#[no_mangle]
pub unsafe extern "C" fn vc_delete_identity(identity: VcHandle) -> i32 {
    vc_engine_destroy(identity)
}

#[no_mangle]
pub unsafe extern "C" fn vc_engine_public_identity(engine: VcHandle, out_public: *mut u8) -> i32 {
    ffi_guard(|| {
        if out_public.is_null() {
            return VcError::InvalidArgument as i32;
        }
        match with_engine(engine, |eng| Ok(eng.local_identity_public())) {
            Ok(pk) => {
                unsafe { std::ptr::copy_nonoverlapping(pk.as_ptr(), out_public, 32) };
                VcError::Ok as i32
            }
            Err(e) => e as i32,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn vc_generate_bundle(
    engine: VcHandle,
    one_time_count: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard(|| {
        match reserve_output(out, out_len, BUNDLE_BOUND) {
            Ok(true) => {}
            Ok(false) => return VcError::InvalidArgument as i32,
            Err(e) => return e as i32,
        }
        let encoded = match with_engine(engine, |eng| {
            eng.generate_public_prekey_bundle(one_time_count)
                .map(|b| b.encode())
                .map_err(VcError::from)
        }) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        copy_out(&encoded, out, out_len)
    })
}

// This helper mirrors a C ABI pointer/length surface; keeping the pairs explicit
// makes validation auditable and avoids a second representation at the FFI boundary.
#[allow(clippy::too_many_arguments)]
fn establish_outbound_inner(
    engine: VcHandle,
    peer: Option<(Vec<u8>, Option<Vec<u8>>)>,
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
    let bound = match packet_bound(first_pt_len) {
        Ok(v) => v,
        Err(e) => return e as i32,
    };
    match reserve_output(out_packet, out_packet_len, bound) {
        Ok(true) => {}
        Ok(false) => return VcError::InvalidArgument as i32,
        Err(e) => return e as i32,
    }
    let bundle = match read_owned(bundle, bundle_len, BUNDLE_BOUND) {
        Ok(v) => match PublicPrekeyBundle::decode(&v) {
            Ok(b) => b,
            Err(_) => return VcError::CryptoFailure as i32,
        },
        Err(e) => return e as i32,
    };
    let conversation = match read_owned(conversation, conversation_len, MAX_FFI_CONVERSATION) {
        Ok(v) => v,
        Err(e) => return e as i32,
    };
    let first_pt = match read_owned(first_pt, first_pt_len, MAX_FFI_MESSAGE) {
        Ok(v) => v,
        Err(e) => return e as i32,
    };
    let ad = match read_owned(ad, ad_len, MAX_FFI_AD) {
        Ok(v) => v,
        Err(e) => return e as i32,
    };

    let result = with_engine(engine, |eng| {
        let value = match &peer {
            Some((peer_id, remote_device)) => eng.establish_outbound_session_for_peer(
                peer_id,
                remote_device.as_deref(),
                &bundle,
                &conversation,
                &first_pt,
                &ad,
            ),
            None => eng.establish_outbound_session(&bundle, &conversation, &first_pt, &ad),
        };
        value.map_err(VcError::from)
    });
    let (sid, packet) = match result {
        Ok(v) => v,
        Err(e) => return e as i32,
    };
    let encoded = packet.encode();
    if out_packet_len.is_null() || encoded.len() > unsafe { *out_packet_len } {
        return VcError::Internal as i32;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(sid.0.as_ptr(), out_session, 16);
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), out_packet, encoded.len());
        *out_packet_len = encoded.len();
    }
    VcError::Ok as i32
}

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
    ffi_guard(|| {
        establish_outbound_inner(
            engine,
            None,
            bundle,
            bundle_len,
            conversation,
            conversation_len,
            first_pt,
            first_pt_len,
            ad,
            ad_len,
            out_session,
            out_packet,
            out_packet_len,
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn vc_establish_outbound_for_peer(
    engine: VcHandle,
    peer_id: *const u8,
    peer_id_len: usize,
    remote_device: *const u8,
    remote_device_len: usize,
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
    ffi_guard(|| {
        let peer_id = match read_owned(peer_id, peer_id_len, MAX_FFI_PEER_ID) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => return VcError::InvalidArgument as i32,
            Err(e) => return e as i32,
        };
        let remote_device = if remote_device.is_null() {
            None
        } else {
            match read_owned(remote_device, remote_device_len, MAX_FFI_DEVICE_ID) {
                Ok(v) => Some(v),
                Err(e) => return e as i32,
            }
        };
        establish_outbound_inner(
            engine,
            Some((peer_id, remote_device)),
            bundle,
            bundle_len,
            conversation,
            conversation_len,
            first_pt,
            first_pt_len,
            ad,
            ad_len,
            out_session,
            out_packet,
            out_packet_len,
        )
    })
}

// This helper mirrors a C ABI pointer/length surface; keeping the pairs explicit
// makes validation auditable and avoids a second representation at the FFI boundary.
#[allow(clippy::too_many_arguments)]
fn process_inbound_inner(
    engine: VcHandle,
    peer: Option<(Vec<u8>, Option<Vec<u8>>)>,
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
    let packet = match read_owned(packet, packet_len, MAX_FFI_PACKET) {
        Ok(v) => match InitiationPacket::decode(&v) {
            Ok(p) => p,
            Err(e) => return VcError::from(e) as i32,
        },
        Err(e) => return e as i32,
    };
    let output_bound = packet.first_message.ciphertext.len();
    match reserve_output(out_pt, out_pt_len, output_bound) {
        Ok(true) => {}
        Ok(false) => return VcError::InvalidArgument as i32,
        Err(e) => return e as i32,
    }
    let conversation = match read_owned(conversation, conversation_len, MAX_FFI_CONVERSATION) {
        Ok(v) => v,
        Err(e) => return e as i32,
    };
    let ad = match read_owned(ad, ad_len, MAX_FFI_AD) {
        Ok(v) => v,
        Err(e) => return e as i32,
    };
    let result = with_engine(engine, |eng| {
        let value = match &peer {
            Some((peer_id, remote_device)) => eng.process_inbound_session_from_peer(
                peer_id,
                remote_device.as_deref(),
                &packet,
                &conversation,
                &ad,
            ),
            None => eng.process_inbound_session(&packet, &conversation, &ad),
        };
        value.map_err(VcError::from)
    });
    let (sid, pt) = match result {
        Ok(v) => v,
        Err(e) => return e as i32,
    };
    if out_pt_len.is_null() || pt.len() > unsafe { *out_pt_len } {
        return VcError::Internal as i32;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(sid.0.as_ptr(), out_session, 16);
        std::ptr::copy_nonoverlapping(pt.as_ptr(), out_pt, pt.len());
        *out_pt_len = pt.len();
    }
    VcError::Ok as i32
}

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
    ffi_guard(|| {
        process_inbound_inner(
            engine,
            None,
            packet,
            packet_len,
            conversation,
            conversation_len,
            ad,
            ad_len,
            out_session,
            out_pt,
            out_pt_len,
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn vc_process_inbound_from_peer(
    engine: VcHandle,
    peer_id: *const u8,
    peer_id_len: usize,
    remote_device: *const u8,
    remote_device_len: usize,
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
    ffi_guard(|| {
        let peer_id = match read_owned(peer_id, peer_id_len, MAX_FFI_PEER_ID) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => return VcError::InvalidArgument as i32,
            Err(e) => return e as i32,
        };
        let remote_device = if remote_device.is_null() {
            None
        } else {
            match read_owned(remote_device, remote_device_len, MAX_FFI_DEVICE_ID) {
                Ok(v) => Some(v),
                Err(e) => return e as i32,
            }
        };
        process_inbound_inner(
            engine,
            Some((peer_id, remote_device)),
            packet,
            packet_len,
            conversation,
            conversation_len,
            ad,
            ad_len,
            out_session,
            out_pt,
            out_pt_len,
        )
    })
}

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
    ffi_guard(|| {
        let sid = match read_sid(session_id) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        let bound = match sealed_bound(plaintext_len) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        match reserve_output(out, out_len, bound) {
            Ok(true) => {}
            Ok(false) => return VcError::InvalidArgument as i32,
            Err(e) => return e as i32,
        }
        let pt = match read_owned(plaintext, plaintext_len, MAX_FFI_MESSAGE) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        let ad = match read_owned(ad, ad_len, MAX_FFI_AD) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        let sealed = match with_engine(engine, |eng| {
            eng.encrypt(&sid, &pt, &ad).map_err(VcError::from)
        }) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        copy_out(&sealed.encode(), out, out_len)
    })
}

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
    ffi_guard(|| {
        let sid = match read_sid(session_id) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        let sealed = match read_owned(sealed, sealed_len, MAX_FFI_PACKET) {
            Ok(v) => match SealedMessage::decode(&v) {
                Ok(s) => s,
                Err(e) => return VcError::from(e) as i32,
            },
            Err(e) => return e as i32,
        };
        match reserve_output(out_pt, out_pt_len, sealed.ciphertext.len()) {
            Ok(true) => {}
            Ok(false) => return VcError::InvalidArgument as i32,
            Err(e) => return e as i32,
        }
        let ad = match read_owned(ad, ad_len, MAX_FFI_AD) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        let pt = match with_engine(engine, |eng| {
            eng.decrypt(&sid, &sealed, &ad).map_err(VcError::from)
        }) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        copy_out(&pt, out_pt, out_pt_len)
    })
}

#[no_mangle]
pub unsafe extern "C" fn vc_pending_outbound_initiation(
    engine: VcHandle,
    session_id: *const u8,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard(|| {
        let sid = match read_sid(session_id) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        let packet = match with_engine(engine, |eng| {
            eng.pending_outbound_initiation(&sid).map_err(VcError::from)
        }) {
            Ok(Some(v)) => v.encode(),
            Ok(None) => {
                if !out_len.is_null() {
                    unsafe { *out_len = 0 };
                }
                return VcError::NotFound as i32;
            }
            Err(e) => return e as i32,
        };
        copy_out(&packet, out, out_len)
    })
}

#[no_mangle]
pub unsafe extern "C" fn vc_acknowledge_outbound_initiation(
    engine: VcHandle,
    session_id: *const u8,
) -> i32 {
    ffi_guard(|| {
        let sid = match read_sid(session_id) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        result_code(with_engine(engine, |eng| {
            eng.acknowledge_outbound_initiation(&sid)
                .map_err(VcError::from)
        }))
    })
}

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
    ffi_guard(|| {
        if public_a.is_null() || public_b.is_null() || out_binary.is_null() {
            return VcError::InvalidArgument as i32;
        }
        let mut pa = [0u8; 32];
        let mut pb = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(public_a, pa.as_mut_ptr(), 32);
            std::ptr::copy_nonoverlapping(public_b, pb.as_mut_ptr(), 32);
        }
        let a = match X25519Public::from_bytes(pa) {
            Ok(v) => v,
            Err(_) => return VcError::CryptoFailure as i32,
        };
        let b = match X25519Public::from_bytes(pb) {
            Ok(v) => v,
            Err(_) => return VcError::CryptoFailure as i32,
        };
        let da = if device_a.is_null() {
            None
        } else {
            match read_owned(device_a, device_a_len, MAX_FFI_DEVICE_ID) {
                Ok(v) => Some(v),
                Err(e) => return e as i32,
            }
        };
        let db = if device_b.is_null() {
            None
        } else {
            match read_owned(device_b, device_b_len, MAX_FFI_DEVICE_ID) {
                Ok(v) => Some(v),
                Err(e) => return e as i32,
            }
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
            Ok(v) => v,
            Err(_) => return VcError::CryptoFailure as i32,
        };
        unsafe { std::ptr::copy_nonoverlapping(fp.binary.as_ptr(), out_binary, 32) };
        if !out_numeric_len.is_null() {
            let digits = fp.numeric.as_bytes();
            if out_numeric.is_null() || unsafe { *out_numeric_len } < digits.len() {
                unsafe { *out_numeric_len = digits.len() };
                return VcError::InvalidArgument as i32;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(digits.as_ptr(), out_numeric, digits.len());
                *out_numeric_len = digits.len();
            }
        }
        VcError::Ok as i32
    })
}

#[no_mangle]
pub unsafe extern "C" fn vc_delete_session(engine: VcHandle, session_id: *const u8) -> i32 {
    ffi_guard(|| {
        let sid = match read_sid(session_id) {
            Ok(v) => v,
            Err(e) => return e as i32,
        };
        result_code(with_engine(engine, |eng| {
            eng.delete_session(&sid).map_err(VcError::from)
        }))
    })
}

#[no_mangle]
pub extern "C" fn vc_protocol_version() -> u16 {
    crate::policy::PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    unsafe fn create_engine(id: &[u8]) -> (VcHandle, [u8; 32]) {
        let mut handle = 0u64;
        let mut pk = [0u8; 32];
        assert_eq!(
            vc_engine_create(id.as_ptr(), id.len(), 1, &mut handle, pk.as_mut_ptr(),),
            VcError::Ok as i32
        );
        (handle, pk)
    }

    unsafe fn size_query_then_copy(f: impl Fn(*mut u8, *mut usize) -> i32) -> Vec<u8> {
        let mut n = 0usize;
        assert_eq!(
            f(std::ptr::null_mut(), &mut n),
            VcError::InvalidArgument as i32
        );
        assert!(n > 0);
        let mut buf = vec![0u8; n];
        assert_eq!(f(buf.as_mut_ptr(), &mut n), VcError::Ok as i32);
        buf.truncate(n);
        buf
    }

    #[test]
    fn panic_guard_maps_panic_to_internal() {
        let code = ffi_guard(|| panic!("ffi-test-panic"));
        assert_eq!(code, VcError::Internal as i32);
    }

    #[test]
    fn protocol_version_is_v2() {
        assert_eq!(vc_protocol_version(), 2);
    }

    #[test]
    fn alice_bob_ffi_interop_and_pending_retry() {
        unsafe {
            let (alice, alice_pk) = create_engine(b"alice");
            let (bob, bob_pk) = create_engine(b"bob");
            let bundle = size_query_then_copy(|out, n| vc_generate_bundle(bob, 2, out, n));
            let conv = b"conv";
            let ad = b"ad";
            let first = b"A1";
            let mut sid_a = [0u8; 16];
            let packet = {
                let mut n = 0usize;
                assert_eq!(
                    vc_establish_outbound(
                        alice,
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
                let mut buf = vec![0u8; n];
                assert_eq!(
                    vc_establish_outbound(
                        alice,
                        bundle.as_ptr(),
                        bundle.len(),
                        conv.as_ptr(),
                        conv.len(),
                        first.as_ptr(),
                        first.len(),
                        ad.as_ptr(),
                        ad.len(),
                        sid_a.as_mut_ptr(),
                        buf.as_mut_ptr(),
                        &mut n,
                    ),
                    VcError::Ok as i32
                );
                buf.truncate(n);
                buf
            };

            let pending = size_query_then_copy(|out, n| {
                vc_pending_outbound_initiation(alice, sid_a.as_ptr(), out, n)
            });
            assert_eq!(packet, pending);

            let parsed = InitiationPacket::decode(&packet).unwrap();
            let mut sid_b = [0u8; 16];
            let mut pt_bound = parsed.first_message.ciphertext.len();
            let mut first_out = vec![0u8; pt_bound];
            assert_eq!(
                vc_process_inbound(
                    bob,
                    packet.as_ptr(),
                    packet.len(),
                    conv.as_ptr(),
                    conv.len(),
                    ad.as_ptr(),
                    ad.len(),
                    sid_b.as_mut_ptr(),
                    first_out.as_mut_ptr(),
                    &mut pt_bound,
                ),
                VcError::Ok as i32
            );
            assert_eq!(&first_out[..pt_bound], first);

            let sealed = size_query_then_copy(|out, n| {
                vc_encrypt(
                    bob,
                    sid_b.as_ptr(),
                    b"B1".as_ptr(),
                    2,
                    ad.as_ptr(),
                    ad.len(),
                    out,
                    n,
                )
            });
            let parsed_sealed = SealedMessage::decode(&sealed).unwrap();
            let mut out_len = parsed_sealed.ciphertext.len();
            let mut out = vec![0u8; out_len];
            assert_eq!(
                vc_decrypt(
                    alice,
                    sid_a.as_ptr(),
                    sealed.as_ptr(),
                    sealed.len(),
                    ad.as_ptr(),
                    ad.len(),
                    out.as_mut_ptr(),
                    &mut out_len,
                ),
                VcError::Ok as i32
            );
            assert_eq!(&out[..out_len], b"B1");

            let mut binary = [0u8; 32];
            let mut numeric = [0u8; 60];
            let mut numeric_len = numeric.len();
            assert_eq!(
                vc_fingerprint(
                    alice_pk.as_ptr(),
                    bob_pk.as_ptr(),
                    b"alice".as_ptr(),
                    5,
                    b"bob".as_ptr(),
                    3,
                    binary.as_mut_ptr(),
                    numeric.as_mut_ptr(),
                    &mut numeric_len,
                ),
                VcError::Ok as i32
            );
            assert_eq!(numeric_len, 60);

            assert_eq!(vc_delete_session(alice, sid_a.as_ptr()), VcError::Ok as i32);
            assert_eq!(vc_engine_destroy(alice), VcError::Ok as i32);
            assert_eq!(vc_engine_destroy(bob), VcError::Ok as i32);
        }
    }

    #[test]
    fn destroy_is_terminal_against_inflight_calls() {
        unsafe {
            let (handle, _) = create_engine(b"destroy-race");
            let barrier = Arc::new(Barrier::new(2));
            let worker_barrier = barrier.clone();
            let worker = thread::spawn(move || {
                worker_barrier.wait();
                let mut out = [0u8; 32];
                vc_engine_public_identity(handle, out.as_mut_ptr())
            });
            barrier.wait();
            let destroy = vc_engine_destroy(handle);
            assert_eq!(destroy, VcError::Ok as i32);
            let result = worker.join().unwrap();
            assert!(result == VcError::Ok as i32 || result == VcError::NotFound as i32);
            let mut out = [0u8; 32];
            assert_eq!(
                vc_engine_public_identity(handle, out.as_mut_ptr()),
                VcError::NotFound as i32
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Production persistent constructor (roadmap item 5)
// ---------------------------------------------------------------------------

/// C callback table supplying a rollback-resistant monotonic anchor.
///
/// The anchor must live **outside the application's restorable data domain**.
/// A row in the same database, or a file beside the state file, does not
/// satisfy the contract: both are restored together with the state they are
/// supposed to be checked against. Acceptable backings are a server-held
/// counter or a hardware/TEE monotonic primitive.
///
/// # Callback contract
///
/// Both callbacks return `0` on success and non-zero on failure, and write
/// their result through the out-pointer only on success.
///
/// * `current(ctx, out)` — read the committed anchor value.
/// * `compare_and_increment(ctx, expected, out)` — atomically move `expected`
///   to `expected + 1`. On failure the implementation **must** have resolved
///   whether the value changed before returning. An implementation whose
///   outcome can remain unknown after an error is not compatible with this
///   interface: an unobserved advance desynchronizes the durable epoch and is
///   indistinguishable from a rollback on the next open.
///
/// # Safety
///
/// * Both function pointers must be non-null and remain valid for the lifetime
///   of the engine handle.
/// * `ctx` is passed back unmodified and must remain valid for the same
///   lifetime. The engine is internally concurrent, so `ctx` and both callbacks
///   **must be safe to call from multiple threads simultaneously**.
/// * The callbacks must not unwind across the ABI boundary.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VcRollbackAnchorCallbacks {
    pub ctx: *mut core::ffi::c_void,
    pub current: Option<unsafe extern "C" fn(*mut core::ffi::c_void, *mut u64) -> i32>,
    pub compare_and_increment:
        Option<unsafe extern "C" fn(*mut core::ffi::c_void, u64, *mut u64) -> i32>,
}

struct FfiRollbackAnchor {
    cb: VcRollbackAnchorCallbacks,
}

// SAFETY: upheld by the documented contract on `VcRollbackAnchorCallbacks` —
// the caller guarantees `ctx` and both callbacks are safe to use concurrently.
// This is asserted, not proven, and is a required audit point for any platform
// adapter built against this interface.
unsafe impl Send for FfiRollbackAnchor {}
unsafe impl Sync for FfiRollbackAnchor {}

impl RollbackAnchor for FfiRollbackAnchor {
    fn current(&self) -> Result<u64, PrimitiveError> {
        let f = self.cb.current.ok_or(PrimitiveError::Internal)?;
        let mut out: u64 = 0;
        let rc = catch_unwind(AssertUnwindSafe(|| unsafe { f(self.cb.ctx, &mut out) }))
            .map_err(|_| PrimitiveError::Internal)?;
        if rc != 0 {
            return Err(PrimitiveError::Internal);
        }
        Ok(out)
    }

    fn compare_and_increment(&self, expected: u64) -> Result<u64, PrimitiveError> {
        let f = self
            .cb
            .compare_and_increment
            .ok_or(PrimitiveError::Internal)?;
        let mut out: u64 = 0;
        let rc = catch_unwind(AssertUnwindSafe(|| unsafe {
            f(self.cb.ctx, expected, &mut out)
        }))
        .map_err(|_| PrimitiveError::Internal)?;
        if rc != 0 {
            return Err(PrimitiveError::Internal);
        }
        Ok(out)
    }
}

const MAX_FFI_PATH: usize = 4 * 1024;

/// Open a **persistent** engine backed by encrypted on-disk storage and a
/// caller-supplied rollback anchor. This is the production constructor.
///
/// `create_if_absent` selects the intent, and the two intents are deliberately
/// not interchangeable:
///
/// * `0` — restore an existing device. Fails with a specific code if the state
///   is stale, lost, or the anchor is unusable.
/// * `1` — provision a new device. Refuses unless the anchor is pristine and no
///   state exists, so it cannot be used to paper over a failed restore.
///
/// # Recovery policy is the caller's decision
///
/// On [`VcError::RollbackDetected`] or [`VcError::StateLost`] this function
/// refuses and **there is deliberately no library-provided recovery call**.
/// The two available policies trade differently and the library will not choose:
///
/// * *Refuse to start.* Safest. A genuinely corrupted anchor locks the user out
///   permanently.
/// * *Re-provision and force re-keying.* Recoverable, but drops message history
///   and destroys the old identity. It must be surfaced to the user; performed
///   silently it is a downgrade an attacker can trigger deliberately, and every
///   peer's safety-number verification is invalidated without explanation.
///
/// Retrying the same call, or calling it again with `create_if_absent = 1`,
/// is not a recovery path and will not succeed.
///
/// # Safety
///
/// `path` must point to `path_len` readable bytes of UTF-8. `storage_key` must
/// point to 32 readable bytes; it is copied and the copy is zeroized before
/// return. `out_handle` must be a valid writable `VcHandle`. `out_public`, if
/// non-null, must be writable for 32 bytes. See
/// [`VcRollbackAnchorCallbacks`] for the anchor contract.
#[no_mangle]
pub unsafe extern "C" fn vc_engine_open_persistent(
    device_id: *const u8,
    device_id_len: usize,
    profile: u8,
    path: *const u8,
    path_len: usize,
    storage_key: *const u8,
    anchor: VcRollbackAnchorCallbacks,
    create_if_absent: u8,
    out_handle: *mut VcHandle,
    out_public: *mut u8,
) -> i32 {
    ffi_guard(|| {
        if out_handle.is_null() || storage_key.is_null() {
            return VcError::InvalidArgument as i32;
        }
        if anchor.current.is_none() || anchor.compare_and_increment.is_none() {
            return VcError::InvalidArgument as i32;
        }
        let profile = match CryptoProfile::from_u8(profile) {
            Ok(p) => p,
            Err(_) => return VcError::InvalidArgument as i32,
        };
        let dev_id = match read_owned(device_id, device_id_len, MAX_FFI_DEVICE_ID) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => return VcError::InvalidArgument as i32,
            Err(e) => return e as i32,
        };
        let path_bytes = match read_owned(path, path_len, MAX_FFI_PATH) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => return VcError::InvalidArgument as i32,
            Err(e) => return e as i32,
        };
        let path_str = match String::from_utf8(path_bytes) {
            Ok(v) => v,
            Err(_) => return VcError::InvalidArgument as i32,
        };

        let mut key = [0u8; 32];
        unsafe { std::ptr::copy_nonoverlapping(storage_key, key.as_mut_ptr(), 32) };
        let storage = EncryptedFileStorage::open(&path_str, key);
        key.zeroize();
        let storage = match storage {
            Ok(v) => v,
            Err(_) => return VcError::Internal as i32,
        };

        let anchor_impl: Arc<dyn RollbackAnchor> = Arc::new(FfiRollbackAnchor { cb: anchor });

        let engine = if create_if_absent == 1 {
            let (st, mc) = match coordinated_backends_for_initialize(storage, anchor_impl) {
                Ok(v) => v,
                // Refuses whenever the anchor is non-pristine or state exists,
                // which is what makes this unusable as a rollback escape hatch.
                Err(_) => return VcError::StateError as i32,
            };
            VoiceChatCryptoEngine::initialize_device_with_backends(
                DeviceConfig {
                    device_id: dev_id,
                    profile,
                },
                st,
                mc,
            )
        } else {
            let (st, mc) = match coordinated_backends_for_restore(storage, anchor_impl) {
                Ok(v) => v,
                Err(rejection) => return VcError::from(rejection) as i32,
            };
            VoiceChatCryptoEngine::restore_device_with_backends(
                DeviceConfig {
                    device_id: dev_id,
                    profile,
                },
                st,
                mc,
            )
        };

        let engine = match engine {
            Ok(v) => v,
            Err(e) => return VcError::from(e) as i32,
        };

        let pk = engine.local_identity_public();
        let shared = Arc::new(EngineSlot::new(engine));
        let handle = {
            let mut reg = match registry().lock() {
                Ok(v) => v,
                Err(_) => return VcError::Internal as i32,
            };
            let handle = match reg.alloc() {
                Ok(v) => v,
                Err(e) => return e as i32,
            };
            reg.engines.insert(handle, shared);
            handle
        };
        if !out_public.is_null() {
            unsafe { std::ptr::copy_nonoverlapping(pk.as_ptr(), out_public, 32) };
        }
        unsafe { *out_handle = handle };
        VcError::Ok as i32
    })
}

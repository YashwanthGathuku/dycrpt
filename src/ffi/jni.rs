//! Android JNI layer (roadmap item 6).
//!
//! # Why this exists
//!
//! `ffi/kotlin/VoiceChatCrypto.kt` has always declared `external fun native*`
//! methods, but no JNI implementation existed anywhere in this crate and `jni`
//! was not a dependency. `System.loadLibrary` would succeed — the cdylib is
//! real — and then every native call would throw `UnsatisfiedLinkError`. The
//! Android bindings had never been able to run. This module supplies the
//! missing symbols.
//!
//! # Design
//!
//! Only the persistent constructor and the operations the Kotlin surface needs
//! are exposed. Key material never crosses the JNI boundary: the engine handle
//! is an opaque `jlong`, handshakes run inside Rust, and the only secret that
//! crosses is the 32-byte storage key, which is zeroized on the Rust side after
//! `EncryptedFileStorage::open` copies it.
//!
//! ## Rollback anchor bridging
//!
//! `vc_engine_open_persistent` takes C function pointers, but on Android the
//! anchor is a Kotlin object (Keystore- or server-backed). [`JniAnchorCtx`]
//! holds a `JavaVM` plus a global reference to that object; the two `extern "C"`
//! thunks attach the calling thread to the JVM and invoke the Kotlin methods.
//!
//! The engine is internally concurrent, so those thunks can be called from
//! several threads at once. `AttachGuard` is acquired per call rather than
//! cached, and the Kotlin implementation **must** be thread-safe. This is
//! asserted by contract, not enforced by the type system — see
//! `docs/KNOWN_LIMITATIONS.md`.
//!
//! ## Exception discipline
//!
//! A pending Java exception left set across a JNI return corrupts the next JNI
//! call in ways that are hard to diagnose. Every call into Kotlin therefore
//! clears any pending exception and converts it into a non-zero return code,
//! which the anchor contract already defines as failure.

#![allow(non_snake_case)]

use std::sync::Arc;

use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jbyte, jint, jlong, jshort};
use jni::{JNIEnv, JavaVM};

use super::{
    vc_engine_destroy, vc_engine_open_persistent, VcError, VcHandle, VcRollbackAnchorCallbacks,
};

/// Context handed to the C anchor thunks. Boxed and kept alive for the lifetime
/// of the engine handle by [`ANCHORS`].
struct JniAnchorCtx {
    vm: JavaVM,
    anchor: jni::objects::GlobalRef,
}

/// Read `long current()` from the Kotlin anchor.
///
/// # Safety
/// `ctx` must be a live `*mut JniAnchorCtx` and `out` a writable `u64`.
unsafe extern "C" fn jni_anchor_current(ctx: *mut core::ffi::c_void, out: *mut u64) -> i32 {
    if ctx.is_null() || out.is_null() {
        return 1;
    }
    let ctx = unsafe { &*(ctx as *const JniAnchorCtx) };
    let Ok(mut env) = ctx.vm.attach_current_thread() else {
        return 1;
    };
    let res = env.call_method(&ctx.anchor, "current", "()J", &[]);
    if env.exception_check().unwrap_or(true) {
        let _ = env.exception_clear();
        return 1;
    }
    match res.and_then(|v| v.j()) {
        Ok(v) if v >= 0 => {
            unsafe { *out = v as u64 };
            0
        }
        _ => 1,
    }
}

/// Call `long compareAndIncrement(long expected)` on the Kotlin anchor.
///
/// The Kotlin contract mirrors the C one: return the new value on success, or
/// throw / return a negative value if the CAS did not apply. It must never
/// return having left the outcome unknown.
///
/// # Safety
/// `ctx` must be a live `*mut JniAnchorCtx` and `out` a writable `u64`.
unsafe extern "C" fn jni_anchor_cas(
    ctx: *mut core::ffi::c_void,
    expected: u64,
    out: *mut u64,
) -> i32 {
    if ctx.is_null() || out.is_null() || expected > i64::MAX as u64 {
        return 1;
    }
    let ctx = unsafe { &*(ctx as *const JniAnchorCtx) };
    let Ok(mut env) = ctx.vm.attach_current_thread() else {
        return 1;
    };
    let res = env.call_method(
        &ctx.anchor,
        "compareAndIncrement",
        "(J)J",
        &[JValue::Long(expected as i64)],
    );
    if env.exception_check().unwrap_or(true) {
        let _ = env.exception_clear();
        return 1;
    }
    match res.and_then(|v| v.j()) {
        Ok(v) if v >= 0 => {
            unsafe { *out = v as u64 };
            0
        }
        _ => 1,
    }
}

/// Anchor contexts, kept alive until the matching engine handle is destroyed.
///
/// The C anchor vtable stores a raw `ctx` pointer with no ownership. If the box
/// were dropped while the engine still held the pointer, every subsequent
/// anchor call would be a use-after-free — which for a *rollback* anchor would
/// mean silently losing rollback detection, not an obvious crash.
static ANCHORS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<VcHandle, Box<JniAnchorCtx>>>,
> = std::sync::OnceLock::new();

fn anchors() -> &'static std::sync::Mutex<std::collections::HashMap<VcHandle, Box<JniAnchorCtx>>> {
    ANCHORS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn throw_state(env: &mut JNIEnv<'_>, code: i32) {
    let _ = env.throw_new(
        "com/voicechat/crypto/VoiceChatCryptoException",
        format!("dycrpt native error {code}"),
    );
}

fn read_bytes(env: &JNIEnv<'_>, arr: &JByteArray<'_>) -> Option<Vec<u8>> {
    env.convert_byte_array(arr).ok()
}

/// `nativeProtocolVersion()`
#[no_mangle]
pub extern "system" fn Java_com_voicechat_crypto_VoiceChatCrypto_nativeProtocolVersion(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jshort {
    super::vc_protocol_version() as jshort
}

/// `nativeEngineOpenPersistent(deviceId, profile, path, storageKey, anchor, createIfAbsent)`
///
/// Returns the engine handle. Throws `VoiceChatCryptoException` carrying the
/// native error code on failure, so Kotlin can distinguish
/// `VC_ROLLBACK_DETECTED` (7) and `VC_STATE_LOST` (8) — both terminal — from
/// `VC_NOT_INITIALIZED` (10), which means "call again with createIfAbsent".
#[no_mangle]
pub extern "system" fn Java_com_voicechat_crypto_VoiceChatCrypto_nativeEngineOpenPersistent<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    device_id: JByteArray<'l>,
    profile: jbyte,
    path: JString<'l>,
    storage_key: JByteArray<'l>,
    anchor: JObject<'l>,
    create_if_absent: jbyte,
) -> jlong {
    let Some(dev) = read_bytes(&env, &device_id) else {
        throw_state(&mut env, VcError::InvalidArgument as i32);
        return 0;
    };
    let Some(mut key) = read_bytes(&env, &storage_key) else {
        throw_state(&mut env, VcError::InvalidArgument as i32);
        return 0;
    };
    if key.len() != 32 {
        key.iter_mut().for_each(|b| *b = 0);
        throw_state(&mut env, VcError::InvalidArgument as i32);
        return 0;
    }
    let path_str: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(_) => {
            key.iter_mut().for_each(|b| *b = 0);
            throw_state(&mut env, VcError::InvalidArgument as i32);
            return 0;
        }
    };
    let (vm, global) = match (env.get_java_vm(), env.new_global_ref(&anchor)) {
        (Ok(vm), Ok(g)) => (vm, g),
        _ => {
            key.iter_mut().for_each(|b| *b = 0);
            throw_state(&mut env, VcError::Internal as i32);
            return 0;
        }
    };

    let ctx = Box::new(JniAnchorCtx { vm, anchor: global });
    let ctx_ptr = (&*ctx) as *const JniAnchorCtx as *mut core::ffi::c_void;
    let callbacks = VcRollbackAnchorCallbacks {
        ctx: ctx_ptr,
        current: Some(jni_anchor_current),
        compare_and_increment: Some(jni_anchor_cas),
    };

    let mut handle: VcHandle = 0;
    let rc = unsafe {
        vc_engine_open_persistent(
            dev.as_ptr(),
            dev.len(),
            profile as u8,
            path_str.as_ptr(),
            path_str.len(),
            key.as_ptr(),
            callbacks,
            create_if_absent as u8,
            &mut handle,
            std::ptr::null_mut(),
        )
    };
    key.iter_mut().for_each(|b| *b = 0);

    if rc != VcError::Ok as i32 {
        // ctx drops here; the engine was never created so nothing retains the
        // pointer.
        throw_state(&mut env, rc);
        return 0;
    }

    match anchors().lock() {
        Ok(mut map) => {
            map.insert(handle, ctx);
        }
        Err(_) => {
            unsafe { vc_engine_destroy(handle) };
            throw_state(&mut env, VcError::Internal as i32);
            return 0;
        }
    }
    handle as jlong
}

/// `nativeEngineDestroy(engine)` — also releases the anchor context.
#[no_mangle]
pub extern "system" fn Java_com_voicechat_crypto_VoiceChatCrypto_nativeEngineDestroy(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    engine: jlong,
) -> jint {
    if engine <= 0 {
        return VcError::InvalidArgument as jint;
    }
    let rc = unsafe { vc_engine_destroy(engine as VcHandle) };
    // Drop the anchor only after the engine is gone, so no in-flight call can
    // still reach through the raw ctx pointer.
    if let Ok(mut map) = anchors().lock() {
        map.remove(&(engine as VcHandle));
    }
    rc as jint
}

/// `nativePublicIdentity(engine)` -> 32 bytes
#[no_mangle]
pub extern "system" fn Java_com_voicechat_crypto_VoiceChatCrypto_nativePublicIdentity<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    engine: jlong,
) -> JByteArray<'l> {
    let mut pk = [0u8; 32];
    let rc = unsafe { super::vc_engine_public_identity(engine as VcHandle, pk.as_mut_ptr()) };
    if rc != VcError::Ok as i32 {
        throw_state(&mut env, rc);
        return JByteArray::default();
    }
    env.byte_array_from_slice(&pk).unwrap_or_default()
}

/// `nativeGenerateBundle(engine, oneTimeCount)`
#[no_mangle]
pub extern "system" fn Java_com_voicechat_crypto_VoiceChatCrypto_nativeGenerateBundle<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    engine: jlong,
    one_time_count: jint,
) -> JByteArray<'l> {
    if one_time_count < 0 {
        throw_state(&mut env, VcError::InvalidArgument as i32);
        return JByteArray::default();
    }
    let mut out = vec![0u8; super::BUNDLE_BOUND];
    let mut len = out.len();
    let rc = unsafe {
        super::vc_generate_bundle(
            engine as VcHandle,
            one_time_count as usize,
            out.as_mut_ptr(),
            &mut len,
        )
    };
    if rc != VcError::Ok as i32 {
        throw_state(&mut env, rc);
        return JByteArray::default();
    }
    out.truncate(len);
    env.byte_array_from_slice(&out).unwrap_or_default()
}

/// `nativeEncrypt(engine, sessionId, plaintext, ad)`
#[no_mangle]
pub extern "system" fn Java_com_voicechat_crypto_VoiceChatCrypto_nativeEncrypt<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    engine: jlong,
    session_id: JByteArray<'l>,
    plaintext: JByteArray<'l>,
    ad: JByteArray<'l>,
) -> JByteArray<'l> {
    let (Some(sid), Some(pt)) = (read_bytes(&env, &session_id), read_bytes(&env, &plaintext))
    else {
        throw_state(&mut env, VcError::InvalidArgument as i32);
        return JByteArray::default();
    };
    if sid.len() != 16 {
        throw_state(&mut env, VcError::InvalidArgument as i32);
        return JByteArray::default();
    }
    let ad_vec = read_bytes(&env, &ad).unwrap_or_default();
    let Ok(bound) = super::packet_bound(pt.len()) else {
        throw_state(&mut env, VcError::LimitExceeded as i32);
        return JByteArray::default();
    };
    let mut out = vec![0u8; bound];
    let mut len = out.len();
    let rc = unsafe {
        super::vc_encrypt(
            engine as VcHandle,
            sid.as_ptr(),
            pt.as_ptr(),
            pt.len(),
            ad_vec.as_ptr(),
            ad_vec.len(),
            out.as_mut_ptr(),
            &mut len,
        )
    };
    if rc != VcError::Ok as i32 {
        throw_state(&mut env, rc);
        return JByteArray::default();
    }
    out.truncate(len);
    env.byte_array_from_slice(&out).unwrap_or_default()
}

/// `nativeDecrypt(engine, sessionId, sealed, ad)`
#[no_mangle]
pub extern "system" fn Java_com_voicechat_crypto_VoiceChatCrypto_nativeDecrypt<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    engine: jlong,
    session_id: JByteArray<'l>,
    sealed: JByteArray<'l>,
    ad: JByteArray<'l>,
) -> JByteArray<'l> {
    let (Some(sid), Some(ct)) = (read_bytes(&env, &session_id), read_bytes(&env, &sealed)) else {
        throw_state(&mut env, VcError::InvalidArgument as i32);
        return JByteArray::default();
    };
    if sid.len() != 16 {
        throw_state(&mut env, VcError::InvalidArgument as i32);
        return JByteArray::default();
    }
    let ad_vec = read_bytes(&env, &ad).unwrap_or_default();
    let mut out = vec![0u8; ct.len() + 1024];
    let mut len = out.len();
    let rc = unsafe {
        super::vc_decrypt(
            engine as VcHandle,
            sid.as_ptr(),
            ct.as_ptr(),
            ct.len(),
            ad_vec.as_ptr(),
            ad_vec.len(),
            out.as_mut_ptr(),
            &mut len,
        )
    };
    if rc != VcError::Ok as i32 {
        throw_state(&mut env, rc);
        return JByteArray::default();
    }
    out.truncate(len);
    env.byte_array_from_slice(&out).unwrap_or_default()
}

/// Number of live anchor contexts. Test/diagnostic aid: a value that grows
/// without bound across create/destroy cycles is a leak of `GlobalRef`s.
#[no_mangle]
pub extern "system" fn Java_com_voicechat_crypto_VoiceChatCrypto_nativeLiveAnchorCount(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jint {
    anchors().lock().map(|m| m.len() as jint).unwrap_or(-1)
}

/// Keeps `Arc` imported for future shared-context work without a warning.
#[allow(dead_code)]
fn _assert_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<Arc<()>>();
}

#![cfg(feature = "ffi")]

//! Roadmap item 5 — production persistent FFI constructor.
//!
//! Exercises `vc_engine_open_persistent` through the real C ABI, including the
//! paths that must fail closed. These are the tests that matter: a persistent
//! constructor that cannot be shown to refuse a rolled-back state is not a
//! production constructor.

use std::sync::atomic::{AtomicU64, Ordering};
use voicechat_crypto::ffi::*;

/// Minimal temp dir. Avoids adding a dev-dependency to a crypto library for the
/// sake of one helper.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("vc-ffi-{tag}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// One process-wide anchor per test, addressed by ctx pointer.
struct Anchor {
    value: AtomicU64,
}

unsafe extern "C" fn cb_current(ctx: *mut core::ffi::c_void, out: *mut u64) -> i32 {
    let a = unsafe { &*(ctx as *const Anchor) };
    unsafe { *out = a.value.load(Ordering::SeqCst) };
    0
}

unsafe extern "C" fn cb_cas(ctx: *mut core::ffi::c_void, expected: u64, out: *mut u64) -> i32 {
    let a = unsafe { &*(ctx as *const Anchor) };
    match a
        .value
        .compare_exchange(expected, expected + 1, Ordering::SeqCst, Ordering::SeqCst)
    {
        Ok(_) => {
            unsafe { *out = expected + 1 };
            0
        }
        Err(_) => 1,
    }
}

unsafe extern "C" fn cb_current_fails(_ctx: *mut core::ffi::c_void, _out: *mut u64) -> i32 {
    1
}

fn callbacks(a: &Anchor) -> VcRollbackAnchorCallbacks {
    VcRollbackAnchorCallbacks {
        ctx: a as *const Anchor as *mut core::ffi::c_void,
        current: Some(cb_current),
        compare_and_increment: Some(cb_cas),
    }
}

fn open(dir: &std::path::Path, name: &str, anchor: &Anchor, create: u8) -> (i32, VcHandle) {
    let path = dir.join(name);
    let path = path.to_str().unwrap();
    let dev = b"device-1";
    let key = [7u8; 32];
    let mut handle: VcHandle = 0;
    let mut pk = [0u8; 32];
    let rc = unsafe {
        vc_engine_open_persistent(
            dev.as_ptr(),
            dev.len(),
            1,
            path.as_ptr(),
            path.len(),
            key.as_ptr(),
            callbacks(anchor),
            create,
            &mut handle,
            pk.as_mut_ptr(),
        )
    };
    (rc, handle)
}

#[test]
fn provision_then_restore_round_trips() {
    let dir = TempDir::new("provision_then_restore_round_trips");
    let anchor = Anchor {
        value: AtomicU64::new(0),
    };

    let (rc, h) = open(dir.path(), "state.bin", &anchor, 1);
    assert_eq!(rc, VcError::Ok as i32, "provisioning must succeed");
    assert_ne!(h, 0);
    assert_eq!(unsafe { vc_engine_destroy(h) }, VcError::Ok as i32);

    let (rc2, h2) = open(dir.path(), "state.bin", &anchor, 0);
    assert_eq!(rc2, VcError::Ok as i32, "restore of own state must succeed");
    assert_eq!(unsafe { vc_engine_destroy(h2) }, VcError::Ok as i32);
}

#[test]
fn restoring_a_never_provisioned_device_reports_not_initialized() {
    let dir = TempDir::new("restoring_a_never_provisioned_device_reports_not_initialized");
    let anchor = Anchor {
        value: AtomicU64::new(0),
    };
    let (rc, _) = open(dir.path(), "absent.bin", &anchor, 0);
    assert_eq!(rc, VcError::NotInitialized as i32);
}

#[test]
fn lost_state_with_advanced_anchor_is_reported_as_state_lost() {
    let dir = TempDir::new("lost_state_with_advanced_anchor_is_reported_as_state_lost");
    // Anchor says this device was provisioned; local state is absent.
    let anchor = Anchor {
        value: AtomicU64::new(9),
    };
    let (rc, _) = open(dir.path(), "gone.bin", &anchor, 0);
    assert_eq!(rc, VcError::StateLost as i32);
}

#[test]
fn provisioning_cannot_be_used_to_escape_a_used_anchor() {
    // The critical property: an app that hits a failed restore must not be able
    // to route around it by asking for a fresh device instead.
    let dir = TempDir::new("provisioning_cannot_be_used_to_escape_a_used_anchor");
    let anchor = Anchor {
        value: AtomicU64::new(9),
    };
    let (rc, _) = open(dir.path(), "escape.bin", &anchor, 1);
    assert_ne!(
        rc,
        VcError::Ok as i32,
        "must not provision over a used anchor"
    );
    assert_eq!(rc, VcError::StateError as i32);
}

#[test]
fn unreadable_anchor_is_distinguished_from_rollback() {
    let dir = TempDir::new("unreadable_anchor_is_distinguished_from_rollback");
    let anchor = Anchor {
        value: AtomicU64::new(0),
    };
    let path = dir.path().join("s.bin");
    let path = path.to_str().unwrap();
    let dev = b"device-1";
    let key = [7u8; 32];
    let mut handle: VcHandle = 0;
    let cbs = VcRollbackAnchorCallbacks {
        ctx: &anchor as *const Anchor as *mut core::ffi::c_void,
        current: Some(cb_current_fails),
        compare_and_increment: Some(cb_cas),
    };
    let rc = unsafe {
        vc_engine_open_persistent(
            dev.as_ptr(),
            dev.len(),
            1,
            path.as_ptr(),
            path.len(),
            key.as_ptr(),
            cbs,
            0,
            &mut handle,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, VcError::AnchorUnavailable as i32);
}

#[test]
fn null_callbacks_are_rejected_not_dereferenced() {
    let dir = TempDir::new("null_callbacks_are_rejected_not_dereferenced");
    let path = dir.path().join("s.bin");
    let path = path.to_str().unwrap();
    let dev = b"device-1";
    let key = [7u8; 32];
    let mut handle: VcHandle = 0;
    let cbs = VcRollbackAnchorCallbacks {
        ctx: std::ptr::null_mut(),
        current: None,
        compare_and_increment: None,
    };
    let rc = unsafe {
        vc_engine_open_persistent(
            dev.as_ptr(),
            dev.len(),
            1,
            path.as_ptr(),
            path.len(),
            key.as_ptr(),
            cbs,
            1,
            &mut handle,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, VcError::InvalidArgument as i32);
}

#[test]
fn null_storage_key_and_out_handle_are_rejected() {
    let dir = TempDir::new("null_storage_key_and_out_handle_are_rejected");
    let anchor = Anchor {
        value: AtomicU64::new(0),
    };
    let path = dir.path().join("s.bin");
    let path = path.to_str().unwrap();
    let dev = b"device-1";
    let key = [7u8; 32];
    let mut handle: VcHandle = 0;

    let rc_nokey = unsafe {
        vc_engine_open_persistent(
            dev.as_ptr(),
            dev.len(),
            1,
            path.as_ptr(),
            path.len(),
            std::ptr::null(),
            callbacks(&anchor),
            1,
            &mut handle,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc_nokey, VcError::InvalidArgument as i32);

    let rc_nohandle = unsafe {
        vc_engine_open_persistent(
            dev.as_ptr(),
            dev.len(),
            1,
            path.as_ptr(),
            path.len(),
            key.as_ptr(),
            callbacks(&anchor),
            1,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc_nohandle, VcError::InvalidArgument as i32);
}

#[test]
fn oversized_path_is_bounded_not_read() {
    let anchor = Anchor {
        value: AtomicU64::new(0),
    };
    let dev = b"device-1";
    let key = [7u8; 32];
    let mut handle: VcHandle = 0;
    let big = vec![b'a'; 8 * 1024];
    let rc = unsafe {
        vc_engine_open_persistent(
            dev.as_ptr(),
            dev.len(),
            1,
            big.as_ptr(),
            big.len(),
            key.as_ptr(),
            callbacks(&anchor),
            1,
            &mut handle,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, VcError::LimitExceeded as i32);
}

#[test]
fn a_genuinely_stale_snapshot_is_refused_as_rollback() {
    // The scenario the whole anchor design exists for: an authentic, correctly
    // decrypting, older state file presented while the anchor has moved on.
    // Restoring it would replay message keys and AEAD nonces.
    let dir = TempDir::new("rollback");
    let anchor = Anchor {
        value: AtomicU64::new(0),
    };
    let live = dir.path().join("state.bin");
    let backup = dir.path().join("state.backup");

    let (rc, h) = open(dir.path(), "state.bin", &anchor, 1);
    assert_eq!(rc, VcError::Ok as i32);

    // Commit some state so the epoch advances past provisioning.
    let mut buf = vec![0u8; 4096];
    let mut len = buf.len();
    assert_eq!(
        unsafe { vc_generate_bundle(h, 2, buf.as_mut_ptr(), &mut len) },
        VcError::Ok as i32
    );

    // Snapshot the state file here — this is the "backup" an attacker or a
    // careless restore-from-cloud would later put back.
    std::fs::copy(&live, &backup).unwrap();
    let anchor_at_backup = anchor.value.load(Ordering::SeqCst);

    // Keep using the device so the anchor advances beyond the backup.
    let mut len2 = buf.len();
    assert_eq!(
        unsafe { vc_generate_bundle(h, 2, buf.as_mut_ptr(), &mut len2) },
        VcError::Ok as i32
    );
    assert!(
        anchor.value.load(Ordering::SeqCst) > anchor_at_backup,
        "anchor must advance on state commit, else this test proves nothing"
    );
    assert_eq!(unsafe { vc_engine_destroy(h) }, VcError::Ok as i32);

    // Roll the state file back.
    std::fs::copy(&backup, &live).unwrap();

    let (rc_rollback, _) = open(dir.path(), "state.bin", &anchor, 0);
    assert_eq!(
        rc_rollback,
        VcError::RollbackDetected as i32,
        "stale snapshot must be refused as a rollback, not opened"
    );

    // And there is no way around it.
    let (rc_escape, _) = open(dir.path(), "state.bin", &anchor, 1);
    assert_ne!(rc_escape, VcError::Ok as i32);
}

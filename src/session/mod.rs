//! VoiceChat session manager — Sesame-style multi-device design.
//!
//! Derived from the public-domain Sesame specification concepts only.
//! No implementation code was copied.
//!
//! Data model supports:
//!   User A ─ Device A1, A2, A3
//!   User B ─ Device B1, B2
//!
//! MVP may use a single active device per user; the structures do not
//! preclude multi-device. Transport-agnostic (no Firebase or network I/O).

pub mod mailbox;
#[cfg(any(test, feature = "sesame"))]
pub mod sesame;

use std::collections::{HashMap, VecDeque};

use crate::fingerprint::{IdentityMaterial, IdentityState, IdentityTracker};
use crate::primitives::error::PrimitiveError;
use crate::ratchet::DoubleRatchetState;

// ---------------------------------------------------------------------------
// Hard limits (anti-DoS)
// ---------------------------------------------------------------------------

/// Maximum devices remembered per remote user.
pub const MAX_DEVICES_PER_USER: usize = 10;

/// Maximum sessions retained per device (active + inactive).
pub const MAX_SESSIONS_PER_DEVICE: usize = 8;

/// Maximum remote users tracked by this device.
pub const MAX_USERS: usize = 10_000;

/// Maximum resend attempts for a single message before giving up.
pub const MAX_RESEND_ATTEMPTS: u32 = 5;

/// Sesame §3.1 — stale records older than this (seconds) may be deleted
/// after the next mailbox fetch. Application clock, not wall NTP.
pub const MAX_LATENCY_SECS: u64 = 86_400;

/// Maximum concurrent initiating (unconfirmed) sessions overall.
pub const MAX_INITIATING_SESSIONS: usize = 64;

// ---------------------------------------------------------------------------
// Identifiers (opaque, application-supplied)
// ---------------------------------------------------------------------------

pub type UserId = Vec<u8>;
pub type DeviceId = Vec<u8>;
pub type SessionId = [u8; 16];

// ---------------------------------------------------------------------------
// Session record
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    /// Created locally; waiting for first successful decrypt on the other side
    /// or first inbound message that confirms it.
    Initiating,
    /// Fully established; usable for send/receive.
    Active,
    /// Previously active; retained for delayed / out-of-order messages.
    Inactive,
    /// Permanently unusable (crypto failure, identity change, explicit delete).
    Failed,
}

/// One Double Ratchet (or future Triple Ratchet) session with a remote device.
pub struct SessionRecord {
    pub id: SessionId,
    pub status: SessionStatus,
    pub ratchet: DoubleRatchetState,
    /// When this session was created or last activated (application clock).
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Device and user records (Sesame-inspired)
// ---------------------------------------------------------------------------

pub struct DeviceRecord {
    pub device_id: DeviceId,
    /// Cryptographic identity of this remote device (if known).
    pub identity: Option<IdentityMaterial>,
    pub active: Option<SessionRecord>,
    pub inactive: VecDeque<SessionRecord>,
    pub stale: bool,
    pub stale_timestamp: Option<u64>,
}

impl DeviceRecord {
    fn session_count(&self) -> usize {
        self.inactive.len() + if self.active.is_some() { 1 } else { 0 }
    }

    /// Promote an inactive session to active; demote previous active.
    fn activate(&mut self, session_id: &SessionId) -> Result<(), PrimitiveError> {
        if let Some(ref active) = self.active {
            if active.id == *session_id {
                return Ok(()); // already active
            }
        }
        let pos = self
            .inactive
            .iter()
            .position(|s| s.id == *session_id)
            .ok_or(PrimitiveError::Internal)?;
        let mut new_active = self.inactive.remove(pos).ok_or(PrimitiveError::Internal)?;
        new_active.status = SessionStatus::Active;
        if let Some(mut old) = self.active.take() {
            old.status = SessionStatus::Inactive;
            self.inactive.push_front(old);
        }
        // Bound inactive list
        while self.inactive.len() + 1 > MAX_SESSIONS_PER_DEVICE {
            self.inactive.pop_back();
        }
        self.active = Some(new_active);
        Ok(())
    }
}

pub struct UserRecord {
    pub user_id: UserId,
    pub devices: HashMap<DeviceId, DeviceRecord>,
    /// Tracks cryptographic identity changes for this user (any device).
    pub identity_tracker: IdentityTracker,
    pub stale: bool,
    pub stale_timestamp: Option<u64>,
}

// ---------------------------------------------------------------------------
// Session manager
// ---------------------------------------------------------------------------

/// Local device’s view of all remote users and their devices.
pub struct SessionManager {
    pub local_user_id: UserId,
    pub local_device_id: DeviceId,
    pub local_identity: IdentityMaterial,
    pub(crate) users: HashMap<UserId, UserRecord>,
    /// Global count of initiating sessions (anti-DoS).
    initiating_count: usize,
}

impl SessionManager {
    pub fn new(
        local_user_id: UserId,
        local_device_id: DeviceId,
        local_identity: IdentityMaterial,
    ) -> Self {
        Self {
            local_user_id,
            local_device_id,
            local_identity,
            users: HashMap::new(),
            initiating_count: 0,
        }
    }

    /// Number of remote users currently tracked.
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// Prepare or retrieve the active session for a remote device.
    /// Creates an initiating session if none exists (subject to limits).
    pub fn prepare_outbound(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        remote_identity: &IdentityMaterial,
        sk: &[u8; 32],
        remote_dh_public: &crate::primitives::x25519::X25519Public,
        now: u64,
    ) -> Result<SessionId, PrimitiveError> {
        self.ensure_user_device(remote_user, remote_device, remote_identity, now)?;

        // Identity-change gate
        let user = self
            .users
            .get_mut(remote_user)
            .ok_or(PrimitiveError::Internal)?;
        match user.identity_tracker.observe(remote_identity) {
            IdentityState::IdentityChanged { .. } => {
                return Err(PrimitiveError::Internal); // application must surface IDENTITY_CHANGED
            }
            IdentityState::Unknown | IdentityState::Verified => {}
        }

        let device = user
            .devices
            .get_mut(remote_device)
            .ok_or(PrimitiveError::Internal)?;
        if let Some(ref active) = device.active {
            if active.status == SessionStatus::Active || active.status == SessionStatus::Initiating
            {
                return Ok(active.id);
            }
        }

        // Need a new initiating session
        if self.initiating_count >= MAX_INITIATING_SESSIONS {
            return Err(PrimitiveError::InvalidLength); // resource limit
        }
        if device.session_count() >= MAX_SESSIONS_PER_DEVICE {
            // Evict oldest inactive
            device.inactive.pop_back();
        }

        let ratchet =
            DoubleRatchetState::init_alice(sk, remote_dh_public, crate::ratchet::DEFAULT_MAX_SKIP)?;
        let id = new_session_id()?;
        let record = SessionRecord {
            id,
            status: SessionStatus::Initiating,
            ratchet,
            timestamp: now,
        };
        device.active = Some(record);
        self.initiating_count += 1;
        Ok(id)
    }

    /// Mark a session as established (e.g. after first successful use).
    pub fn confirm_session(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        session_id: &SessionId,
    ) -> Result<(), PrimitiveError> {
        let device = self
            .users
            .get_mut(remote_user)
            .and_then(|u| u.devices.get_mut(remote_device))
            .ok_or(PrimitiveError::Internal)?;
        if let Some(ref mut active) = device.active {
            if active.id == *session_id && active.status == SessionStatus::Initiating {
                active.status = SessionStatus::Active;
                self.initiating_count = self.initiating_count.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// Create a matching (Bob) session from a shared secret and the local
    /// DH secret used in the handshake (Sesame §2.2 recipient session creation).
    pub fn prepare_inbound(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        remote_identity: &IdentityMaterial,
        sk: &[u8; 32],
        local_dh: crate::primitives::x25519::X25519Secret,
        now: u64,
    ) -> Result<SessionId, PrimitiveError> {
        self.ensure_user_device(remote_user, remote_device, remote_identity, now)?;
        let user = self
            .users
            .get_mut(remote_user)
            .ok_or(PrimitiveError::Internal)?;
        match user.identity_tracker.observe(remote_identity) {
            IdentityState::IdentityChanged { .. } => return Err(PrimitiveError::Internal),
            IdentityState::Unknown | IdentityState::Verified => {}
        }
        let device = user
            .devices
            .get_mut(remote_device)
            .ok_or(PrimitiveError::Internal)?;
        if let Some(ref active) = device.active {
            return Ok(active.id);
        }
        let ratchet = DoubleRatchetState::init_bob(sk, local_dh, crate::ratchet::DEFAULT_MAX_SKIP);
        let id = new_session_id()?;
        device.active = Some(SessionRecord {
            id,
            status: SessionStatus::Active,
            ratchet,
            timestamp: now,
        });
        Ok(id)
    }

    /// Sesame §3.1 — delete stale records older than [`MAX_LATENCY_SECS`].
    pub fn sweep_stale(&mut self, now: u64) {
        self.users.retain(|_, user| {
            if user.stale {
                if let Some(ts) = user.stale_timestamp {
                    if now.saturating_sub(ts) > MAX_LATENCY_SECS {
                        return false;
                    }
                }
            }
            user.devices.retain(|_, dev| {
                if dev.stale {
                    if let Some(ts) = dev.stale_timestamp {
                        return now.saturating_sub(ts) <= MAX_LATENCY_SECS;
                    }
                }
                true
            });
            !user.devices.is_empty()
        });
    }

    /// Mark a device record stale (Sesame §3.3 step 6).
    pub fn mark_device_stale(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        now: u64,
    ) -> Result<(), PrimitiveError> {
        let dev = self
            .users
            .get_mut(remote_user)
            .and_then(|u| u.devices.get_mut(remote_device))
            .ok_or(PrimitiveError::Internal)?;
        dev.stale = true;
        dev.stale_timestamp = Some(now);
        Ok(())
    }

    /// Process an inbound message that may activate an inactive session
    /// or create a matching session (Bob side after PQXDH).
    pub fn receive_on_session(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        session_id: &SessionId,
    ) -> Result<(), PrimitiveError> {
        let device = self
            .users
            .get_mut(remote_user)
            .and_then(|u| u.devices.get_mut(remote_device))
            .ok_or(PrimitiveError::Internal)?;
        // If the session is inactive, promote it
        if device.inactive.iter().any(|s| s.id == *session_id) {
            device.activate(session_id)?;
        }
        Ok(())
    }

    /// Explicitly mark a session failed (crypto failure, etc.).
    pub fn mark_failed(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        session_id: &SessionId,
    ) -> Result<(), PrimitiveError> {
        let device = self
            .users
            .get_mut(remote_user)
            .and_then(|u| u.devices.get_mut(remote_device))
            .ok_or(PrimitiveError::Internal)?;
        if let Some(ref mut active) = device.active {
            if active.id == *session_id {
                active.status = SessionStatus::Failed;
                return Ok(());
            }
        }
        for s in device.inactive.iter_mut() {
            if s.id == *session_id {
                s.status = SessionStatus::Failed;
                return Ok(());
            }
        }
        Err(PrimitiveError::Internal)
    }

    /// Acknowledge a remote identity change (user verified new safety number).
    pub fn acknowledge_identity(
        &mut self,
        remote_user: &UserId,
        new_identity: IdentityMaterial,
    ) -> Result<(), PrimitiveError> {
        let user = self
            .users
            .get_mut(remote_user)
            .ok_or(PrimitiveError::Internal)?;
        user.identity_tracker.acknowledge(new_identity);
        Ok(())
    }

    /// Current identity state for a remote user.
    pub fn identity_state(
        &self,
        remote_user: &UserId,
        observed: &IdentityMaterial,
    ) -> Result<IdentityState, PrimitiveError> {
        let user = self
            .users
            .get(remote_user)
            .ok_or(PrimitiveError::Internal)?;
        Ok(user.identity_tracker.observe(observed))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn ensure_user_device(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        remote_identity: &IdentityMaterial,
        now: u64,
    ) -> Result<(), PrimitiveError> {
        if !self.users.contains_key(remote_user) {
            if self.users.len() >= MAX_USERS {
                return Err(PrimitiveError::InvalidLength);
            }
            self.users.insert(
                remote_user.clone(),
                UserRecord {
                    user_id: remote_user.clone(),
                    devices: HashMap::new(),
                    identity_tracker: IdentityTracker::new(),
                    stale: false,
                    stale_timestamp: None,
                },
            );
        }
        let user = self
            .users
            .get_mut(remote_user)
            .ok_or(PrimitiveError::Internal)?;
        if !user.devices.contains_key(remote_device) {
            if user.devices.len() >= MAX_DEVICES_PER_USER {
                return Err(PrimitiveError::InvalidLength);
            }
            user.devices.insert(
                remote_device.clone(),
                DeviceRecord {
                    device_id: remote_device.clone(),
                    identity: Some(remote_identity.clone()),
                    active: None,
                    inactive: VecDeque::new(),
                    stale: false,
                    stale_timestamp: None,
                },
            );
        }
        let _ = now;
        Ok(())
    }
}

fn new_session_id() -> Result<SessionId, PrimitiveError> {
    let mut id = [0u8; 16];
    crate::primitives::random::fill_random(&mut id)?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// Deterministic simulations
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::IdentityMaterial;
    use crate::primitives::x25519::X25519Secret;

    fn id_material(seed: u8) -> IdentityMaterial {
        let mut b = [seed; 32];
        if b == [0u8; 32] {
            b[0] = 1;
        }
        IdentityMaterial {
            identity_key: X25519Secret::from_bytes(b).public_key(),
            device_id: Some(vec![seed]),
        }
    }

    fn sk(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn single_device_outbound_creates_initiating() {
        let local = id_material(1);
        let remote = id_material(2);
        let mut mgr = SessionManager::new(b"user-a".to_vec(), b"dev-a1".to_vec(), local);
        let bob_dh = X25519Secret::generate().unwrap();
        let sid = mgr
            .prepare_outbound(
                &b"user-b".to_vec(),
                &b"dev-b1".to_vec(),
                &remote,
                &sk(9),
                &bob_dh.public_key(),
                1000,
            )
            .unwrap();
        assert_eq!(mgr.initiating_count, 1);
        mgr.confirm_session(&b"user-b".to_vec(), &b"dev-b1".to_vec(), &sid)
            .unwrap();
        assert_eq!(mgr.initiating_count, 0);
    }

    #[test]
    fn device_limit_enforced() {
        let local = id_material(1);
        let mut mgr = SessionManager::new(b"user-a".to_vec(), b"dev-a1".to_vec(), local);
        let bob_dh = X25519Secret::generate().unwrap();
        for i in 0..MAX_DEVICES_PER_USER {
            let remote = id_material(10 + i as u8);
            let dev = vec![i as u8];
            mgr.prepare_outbound(
                &b"user-b".to_vec(),
                &dev,
                &remote,
                &sk(9),
                &bob_dh.public_key(),
                1000 + i as u64,
            )
            .unwrap();
        }
        // One more must fail
        let remote = id_material(99);
        let err = mgr.prepare_outbound(
            &b"user-b".to_vec(),
            &vec![99u8],
            &remote,
            &sk(9),
            &bob_dh.public_key(),
            2000,
        );
        assert!(err.is_err());
    }

    #[test]
    fn identity_change_blocks_outbound() {
        let local = id_material(1);
        let remote1 = id_material(2);
        let mut mgr = SessionManager::new(b"user-a".to_vec(), b"dev-a1".to_vec(), local);
        let bob_dh = X25519Secret::generate().unwrap();
        mgr.prepare_outbound(
            &b"user-b".to_vec(),
            &b"dev-b1".to_vec(),
            &remote1,
            &sk(9),
            &bob_dh.public_key(),
            1000,
        )
        .unwrap();
        // Acknowledge so tracker has a baseline
        mgr.acknowledge_identity(&b"user-b".to_vec(), remote1.clone())
            .unwrap();

        // New identity (SIM-swap style)
        let remote2 = id_material(3);
        let err = mgr.prepare_outbound(
            &b"user-b".to_vec(),
            &b"dev-b1".to_vec(),
            &remote2,
            &sk(9),
            &bob_dh.public_key(),
            2000,
        );
        assert!(err.is_err());

        // After explicit ack, allowed again
        mgr.acknowledge_identity(&b"user-b".to_vec(), remote2.clone())
            .unwrap();
        let ok = mgr.prepare_outbound(
            &b"user-b".to_vec(),
            &b"dev-b1".to_vec(),
            &remote2,
            &sk(9),
            &bob_dh.public_key(),
            3000,
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn multi_device_data_model() {
        // Data model holds multiple devices for one user without special-casing.
        let local = id_material(1);
        let mut mgr = SessionManager::new(b"user-a".to_vec(), b"dev-a1".to_vec(), local);
        let bob_dh = X25519Secret::generate().unwrap();
        for (i, seed) in [(1u8, 20u8), (2, 21), (3, 22)] {
            let remote = id_material(seed);
            mgr.prepare_outbound(
                &b"user-b".to_vec(),
                &vec![i],
                &remote,
                &sk(9),
                &bob_dh.public_key(),
                1000 + i as u64,
            )
            .unwrap();
        }
        let user = mgr.users.get(&b"user-b".to_vec()).unwrap();
        assert_eq!(user.devices.len(), 3);
    }
}

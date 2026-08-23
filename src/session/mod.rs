//! Sesame-style multi-device session manager.
//!
//! This module remains a transport/session experiment; production application
//! code should use `engine::VoiceChatCryptoEngine`. It is nevertheless hardened
//! so direct library use cannot silently replace a device identity, allocate
//! unbounded identifiers, or permanently leak initiating-session quota.

pub mod mailbox;
#[cfg(any(test, feature = "sesame"))]
pub mod sesame;

use std::collections::{HashMap, VecDeque};

use crate::fingerprint::{
    validate_identity_material, IdentityMaterial, IdentityState, IdentityTracker,
};
use crate::primitives::error::PrimitiveError;
use crate::ratchet::DoubleRatchetState;

pub const MAX_DEVICES_PER_USER: usize = 10;
pub const MAX_SESSIONS_PER_DEVICE: usize = 8;
pub const MAX_USERS: usize = 10_000;
pub const MAX_RESEND_ATTEMPTS: u32 = 5;
pub const MAX_LATENCY_SECS: u64 = 86_400;
pub const MAX_INITIATING_SESSIONS: usize = 64;
pub const MAX_USER_ID_LEN: usize = 4096;
pub const MAX_DEVICE_ID_LEN: usize = 4096;

pub type UserId = Vec<u8>;
pub type DeviceId = Vec<u8>;
pub type SessionId = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Initiating,
    Active,
    Inactive,
    Failed,
}

pub struct SessionRecord {
    pub id: SessionId,
    pub status: SessionStatus,
    pub ratchet: DoubleRatchetState,
    pub timestamp: u64,
}

pub struct DeviceRecord {
    pub device_id: DeviceId,
    /// First-seen/current cryptographic identity for this application device.
    pub identity: Option<IdentityMaterial>,
    /// Identity trust is tracked per device. A user may legitimately own
    /// multiple devices with different identity keys.
    pub identity_tracker: IdentityTracker,
    pub active: Option<SessionRecord>,
    pub inactive: VecDeque<SessionRecord>,
    pub stale: bool,
    pub stale_timestamp: Option<u64>,
}

impl DeviceRecord {
    fn session_count(&self) -> usize {
        self.inactive.len() + usize::from(self.active.is_some())
    }

    fn activate(&mut self, session_id: &SessionId) -> Result<(), PrimitiveError> {
        if self.active.as_ref().is_some_and(|active| active.id == *session_id) {
            return Ok(());
        }
        let pos = self
            .inactive
            .iter()
            .position(|session| session.id == *session_id)
            .ok_or(PrimitiveError::Internal)?;
        let mut new_active = self
            .inactive
            .remove(pos)
            .ok_or(PrimitiveError::Internal)?;
        new_active.status = SessionStatus::Active;
        if let Some(mut old) = self.active.take() {
            old.status = SessionStatus::Inactive;
            self.inactive.push_front(old);
        }
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
    /// Legacy user-level tracker retained for API compatibility only. Security
    /// gates use the per-device tracker above because devices may have distinct
    /// identity keys.
    pub identity_tracker: IdentityTracker,
    pub stale: bool,
    pub stale_timestamp: Option<u64>,
}

pub struct SessionManager {
    pub local_user_id: UserId,
    pub local_device_id: DeviceId,
    pub local_identity: IdentityMaterial,
    pub(crate) users: HashMap<UserId, UserRecord>,
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

    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    pub fn prepare_outbound(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        remote_identity: &IdentityMaterial,
        sk: &[u8; 32],
        remote_dh_public: &crate::primitives::x25519::X25519Public,
        now: u64,
    ) -> Result<SessionId, PrimitiveError> {
        self.ensure_user_device(remote_user, remote_device, remote_identity)?;
        self.ensure_device_identity(remote_user, remote_device, remote_identity)?;

        let can_reuse = self
            .users
            .get(remote_user)
            .and_then(|user| user.devices.get(remote_device))
            .and_then(|device| device.active.as_ref())
            .filter(|active| {
                matches!(active.status, SessionStatus::Active | SessionStatus::Initiating)
            })
            .map(|active| active.id);
        if let Some(id) = can_reuse {
            return Ok(id);
        }

        if self.initiating_count >= MAX_INITIATING_SESSIONS {
            return Err(PrimitiveError::LimitExceeded);
        }
        let id = self.new_unique_session_id()?;
        let ratchet =
            DoubleRatchetState::init_alice(sk, remote_dh_public, crate::ratchet::DEFAULT_MAX_SKIP)?;
        let device = self
            .users
            .get_mut(remote_user)
            .and_then(|user| user.devices.get_mut(remote_device))
            .ok_or(PrimitiveError::Internal)?;
        if device.session_count() >= MAX_SESSIONS_PER_DEVICE {
            device.inactive.pop_back();
        }
        device.active = Some(SessionRecord {
            id,
            status: SessionStatus::Initiating,
            ratchet,
            timestamp: now,
        });
        self.initiating_count = self
            .initiating_count
            .checked_add(1)
            .ok_or(PrimitiveError::LimitExceeded)?;
        Ok(id)
    }

    pub fn confirm_session(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        session_id: &SessionId,
    ) -> Result<(), PrimitiveError> {
        validate_remote_ids(remote_user, remote_device)?;
        let device = self
            .users
            .get_mut(remote_user)
            .and_then(|user| user.devices.get_mut(remote_device))
            .ok_or(PrimitiveError::Internal)?;
        if let Some(active) = device.active.as_mut() {
            if active.id == *session_id && active.status == SessionStatus::Initiating {
                active.status = SessionStatus::Active;
                self.initiating_count = self.initiating_count.saturating_sub(1);
            }
        }
        Ok(())
    }

    pub fn prepare_inbound(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        remote_identity: &IdentityMaterial,
        sk: &[u8; 32],
        local_dh: crate::primitives::x25519::X25519Secret,
        now: u64,
    ) -> Result<SessionId, PrimitiveError> {
        self.ensure_user_device(remote_user, remote_device, remote_identity)?;
        self.ensure_device_identity(remote_user, remote_device, remote_identity)?;
        if let Some(id) = self
            .users
            .get(remote_user)
            .and_then(|user| user.devices.get(remote_device))
            .and_then(|device| device.active.as_ref())
            .filter(|active| active.status != SessionStatus::Failed)
            .map(|active| active.id)
        {
            return Ok(id);
        }

        let id = self.new_unique_session_id()?;
        let ratchet = DoubleRatchetState::init_bob(sk, local_dh, crate::ratchet::DEFAULT_MAX_SKIP);
        let device = self
            .users
            .get_mut(remote_user)
            .and_then(|user| user.devices.get_mut(remote_device))
            .ok_or(PrimitiveError::Internal)?;
        if device.session_count() >= MAX_SESSIONS_PER_DEVICE {
            device.inactive.pop_back();
        }
        device.active = Some(SessionRecord {
            id,
            status: SessionStatus::Active,
            ratchet,
            timestamp: now,
        });
        Ok(id)
    }

    pub fn sweep_stale(&mut self, now: u64) {
        self.users.retain(|_, user| {
            if user.stale
                && user
                    .stale_timestamp
                    .is_some_and(|ts| now.saturating_sub(ts) > MAX_LATENCY_SECS)
            {
                return false;
            }
            user.devices.retain(|_, device| {
                !device.stale
                    || device
                        .stale_timestamp
                        .is_none_or(|ts| now.saturating_sub(ts) <= MAX_LATENCY_SECS)
            });
            !user.devices.is_empty()
        });
        self.recompute_initiating_count();
    }

    pub fn mark_device_stale(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        now: u64,
    ) -> Result<(), PrimitiveError> {
        validate_remote_ids(remote_user, remote_device)?;
        let device = self
            .users
            .get_mut(remote_user)
            .and_then(|user| user.devices.get_mut(remote_device))
            .ok_or(PrimitiveError::Internal)?;
        device.stale = true;
        device.stale_timestamp = Some(now);
        Ok(())
    }

    pub fn receive_on_session(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        session_id: &SessionId,
    ) -> Result<(), PrimitiveError> {
        validate_remote_ids(remote_user, remote_device)?;
        let device = self
            .users
            .get_mut(remote_user)
            .and_then(|user| user.devices.get_mut(remote_device))
            .ok_or(PrimitiveError::Internal)?;
        if device.inactive.iter().any(|session| session.id == *session_id) {
            device.activate(session_id)?;
            self.recompute_initiating_count();
        }
        Ok(())
    }

    pub fn mark_failed(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        session_id: &SessionId,
    ) -> Result<(), PrimitiveError> {
        validate_remote_ids(remote_user, remote_device)?;
        let device = self
            .users
            .get_mut(remote_user)
            .and_then(|user| user.devices.get_mut(remote_device))
            .ok_or(PrimitiveError::Internal)?;
        let mut found = false;
        if let Some(active) = device.active.as_mut() {
            if active.id == *session_id {
                active.status = SessionStatus::Failed;
                found = true;
            }
        }
        if !found {
            if let Some(session) = device
                .inactive
                .iter_mut()
                .find(|session| session.id == *session_id)
            {
                session.status = SessionStatus::Failed;
                found = true;
            }
        }
        if !found {
            return Err(PrimitiveError::Internal);
        }
        self.recompute_initiating_count();
        Ok(())
    }

    /// Legacy single-device acknowledgement. If a user has multiple devices,
    /// the target is ambiguous and callers must use `acknowledge_device_identity`.
    pub fn acknowledge_identity(
        &mut self,
        remote_user: &UserId,
        new_identity: IdentityMaterial,
    ) -> Result<(), PrimitiveError> {
        validate_user_id(remote_user)?;
        validate_identity_material(&new_identity)?;
        let user = self
            .users
            .get_mut(remote_user)
            .ok_or(PrimitiveError::Internal)?;
        if user.devices.len() != 1 {
            return Err(PrimitiveError::InvalidLength);
        }
        let device = user
            .devices
            .values_mut()
            .next()
            .ok_or(PrimitiveError::Internal)?;
        device.identity_tracker.acknowledge(new_identity.clone());
        device.identity = Some(new_identity.clone());
        user.identity_tracker.acknowledge(new_identity);
        Ok(())
    }

    pub fn acknowledge_device_identity(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        new_identity: IdentityMaterial,
    ) -> Result<(), PrimitiveError> {
        validate_remote_ids(remote_user, remote_device)?;
        validate_identity_material(&new_identity)?;
        let user = self
            .users
            .get_mut(remote_user)
            .ok_or(PrimitiveError::Internal)?;
        let device = user
            .devices
            .get_mut(remote_device)
            .ok_or(PrimitiveError::Internal)?;
        device.identity_tracker.acknowledge(new_identity.clone());
        device.identity = Some(new_identity);
        Ok(())
    }

    /// Legacy user-level identity state. Multi-device users are ambiguous.
    pub fn identity_state(
        &self,
        remote_user: &UserId,
        observed: &IdentityMaterial,
    ) -> Result<IdentityState, PrimitiveError> {
        validate_user_id(remote_user)?;
        validate_identity_material(observed)?;
        let user = self.users.get(remote_user).ok_or(PrimitiveError::Internal)?;
        if user.devices.len() != 1 {
            return Err(PrimitiveError::InvalidLength);
        }
        let device = user.devices.values().next().ok_or(PrimitiveError::Internal)?;
        Ok(device.identity_tracker.observe(observed))
    }

    pub fn device_identity_state(
        &self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        observed: &IdentityMaterial,
    ) -> Result<IdentityState, PrimitiveError> {
        validate_remote_ids(remote_user, remote_device)?;
        validate_identity_material(observed)?;
        let device = self
            .users
            .get(remote_user)
            .and_then(|user| user.devices.get(remote_device))
            .ok_or(PrimitiveError::Internal)?;
        if device
            .identity
            .as_ref()
            .is_some_and(|first_seen| first_seen != observed)
            && matches!(device.identity_tracker.observe(observed), IdentityState::Unknown)
        {
            return Ok(IdentityState::IdentityChanged {
                previous: device.identity.clone().ok_or(PrimitiveError::Internal)?,
                current: observed.clone(),
                reason: identity_change_reason(
                    device.identity.as_ref().ok_or(PrimitiveError::Internal)?,
                    observed,
                ),
            });
        }
        Ok(device.identity_tracker.observe(observed))
    }

    fn ensure_user_device(
        &mut self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        remote_identity: &IdentityMaterial,
    ) -> Result<(), PrimitiveError> {
        validate_remote_ids(remote_user, remote_device)?;
        validate_identity_material(remote_identity)?;

        if let Some(user) = self.users.get(remote_user) {
            if let Some(device) = user.devices.get(remote_device) {
                if device
                    .identity
                    .as_ref()
                    .is_some_and(|first_seen| first_seen != remote_identity)
                {
                    return Err(PrimitiveError::Internal);
                }
                return Ok(());
            }
            if user.devices.len() >= MAX_DEVICES_PER_USER {
                return Err(PrimitiveError::LimitExceeded);
            }
        } else if self.users.len() >= MAX_USERS {
            return Err(PrimitiveError::LimitExceeded);
        }

        if !self.users.contains_key(remote_user) {
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
        user.devices.insert(
            remote_device.clone(),
            DeviceRecord {
                device_id: remote_device.clone(),
                identity: Some(remote_identity.clone()),
                identity_tracker: IdentityTracker::new(),
                active: None,
                inactive: VecDeque::new(),
                stale: false,
                stale_timestamp: None,
            },
        );
        Ok(())
    }

    fn ensure_device_identity(
        &self,
        remote_user: &UserId,
        remote_device: &DeviceId,
        remote_identity: &IdentityMaterial,
    ) -> Result<(), PrimitiveError> {
        let state = self.device_identity_state(remote_user, remote_device, remote_identity)?;
        if matches!(state, IdentityState::IdentityChanged { .. }) {
            return Err(PrimitiveError::Internal);
        }
        Ok(())
    }

    fn recompute_initiating_count(&mut self) {
        self.initiating_count = self
            .users
            .values()
            .flat_map(|user| user.devices.values())
            .map(|device| {
                usize::from(
                    device
                        .active
                        .as_ref()
                        .is_some_and(|session| session.status == SessionStatus::Initiating),
                ) + device
                    .inactive
                    .iter()
                    .filter(|session| session.status == SessionStatus::Initiating)
                    .count()
            })
            .sum();
    }

    fn new_unique_session_id(&self) -> Result<SessionId, PrimitiveError> {
        for _ in 0..8 {
            let mut id = [0u8; 16];
            crate::primitives::random::fill_random(&mut id)?;
            if id != [0u8; 16] && !self.session_id_exists(&id) {
                return Ok(id);
            }
        }
        Err(PrimitiveError::Internal)
    }

    fn session_id_exists(&self, id: &SessionId) -> bool {
        self.users.values().any(|user| {
            user.devices.values().any(|device| {
                device.active.as_ref().is_some_and(|session| session.id == *id)
                    || device.inactive.iter().any(|session| session.id == *id)
            })
        })
    }
}

fn validate_user_id(user: &[u8]) -> Result<(), PrimitiveError> {
    if user.is_empty() || user.len() > MAX_USER_ID_LEN {
        Err(PrimitiveError::InvalidLength)
    } else {
        Ok(())
    }
}

fn validate_device_id(device: &[u8]) -> Result<(), PrimitiveError> {
    if device.is_empty() || device.len() > MAX_DEVICE_ID_LEN {
        Err(PrimitiveError::InvalidLength)
    } else {
        Ok(())
    }
}

fn validate_remote_ids(user: &[u8], device: &[u8]) -> Result<(), PrimitiveError> {
    validate_user_id(user)?;
    validate_device_id(device)
}

fn identity_change_reason(
    previous: &IdentityMaterial,
    current: &IdentityMaterial,
) -> crate::fingerprint::IdentityChangeReason {
    use crate::fingerprint::IdentityChangeReason;
    let key_changed = previous.identity_key.to_bytes() != current.identity_key.to_bytes();
    let device_changed = previous.device_id != current.device_id;
    match (key_changed, device_changed) {
        (true, true) => IdentityChangeReason::Both,
        (true, false) => IdentityChangeReason::IdentityKeyChanged,
        (false, true) => IdentityChangeReason::DeviceIdChanged,
        (false, false) => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::x25519::X25519Secret;

    fn id_material(seed: u8) -> IdentityMaterial {
        let mut bytes = [seed; 32];
        if bytes == [0u8; 32] {
            bytes[0] = 1;
        }
        IdentityMaterial {
            identity_key: X25519Secret::from_bytes(bytes).public_key(),
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
    fn oversized_remote_id_is_rejected_before_insertion() {
        let local = id_material(1);
        let remote = id_material(2);
        let mut mgr = SessionManager::new(b"user-a".to_vec(), b"dev-a1".to_vec(), local);
        let bob_dh = X25519Secret::generate().unwrap();
        let oversized = vec![7u8; MAX_USER_ID_LEN + 1];
        assert!(mgr
            .prepare_outbound(
                &oversized,
                &b"dev-b1".to_vec(),
                &remote,
                &sk(9),
                &bob_dh.public_key(),
                1,
            )
            .is_err());
        assert_eq!(mgr.user_count(), 0);
    }

    #[test]
    fn first_seen_identity_replacement_is_blocked_even_before_ack() {
        let local = id_material(1);
        let remote1 = id_material(2);
        let remote2 = id_material(3);
        let mut mgr = SessionManager::new(b"user-a".to_vec(), b"dev-a1".to_vec(), local);
        let bob_dh = X25519Secret::generate().unwrap();
        mgr.prepare_outbound(
            &b"user-b".to_vec(),
            &b"dev-b1".to_vec(),
            &remote1,
            &sk(9),
            &bob_dh.public_key(),
            1,
        )
        .unwrap();
        assert!(mgr
            .prepare_outbound(
                &b"user-b".to_vec(),
                &b"dev-b1".to_vec(),
                &remote2,
                &sk(9),
                &bob_dh.public_key(),
                2,
            )
            .is_err());
    }

    #[test]
    fn explicit_single_device_ack_allows_replacement() {
        let local = id_material(1);
        let remote1 = id_material(2);
        let remote2 = id_material(3);
        let mut mgr = SessionManager::new(b"user-a".to_vec(), b"dev-a1".to_vec(), local);
        let bob_dh = X25519Secret::generate().unwrap();
        mgr.prepare_outbound(
            &b"user-b".to_vec(),
            &b"dev-b1".to_vec(),
            &remote1,
            &sk(9),
            &bob_dh.public_key(),
            1,
        )
        .unwrap();
        mgr.acknowledge_identity(&b"user-b".to_vec(), remote2.clone())
            .unwrap();
        assert!(mgr
            .prepare_outbound(
                &b"user-b".to_vec(),
                &b"dev-b1".to_vec(),
                &remote2,
                &sk(9),
                &bob_dh.public_key(),
                2,
            )
            .is_ok());
    }

    #[test]
    fn multi_device_ack_requires_device_specific_api() {
        let local = id_material(1);
        let mut mgr = SessionManager::new(b"user-a".to_vec(), b"dev-a1".to_vec(), local);
        let bob_dh = X25519Secret::generate().unwrap();
        let a = id_material(2);
        let b = id_material(3);
        mgr.prepare_outbound(
            &b"user-b".to_vec(),
            &b"d1".to_vec(),
            &a,
            &sk(9),
            &bob_dh.public_key(),
            1,
        )
        .unwrap();
        mgr.prepare_outbound(
            &b"user-b".to_vec(),
            &b"d2".to_vec(),
            &b,
            &sk(9),
            &bob_dh.public_key(),
            1,
        )
        .unwrap();
        assert!(mgr.acknowledge_identity(&b"user-b".to_vec(), a).is_err());
    }

    #[test]
    fn stale_sweep_reclaims_initiating_quota() {
        let local = id_material(1);
        let remote = id_material(2);
        let mut mgr = SessionManager::new(b"user-a".to_vec(), b"dev-a1".to_vec(), local);
        let bob_dh = X25519Secret::generate().unwrap();
        mgr.prepare_outbound(
            &b"user-b".to_vec(),
            &b"dev-b1".to_vec(),
            &remote,
            &sk(9),
            &bob_dh.public_key(),
            1,
        )
        .unwrap();
        assert_eq!(mgr.initiating_count, 1);
        mgr.mark_device_stale(&b"user-b".to_vec(), &b"dev-b1".to_vec(), 1)
            .unwrap();
        mgr.sweep_stale(1 + MAX_LATENCY_SECS + 1);
        assert_eq!(mgr.initiating_count, 0);
    }

    #[test]
    fn device_limit_enforced() {
        let local = id_material(1);
        let mut mgr = SessionManager::new(b"user-a".to_vec(), b"dev-a1".to_vec(), local);
        let bob_dh = X25519Secret::generate().unwrap();
        for i in 0..MAX_DEVICES_PER_USER {
            let remote = id_material(10 + i as u8);
            mgr.prepare_outbound(
                &b"user-b".to_vec(),
                &vec![i as u8],
                &remote,
                &sk(9),
                &bob_dh.public_key(),
                1000 + i as u64,
            )
            .unwrap();
        }
        assert!(mgr
            .prepare_outbound(
                &b"user-b".to_vec(),
                &vec![99u8],
                &id_material(99),
                &sk(9),
                &bob_dh.public_key(),
                2000,
            )
            .is_err());
    }
}

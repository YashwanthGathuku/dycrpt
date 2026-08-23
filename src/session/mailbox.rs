//! Transport-agnostic mailbox (Sesame Rev 2 §2.2 / §5.1).
//!
//! The real transport implements [`Directory`]. `MemoryDirectory` is a bounded
//! simulation backend; it deliberately rejects silent identity replacement and
//! attacker-sized identifiers/mailboxes so tests exercise fail-closed behavior.

use super::{
    DeviceId, UserId, MAX_DEVICE_ID_LEN, MAX_DEVICES_PER_USER, MAX_USER_ID_LEN, MAX_USERS,
};
use crate::primitives::error::PrimitiveError;
use crate::primitives::x25519::X25519Public;

pub const MAX_MAILBOX_MESSAGES: usize = 4096;
pub const MAX_MAILBOX_HEADER_LEN: usize = 64 * 1024;
pub const MAX_MAILBOX_CIPHERTEXT_LEN: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailboxBody {
    Encrypted {
        message_id: [u8; 16],
        session_id: [u8; 16],
        header: Vec<u8>,
        ciphertext: Vec<u8>,
        initiation: bool,
    },
    RetryRequest {
        message_id: [u8; 16],
    },
    DeliveryReceipt {
        message_id: [u8; 16],
    },
}

#[derive(Clone, Debug)]
pub struct MailboxEnvelope {
    pub from_user: UserId,
    pub from_device: DeviceId,
    pub body: MailboxBody,
}

pub trait Directory {
    fn register(
        &mut self,
        user: UserId,
        device: DeviceId,
        identity_public: [u8; 32],
    ) -> Result<(), PrimitiveError>;

    fn query_devices(&self, user: &UserId) -> Result<Vec<(DeviceId, [u8; 32])>, PrimitiveError>;

    fn send(
        &mut self,
        to_user: &UserId,
        to_device: &DeviceId,
        env: MailboxEnvelope,
    ) -> Result<(), PrimitiveError>;

    fn fetch(&mut self, user: &UserId, device: &DeviceId) -> Vec<MailboxEnvelope>;
}

#[derive(Default)]
pub struct MemoryDirectory {
    devices: std::collections::HashMap<UserId, Vec<(DeviceId, [u8; 32])>>,
    boxes: std::collections::HashMap<(UserId, DeviceId), Vec<MailboxEnvelope>>,
}

impl Directory for MemoryDirectory {
    fn register(
        &mut self,
        user: UserId,
        device: DeviceId,
        identity_public: [u8; 32],
    ) -> Result<(), PrimitiveError> {
        validate_ids(&user, &device)?;
        X25519Public::from_bytes(identity_public)?;

        if let Some(existing) = self.devices.get(&user) {
            if let Some((_, old_identity)) = existing.iter().find(|(id, _)| id == &device) {
                if old_identity != &identity_public {
                    return Err(PrimitiveError::InvalidPublicKey);
                }
                return Ok(());
            }
            if existing.len() >= MAX_DEVICES_PER_USER {
                return Err(PrimitiveError::LimitExceeded);
            }
        } else if self.devices.len() >= MAX_USERS {
            return Err(PrimitiveError::LimitExceeded);
        }

        self.devices
            .entry(user.clone())
            .or_default()
            .push((device.clone(), identity_public));
        self.boxes.entry((user, device)).or_default();
        Ok(())
    }

    fn query_devices(&self, user: &UserId) -> Result<Vec<(DeviceId, [u8; 32])>, PrimitiveError> {
        validate_user(user)?;
        self.devices
            .get(user)
            .cloned()
            .ok_or(PrimitiveError::Internal)
    }

    fn send(
        &mut self,
        to_user: &UserId,
        to_device: &DeviceId,
        env: MailboxEnvelope,
    ) -> Result<(), PrimitiveError> {
        validate_ids(to_user, to_device)?;
        validate_ids(&env.from_user, &env.from_device)?;
        validate_body(&env.body)?;
        let mailbox = self
            .boxes
            .get_mut(&(to_user.clone(), to_device.clone()))
            .ok_or(PrimitiveError::Internal)?;
        if mailbox.len() >= MAX_MAILBOX_MESSAGES {
            return Err(PrimitiveError::LimitExceeded);
        }
        mailbox.push(env);
        Ok(())
    }

    fn fetch(&mut self, user: &UserId, device: &DeviceId) -> Vec<MailboxEnvelope> {
        if validate_ids(user, device).is_err() {
            return Vec::new();
        }
        self.boxes
            .get_mut(&(user.clone(), device.clone()))
            .map(std::mem::take)
            .unwrap_or_default()
    }
}

fn validate_user(user: &[u8]) -> Result<(), PrimitiveError> {
    if user.is_empty() || user.len() > MAX_USER_ID_LEN {
        Err(PrimitiveError::InvalidLength)
    } else {
        Ok(())
    }
}

fn validate_device(device: &[u8]) -> Result<(), PrimitiveError> {
    if device.is_empty() || device.len() > MAX_DEVICE_ID_LEN {
        Err(PrimitiveError::InvalidLength)
    } else {
        Ok(())
    }
}

fn validate_ids(user: &[u8], device: &[u8]) -> Result<(), PrimitiveError> {
    validate_user(user)?;
    validate_device(device)
}

fn validate_body(body: &MailboxBody) -> Result<(), PrimitiveError> {
    match body {
        MailboxBody::Encrypted {
            message_id,
            session_id,
            header,
            ciphertext,
            ..
        } => {
            if *message_id == [0u8; 16]
                || *session_id == [0u8; 16]
                || header.len() > MAX_MAILBOX_HEADER_LEN
                || ciphertext.is_empty()
                || ciphertext.len() > MAX_MAILBOX_CIPHERTEXT_LEN
            {
                return Err(PrimitiveError::InvalidLength);
            }
        }
        MailboxBody::RetryRequest { message_id }
        | MailboxBody::DeliveryReceipt { message_id } => {
            if *message_id == [0u8; 16] {
                return Err(PrimitiveError::InvalidLength);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::x25519::X25519Secret;

    fn public(seed: u8) -> [u8; 32] {
        X25519Secret::from_bytes([seed; 32]).public_key().to_bytes()
    }

    #[test]
    fn registration_does_not_silently_replace_identity() {
        let mut directory = MemoryDirectory::default();
        directory
            .register(b"u".to_vec(), b"d".to_vec(), public(1))
            .unwrap();
        assert!(directory
            .register(b"u".to_vec(), b"d".to_vec(), public(2))
            .is_err());
        assert_eq!(directory.query_devices(&b"u".to_vec()).unwrap()[0].1, public(1));
    }

    #[test]
    fn oversized_registration_is_rejected_before_state_creation() {
        let mut directory = MemoryDirectory::default();
        assert!(directory
            .register(vec![1u8; MAX_USER_ID_LEN + 1], b"d".to_vec(), public(1))
            .is_err());
        assert!(directory.devices.is_empty());
        assert!(directory.boxes.is_empty());
    }

    #[test]
    fn mailbox_message_count_is_bounded() {
        let mut directory = MemoryDirectory::default();
        directory
            .register(b"u".to_vec(), b"d".to_vec(), public(1))
            .unwrap();
        let env = MailboxEnvelope {
            from_user: b"s".to_vec(),
            from_device: b"sd".to_vec(),
            body: MailboxBody::DeliveryReceipt {
                message_id: [1u8; 16],
            },
        };
        for _ in 0..MAX_MAILBOX_MESSAGES {
            directory
                .send(&b"u".to_vec(), &b"d".to_vec(), env.clone())
                .unwrap();
        }
        assert!(directory
            .send(&b"u".to_vec(), &b"d".to_vec(), env)
            .is_err());
    }
}

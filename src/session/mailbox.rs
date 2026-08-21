//! Transport-agnostic mailbox (Sesame Rev 2 §2.2 / §5.1).
//!
//! The real VoiceChat transport implements this trait. Tests use
//! [`MemoryDirectory`].

use super::{DeviceId, UserId};
use crate::primitives::error::PrimitiveError;

/// Unencrypted Sesame control or encrypted payload sitting in a mailbox.
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

/// Server directory + mailboxes. No cryptographic trust.
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
        let list = self.devices.entry(user.clone()).or_default();
        if !list.iter().any(|(d, _)| d == &device) {
            list.push((device.clone(), identity_public));
        }
        self.boxes.entry((user, device)).or_default();
        Ok(())
    }

    fn query_devices(&self, user: &UserId) -> Result<Vec<(DeviceId, [u8; 32])>, PrimitiveError> {
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
        self.boxes
            .get_mut(&(to_user.clone(), to_device.clone()))
            .ok_or(PrimitiveError::Internal)?
            .push(env);
        Ok(())
    }

    fn fetch(&mut self, user: &UserId, device: &DeviceId) -> Vec<MailboxEnvelope> {
        self.boxes
            .get_mut(&(user.clone(), device.clone()))
            .map(std::mem::take)
            .unwrap_or_default()
    }
}

//! Sesame send / receive / retry / delivery-receipt (experimental).
//!
//! This module is compiled only for tests or the explicit `sesame` feature.
//! It is not the production application engine. Retries resend the exact
//! previously emitted ciphertext/header/session tuple; they never re-encrypt a
//! logical message and therefore cannot advance one ratchet while a peer treats
//! the message as an already-delivered duplicate.

use std::collections::VecDeque;

use super::mailbox::{
    Directory, MailboxBody, MailboxEnvelope, MAX_MAILBOX_CIPHERTEXT_LEN,
};
use super::{DeviceId, SessionId, SessionManager, UserId, MAX_RESEND_ATTEMPTS};
use crate::fingerprint::IdentityMaterial;
use crate::primitives::aead::TAG_LEN;
use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::sha256_parts;
use crate::primitives::x25519::X25519Public;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_SEND_RECIPIENTS: usize = 64;
const MAX_PENDING_RECORDS: usize = 4096;
const MAX_RECEIVED_IDS: usize = 4096;
const MAX_SESAME_PLAINTEXT: usize = MAX_MAILBOX_CIPHERTEXT_LEN - TAG_LEN;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct MessageRecord {
    message_id: [u8; 16],
    #[zeroize(skip)]
    recipient_user: UserId,
    #[zeroize(skip)]
    recipient_device: DeviceId,
    #[zeroize(skip)]
    session_id: SessionId,
    attempts: u32,
    header: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceivedId {
    from_user: UserId,
    from_device: DeviceId,
    message_id: [u8; 16],
}

pub struct SesameNode {
    pub user: UserId,
    pub device: DeviceId,
    pub mgr: SessionManager,
    records: Vec<MessageRecord>,
    received: VecDeque<ReceivedId>,
}

impl SesameNode {
    pub fn new(user: UserId, device: DeviceId, mgr: SessionManager) -> Self {
        Self {
            user,
            device,
            mgr,
            records: Vec::new(),
            received: VecDeque::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send<D: Directory>(
        &mut self,
        dir: &mut D,
        recipients: &[UserId],
        plaintext: &[u8],
        remote_identity: &IdentityMaterial,
        sk: &[u8; 32],
        remote_dh: &X25519Public,
        now: u64,
    ) -> Result<Vec<[u8; 16]>, PrimitiveError> {
        if recipients.len() > MAX_SEND_RECIPIENTS || plaintext.len() > MAX_SESAME_PLAINTEXT {
            return Err(PrimitiveError::LimitExceeded);
        }
        let mut ids = Vec::new();
        for user in recipients {
            let devices = match dir.query_devices(user) {
                Ok(devices) => devices,
                Err(_) => continue,
            };
            for (dev, directory_identity) in &devices {
                if user == &self.user && dev == &self.device {
                    continue;
                }
                if directory_identity != &remote_identity.identity_key.to_bytes() {
                    return Err(PrimitiveError::InvalidPublicKey);
                }
                if self.records.len() >= MAX_PENDING_RECORDS {
                    return Err(PrimitiveError::LimitExceeded);
                }

                let sid = self
                    .mgr
                    .prepare_outbound(user, dev, remote_identity, sk, remote_dh, now)?;
                let (header, ciphertext, trial) = {
                    let record = self
                        .mgr
                        .users
                        .get_mut(user)
                        .and_then(|u| u.devices.get_mut(dev))
                        .and_then(|d| d.active.as_mut())
                        .ok_or(PrimitiveError::Internal)?;
                    if record.id != sid {
                        return Err(PrimitiveError::Internal);
                    }
                    let mut trial = record.ratchet.clone_for_trial();
                    let (header, ciphertext) = trial.encrypt(plaintext, b"sesame")?;
                    (header.encode(), ciphertext, trial)
                };
                let message_id = msg_id(&sid, &header, &ciphertext);
                if message_id == [0u8; 16] {
                    return Err(PrimitiveError::Internal);
                }

                dir.send(
                    user,
                    dev,
                    MailboxEnvelope {
                        from_user: self.user.clone(),
                        from_device: self.device.clone(),
                        body: MailboxBody::Encrypted {
                            message_id,
                            session_id: sid,
                            header: header.clone(),
                            ciphertext: ciphertext.clone(),
                            initiation: true,
                        },
                    },
                )?;

                // The transport accepted the exact ciphertext, so commit the
                // speculative ratchet transition and retain those exact bytes
                // for idempotent retry.
                let record = self
                    .mgr
                    .users
                    .get_mut(user)
                    .and_then(|u| u.devices.get_mut(dev))
                    .and_then(|d| d.active.as_mut())
                    .ok_or(PrimitiveError::Internal)?;
                if record.id != sid {
                    return Err(PrimitiveError::Internal);
                }
                record.ratchet = trial;
                self.records.push(MessageRecord {
                    message_id,
                    recipient_user: user.clone(),
                    recipient_device: dev.clone(),
                    session_id: sid,
                    attempts: 1,
                    header,
                    ciphertext,
                });
                ids.push(message_id);
            }
        }
        Ok(ids)
    }

    pub fn receive_all<D: Directory>(
        &mut self,
        dir: &mut D,
        _remote_identity: &IdentityMaterial,
        _now: u64,
    ) -> Result<Vec<Vec<u8>>, PrimitiveError> {
        let inbox = dir.fetch(&self.user, &self.device);
        let mut out = Vec::new();
        for env in inbox {
            match env.body {
                MailboxBody::Encrypted {
                    message_id,
                    session_id,
                    header,
                    ciphertext,
                    ..
                } => {
                    if self.already_received(&env.from_user, &env.from_device, &message_id) {
                        self.send_receipt_best_effort(
                            dir,
                            &env.from_user,
                            &env.from_device,
                            message_id,
                        );
                        continue;
                    }
                    let header = crate::ratchet::Header::decode(&header)?;
                    match self.try_decrypt(
                        &env.from_user,
                        &env.from_device,
                        &session_id,
                        &header,
                        &ciphertext,
                    ) {
                        Ok(plaintext) => {
                            self.mgr.receive_on_session(
                                &env.from_user,
                                &env.from_device,
                                &session_id,
                            )?;
                            self.mgr.confirm_session(
                                &env.from_user,
                                &env.from_device,
                                &session_id,
                            )?;
                            self.remember_received(
                                env.from_user.clone(),
                                env.from_device.clone(),
                                message_id,
                            );
                            // Receipt transport failure must not suppress a
                            // successfully authenticated plaintext. A later
                            // exact retry will hit `received` and resend receipt.
                            self.send_receipt_best_effort(
                                dir,
                                &env.from_user,
                                &env.from_device,
                                message_id,
                            );
                            out.push(plaintext);
                        }
                        Err(_) => {
                            let _ = dir.send(
                                &env.from_user,
                                &env.from_device,
                                MailboxEnvelope {
                                    from_user: self.user.clone(),
                                    from_device: self.device.clone(),
                                    body: MailboxBody::RetryRequest { message_id },
                                },
                            );
                        }
                    }
                }
                MailboxBody::RetryRequest { message_id } => {
                    self.handle_retry(
                        dir,
                        &env.from_user,
                        &env.from_device,
                        message_id,
                    )?;
                }
                MailboxBody::DeliveryReceipt { message_id } => {
                    self.records.retain(|record| {
                        !(record.message_id == message_id
                            && record.recipient_user == env.from_user
                            && record.recipient_device == env.from_device)
                    });
                }
            }
        }
        Ok(out)
    }

    fn try_decrypt(
        &mut self,
        user: &UserId,
        device: &DeviceId,
        session_id: &SessionId,
        header: &crate::ratchet::Header,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PrimitiveError> {
        let device = self
            .mgr
            .users
            .get_mut(user)
            .and_then(|user| user.devices.get_mut(device))
            .ok_or(PrimitiveError::Internal)?;
        if let Some(record) = device.active.as_mut() {
            if record.id == *session_id {
                return record.ratchet.decrypt(header, ciphertext, b"sesame");
            }
        }
        if let Some(record) = device
            .inactive
            .iter_mut()
            .find(|record| record.id == *session_id)
        {
            return record.ratchet.decrypt(header, ciphertext, b"sesame");
        }
        // No compatibility fallback. A wire session id must name the exact
        // state that performs the cryptographic transition.
        Err(PrimitiveError::InvalidLength)
    }

    fn handle_retry<D: Directory>(
        &mut self,
        dir: &mut D,
        from_user: &UserId,
        from_device: &DeviceId,
        message_id: [u8; 16],
    ) -> Result<(), PrimitiveError> {
        let index = self.records.iter().position(|record| {
            record.message_id == message_id
                && &record.recipient_user == from_user
                && &record.recipient_device == from_device
        });
        let Some(index) = index else {
            // A spoofed/misattributed control message cannot consume retry
            // quota or mutate any pending record.
            return Ok(());
        };
        if self.records[index].attempts >= MAX_RESEND_ATTEMPTS {
            return Err(PrimitiveError::LimitExceeded);
        }

        let record = &self.records[index];
        dir.send(
            from_user,
            from_device,
            MailboxEnvelope {
                from_user: self.user.clone(),
                from_device: self.device.clone(),
                body: MailboxBody::Encrypted {
                    message_id: record.message_id,
                    session_id: record.session_id,
                    header: record.header.clone(),
                    ciphertext: record.ciphertext.clone(),
                    initiation: true,
                },
            },
        )?;
        self.records[index].attempts = self.records[index]
            .attempts
            .checked_add(1)
            .ok_or(PrimitiveError::LimitExceeded)?;
        Ok(())
    }

    fn already_received(
        &self,
        from_user: &UserId,
        from_device: &DeviceId,
        message_id: &[u8; 16],
    ) -> bool {
        self.received.iter().any(|record| {
            &record.from_user == from_user
                && &record.from_device == from_device
                && &record.message_id == message_id
        })
    }

    fn remember_received(
        &mut self,
        from_user: UserId,
        from_device: DeviceId,
        message_id: [u8; 16],
    ) {
        if self.received.len() >= MAX_RECEIVED_IDS {
            self.received.pop_front();
        }
        self.received.push_back(ReceivedId {
            from_user,
            from_device,
            message_id,
        });
    }

    fn send_receipt_best_effort<D: Directory>(
        &self,
        dir: &mut D,
        to_user: &UserId,
        to_device: &DeviceId,
        message_id: [u8; 16],
    ) {
        let _ = dir.send(
            to_user,
            to_device,
            MailboxEnvelope {
                from_user: self.user.clone(),
                from_device: self.device.clone(),
                body: MailboxBody::DeliveryReceipt { message_id },
            },
        );
    }
}

fn msg_id(session_id: &SessionId, header: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let digest = sha256_parts(&[b"VoiceChat/Sesame/v2/MessageId", session_id, header, ciphertext]);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::x25519::X25519Secret;
    use crate::session::mailbox::MemoryDirectory;

    fn mat(seed: u8) -> IdentityMaterial {
        let mut bytes = [seed; 32];
        bytes[0] |= 1;
        IdentityMaterial {
            identity_key: X25519Secret::from_bytes(bytes).public_key(),
            device_id: Some(vec![seed]),
        }
    }

    fn setup() -> (
        MemoryDirectory,
        SesameNode,
        SesameNode,
        IdentityMaterial,
        IdentityMaterial,
        X25519Secret,
        [u8; 32],
    ) {
        let alice_id = mat(1);
        let bob_id = mat(2);
        let mut directory = MemoryDirectory::default();
        directory
            .register(
                b"alice".to_vec(),
                b"a1".to_vec(),
                alice_id.identity_key.to_bytes(),
            )
            .unwrap();
        directory
            .register(
                b"bob".to_vec(),
                b"b1".to_vec(),
                bob_id.identity_key.to_bytes(),
            )
            .unwrap();
        let alice = SesameNode::new(
            b"alice".to_vec(),
            b"a1".to_vec(),
            SessionManager::new(b"alice".to_vec(), b"a1".to_vec(), alice_id.clone()),
        );
        let bob = SesameNode::new(
            b"bob".to_vec(),
            b"b1".to_vec(),
            SessionManager::new(b"bob".to_vec(), b"b1".to_vec(), bob_id.clone()),
        );
        (
            directory,
            alice,
            bob,
            alice_id,
            bob_id,
            X25519Secret::generate().unwrap(),
            [9u8; 32],
        )
    }

    #[test]
    fn sesame_send_receive_receipt() {
        let (mut directory, mut alice, mut bob, alice_id, bob_id, bob_dh, sk) = setup();
        alice
            .send(
                &mut directory,
                &[b"bob".to_vec()],
                b"hello-sesame",
                &bob_id,
                &sk,
                &bob_dh.public_key(),
                1,
            )
            .unwrap();
        bob.mgr
            .prepare_inbound(
                &b"alice".to_vec(),
                &b"a1".to_vec(),
                &alice_id,
                &sk,
                X25519Secret::from_bytes(bob_dh.to_bytes()),
                2,
            )
            .unwrap();
        let first = bob.receive_all(&mut directory, &alice_id, 3).unwrap();
        assert_eq!(first, vec![b"hello-sesame".to_vec()]);
        alice.receive_all(&mut directory, &bob_id, 4).unwrap();
        assert!(alice.records.is_empty());
    }

    #[test]
    fn wrong_session_id_does_not_fall_back_to_active_ratchet() {
        let (mut directory, mut alice, mut bob, alice_id, bob_id, bob_dh, sk) = setup();
        alice
            .send(
                &mut directory,
                &[b"bob".to_vec()],
                b"strict-route",
                &bob_id,
                &sk,
                &bob_dh.public_key(),
                1,
            )
            .unwrap();
        bob.mgr
            .prepare_inbound(
                &b"alice".to_vec(),
                &b"a1".to_vec(),
                &alice_id,
                &sk,
                X25519Secret::from_bytes(bob_dh.to_bytes()),
                2,
            )
            .unwrap();

        let mut original = directory.fetch(&b"bob".to_vec(), &b"b1".to_vec());
        assert_eq!(original.len(), 1);
        let original = original.pop().unwrap();
        let mut wrong = original.clone();
        if let MailboxBody::Encrypted { session_id, .. } = &mut wrong.body {
            session_id[0] ^= 0x80;
        }
        directory
            .send(&b"bob".to_vec(), &b"b1".to_vec(), wrong)
            .unwrap();
        directory
            .send(&b"bob".to_vec(), &b"b1".to_vec(), original)
            .unwrap();

        let out = bob.receive_all(&mut directory, &alice_id, 3).unwrap();
        assert_eq!(out, vec![b"strict-route".to_vec()]);
    }

    #[test]
    fn retry_resends_exact_ciphertext_without_ratchet_advance() {
        let (mut directory, mut alice, _bob, _alice_id, bob_id, bob_dh, sk) = setup();
        alice
            .send(
                &mut directory,
                &[b"bob".to_vec()],
                b"retry-me",
                &bob_id,
                &sk,
                &bob_dh.public_key(),
                1,
            )
            .unwrap();
        let record = alice.records[0].clone();
        directory
            .send(
                &b"alice".to_vec(),
                &b"a1".to_vec(),
                MailboxEnvelope {
                    from_user: b"bob".to_vec(),
                    from_device: b"b1".to_vec(),
                    body: MailboxBody::RetryRequest {
                        message_id: record.message_id,
                    },
                },
            )
            .unwrap();
        alice.receive_all(&mut directory, &bob_id, 2).unwrap();

        let sent = directory.fetch(&b"bob".to_vec(), &b"b1".to_vec());
        assert_eq!(sent.len(), 2);
        let encrypted: Vec<_> = sent
            .iter()
            .filter_map(|env| match &env.body {
                MailboxBody::Encrypted {
                    message_id,
                    session_id,
                    header,
                    ciphertext,
                    ..
                } => Some((*message_id, *session_id, header.clone(), ciphertext.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(encrypted.len(), 2);
        assert_eq!(encrypted[0], encrypted[1]);
        assert_eq!(alice.records[0].attempts, 2);
    }

    #[test]
    fn spoofed_receipt_from_wrong_device_does_not_delete_record() {
        let (mut directory, mut alice, _bob, _alice_id, bob_id, bob_dh, sk) = setup();
        alice
            .send(
                &mut directory,
                &[b"bob".to_vec()],
                b"pending",
                &bob_id,
                &sk,
                &bob_dh.public_key(),
                1,
            )
            .unwrap();
        let message_id = alice.records[0].message_id;
        directory
            .send(
                &b"alice".to_vec(),
                &b"a1".to_vec(),
                MailboxEnvelope {
                    from_user: b"bob".to_vec(),
                    from_device: b"wrong-device".to_vec(),
                    body: MailboxBody::DeliveryReceipt { message_id },
                },
            )
            .unwrap();
        alice.receive_all(&mut directory, &bob_id, 2).unwrap();
        assert_eq!(alice.records.len(), 1);
    }

    #[test]
    fn duplicate_exact_message_is_not_delivered_twice() {
        let (mut directory, mut alice, mut bob, alice_id, bob_id, bob_dh, sk) = setup();
        alice
            .send(
                &mut directory,
                &[b"bob".to_vec()],
                b"once",
                &bob_id,
                &sk,
                &bob_dh.public_key(),
                1,
            )
            .unwrap();
        bob.mgr
            .prepare_inbound(
                &b"alice".to_vec(),
                &b"a1".to_vec(),
                &alice_id,
                &sk,
                X25519Secret::from_bytes(bob_dh.to_bytes()),
                2,
            )
            .unwrap();
        let original = directory.fetch(&b"bob".to_vec(), &b"b1".to_vec()).pop().unwrap();
        directory
            .send(&b"bob".to_vec(), &b"b1".to_vec(), original.clone())
            .unwrap();
        assert_eq!(
            bob.receive_all(&mut directory, &alice_id, 3).unwrap(),
            vec![b"once".to_vec()]
        );
        directory
            .send(&b"bob".to_vec(), &b"b1".to_vec(), original)
            .unwrap();
        assert!(bob.receive_all(&mut directory, &alice_id, 4).unwrap().is_empty());
    }
}

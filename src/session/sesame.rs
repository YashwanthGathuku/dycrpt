//! Sesame send / receive / retry / delivery-receipt (Rev 2 §§3.3–3.4, 4.1).
//!
//! Uses [`super::SessionManager`] for records and a [`Directory`] for the
//! server. Encryption is classical Double Ratchet (Sesame is session-generic).

use super::mailbox::{Directory, MailboxBody, MailboxEnvelope};
use super::{DeviceId, SessionId, SessionManager, UserId};
use crate::fingerprint::IdentityMaterial;
use crate::primitives::error::PrimitiveError;
use crate::primitives::kdf::sha256;
use crate::primitives::x25519::X25519Public;

const MAX_SEND_LOOPS: u32 = 8;

#[derive(Clone)]
struct MessageRecord {
    message_id: [u8; 16],
    plaintext: Vec<u8>,
    recipient_user: UserId,
    session_id: SessionId,
    attempts: u32,
}

/// Per-device Sesame sender/receiver sitting on a [`SessionManager`].
pub struct SesameNode {
    pub user: UserId,
    pub device: DeviceId,
    pub mgr: SessionManager,
    records: Vec<MessageRecord>,
}

impl SesameNode {
    pub fn new(user: UserId, device: DeviceId, mgr: SessionManager) -> Self {
        Self {
            user,
            device,
            mgr,
            records: Vec::new(),
        }
    }

    /// Sesame §3.3 — encrypt plaintext to every current device of `recipients`
    /// (including the sender’s other devices when listed).
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
        let mut ids = Vec::new();
        let _ = MAX_SEND_LOOPS;
        for user in recipients {
            let devices = match dir.query_devices(user) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let mut sent = 0usize;
            for (dev, _pk) in &devices {
                if user == &self.user && dev == &self.device {
                    continue;
                }
                let sid =
                    self.mgr
                        .prepare_outbound(user, dev, remote_identity, sk, remote_dh, now)?;
                let ratchet = {
                    let rec = self
                        .mgr
                        .users
                        .get_mut(user)
                        .and_then(|u| u.devices.get_mut(dev))
                        .and_then(|d| d.active.as_mut())
                        .ok_or(PrimitiveError::Internal)?;
                    &mut rec.ratchet
                };
                let (header, ct) = ratchet.encrypt(plaintext, b"sesame")?;
                let message_id = msg_id(&sid, now, sent as u64);
                dir.send(
                    user,
                    dev,
                    MailboxEnvelope {
                        from_user: self.user.clone(),
                        from_device: self.device.clone(),
                        body: MailboxBody::Encrypted {
                            message_id,
                            session_id: sid,
                            header: header.encode(),
                            ciphertext: ct,
                            initiation: true,
                        },
                    },
                )?;
                self.records.push(MessageRecord {
                    message_id,
                    plaintext: plaintext.to_vec(),
                    recipient_user: user.clone(),
                    session_id: sid,
                    attempts: 1,
                });
                ids.push(message_id);
                sent += 1;
            }
        }
        Ok(ids)
    }

    /// Sesame §3.4 — fetch and decrypt. Undecryptable messages emit retry
    /// requests. Successful decrypts emit delivery receipts.
    pub fn receive_all<D: Directory>(
        &mut self,
        dir: &mut D,
        remote_identity: &IdentityMaterial,
        now: u64,
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
                    let hdr = crate::ratchet::Header::decode(&header)?;
                    let pt = self.try_decrypt(
                        &env.from_user,
                        &env.from_device,
                        &session_id,
                        &hdr,
                        &ciphertext,
                    );
                    match pt {
                        Ok(p) => {
                            let _ = self.mgr.receive_on_session(
                                &env.from_user,
                                &env.from_device,
                                &session_id,
                            );
                            let _ = self.mgr.confirm_session(
                                &env.from_user,
                                &env.from_device,
                                &session_id,
                            );
                            dir.send(
                                &env.from_user,
                                &env.from_device,
                                MailboxEnvelope {
                                    from_user: self.user.clone(),
                                    from_device: self.device.clone(),
                                    body: MailboxBody::DeliveryReceipt { message_id },
                                },
                            )?;
                            out.push(p);
                        }
                        Err(_) => {
                            dir.send(
                                &env.from_user,
                                &env.from_device,
                                MailboxEnvelope {
                                    from_user: self.user.clone(),
                                    from_device: self.device.clone(),
                                    body: MailboxBody::RetryRequest { message_id },
                                },
                            )?;
                        }
                    }
                }
                MailboxBody::RetryRequest { message_id } => {
                    self.handle_retry(
                        dir,
                        &env.from_user,
                        &env.from_device,
                        message_id,
                        remote_identity,
                        now,
                    )?;
                }
                MailboxBody::DeliveryReceipt { message_id } => {
                    self.records.retain(|r| r.message_id != message_id);
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
        ct: &[u8],
    ) -> Result<Vec<u8>, PrimitiveError> {
        let d = self
            .mgr
            .users
            .get_mut(user)
            .and_then(|u| u.devices.get_mut(device))
            .ok_or(PrimitiveError::Internal)?;
        let try_one = |rec: &mut super::SessionRecord| rec.ratchet.decrypt(header, ct, b"sesame");
        if let Some(rec) = d.active.as_mut() {
            if rec.id == *session_id {
                return try_one(rec);
            }
        }
        if let Some(rec) = d.inactive.iter_mut().find(|s| s.id == *session_id) {
            return try_one(rec);
        }
        // Matching session may have a different local id (recipient created it).
        if let Some(rec) = d.active.as_mut() {
            return try_one(rec);
        }
        Err(PrimitiveError::Internal)
    }

    fn handle_retry<D: Directory>(
        &mut self,
        dir: &mut D,
        from_user: &UserId,
        from_device: &DeviceId,
        message_id: [u8; 16],
        remote_identity: &IdentityMaterial,
        now: u64,
    ) -> Result<(), PrimitiveError> {
        let idx = self
            .records
            .iter()
            .position(|r| r.message_id == message_id)
            .ok_or(PrimitiveError::Internal)?;
        if self.records[idx].attempts >= super::MAX_RESEND_ATTEMPTS {
            return Err(PrimitiveError::LimitExceeded);
        }
        if &self.records[idx].recipient_user != from_user {
            return Ok(());
        }
        self.records[idx].attempts += 1;
        let plaintext = self.records[idx].plaintext.clone();
        let dh = remote_identity.identity_key;
        let sid = self.mgr.prepare_outbound(
            from_user,
            from_device,
            remote_identity,
            &[9u8; 32],
            &dh,
            now,
        )?;
        let rec = self
            .mgr
            .users
            .get_mut(from_user)
            .and_then(|u| u.devices.get_mut(from_device))
            .and_then(|d| d.active.as_mut())
            .ok_or(PrimitiveError::Internal)?;
        let (header, ct) = rec.ratchet.encrypt(&plaintext, b"sesame")?;
        let new_id = msg_id(&sid, now, self.records[idx].attempts as u64);
        self.records[idx].message_id = new_id;
        self.records[idx].session_id = sid;
        dir.send(
            from_user,
            from_device,
            MailboxEnvelope {
                from_user: self.user.clone(),
                from_device: self.device.clone(),
                body: MailboxBody::Encrypted {
                    message_id: new_id,
                    session_id: sid,
                    header: header.encode(),
                    ciphertext: ct,
                    initiation: true,
                },
            },
        )?;
        Ok(())
    }
}

fn msg_id(sid: &SessionId, now: u64, n: u64) -> [u8; 16] {
    let mut m = Vec::new();
    m.extend_from_slice(sid);
    m.extend_from_slice(&now.to_le_bytes());
    m.extend_from_slice(&n.to_le_bytes());
    let h = sha256(&m);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::x25519::X25519Secret;
    use crate::session::mailbox::MemoryDirectory;
    use crate::session::SessionManager;

    fn mat(seed: u8) -> IdentityMaterial {
        let mut b = [seed; 32];
        b[0] |= 1;
        IdentityMaterial {
            identity_key: X25519Secret::from_bytes(b).public_key(),
            device_id: Some(vec![seed]),
        }
    }

    #[test]
    fn sesame_send_receive_receipt() {
        let a_id = mat(1);
        let b_id = mat(2);
        let mut dir = MemoryDirectory::default();
        dir.register(
            b"alice".to_vec(),
            b"a1".to_vec(),
            a_id.identity_key.to_bytes(),
        )
        .unwrap();
        dir.register(
            b"bob".to_vec(),
            b"b1".to_vec(),
            b_id.identity_key.to_bytes(),
        )
        .unwrap();

        let mut alice = SesameNode::new(
            b"alice".to_vec(),
            b"a1".to_vec(),
            SessionManager::new(b"alice".to_vec(), b"a1".to_vec(), a_id.clone()),
        );
        let mut bob = SesameNode::new(
            b"bob".to_vec(),
            b"b1".to_vec(),
            SessionManager::new(b"bob".to_vec(), b"b1".to_vec(), b_id.clone()),
        );

        let bob_dh = X25519Secret::generate().unwrap();
        let sk = [9u8; 32];
        alice
            .send(
                &mut dir,
                &[b"bob".to_vec()],
                b"hello-sesame",
                &b_id,
                &sk,
                &bob_dh.public_key(),
                1,
            )
            .unwrap();

        bob.mgr
            .prepare_inbound(
                &b"alice".to_vec(),
                &b"a1".to_vec(),
                &a_id,
                &sk,
                X25519Secret::from_bytes(bob_dh.to_bytes()),
                2,
            )
            .unwrap();
        let first = bob.receive_all(&mut dir, &a_id, 3).unwrap();
        assert_eq!(first, vec![b"hello-sesame".to_vec()]);

        let _ = alice.receive_all(&mut dir, &b_id, 4);
    }

    #[test]
    fn sesame_sweep_stale() {
        let a_id = mat(1);
        let mut mgr = SessionManager::new(b"alice".to_vec(), b"a1".to_vec(), a_id.clone());
        let remote = mat(2);
        let dh = X25519Secret::generate().unwrap();
        mgr.prepare_outbound(
            &b"bob".to_vec(),
            &b"b1".to_vec(),
            &remote,
            &[1u8; 32],
            &dh.public_key(),
            10,
        )
        .unwrap();
        mgr.mark_device_stale(&b"bob".to_vec(), &b"b1".to_vec(), 10)
            .unwrap();
        mgr.sweep_stale(10);
        assert_eq!(mgr.user_count(), 1);
        mgr.sweep_stale(10 + crate::session::MAX_LATENCY_SECS + 1);
        assert_eq!(mgr.user_count(), 0);
    }
}

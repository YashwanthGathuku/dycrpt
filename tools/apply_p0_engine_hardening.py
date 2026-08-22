from pathlib import Path

ENGINE = Path("src/engine/mod.rs")
text = ENGINE.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match, found {count}: {old[:120]!r}")
    text = text.replace(old, new, 1)


replace_once(
    "use crate::storage::{MemoryStorage, StateBlob, TransactionalStorage};",
    "use crate::storage::monotonic::{MemoryCounter, MonotonicCounter};\n"
    "use crate::storage::{MemoryStorage, RollbackGuard, StateBlob, StorageEpoch, TransactionalStorage};",
)

replace_once(
    "    storage: MemoryStorage,\n}",
    "    storage: Box<dyn TransactionalStorage>,\n"
    "    monotonic: Box<dyn MonotonicCounter>,\n"
    "    rollback_guard: RollbackGuard,\n"
    "    /// Once a counter has advanced but durable commit outcome is unknown,\n"
    "    /// no more crypto operations are allowed in this process.\n"
    "    storage_poisoned: bool,\n}"
)

old_init = '''    /// Initialize a new local device identity (application: initializeDevice).
    pub fn initialize_device(config: DeviceConfig) -> Result<Self, CryptoError> {
        let identity = IdentityKeyPair::generate().map_err(CryptoError::from)?;
        let prekeys = PrekeyStore::new(&identity).map_err(CryptoError::from)?;
        let mut engine = Self {
            identity,
            device_id: config.device_id,
            profile: config.profile,
            prekeys,
            sessions: HashMap::new(),
            replay: ReplayCache::new(4096),
            trust: TrustStore::new(),
            storage: MemoryStorage::default(),
        };
        engine.persist_device_state()?;
        Ok(engine)
    }

    const KEY_IDENTITY: &'static [u8] = b"identity";
    const KEY_PREKEYS: &'static [u8] = b"prekeys";
    const KEY_REPLAY: &'static [u8] = b"replay";
    const KEY_TRUST: &'static [u8] = b"trust";
'''

new_init = '''    /// Initialize a new local device identity using process-local test storage.
    /// Production mobile integrations should use `initialize_device_with_backends`
    /// with durable encrypted storage and a non-restorable monotonic counter.
    pub fn initialize_device(config: DeviceConfig) -> Result<Self, CryptoError> {
        Self::initialize_device_with_backends(
            config,
            Box::new(MemoryStorage::default()),
            Box::new(MemoryCounter::default()),
        )
    }

    /// Initialize a brand-new device with caller-provided persistence backends.
    ///
    /// The storage must not already contain a VoiceChat identity. This prevents
    /// accidental overwrite of an existing cryptographic identity.
    pub fn initialize_device_with_backends(
        config: DeviceConfig,
        storage: Box<dyn TransactionalStorage>,
        monotonic: Box<dyn MonotonicCounter>,
    ) -> Result<Self, CryptoError> {
        if storage
            .get(Self::KEY_IDENTITY)
            .map_err(|_| CryptoError::Storage)?
            .is_some()
        {
            return Err(CryptoError::Storage);
        }
        let identity = IdentityKeyPair::generate().map_err(CryptoError::from)?;
        let prekeys = PrekeyStore::new(&identity).map_err(CryptoError::from)?;
        let mut engine = Self {
            identity,
            device_id: config.device_id,
            profile: config.profile,
            prekeys,
            sessions: HashMap::new(),
            replay: ReplayCache::new(4096),
            trust: TrustStore::new(),
            storage,
            monotonic,
            rollback_guard: RollbackGuard::default(),
            storage_poisoned: false,
        };
        engine.persist_device_state()?;
        Ok(engine)
    }

    /// Restore a previously initialized device from durable storage.
    ///
    /// A snapshot is accepted only when its transaction-bound epoch equals the
    /// external monotonic counter. Older backups and uncertain partial commits
    /// therefore fail closed before any ratchet state is used.
    pub fn restore_device_with_backends(
        config: DeviceConfig,
        storage: Box<dyn TransactionalStorage>,
        monotonic: Box<dyn MonotonicCounter>,
    ) -> Result<Self, CryptoError> {
        let identity_blob = storage
            .get(Self::KEY_IDENTITY)
            .map_err(|_| CryptoError::Storage)?
            .ok_or(CryptoError::Storage)?;
        let prekeys_blob = storage
            .get(Self::KEY_PREKEYS)
            .map_err(|_| CryptoError::Storage)?
            .ok_or(CryptoError::Storage)?;
        let epoch_blob = storage
            .get(Self::KEY_STORAGE_EPOCH)
            .map_err(|_| CryptoError::Storage)?
            .ok_or(CryptoError::Storage)?;
        if epoch_blob.0.len() != 8 {
            return Err(CryptoError::Storage);
        }
        let persisted_epoch = u64::from_le_bytes(
            epoch_blob.0.as_slice().try_into().map_err(|_| CryptoError::Storage)?,
        );
        let counter_epoch = monotonic.current().map_err(|_| CryptoError::Storage)?;
        if persisted_epoch != counter_epoch {
            return Err(CryptoError::Storage);
        }

        let identity = IdentityKeyPair::deserialize(&identity_blob.0).map_err(CryptoError::from)?;
        let prekeys = PrekeyStore::deserialize(&prekeys_blob.0).map_err(CryptoError::from)?;
        let replay = match storage
            .get(Self::KEY_REPLAY)
            .map_err(|_| CryptoError::Storage)?
        {
            Some(blob) => ReplayCache::deserialize(&blob.0).map_err(CryptoError::from)?,
            None => ReplayCache::new(4096),
        };
        let trust = match storage
            .get(Self::KEY_TRUST)
            .map_err(|_| CryptoError::Storage)?
        {
            Some(blob) => TrustStore::deserialize(&blob.0).map_err(CryptoError::from)?,
            None => TrustStore::new(),
        };

        let mut sessions = HashMap::new();
        for key in storage.keys().map_err(|_| CryptoError::Storage)? {
            let Some(blob) = storage.get(&key).map_err(|_| CryptoError::Storage)? else {
                continue;
            };
            if blob.0.len() >= 8 && &blob.0[..8] == b"VCSESS01" {
                let (sid, sess) = decode_session(&blob.0)?;
                sessions.insert(sid, sess);
            }
        }

        let mut rollback_guard = RollbackGuard::default();
        rollback_guard
            .observe(StorageEpoch(persisted_epoch))
            .map_err(|_| CryptoError::Storage)?;
        let mut engine = Self {
            identity,
            device_id: config.device_id,
            profile: config.profile,
            prekeys,
            sessions,
            replay,
            trust,
            storage,
            monotonic,
            rollback_guard,
            storage_poisoned: false,
        };
        for sess in engine.sessions.values_mut() {
            sess.identity_tracker = engine.trust.tracker_for(&sess.remote_identity);
        }
        Ok(engine)
    }

    const KEY_IDENTITY: &'static [u8] = b"identity";
    const KEY_PREKEYS: &'static [u8] = b"prekeys";
    const KEY_REPLAY: &'static [u8] = b"replay";
    const KEY_TRUST: &'static [u8] = b"trust";
    const KEY_STORAGE_EPOCH: &'static [u8] = b"storage-epoch-v1";
'''
replace_once(old_init, new_init)

old_commit = '''    fn commit_pairs(&mut self, pairs: &[(&[u8], Vec<u8>)]) -> Result<(), CryptoError> {
        let tx = self.storage.begin().map_err(|_| CryptoError::Storage)?;
        for (k, v) in pairs {
            if self.storage.put(tx, k, &StateBlob(v.clone())).is_err() {
                let _ = self.storage.abort(tx);
                return Err(CryptoError::Storage);
            }
        }
        self.storage.commit(tx).map_err(|_| CryptoError::Storage)?;
        let _ = self.storage.advance_epoch();
        Ok(())
    }
'''

new_commit = '''    fn ensure_storage_healthy(&self) -> Result<(), CryptoError> {
        if self.storage_poisoned {
            Err(CryptoError::Storage)
        } else {
            Ok(())
        }
    }

    /// Atomically apply durable puts/deletes and bind the transaction to the
    /// next external monotonic epoch. If the counter advances and any later
    /// storage step fails, the engine is poisoned: continuing could reuse a
    /// ratchet message key after rollback, so availability is sacrificed for
    /// confidentiality.
    fn commit_changes(
        &mut self,
        pairs: &[(&[u8], Vec<u8>)],
        deletes: &[&[u8]],
    ) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        let epoch = self
            .monotonic
            .increment()
            .map_err(|_| CryptoError::Storage)?;

        let tx = match self.storage.begin() {
            Ok(tx) => tx,
            Err(_) => {
                self.storage_poisoned = true;
                return Err(CryptoError::Storage);
            }
        };

        for (k, v) in pairs {
            if self.storage.put(tx, k, &StateBlob(v.clone())).is_err() {
                let _ = self.storage.abort(tx);
                self.storage_poisoned = true;
                return Err(CryptoError::Storage);
            }
        }
        for key in deletes {
            if self.storage.delete(tx, key).is_err() {
                let _ = self.storage.abort(tx);
                self.storage_poisoned = true;
                return Err(CryptoError::Storage);
            }
        }
        if self
            .storage
            .put(
                tx,
                Self::KEY_STORAGE_EPOCH,
                &StateBlob(epoch.to_le_bytes().to_vec()),
            )
            .is_err()
        {
            let _ = self.storage.abort(tx);
            self.storage_poisoned = true;
            return Err(CryptoError::Storage);
        }

        if self.storage.commit(tx).is_err() {
            self.storage_poisoned = true;
            return Err(CryptoError::Storage);
        }
        self.rollback_guard
            .observe(StorageEpoch(epoch))
            .map_err(|_| CryptoError::Storage)?;
        Ok(())
    }

    fn commit_pairs(&mut self, pairs: &[(&[u8], Vec<u8>)]) -> Result<(), CryptoError> {
        self.commit_changes(pairs, &[])
    }

    fn verify_storage_epoch(&mut self) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        let blob = self
            .storage
            .get(Self::KEY_STORAGE_EPOCH)
            .map_err(|_| CryptoError::Storage)?
            .ok_or(CryptoError::Storage)?;
        if blob.0.len() != 8 {
            return Err(CryptoError::Storage);
        }
        let persisted = u64::from_le_bytes(
            blob.0.as_slice().try_into().map_err(|_| CryptoError::Storage)?,
        );
        let current = self
            .monotonic
            .current()
            .map_err(|_| CryptoError::Storage)?;
        if persisted != current {
            self.storage_poisoned = true;
            return Err(CryptoError::Storage);
        }
        self.rollback_guard
            .observe(StorageEpoch(persisted))
            .map_err(|_| CryptoError::Storage)
    }
'''
replace_once(old_commit, new_commit)

replace_once(
    '''    pub fn simulate_crash_reload(&mut self) -> Result<(), CryptoError> {
        if let Some(blob) = self''',
    '''    pub fn simulate_crash_reload(&mut self) -> Result<(), CryptoError> {
        self.verify_storage_epoch()?;
        if let Some(blob) = self''',
)
replace_once(
    "        let keys = self.storage.keys();\n",
    "        let keys = self.storage.keys().map_err(|_| CryptoError::Storage)?;\n",
)

old_replay_key = '''    fn replay_key(
        session_id: &SessionId,
        sealed: &SealedMessage,
        conversation: &[u8],
        sender_device: &[u8],
    ) -> ReplayKey {
        let mut mid = Vec::new();
        mid.extend_from_slice(&crate::policy::PROTOCOL_VERSION.to_le_bytes());
        mid.extend_from_slice(&session_id.0);
        mid.extend_from_slice(&sealed.header);
        mid.extend_from_slice(&sealed.ciphertext[..sealed.ciphertext.len().min(32)]);
        ReplayKey {
            conversation_id: conversation.to_vec(),
            sender_device_id: sender_device.to_vec(),
            message_id: mid,
        }
    }
'''
new_replay_key = old_replay_key + '''
    /// Stable replay identity for a complete PQXDH initiation. It intentionally
    /// excludes Bob's newly generated local session id; otherwise replaying the
    /// exact same last-resort-prekey initiation would get a fresh replay key.
    fn initiation_replay_key(
        &self,
        message: &InitiationPacket,
        conversation: &[u8],
    ) -> ReplayKey {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&crate::policy::PROTOCOL_VERSION.to_le_bytes());
        transcript.push(self.profile.as_u8());
        transcript.extend_from_slice(&(conversation.len() as u64).to_le_bytes());
        transcript.extend_from_slice(conversation);
        transcript.extend_from_slice(&message.encode());
        let digest = crate::primitives::kdf::sha256(&transcript);
        ReplayKey {
            conversation_id: conversation.to_vec(),
            sender_device_id: message.sender_identity_public.to_vec(),
            message_id: digest.to_vec(),
        }
    }
'''
replace_once(old_replay_key, new_replay_key)

replace_once(
    '''    ) -> Result<(SessionId, Vec<u8>), CryptoError> {
        let alice_ik =
            X25519Public::from_bytes(message.sender_identity_public).map_err(CryptoError::from)?;''',
    '''    ) -> Result<(SessionId, Vec<u8>), CryptoError> {
        self.ensure_storage_healthy()?;
        let initiation_replay = self.initiation_replay_key(message, conversation_context);
        if self.replay.contains(&initiation_replay) {
            return Err(CryptoError::Replay);
        }

        let alice_ik =
            X25519Public::from_bytes(message.sender_identity_public).map_err(CryptoError::from)?;''',
)

replace_once(
    '''        let plaintext = match self.apply_decrypt(&sid, &message.first_message, associated_data) {
            Ok(pt) => pt,
            Err(e) => {
                self.sessions.remove(&sid);
                return Err(e);
            }
        };

        if let Some(id) = message.used_ec_opk_id {''',
    '''        let plaintext = match self.apply_decrypt(&sid, &message.first_message, associated_data) {
            Ok(pt) => pt,
            Err(e) => {
                self.sessions.remove(&sid);
                return Err(e);
            }
        };

        // Insert only after the first ciphertext authenticated successfully, so
        // unauthenticated garbage cannot poison the initiation replay cache.
        if self
            .replay
            .check_and_insert(initiation_replay)
            .map_err(|_| CryptoError::Internal)?
        {
            self.sessions.remove(&sid);
            return Err(CryptoError::Replay);
        }

        if let Some(id) = message.used_ec_opk_id {''',
)

replace_once(
    '''    ) -> Result<SealedMessage, CryptoError> {
        let sess = self
            .sessions
            .get_mut(session_id)''',
    '''    ) -> Result<SealedMessage, CryptoError> {
        self.ensure_storage_healthy()?;
        let sess = self
            .sessions
            .get_mut(session_id)''',
)

replace_once(
    '''    ) -> Result<Vec<u8>, CryptoError> {
        let plaintext = self.apply_decrypt(session_id, sealed, associated_data)?;''',
    '''    ) -> Result<Vec<u8>, CryptoError> {
        self.ensure_storage_healthy()?;
        let plaintext = self.apply_decrypt(session_id, sealed, associated_data)?;''',
)

old_delete = '''    fn delete_session(&mut self, session_id: &SessionId) -> Result<(), CryptoError> {
        self.sessions
            .remove(session_id)
            .ok_or(CryptoError::NoSession)?;
        let tx = self.storage.begin().map_err(|_| CryptoError::Storage)?;
        let _ = self.storage.delete(tx, &session_id.0);
        let _ = self.storage.commit(tx);
        Ok(())
    }

    fn delete_all_sessions(&mut self) -> Result<(), CryptoError> {
        self.sessions.clear();
        self.storage.clear();
        Ok(())
    }
'''
new_delete = '''    fn delete_session(&mut self, session_id: &SessionId) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        if !self.sessions.contains_key(session_id) {
            return Err(CryptoError::NoSession);
        }
        // Durable delete first. Only report success/remove RAM state after the
        // transaction and monotonic epoch are safely committed.
        self.commit_changes(&[], &[session_id.0.as_slice()])?;
        self.sessions.remove(session_id);
        Ok(())
    }

    fn delete_all_sessions(&mut self) -> Result<(), CryptoError> {
        self.ensure_storage_healthy()?;
        let mut session_keys = Vec::new();
        for key in self.storage.keys().map_err(|_| CryptoError::Storage)? {
            let Some(blob) = self.storage.get(&key).map_err(|_| CryptoError::Storage)? else {
                continue;
            };
            if blob.0.len() >= 8 && &blob.0[..8] == b"VCSESS01" {
                session_keys.push(key);
            }
        }
        let refs: Vec<&[u8]> = session_keys.iter().map(Vec::as_slice).collect();
        self.commit_changes(&[], &refs)?;
        self.sessions.clear();
        Ok(())
    }
'''
replace_once(old_delete, new_delete)

# Add direct regressions to the engine unit suite.
insert_before = '''    #[test]
    fn trust_not_implied_by_session_until_ack() {'''
regressions = '''    #[test]
    fn initiation_replay_without_one_time_prekeys_is_rejected() {
        let mut alice = VoiceChatCryptoEngine::initialize_device(cfg()).unwrap();
        let mut bob = VoiceChatCryptoEngine::initialize_device(DeviceConfig {
            device_id: b"bob".to_vec(),
            profile: CryptoProfile::ClassicalV1,
        })
        .unwrap();
        // Zero one-time keys forces signed EC + last-resort PQ material.
        let bundle = bob.generate_public_prekey_bundle(0).unwrap();
        assert!(bundle.one_time_ec.is_none());
        assert!(!bundle.is_pq_one_time);
        let (_sid_a, init) = alice
            .establish_outbound_session(&bundle, b"replay-conv", b"hello", b"ad")
            .unwrap();
        let (_sid_b, pt) = bob
            .process_inbound_session(&init, b"replay-conv", b"ad")
            .unwrap();
        assert_eq!(pt, b"hello");
        assert_eq!(
            bob.process_inbound_session(&init, b"replay-conv", b"ad")
                .unwrap_err(),
            CryptoError::Replay
        );
    }

    #[test]
    fn delete_session_remains_deleted_after_reload() {
        let (mut alice, _bob, sid_a, _sid_b) = linked_pair();
        alice.delete_session(&sid_a).unwrap();
        alice.simulate_crash_reload().unwrap();
        assert!(!alice.has_session(&sid_a));
    }

'''
replace_once(insert_before, regressions + insert_before)

ENGINE.write_text(text)
print("patched", ENGINE)

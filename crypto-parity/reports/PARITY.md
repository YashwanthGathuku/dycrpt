# PARITY.md

Backend under test: **VoiceChatCrypto**.
Reference backend: **NOT_LINKED** (libsignal AGPL isolated).

Mode: quick

| id | category | axis | P0 | result | note |
|---|---|---|---|---|---|
| `pqxdh.sk_last_resort` | pqxdh | core | Y | Pass |  |
| `pqxdh.sk_ec_opk` | pqxdh | core | Y | Pass |  |
| `pqxdh.sk_pq_opk` | pqxdh | core | Y | Pass |  |
| `pqxdh.signed_prekey_verify` | pqxdh | core |  | Pass |  |
| `pqxdh.pq_prekey_verify` | pqxdh | core |  | Pass |  |
| `pqxdh.session_with_ec_opk` | pqxdh | core |  | Pass |  |
| `pqxdh.session_without_ec_opk` | pqxdh | core |  | Pass |  |
| `pqxdh.one_time_pq` | pqxdh | core |  | Pass |  |
| `pqxdh.last_resort_pq` | pqxdh | core |  | Pass |  |
| `pqxdh.wrong_identity` | pqxdh | core | Y | Pass |  |
| `pqxdh.modified_spk_sig` | pqxdh | core |  | Pass |  |
| `pqxdh.modified_pq_sig` | pqxdh | core |  | Pass |  |
| `pqxdh.modified_kem_ct` | pqxdh | core |  | Pass |  |
| `pqxdh.wrong_prekey_id` | pqxdh | core |  | Pass |  |
| `pqxdh.consumed_opk_reuse` | pqxdh | core | Y | Pass |  |
| `pqxdh.concurrent_opk_consume` | pqxdh | core | Y | Pass |  |
| `pqxdh.stale_bundle` | pqxdh | core |  | Pass |  |
| `pqxdh.handshake_batch_64` | pqxdh | core | Y | Pass |  |
| `dr.schedule_a1a2a3_b1b2_a4` | ratchet | core |  | Pass |  |
| `dr.reorder_a1_a4_a2_a5_a3` | ratchet | core |  | Pass |  |
| `dr.one_three_two` | ratchet | core |  | Pass |  |
| `dr.skip_fill` | ratchet | core |  | Pass |  |
| `dr.drop_permanent` | ratchet | core |  | Pass |  |
| `dr.restart_after_seven` | ratchet | ops |  | Pass |  |
| `dr.max_skip` | ratchet | core |  | Pass |  |
| `dr.header_roundtrip` | ratchet | core |  | Pass |  |
| `engine.establish` | ratchet | core | Y | Pass |  |
| `engine.ooo` | ooo | core |  | Pass |  |
| `engine.drop_later` | ooo | core |  | Pass |  |
| `engine.wrong_conversation_ad` | ooo | vc |  | Pass |  |
| `p0.tamper_no_commit` | tamper | core | Y | Pass |  |
| `tamper.header_dh` | tamper | core | Y | Pass |  |
| `tamper.counter` | tamper | core |  | Pass |  |
| `tamper.ad` | tamper | core |  | Pass |  |
| `tamper.engine_ct` | tamper | core | Y | Pass |  |
| `p0.replay` | replay | core | Y | Pass |  |
| `replay.after_reload` | replay | ops | Y | Pass |  |
| `p0.crash_opk` | persist | ops | Y | Pass |  |
| `persist.reload_conversation` | persist | ops |  | Pass |  |
| `persist.trial_diverges` | persist | ops |  | Pass |  |
| `persist.storage_abort` | persist | ops | Y | Pass |  |
| `persist.rollback_guard` | persist | ops |  | Pass |  |
| `prekey.replenish` | prekey | core |  | Pass |  |
| `prekey.last_resort` | prekey | core |  | Pass |  |
| `p0.identity_changed` | identity | vc | Y | Pass |  |
| `p0.trust_not_from_session` | identity | vc | Y | Pass |  |
| `identity.ack_persists` | identity | vc | Y | Pass |  |
| `identity.fingerprint_symmetric` | identity | vc |  | Pass |  |
| `identity.device_change` | identity | vc |  | Pass |  |
| `vc.default_classical` | identity | vc |  | Pass |  |
| `vc.no_silent_downgrade` | resource | vc |  | Pass |  |
| `vc.voice_profile_forbidden` | resource | vc | Y | Pass |  |
| `vc.voice_payload_ok` | resource | vc |  | Pass |  |
| `envelope.conversation_binding` | mobile | vc |  | Pass |  |
| `envelope.device_binding` | mobile | vc |  | Pass |  |
| `envelope.version_reject` | serial | ops |  | Pass |  |
| `envelope.truncated` | serial | ops |  | Pass |  |
| `envelope.trailing` | serial | ops |  | Pass |  |
| `envelope.oversized` | serial | ops |  | Pass |  |
| `serial.initiation_malformed` | serial | ops |  | Pass |  |
| `serial.sealed_malformed` | serial | ops |  | Pass |  |
| `serial.header_truncated` | serial | ops |  | Pass |  |
| `resource.delete_session` | mobile | ops |  | Pass |  |
| `resource.max_skip` | ooo | core |  | Pass |  |
| `resource.padding` | mobile | vc |  | Pass |  |
| `resource.random_session_ids` | mobile | ops |  | Pass |  |
| `prekey.engine_handshake_uses_spk` | prekey | core |  | Pass |  |
| `prekey.opk_reuse_engine` | prekey | core | Y | Pass |  |
| `ooo.engine_ooo` | ooo | core |  | Pass |  |
| `tamper.engine_ad` | tamper | core |  | Pass |  |
| `replay.engine_first_message` | replay | core | Y | Pass |  |
| `persist.handshake_atomic` | persist | ops | Y | Pass |  |
| `prekey.consume_once` | prekey | core | Y | Pass |  |
| `tamper.no_fail_open` | tamper | core | Y | Pass |  |

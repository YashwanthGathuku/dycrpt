-- Deterministic non-cryptographic fixture data for allocator CI only.
-- These bytes are deliberately NOT valid production keys. The allocator test
-- checks database atomicity/idempotency, not cryptographic validation.

INSERT INTO voicechat_crypto.device_prekeys (
    device_id, identity_key,
    signed_prekey_id, signed_prekey, signed_prekey_sig,
    last_resort_pq_id, last_resort_pq, last_resort_pq_sig
) VALUES (
    decode('6465766963652d6369', 'hex'),
    decode(repeat('11', 32), 'hex'),
    1,
    decode(repeat('22', 32), 'hex'),
    decode(repeat('33', 64), 'hex'),
    1,
    decode(repeat('44', 1184), 'hex'),
    decode(repeat('55', 64), 'hex')
)
ON CONFLICT (device_id) DO UPDATE SET
    identity_key = EXCLUDED.identity_key,
    signed_prekey_id = EXCLUDED.signed_prekey_id,
    signed_prekey = EXCLUDED.signed_prekey,
    signed_prekey_sig = EXCLUDED.signed_prekey_sig,
    last_resort_pq_id = EXCLUDED.last_resort_pq_id,
    last_resort_pq = EXCLUDED.last_resort_pq,
    last_resort_pq_sig = EXCLUDED.last_resort_pq_sig;

DELETE FROM voicechat_crypto.allocation_receipts
 WHERE device_id = decode('6465766963652d6369', 'hex');
DELETE FROM voicechat_crypto.one_time_ec_prekeys
 WHERE device_id = decode('6465766963652d6369', 'hex');
DELETE FROM voicechat_crypto.one_time_pq_prekeys
 WHERE device_id = decode('6465766963652d6369', 'hex');

INSERT INTO voicechat_crypto.one_time_ec_prekeys(device_id, prekey_id, public_key)
SELECT
    decode('6465766963652d6369', 'hex'),
    i,
    decode(lpad(to_hex(i), 64, '0'), 'hex')
FROM generate_series(1000, 1999) AS i;

INSERT INTO voicechat_crypto.one_time_pq_prekeys(device_id, prekey_id, public_key, signature)
SELECT
    decode('6465766963652d6369', 'hex'),
    i,
    decode(repeat('66', 1184), 'hex') || int8send(i),
    decode(repeat('77', 64), 'hex')
FROM generate_series(2000, 2999) AS i;

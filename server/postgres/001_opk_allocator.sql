-- VoiceChat / dycrpt prekey allocator reference schema.
-- PostgreSQL 14+.
--
-- Security invariant:
--   for a given (recipient_device, prekey_kind, prekey_id), at most one
--   successful unique allocation request may consume that one-time prekey.
--
-- Client retries MUST reuse request_token. The receipt row makes a retry return
-- the exact same bundle even though the one-time inventory row was deleted.

BEGIN;

CREATE SCHEMA IF NOT EXISTS voicechat_crypto;

CREATE TABLE IF NOT EXISTS voicechat_crypto.device_prekeys (
    device_id           bytea PRIMARY KEY,
    identity_key        bytea NOT NULL CHECK (octet_length(identity_key) = 32),
    signed_prekey_id    bigint NOT NULL CHECK (signed_prekey_id BETWEEN 0 AND 4294967295),
    signed_prekey       bytea NOT NULL CHECK (octet_length(signed_prekey) = 32),
    signed_prekey_sig   bytea NOT NULL CHECK (octet_length(signed_prekey_sig) = 64),
    last_resort_pq_id   bigint NOT NULL CHECK (last_resort_pq_id BETWEEN 0 AND 4294967295),
    last_resort_pq      bytea NOT NULL,
    last_resort_pq_sig  bytea NOT NULL CHECK (octet_length(last_resort_pq_sig) = 64),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS voicechat_crypto.one_time_ec_prekeys (
    device_id       bytea NOT NULL REFERENCES voicechat_crypto.device_prekeys(device_id) ON DELETE CASCADE,
    prekey_id       bigint NOT NULL CHECK (prekey_id BETWEEN 0 AND 4294967295),
    public_key      bytea NOT NULL CHECK (octet_length(public_key) = 32),
    uploaded_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, prekey_id)
);

CREATE TABLE IF NOT EXISTS voicechat_crypto.one_time_pq_prekeys (
    device_id       bytea NOT NULL REFERENCES voicechat_crypto.device_prekeys(device_id) ON DELETE CASCADE,
    prekey_id       bigint NOT NULL CHECK (prekey_id BETWEEN 0 AND 4294967295),
    public_key      bytea NOT NULL,
    signature       bytea NOT NULL CHECK (octet_length(signature) = 64),
    uploaded_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, prekey_id)
);

-- The complete response is persisted for request-token idempotency. Do not
-- reconstruct an old retry from today's rotated signed/last-resort prekeys.
CREATE TABLE IF NOT EXISTS voicechat_crypto.allocation_receipts (
    device_id           bytea NOT NULL,
    request_token       uuid NOT NULL,
    identity_key        bytea NOT NULL,
    signed_prekey_id    bigint NOT NULL,
    signed_prekey       bytea NOT NULL,
    signed_prekey_sig   bytea NOT NULL,
    ec_opk_id           bigint,
    ec_opk_public       bytea,
    pq_prekey_id        bigint NOT NULL,
    pq_prekey_public    bytea NOT NULL,
    pq_prekey_sig       bytea NOT NULL,
    pq_is_one_time      boolean NOT NULL,
    allocated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, request_token),
    CHECK ((ec_opk_id IS NULL) = (ec_opk_public IS NULL))
);

CREATE INDEX IF NOT EXISTS one_time_ec_prekeys_fifo
    ON voicechat_crypto.one_time_ec_prekeys(device_id, prekey_id);
CREATE INDEX IF NOT EXISTS one_time_pq_prekeys_fifo
    ON voicechat_crypto.one_time_pq_prekeys(device_id, prekey_id);

-- Defense in depth: even if allocator code is later modified incorrectly, the
-- database refuses to record the same one-time ID for two unique requests.
CREATE UNIQUE INDEX IF NOT EXISTS allocation_receipt_ec_once
    ON voicechat_crypto.allocation_receipts(device_id, ec_opk_id)
    WHERE ec_opk_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS allocation_receipt_pq_once
    ON voicechat_crypto.allocation_receipts(device_id, pq_prekey_id)
    WHERE pq_is_one_time;

CREATE OR REPLACE FUNCTION voicechat_crypto.allocate_prekey_bundle(
    p_device_id bytea,
    p_request_token uuid
)
RETURNS TABLE (
    identity_key bytea,
    signed_prekey_id bigint,
    signed_prekey bytea,
    signed_prekey_sig bytea,
    ec_opk_id bigint,
    ec_opk_public bytea,
    pq_prekey_id bigint,
    pq_prekey_public bytea,
    pq_prekey_sig bytea,
    pq_is_one_time boolean
)
LANGUAGE plpgsql
AS $$
DECLARE
    d voicechat_crypto.device_prekeys%ROWTYPE;
    ec voicechat_crypto.one_time_ec_prekeys%ROWTYPE;
    pq voicechat_crypto.one_time_pq_prekeys%ROWTYPE;
    receipt voicechat_crypto.allocation_receipts%ROWTYPE;
BEGIN
    -- Fast idempotent retry path. A concurrent first request may still be in
    -- flight; in that case the unique receipt insertion below serializes it.
    SELECT * INTO receipt
      FROM voicechat_crypto.allocation_receipts r
     WHERE r.device_id = p_device_id AND r.request_token = p_request_token;
    IF FOUND THEN
        RETURN QUERY SELECT
            receipt.identity_key,
            receipt.signed_prekey_id,
            receipt.signed_prekey,
            receipt.signed_prekey_sig,
            receipt.ec_opk_id,
            receipt.ec_opk_public,
            receipt.pq_prekey_id,
            receipt.pq_prekey_public,
            receipt.pq_prekey_sig,
            receipt.pq_is_one_time;
        RETURN;
    END IF;

    -- Lock the durable device bundle so a rotation cannot split one allocation
    -- across old/new signed or last-resort keys.
    SELECT * INTO STRICT d
      FROM voicechat_crypto.device_prekeys
     WHERE device_id = p_device_id
     FOR SHARE;

    SELECT * INTO ec
      FROM voicechat_crypto.one_time_ec_prekeys
     WHERE device_id = p_device_id
     ORDER BY prekey_id
     FOR UPDATE SKIP LOCKED
     LIMIT 1;

    SELECT * INTO pq
      FROM voicechat_crypto.one_time_pq_prekeys
     WHERE device_id = p_device_id
     ORDER BY prekey_id
     FOR UPDATE SKIP LOCKED
     LIMIT 1;

    -- The receipt is inserted BEFORE inventory deletion inside the same DB
    -- transaction. If anything fails, both receipt and deletions roll back.
    IF pq.prekey_id IS NOT NULL THEN
        INSERT INTO voicechat_crypto.allocation_receipts (
            device_id, request_token, identity_key,
            signed_prekey_id, signed_prekey, signed_prekey_sig,
            ec_opk_id, ec_opk_public,
            pq_prekey_id, pq_prekey_public, pq_prekey_sig, pq_is_one_time
        ) VALUES (
            p_device_id, p_request_token, d.identity_key,
            d.signed_prekey_id, d.signed_prekey, d.signed_prekey_sig,
            ec.prekey_id, ec.public_key,
            pq.prekey_id, pq.public_key, pq.signature, true
        )
        ON CONFLICT (device_id, request_token) DO NOTHING;
    ELSE
        INSERT INTO voicechat_crypto.allocation_receipts (
            device_id, request_token, identity_key,
            signed_prekey_id, signed_prekey, signed_prekey_sig,
            ec_opk_id, ec_opk_public,
            pq_prekey_id, pq_prekey_public, pq_prekey_sig, pq_is_one_time
        ) VALUES (
            p_device_id, p_request_token, d.identity_key,
            d.signed_prekey_id, d.signed_prekey, d.signed_prekey_sig,
            ec.prekey_id, ec.public_key,
            d.last_resort_pq_id, d.last_resort_pq, d.last_resort_pq_sig, false
        )
        ON CONFLICT (device_id, request_token) DO NOTHING;
    END IF;

    -- If a concurrent identical token won the receipt race, return its exact
    -- receipt and DO NOT consume the rows selected by this transaction.
    SELECT * INTO STRICT receipt
      FROM voicechat_crypto.allocation_receipts r
     WHERE r.device_id = p_device_id AND r.request_token = p_request_token
     FOR UPDATE;

    -- Only the transaction whose selected values equal the winning receipt may
    -- consume inventory. This makes duplicate request-token races idempotent.
    IF ec.prekey_id IS NOT NULL AND receipt.ec_opk_id = ec.prekey_id THEN
        DELETE FROM voicechat_crypto.one_time_ec_prekeys
         WHERE device_id = p_device_id AND prekey_id = ec.prekey_id;
    END IF;

    IF pq.prekey_id IS NOT NULL
       AND receipt.pq_is_one_time
       AND receipt.pq_prekey_id = pq.prekey_id THEN
        DELETE FROM voicechat_crypto.one_time_pq_prekeys
         WHERE device_id = p_device_id AND prekey_id = pq.prekey_id;
    END IF;

    RETURN QUERY SELECT
        receipt.identity_key,
        receipt.signed_prekey_id,
        receipt.signed_prekey,
        receipt.signed_prekey_sig,
        receipt.ec_opk_id,
        receipt.ec_opk_public,
        receipt.pq_prekey_id,
        receipt.pq_prekey_public,
        receipt.pq_prekey_sig,
        receipt.pq_is_one_time;
END;
$$;

-- Uploads are insert-only. Reusing an existing one-time ID is a hard error;
-- clients must generate fresh monotonically unique IDs instead of overwriting.
CREATE OR REPLACE FUNCTION voicechat_crypto.upload_ec_opk(
    p_device_id bytea,
    p_prekey_id bigint,
    p_public_key bytea
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO voicechat_crypto.one_time_ec_prekeys(device_id, prekey_id, public_key)
    VALUES (p_device_id, p_prekey_id, p_public_key);
END;
$$;

CREATE OR REPLACE FUNCTION voicechat_crypto.upload_pq_opk(
    p_device_id bytea,
    p_prekey_id bigint,
    p_public_key bytea,
    p_signature bytea
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO voicechat_crypto.one_time_pq_prekeys(device_id, prekey_id, public_key, signature)
    VALUES (p_device_id, p_prekey_id, p_public_key, p_signature);
END;
$$;

COMMIT;

-- Server-anchored rollback counter reference implementation.
-- PostgreSQL 14+.
--
-- This database MUST be outside the device/app backup domain. Restoring an old
-- mobile database must not restore this table. The transport endpoint exposing
-- these functions must authenticate the device/account and bind p_device_id to
-- the authenticated principal; never trust an arbitrary client-supplied ID.

BEGIN;

CREATE SCHEMA IF NOT EXISTS voicechat_crypto;

CREATE TABLE IF NOT EXISTS voicechat_crypto.rollback_anchor (
    device_id       bytea PRIMARY KEY,
    epoch           bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS voicechat_crypto.rollback_anchor_receipts (
    device_id       bytea NOT NULL REFERENCES voicechat_crypto.rollback_anchor(device_id) ON DELETE CASCADE,
    request_token   uuid NOT NULL,
    expected_epoch  bigint NOT NULL CHECK (expected_epoch >= 0),
    committed_epoch bigint NOT NULL CHECK (committed_epoch > expected_epoch),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, request_token),
    CHECK (committed_epoch = expected_epoch + 1)
);

CREATE OR REPLACE FUNCTION voicechat_crypto.register_rollback_anchor(
    p_device_id bytea,
    p_initial_epoch bigint DEFAULT 0
) RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
    result bigint;
BEGIN
    IF p_initial_epoch < 0 THEN
        RAISE EXCEPTION 'negative rollback epoch';
    END IF;
    INSERT INTO voicechat_crypto.rollback_anchor(device_id, epoch)
    VALUES (p_device_id, p_initial_epoch)
    ON CONFLICT (device_id) DO NOTHING;

    SELECT epoch INTO STRICT result
      FROM voicechat_crypto.rollback_anchor
     WHERE device_id = p_device_id;
    RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION voicechat_crypto.current_rollback_epoch(
    p_device_id bytea
) RETURNS bigint
LANGUAGE sql
STABLE
AS $$
    SELECT epoch
      FROM voicechat_crypto.rollback_anchor
     WHERE device_id = p_device_id
$$;

-- Compare-and-increment with an idempotency token. A retry using the same token
-- returns the original committed result; a different request may advance only
-- from the exact expected epoch.
CREATE OR REPLACE FUNCTION voicechat_crypto.advance_rollback_epoch(
    p_device_id bytea,
    p_expected_epoch bigint,
    p_request_token uuid
) RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
    prior voicechat_crypto.rollback_anchor_receipts%ROWTYPE;
    current_value bigint;
    next_value bigint;
BEGIN
    IF p_expected_epoch < 0 OR p_expected_epoch = 9223372036854775807 THEN
        RAISE EXCEPTION 'invalid expected epoch';
    END IF;

    SELECT * INTO prior
      FROM voicechat_crypto.rollback_anchor_receipts
     WHERE device_id = p_device_id AND request_token = p_request_token;
    IF FOUND THEN
        IF prior.expected_epoch <> p_expected_epoch THEN
            RAISE EXCEPTION 'request token reused with different expected epoch';
        END IF;
        RETURN prior.committed_epoch;
    END IF;

    SELECT epoch INTO STRICT current_value
      FROM voicechat_crypto.rollback_anchor
     WHERE device_id = p_device_id
     FOR UPDATE;

    IF current_value <> p_expected_epoch THEN
        RAISE EXCEPTION 'rollback epoch mismatch: expected %, current %',
            p_expected_epoch, current_value;
    END IF;

    next_value := current_value + 1;
    UPDATE voicechat_crypto.rollback_anchor
       SET epoch = next_value, updated_at = now()
     WHERE device_id = p_device_id;

    INSERT INTO voicechat_crypto.rollback_anchor_receipts(
        device_id, request_token, expected_epoch, committed_epoch
    ) VALUES (
        p_device_id, p_request_token, current_value, next_value
    );

    RETURN next_value;
END;
$$;

COMMIT;

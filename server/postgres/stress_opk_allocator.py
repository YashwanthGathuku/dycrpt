#!/usr/bin/env python3
"""Concurrency/invariant test for 001_opk_allocator.sql.

Usage:
  DATABASE_URL=postgresql://... python server/postgres/stress_opk_allocator.py \
      --device-hex 6465766963652d31 --requests 10000 --workers 100

Prerequisite: populate the device with at least `requests` EC and PQ one-time
prekeys when testing zero-fallback uniqueness. The script does not fabricate
cryptographic keys; it tests the allocator against real uploaded inventory.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import sys
import uuid
from dataclasses import dataclass

try:
    import psycopg
except ImportError as exc:  # pragma: no cover - operator setup path
    raise SystemExit("psycopg v3 is required: pip install 'psycopg[binary]'") from exc


@dataclass(frozen=True)
class Allocation:
    identity_key: bytes
    signed_prekey_id: int
    signed_prekey: bytes
    signed_prekey_sig: bytes
    ec_opk_id: int | None
    ec_opk_public: bytes | None
    pq_prekey_id: int
    pq_prekey_public: bytes
    pq_prekey_sig: bytes
    pq_is_one_time: bool


def allocate(dsn: str, device: bytes, token: uuid.UUID) -> Allocation:
    with psycopg.connect(dsn, autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM voicechat_crypto.allocate_prekey_bundle(%s, %s)",
                (device, token),
            )
            row = cur.fetchone()
            if row is None:
                raise RuntimeError("allocator returned no row")
        conn.commit()
    return Allocation(*row)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device-hex", required=True)
    parser.add_argument("--requests", type=int, default=10_000)
    parser.add_argument("--workers", type=int, default=100)
    parser.add_argument(
        "--require-one-time-pq",
        action="store_true",
        help="fail if any request falls back to the last-resort PQ prekey",
    )
    args = parser.parse_args()

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        parser.error("DATABASE_URL must be set")
    if args.requests < 1 or args.workers < 1:
        parser.error("requests/workers must be positive")
    device = bytes.fromhex(args.device_hex)
    if not device:
        parser.error("device id must not be empty")

    tokens = [uuid.uuid4() for _ in range(args.requests)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(allocate, dsn, device, token) for token in tokens]
        allocations = [future.result() for future in futures]

    ec_ids = [a.ec_opk_id for a in allocations if a.ec_opk_id is not None]
    if len(ec_ids) != len(set(ec_ids)):
        raise AssertionError("duplicate EC one-time prekey allocated to unique request tokens")

    pq_ids = [a.pq_prekey_id for a in allocations if a.pq_is_one_time]
    if len(pq_ids) != len(set(pq_ids)):
        raise AssertionError("duplicate PQ one-time prekey allocated to unique request tokens")

    if args.require_one_time_pq and any(not a.pq_is_one_time for a in allocations):
        raise AssertionError("inventory exhausted: allocator used last-resort PQ key")

    # Replay every request token. Idempotency requires byte-for-byte identical
    # allocations and must not consume another one-time key.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(allocate, dsn, device, token) for token in tokens]
        retries = [future.result() for future in futures]

    for token, first, retry in zip(tokens, allocations, retries, strict=True):
        if first != retry:
            raise AssertionError(f"idempotency mismatch for request token {token}")

    # Verify the database itself has no allocation receipt reuse across unique
    # request tokens for one-time IDs.
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT ec_opk_id, count(*)
              FROM voicechat_crypto.allocation_receipts
             WHERE device_id = %s AND ec_opk_id IS NOT NULL
             GROUP BY ec_opk_id HAVING count(*) > 1
            """,
            (device,),
        )
        if cur.fetchone() is not None:
            raise AssertionError("database contains duplicate EC allocation receipt")
        cur.execute(
            """
            SELECT pq_prekey_id, count(*)
              FROM voicechat_crypto.allocation_receipts
             WHERE device_id = %s AND pq_is_one_time
             GROUP BY pq_prekey_id HAVING count(*) > 1
            """,
            (device,),
        )
        if cur.fetchone() is not None:
            raise AssertionError("database contains duplicate PQ allocation receipt")

    print(
        f"PASS: {len(allocations)} unique allocations, "
        f"{len(ec_ids)} EC OPKs, {len(pq_ids)} PQ OPKs; retries identical"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise

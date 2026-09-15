#!/usr/bin/env python3
"""Concurrency/invariant test for 001_opk_allocator.sql.

Release mode requires at least 10,000 unique allocation tokens and at least 100
concurrent workers. A smaller run is permitted only with `--allow-smoke` for PR
smoke testing and cannot satisfy the final release gate.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

try:
    import psycopg
except ImportError as exc:  # pragma: no cover - operator setup path
    raise SystemExit("psycopg v3 is required: pip install 'psycopg[binary]'") from exc

SHA40 = re.compile(r"^[0-9a-f]{40}$")


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
    with psycopg.connect(dsn, autocommit=False, connect_timeout=15) as conn:
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
    parser.add_argument("--workers", type=int, default=128)
    parser.add_argument("--allow-smoke", action="store_true")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--commit", default=os.environ.get("DYCRPT_COMMIT", ""))
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
    if not args.allow_smoke and (args.requests < 10_000 or args.workers < 100):
        parser.error("release stress requires requests>=10000 and workers>=100")
    if args.commit and not SHA40.fullmatch(args.commit):
        parser.error("--commit/DYCRPT_COMMIT must be a lowercase 40-character SHA")
    device = bytes.fromhex(args.device_hex)
    if not device:
        parser.error("device id must not be empty")

    tokens = [uuid.uuid4() for _ in range(args.requests)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        allocations = list(pool.map(lambda token: allocate(dsn, device, token), tokens))

    ec_ids = [a.ec_opk_id for a in allocations if a.ec_opk_id is not None]
    if len(ec_ids) != len(set(ec_ids)):
        raise AssertionError("duplicate EC one-time prekey allocated to unique request tokens")

    pq_ids = [a.pq_prekey_id for a in allocations if a.pq_is_one_time]
    if len(pq_ids) != len(set(pq_ids)):
        raise AssertionError("duplicate PQ one-time prekey allocated to unique request tokens")

    if args.require_one_time_pq and any(not a.pq_is_one_time for a in allocations):
        raise AssertionError("inventory exhausted: allocator used last-resort PQ key")

    # Replay every request token. Idempotency requires byte-for-byte identical
    # logical allocations and must not consume another one-time key.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        retries = list(pool.map(lambda token: allocate(dsn, device, token), tokens))

    for token, first, retry in zip(tokens, allocations, retries, strict=True):
        if first != retry:
            raise AssertionError(f"idempotency mismatch for request token {token}")

    with psycopg.connect(dsn, connect_timeout=15) as conn, conn.cursor() as cur:
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
        cur.execute(
            """
            SELECT count(*)
              FROM voicechat_crypto.allocation_receipts
             WHERE device_id = %s
            """,
            (device,),
        )
        receipt_count = int(cur.fetchone()[0])

    if receipt_count != args.requests:
        raise AssertionError(f"receipt count {receipt_count} != requests {args.requests}")

    evidence = {
        "schema": "dycrpt-opk-stress-v1",
        "commit": args.commit or None,
        "requests": args.requests,
        "workers": args.workers,
        "ec_unique": len(ec_ids),
        "pq_unique": len(pq_ids),
        "duplicate_ec": 0,
        "duplicate_pq": 0,
        "idempotent_retries": args.requests,
        "receipt_count": receipt_count,
        "one_time_pq_required": bool(args.require_one_time_pq),
        "release_scale": args.requests >= 10_000 and args.workers >= 100,
        "passed": True,
    }
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise

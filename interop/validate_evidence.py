#!/usr/bin/env python3
"""Fail-closed validator for dycrpt physical-device evidence.

No third-party Python dependency is required. The JSON Schema is retained for
external tooling, while this validator enforces the release-critical semantic
rules and scans evidence keys for accidental secret logging.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT = re.compile(r"^sha256:[0-9a-f]{64}$")
DIRECTIONS = {
    "android-android": ("android", "android"),
    "ios-ios": ("ios", "ios"),
    "android-ios": ("android", "ios"),
    "ios-android": ("ios", "android"),
}
CASES = {
    "pqxdh-first",
    "bidirectional-ratchet",
    "network-reordering",
    "duplicate-ciphertext",
    "tamper-recovery",
    "crash-after-commit",
    "crash-before-commit",
    "initiation-retry",
    "identity-replacement",
    "prekey-rotation",
    "opk-concurrency",
    "storage-rollback",
}
SENSITIVE_KEY_FRAGMENTS = {
    "private_key",
    "privatekey",
    "secret_key",
    "secretkey",
    "storage_key",
    "storagekey",
    "root_key",
    "rootkey",
    "chain_key",
    "chainkey",
    "message_key",
    "messagekey",
    "ratchet_key",
    "ratchetkey",
    "shared_secret",
    "sharedsecret",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "plaintext",
    "decrypted_state",
}


class EvidenceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def scan_sensitive_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9_]", "", str(key).lower())
            for fragment in SENSITIVE_KEY_FRAGMENTS:
                if fragment in normalized:
                    raise EvidenceError(f"sensitive field name forbidden at {path}.{key}")
            scan_sensitive_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            scan_sensitive_keys(child, f"{path}[{idx}]")


def validate_endpoint(endpoint: Any, expected_platform: str, label: str) -> None:
    require(isinstance(endpoint, dict), f"{label} must be an object")
    required = {"platform", "device", "os", "app_build", "native_sha256"}
    require(set(endpoint) == required, f"{label} fields must equal {sorted(required)}")
    require(endpoint["platform"] == expected_platform, f"{label}.platform mismatch")
    for field, maximum in (("device", 256), ("os", 128), ("app_build", 128)):
        value = endpoint[field]
        require(isinstance(value, str) and 0 < len(value) <= maximum, f"invalid {label}.{field}")
    require(
        isinstance(endpoint["native_sha256"], str) and SHA256.fullmatch(endpoint["native_sha256"]),
        f"invalid {label}.native_sha256",
    )


def validate_record(record: Any, expected_commit: str | None = None) -> str:
    require(isinstance(record, dict), "top-level evidence must be an object")
    allowed = {
        "schema",
        "dycrpt_commit",
        "direction",
        "physical_devices",
        "profile",
        "protocol_version",
        "endpoint_a",
        "endpoint_b",
        "cases",
        "private_key_material_logged",
    }
    require(set(record) == allowed, f"top-level fields must equal {sorted(allowed)}")
    scan_sensitive_keys(record)

    require(record["schema"] == "dycrpt-physical-interop-v1", "wrong evidence schema")
    commit = record["dycrpt_commit"]
    require(isinstance(commit, str) and SHA40.fullmatch(commit), "invalid dycrpt_commit")
    if expected_commit is not None:
        require(commit == expected_commit, f"commit mismatch: evidence={commit} expected={expected_commit}")

    direction = record["direction"]
    require(direction in DIRECTIONS, f"unsupported direction {direction!r}")
    require(record["physical_devices"] is True, "emulator/simulator evidence is not release evidence")
    require(record["profile"] == "ClassicalV1", "production interop gate requires ClassicalV1")
    require(record["protocol_version"] == 2, "production interop gate requires protocol v2")
    require(record["private_key_material_logged"] is False, "evidence reports private material logging")

    expected_a, expected_b = DIRECTIONS[direction]
    validate_endpoint(record["endpoint_a"], expected_a, "endpoint_a")
    validate_endpoint(record["endpoint_b"], expected_b, "endpoint_b")

    cases = record["cases"]
    require(isinstance(cases, list), "cases must be an array")
    observed: set[str] = set()
    for index, case in enumerate(cases):
        require(isinstance(case, dict), f"cases[{index}] must be an object")
        require(set(case) == {"id", "pass", "artifacts"}, f"unexpected fields in cases[{index}]")
        case_id = case["id"]
        require(case_id in CASES, f"unknown case id {case_id!r}")
        require(case_id not in observed, f"duplicate case id {case_id!r}")
        observed.add(case_id)
        require(case["pass"] is True, f"case {case_id!r} did not pass")
        artifacts = case["artifacts"]
        require(isinstance(artifacts, list) and artifacts, f"case {case_id!r} lacks artifact hashes")
        for artifact in artifacts:
            require(isinstance(artifact, str) and ARTIFACT.fullmatch(artifact), f"invalid artifact hash in {case_id}")

    require(observed == CASES, f"missing/extra mandatory cases: missing={sorted(CASES - observed)}")
    return direction


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot load {path}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument(
        "--single",
        action="store_true",
        help="validate records independently without requiring all four directions",
    )
    args = parser.parse_args()

    if args.expected_commit is not None and not SHA40.fullmatch(args.expected_commit):
        parser.error("--expected-commit must be a lowercase 40-character git SHA")

    try:
        directions: list[str] = []
        for path in args.files:
            direction = validate_record(load(path), args.expected_commit)
            directions.append(direction)
            print(f"PASS {path}: {direction}")
        if not args.single:
            require(len(directions) == 4, "release matrix requires exactly four evidence records")
            require(set(directions) == set(DIRECTIONS), f"release matrix directions={sorted(directions)}")
            require(len(set(directions)) == len(directions), "duplicate direction evidence")
    except EvidenceError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print("PHYSICAL INTEROP EVIDENCE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

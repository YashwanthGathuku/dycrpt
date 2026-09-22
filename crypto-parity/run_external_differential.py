#!/usr/bin/env python3
"""Compare dycrpt and an external reference oracle over normalized JSONL."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
MAX_OUTPUT = 8 * 1024 * 1024
COMPARABLE_AXES = {"signal-core", "operational"}
VALID_AXES = COMPARABLE_AXES | {"voicechat"}
VALID_STATUS = {"pass", "fail", "unsupported"}
VALID_CLASS = {
    "pass", "fail", "intentional-difference", "spec-variant", "unknown", "unsupported"
}
SENSITIVE_FRAGMENTS = {
    "private_key", "privatekey", "secret_key", "secretkey", "shared_secret",
    "sharedsecret", "root_key", "rootkey", "chain_key", "chainkey",
    "message_key", "messagekey", "storage_key", "storagekey", "access_token",
    "accesstoken", "refresh_token", "refreshtoken", "plaintext", "decrypted_state",
}


class DiffError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DiffError(message)


def scan_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9_]", "", str(key).lower())
            if any(fragment in normalized for fragment in SENSITIVE_FRAGMENTS):
                raise DiffError(f"forbidden secret-looking field at {path}.{key}")
            scan_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_keys(child, f"{path}[{index}]")


def run_oracle(command: str, timeout: int, extra_env: dict[str, str]) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, Any], int]:
    argv = shlex.split(command)
    require(argv, "oracle command is empty")
    env = os.environ.copy()
    env.update(extra_env)
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiffError(f"cannot execute oracle {argv[0]!r}: {exc}") from exc

    require(len(completed.stdout) <= MAX_OUTPUT, "oracle stdout exceeded 8 MiB")
    try:
        text = completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DiffError("oracle output is not UTF-8") from exc

    records: list[Any] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DiffError(f"oracle line {line_number} is invalid JSON: {exc}") from exc
        scan_keys(record)
        records.append(record)

    require(records, "oracle produced no JSON records")
    require(isinstance(records[0], dict) and records[0].get("type") == "metadata", "first record must be metadata")
    require(isinstance(records[-1], dict) and records[-1].get("type") == "summary", "last record must be summary")
    metadata = records[0]
    summary = records[-1]
    require(metadata.get("schema") == "dycrpt-external-oracle-v1", "wrong oracle schema")
    require(metadata.get("private_material_logged") is False, "oracle reports private material logging")
    commit = metadata.get("commit")
    require(isinstance(commit, str) and SHA40.fullmatch(commit), "oracle commit must be lowercase 40-char SHA")
    implementation = metadata.get("implementation")
    require(isinstance(implementation, str) and 0 < len(implementation) <= 256, "invalid implementation ID")

    scenarios: dict[str, dict[str, Any]] = {}
    for record in records[1:-1]:
        require(isinstance(record, dict) and record.get("type") == "scenario", "middle records must be scenarios")
        required = {"type", "id", "category", "axis", "p0", "status", "classification", "note"}
        require(set(record) == required, f"unexpected scenario fields for {record.get('id')!r}")
        scenario_id = record["id"]
        require(isinstance(scenario_id, str) and 0 < len(scenario_id) <= 256, "invalid scenario id")
        require(scenario_id not in scenarios, f"duplicate scenario id {scenario_id!r}")
        require(record["axis"] in VALID_AXES, f"bad axis for {scenario_id}")
        require(record["status"] in VALID_STATUS, f"bad status for {scenario_id}")
        require(record["classification"] in VALID_CLASS, f"bad classification for {scenario_id}")
        require(isinstance(record["p0"], bool), f"bad p0 flag for {scenario_id}")
        require(isinstance(record["note"], str) and len(record["note"]) <= 2048, f"bad note for {scenario_id}")
        require(record["classification"] != "unknown", f"unknown classification for {scenario_id}")
        scenarios[scenario_id] = record

    require(summary.get("type") == "summary", "bad summary")
    require(summary.get("scenarios") == len(scenarios), "summary scenario count mismatch")
    return metadata, scenarios, summary, completed.returncode


def compare(candidate: tuple, reference: tuple, expected_commit: str) -> dict[str, Any]:
    c_meta, c_rows, c_summary, c_rc = candidate
    r_meta, r_rows, r_summary, r_rc = reference
    require(c_meta["implementation"] == "dycrpt", "candidate oracle must identify as dycrpt")
    require(c_meta["commit"] == expected_commit, "candidate oracle commit mismatch")
    require(r_meta["implementation"] != "dycrpt", "reference implementation must be independent")

    candidate_comparable = {k for k, v in c_rows.items() if v["axis"] in COMPARABLE_AXES}
    reference_comparable = {k for k, v in r_rows.items() if v["axis"] in COMPARABLE_AXES}
    require(candidate_comparable == reference_comparable, (
        f"comparable scenario set mismatch: candidate-only={sorted(candidate_comparable-reference_comparable)} "
        f"reference-only={sorted(reference_comparable-candidate_comparable)}"
    ))

    comparisons: list[dict[str, Any]] = []
    divergences = 0
    p0_divergences = 0
    unsupported = 0
    for scenario_id in sorted(c_rows):
        c = c_rows[scenario_id]
        r = r_rows.get(scenario_id)
        if c["axis"] == "voicechat" and (r is None or r.get("status") == "unsupported"):
            comparisons.append({"id": scenario_id, "axis": "voicechat", "comparable": False, "match": True})
            continue
        require(r is not None, f"reference missing scenario {scenario_id}")
        if c["axis"] in COMPARABLE_AXES:
            require(r["status"] != "unsupported", f"reference unsupported comparable scenario {scenario_id}")
        if r["status"] == "unsupported":
            unsupported += 1
        same = c["status"] == r["status"]
        if not same:
            divergences += 1
            if c["p0"] or r["p0"]:
                p0_divergences += 1
        comparisons.append({
            "id": scenario_id,
            "axis": c["axis"],
            "p0": bool(c["p0"] or r["p0"]),
            "candidate_status": c["status"],
            "reference_status": r["status"],
            "match": same,
            "comparable": True,
        })

    require(c_rc == 0, f"candidate oracle exited {c_rc}")
    require(r_rc == 0, f"reference oracle exited {r_rc}")
    require(c_summary.get("failures") == 0, "candidate oracle self-check has failures")
    require(r_summary.get("failures") == 0, "reference oracle self-check has failures")
    require(divergences == 0, f"behavioral divergences={divergences}, p0={p0_divergences}")

    return {
        "schema": "dycrpt-external-differential-v1",
        "candidate_commit": c_meta["commit"],
        "candidate_implementation": c_meta["implementation"],
        "reference_commit": r_meta["commit"],
        "reference_implementation": r_meta["implementation"],
        "comparable_scenarios": len(candidate_comparable),
        "total_candidate_scenarios": len(c_rows),
        "unsupported_voicechat_rows": unsupported,
        "divergences": divergences,
        "p0_divergences": p0_divergences,
        "private_material_logged": False,
        "passed": True,
        "comparisons": comparisons,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, help="dycrpt oracle command")
    parser.add_argument("--reference", required=True, help="external reference oracle command")
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--out", type=Path, default=Path("crypto-parity/reports/external-differential.json"))
    args = parser.parse_args()
    if not SHA40.fullmatch(args.candidate_commit):
        parser.error("--candidate-commit must be a lowercase 40-character SHA")
    if args.timeout < 1 or args.timeout > 3600:
        parser.error("--timeout must be 1..3600 seconds")

    try:
        candidate = run_oracle(args.candidate, args.timeout, {"DYCRPT_COMMIT": args.candidate_commit})
        reference = run_oracle(args.reference, args.timeout, {})
        report = compare(candidate, reference, args.candidate_commit)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    except DiffError as exc:
        print(f"EXTERNAL DIFFERENTIAL FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"EXTERNAL DIFFERENTIAL PASS: {report['comparable_scenarios']} comparable scenarios")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

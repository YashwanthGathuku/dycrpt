#!/usr/bin/env python3
"""Validate independent cryptography audit evidence for one exact release SHA."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
STATUSES = {"fixed", "accepted", "not-applicable"}


class AuditError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def validate(record: Any, expected_commit: str) -> None:
    require(isinstance(record, dict), "audit evidence must be an object")
    required = {
        "schema",
        "audited_commit",
        "reviewer",
        "independent",
        "report_sha256",
        "signature_sha256",
        "classical_v1_suitable",
        "residual_risk_statement",
        "findings",
    }
    require(set(record) == required, f"audit fields must equal {sorted(required)}")
    require(record["schema"] == "dycrpt-independent-audit-v1", "wrong audit schema")
    require(record["audited_commit"] == expected_commit, "audit is not for exact release candidate")
    require(record["independent"] is True, "reviewer is not declared independent")
    require(record["classical_v1_suitable"] is True, "reviewer did not approve ClassicalV1 assumptions")
    require(isinstance(record["report_sha256"], str) and SHA256.fullmatch(record["report_sha256"]), "bad report hash")
    require(isinstance(record["signature_sha256"], str) and SHA256.fullmatch(record["signature_sha256"]), "bad signature hash")
    require(
        isinstance(record["residual_risk_statement"], str)
        and 20 <= len(record["residual_risk_statement"]) <= 8192,
        "residual risk statement is missing/too short",
    )

    reviewer = record["reviewer"]
    require(isinstance(reviewer, dict), "reviewer must be an object")
    reviewer_fields = {"name", "organization", "contact", "qualifications"}
    require(set(reviewer) == reviewer_fields, "unexpected reviewer fields")
    require(isinstance(reviewer["name"], str) and len(reviewer["name"]) >= 2, "missing reviewer name")
    require(isinstance(reviewer["organization"], str) and reviewer["organization"], "missing reviewer organization")
    require(isinstance(reviewer["contact"], str) and len(reviewer["contact"]) >= 3, "missing reviewer contact")
    require(
        isinstance(reviewer["qualifications"], str) and len(reviewer["qualifications"]) >= 20,
        "reviewer qualifications insufficiently documented",
    )

    findings = record["findings"]
    require(isinstance(findings, list), "findings must be an array")
    seen: set[str] = set()
    for idx, finding in enumerate(findings):
        require(isinstance(finding, dict), f"finding[{idx}] must be an object")
        fields = {"id", "severity", "status", "title", "disposition", "verified_commit"}
        require(set(finding) == fields, f"unexpected fields in finding[{idx}]")
        fid = finding["id"]
        require(isinstance(fid, str) and 0 < len(fid) <= 128, f"bad finding id at {idx}")
        require(fid not in seen, f"duplicate finding id {fid}")
        seen.add(fid)
        severity = finding["severity"]
        status = finding["status"]
        require(severity in SEVERITIES, f"bad severity for {fid}")
        require(status in STATUSES, f"bad status for {fid}")
        require(finding["verified_commit"] == expected_commit, f"finding {fid} not reverified on candidate")
        require(isinstance(finding["title"], str) and finding["title"], f"missing title for {fid}")
        require(
            isinstance(finding["disposition"], str) and len(finding["disposition"]) >= 10,
            f"missing disposition for {fid}",
        )
        if severity in {"critical", "high"}:
            require(status in {"fixed", "not-applicable"}, f"{severity} finding {fid} cannot be accepted")
        if severity == "medium" and status == "accepted":
            require(len(finding["disposition"]) >= 40, f"accepted medium {fid} needs detailed rationale")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    if not SHA40.fullmatch(args.expected_commit):
        parser.error("--expected-commit must be a lowercase 40-character SHA")
    try:
        record = json.loads(args.evidence.read_text(encoding="utf-8"))
        validate(record, args.expected_commit)
    except (OSError, json.JSONDecodeError, AuditError) as exc:
        print(f"INDEPENDENT AUDIT FAIL: {exc}", file=sys.stderr)
        return 1
    print("INDEPENDENT AUDIT EVIDENCE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

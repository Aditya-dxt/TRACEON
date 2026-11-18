"""Deterministic, versioned policy evaluation over scanner output."""

import uuid

from ..db.models import Asset, Scan, utc_now
from ..models import Verdict, VerdictKind

POLICY_ID = "default"
POLICY_VERSION = 1


def evaluate_scan(asset: Asset, scan: Scan) -> Verdict:
    """Apply the documented precedence: deterministic critical, high, medium, clean."""

    result = scan.result_json or {}
    findings = result.get("findings", [])
    reasons: list[str] = []
    verdict = VerdictKind.APPROVE

    for finding in findings:
        severity = finding.get("severity")
        deterministic = finding.get("deterministic") is True
        title = str(finding.get("title", finding.get("check", "Finding")))
        if severity == "critical" and deterministic:
            verdict = VerdictKind.BLOCK
            reasons.append(f"Deterministic critical finding: {title}")
        elif severity in {"critical", "high"} and verdict != VerdictKind.BLOCK:
            verdict = VerdictKind.QUARANTINE
            reasons.append(f"High-risk finding requires review: {title}")
        elif severity == "medium" and verdict not in {
            VerdictKind.BLOCK,
            VerdictKind.QUARANTINE,
        }:
            verdict = VerdictKind.CONDITIONAL
            reasons.append(f"Medium-severity finding requires conditions: {title}")

    failed = [check for check in result.get("checks_run", []) if check.get("status") == "fail"]
    errored = [check for check in result.get("checks_run", []) if check.get("status") == "error"]
    if failed and verdict != VerdictKind.BLOCK:
        verdict = VerdictKind.QUARANTINE
        reasons.extend(f"Required check failed: {check.get('name', 'unknown')}" for check in failed)
    if errored and verdict not in {VerdictKind.BLOCK, VerdictKind.QUARANTINE}:
        verdict = VerdictKind.QUARANTINE
        reasons.extend(f"Check errored: {check.get('name', 'unknown')}" for check in errored)
    if not reasons:
        reasons.append("All checks passed with no findings above informational")

    return Verdict(
        decision_id=f"d_{uuid.uuid4().hex[:16]}",
        asset_id=asset.asset_id,
        verdict=verdict,
        reasons=reasons,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        decided_at=utc_now(),
    )

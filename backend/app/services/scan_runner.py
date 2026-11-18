"""In-process bridge from stored assets to the Traceon scanner package."""

import logging
import sys
import uuid
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scanner import scan_artifact  # noqa: E402

from ..db.models import Asset, Decision, FindingRecord, Scan, utc_now
from ..db.session import SessionLocal
from ..models import ScanResult
from .audit import append_audit_event
from .policy import evaluate_scan

logger = logging.getLogger(__name__)


def new_scan_id() -> str:
    """Generate the backend scan request ID returned by POST /v1/scans."""

    return f"sc_{uuid.uuid4().hex[:8]}"


def _mark_failed(scan_id: str) -> None:
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.completed_at = utc_now()
            session.commit()


def run_scan(scan_id: str) -> None:
    """Run one stored asset through scanner.scan_artifact and persist its report."""

    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None or scan.status != "queued":
            return
        asset = session.get(Asset, scan.asset_id)
        storage_path = Path(asset.storage_path) if asset and asset.storage_path else None
        if storage_path is None or not storage_path.is_file():
            scan.status = "failed"
            scan.started_at = utc_now()
            scan.completed_at = utc_now()
            session.commit()
            logger.warning("Scan %s failed because its stored asset is unavailable", scan_id)
            return
        scan.status = "running"
        scan.started_at = utc_now()
        session.commit()

    try:
        if not storage_path.is_file():
            raise FileNotFoundError
        result = scan_artifact(str(storage_path))
        validated = ScanResult.model_validate(result)
    except Exception:
        logger.exception("Scanner integration failed for scan %s", scan_id)
        _mark_failed(scan_id)
        return

    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        asset = session.get(Asset, scan.asset_id)
        if asset is None:
            scan.status = "failed"
            scan.completed_at = utc_now()
            session.commit()
            return
        scan.scanner_scan_id = validated.scan_id
        scan.engine_version = validated.engine_version
        scan.started_at = validated.started_at
        scan.completed_at = validated.completed_at
        scan.status = "completed"
        # Store exactly the dictionary returned by the scanner. The Pydantic
        # model above validates it but does not replace or normalize this value.
        scan.result_json = result
        scan.findings.extend(
            FindingRecord(
                finding_id=finding.finding_id,
                check=finding.check,
                category=finding.category.value,
                severity=finding.severity.value,
                confidence=finding.confidence.value,
                deterministic=finding.deterministic,
                title=finding.title,
                evidence=finding.evidence,
                recommendation=finding.recommendation,
            )
            for finding in validated.findings
        )
        verdict = evaluate_scan(asset, scan)
        session.add(
            Decision(
                decision_id=verdict.decision_id,
                asset_id=asset.asset_id,
                scan_id=scan.scan_id,
                verdict=verdict.verdict.value,
                reasons=verdict.reasons,
                policy_id=verdict.policy_id,
                policy_version=verdict.policy_version,
                decided_at=verdict.decided_at,
            )
        )
        append_audit_event(
            session,
            event_type="scan.completed",
            entity_type="scan",
            entity_id=scan.scan_id,
            payload={
                "asset_id": asset.asset_id,
                "sha256": asset.sha256,
                "decision_id": verdict.decision_id,
                "verdict": verdict.verdict.value,
            },
        )
        session.commit()

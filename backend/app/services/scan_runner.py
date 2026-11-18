"""In-process bridge from stored assets to the Traceon scanner package."""

import logging
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import unquote, urlsplit

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scanner import scan_artifact  # noqa: E402

from ..db.models import Asset, AttestationRecord, Decision, FindingRecord, Scan, utc_now
from ..db.session import SessionLocal
from ..models import ScanResult
from .audit import append_audit_event
from .attestation import build_bom, build_statement, sign_dsse
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


def _run_remote_sandbox(storage_path: str) -> dict:
    """Ask the authenticated internal Cloud Run worker to scan one GCS object."""

    from google.auth.transport.requests import AuthorizedSession, Request
    from google.oauth2 import id_token

    worker_url = os.getenv("TRACEON_SANDBOX_URL", "").rstrip("/")
    if not worker_url:
        raise RuntimeError("TRACEON_SANDBOX_URL is not configured")
    parsed = urlsplit(storage_path)
    expected_bucket = os.getenv("TRACEON_QUARANTINE_BUCKET", "")
    if parsed.scheme != "gs" or not expected_bucket or parsed.netloc != expected_bucket:
        raise RuntimeError("Asset does not reference the configured quarantine bucket")
    generation = int(parsed.fragment) if parsed.fragment else None
    object_name = unquote(parsed.path.lstrip("/"))
    credentials = id_token.fetch_id_token_credentials(worker_url, request=Request())
    response = AuthorizedSession(credentials).post(
        f"{worker_url}/scan",
        json={"object_name": object_name, "generation": generation},
        timeout=(10, 210),
    )
    if response.status_code != 200:
        raise RuntimeError(f"Isolated scanner returned HTTP {response.status_code}")
    result = response.json()
    if not isinstance(result, dict):
        raise RuntimeError("Isolated scanner returned an invalid result")
    return result


def run_scan(scan_id: str) -> None:
    """Run one stored asset through scanner.scan_artifact and persist its report."""

    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        if scan is None or scan.status != "queued":
            return
        asset = session.get(Asset, scan.asset_id)
        stored_path = asset.storage_path if asset else None
        local_path = Path(stored_path) if stored_path and not stored_path.startswith("gs://") else None
        if not stored_path or (local_path is not None and not local_path.is_file()):
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
        if stored_path.startswith("gs://"):
            result = _run_remote_sandbox(stored_path)
        else:
            if local_path is None or not local_path.is_file():
                raise FileNotFoundError
            result = scan_artifact(str(local_path))
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
        decision = Decision(
                decision_id=verdict.decision_id,
                asset_id=asset.asset_id,
                scan_id=scan.scan_id,
                verdict=verdict.verdict.value,
                reasons=verdict.reasons,
                policy_id=verdict.policy_id,
                policy_version=verdict.policy_version,
                decided_at=verdict.decided_at,
            )
        session.add(decision)
        session.flush()
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
        if decision.verdict in {"APPROVE", "CONDITIONAL"}:
            try:
                bom = build_bom(asset, scan)
                envelope = sign_dsse(build_statement(asset, scan, decision, bom))
                envelope["bom"] = bom
                attestation_id = f"att_{uuid.uuid4().hex[:16]}"
                session.add(
                    AttestationRecord(
                        attestation_id=attestation_id,
                        asset_id=asset.asset_id,
                        scan_id=scan.scan_id,
                        document=envelope,
                    )
                )
                append_audit_event(
                    session,
                    event_type="attestation.signed",
                    entity_type="attestation",
                    entity_id=attestation_id,
                    payload={"asset_id": asset.asset_id, "scan_id": scan.scan_id, "keyid": envelope["signatures"][0]["keyid"]},
                )
            except Exception:
                logger.exception("Could not sign eligible attestation for scan %s", scan_id)
                append_audit_event(
                    session,
                    event_type="attestation.signing_failed",
                    entity_type="scan",
                    entity_id=scan.scan_id,
                    payload={"asset_id": asset.asset_id, "reason": "signing unavailable"},
                )
        session.commit()

"""FastAPI entry point for the Traceon backend."""

import logging

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .config import cors_origins
from .db.models import Asset, AttestationRecord, Decision, FindingRecord, Scan, utc_now
from .db.session import get_session
from .models import (
    AssetImportResponse,
    ErrorResponse,
    HealthResponse,
    ImportAssetRequest,
    ScanAcceptedResponse,
    StartScanRequest,
    VerifyRequest,
)
from .services.scan_runner import new_scan_id, run_scan
from .services.huggingface import import_model_file
from .services.attestation import verify_dsse

logger = logging.getLogger(__name__)

app = FastAPI(title="Traceon API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    response = ErrorResponse(
        error="Request validation failed",
        code="VALIDATION_ERROR",
    )
    return JSONResponse(status_code=422, content=response.model_dump())


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict):
        error = str(exc.detail.get("error", "Request failed"))
        code = str(exc.detail.get("code", "HTTP_ERROR"))
    else:
        error = exc.detail if isinstance(exc.detail, str) else "Request failed"
        code = "HTTP_ERROR"
    response = ErrorResponse(error=error, code=code)
    return JSONResponse(
        status_code=exc.status_code,
        content=response.model_dump(),
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "Unhandled API error",
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    response = ErrorResponse(
        error="Internal server error",
        code="INTERNAL_SERVER_ERROR",
    )
    return JSONResponse(status_code=500, content=response.model_dump())


@app.get("/v1/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/v1/assets")
async def list_assets(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    verdict: str | None = Query(default=None, pattern="^(BLOCK|QUARANTINE|CONDITIONAL|APPROVE)$"),
    session: Session = Depends(get_session),
) -> list[dict]:
    latest_decision_id = (
        select(Decision.decision_id)
        .where(Decision.asset_id == Asset.asset_id)
        .order_by(Decision.decided_at.desc())
        .limit(1)
        .scalar_subquery()
    )
    query = select(Asset)
    if verdict:
        query = query.join(Decision, Decision.decision_id == latest_decision_id).where(Decision.verdict == verdict)
    assets = session.scalars(query.order_by(Asset.created_at.desc()).offset(offset).limit(limit)).all()
    results = []
    for asset in assets:
        decision = session.scalar(select(Decision).where(Decision.asset_id == asset.asset_id).order_by(Decision.decided_at.desc()).limit(1))
        scan = session.scalar(select(Scan).where(Scan.asset_id == asset.asset_id).order_by(Scan.queued_at.desc()).limit(1))
        attestation = session.scalar(select(AttestationRecord).where(AttestationRecord.asset_id == asset.asset_id).order_by(AttestationRecord.created_at.desc()).limit(1))
        results.append({
            "asset_id": asset.asset_id,
            "name": asset.name,
            "source": asset.source,
            "format": asset.file_format,
            "size_bytes": asset.size_bytes,
            "sha256": asset.sha256,
            "latest_verdict": decision.verdict if decision else None,
            "latest_scan_id": scan.scanner_scan_id or scan.scan_id if scan else None,
            "attestation_id": attestation.attestation_id if attestation else None,
            "created_at": asset.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
    return results


@app.get("/v1/assets/{asset_id}")
async def get_asset(asset_id: str, session: Session = Depends(get_session)) -> dict:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail={"error": "Asset not found", "code": "ASSET_NOT_FOUND"})
    decision = session.scalar(select(Decision).where(Decision.asset_id == asset_id).order_by(Decision.decided_at.desc()).limit(1))
    scan = session.scalar(select(Scan).where(Scan.asset_id == asset_id, Scan.status == "completed").order_by(Scan.completed_at.desc()).limit(1))
    attestation = session.scalar(select(AttestationRecord).where(AttestationRecord.asset_id == asset_id).order_by(AttestationRecord.created_at.desc()).limit(1))
    severities = {name: 0 for name in ("critical", "high", "medium", "low", "informational")}
    if scan:
        for severity, count in session.execute(
            select(FindingRecord.severity, func.count())
            .where(FindingRecord.scan_id == scan.scan_id)
            .group_by(FindingRecord.severity)
        ):
            severities[severity] = count
    return {
        "asset_id": asset.asset_id,
        "name": asset.name,
        "source": asset.source,
        "format": asset.file_format,
        "size_bytes": asset.size_bytes,
        "sha256": asset.sha256,
        "verdict": ({"decision_id": decision.decision_id, "verdict": decision.verdict, "reasons": decision.reasons, "decided_at": decision.decided_at.strftime("%Y-%m-%dT%H:%M:%SZ")} if decision else None),
        "findings_summary": severities,
        "attestation_id": attestation.attestation_id if attestation else None,
        "created_at": asset.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@app.post("/v1/assets/import", status_code=201, response_model=AssetImportResponse)
def import_asset(
    request: ImportAssetRequest,
    session: Session = Depends(get_session),
) -> AssetImportResponse:
    name = request.file_path.rsplit("/", 1)[-1]
    asset_id, commit, size, digest, storage_path = import_model_file(
        request.repo_id, request.revision, request.file_path
    )
    file_format = name.rsplit(".", 1)[-1].lower() if "." in name else "unknown"
    asset = Asset(
        asset_id=asset_id,
        name=name,
        source=f"huggingface:{request.repo_id}@{commit}",
        file_format=file_format,
        size_bytes=size,
        sha256=digest,
        storage_path=storage_path,
        status="quarantined",
    )
    session.add(asset)
    session.flush()
    from .services.audit import append_audit_event

    append_audit_event(
        session,
        event_type="asset.imported",
        entity_type="asset",
        entity_id=asset_id,
        payload={"source": asset.source, "sha256": digest, "size_bytes": size},
    )
    session.commit()
    session.refresh(asset)
    return AssetImportResponse(
        asset_id=asset.asset_id,
        name=asset.name,
        source=asset.source,
        format=asset.file_format,
        size_bytes=asset.size_bytes,
        sha256=asset.sha256,
        status=asset.status,
        created_at=asset.created_at,
    )


@app.post("/v1/scans", status_code=202, response_model=ScanAcceptedResponse)
async def create_scan(
    request: StartScanRequest,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
) -> ScanAcceptedResponse:
    asset = session.get(Asset, request.asset_id)
    if asset is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "Asset not found", "code": "ASSET_NOT_FOUND"},
        )
    if not asset.storage_path:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "Asset has no available scanner input",
                "code": "ASSET_STORAGE_UNAVAILABLE",
            },
        )

    scan = Scan(scan_id=new_scan_id(), asset_id=asset.asset_id, status="queued")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    background_tasks.add_task(run_scan, scan.scan_id)
    return ScanAcceptedResponse(
        scan_id=scan.scan_id,
        asset_id=scan.asset_id,
        status="queued",
        queued_at=scan.queued_at,
    )


@app.get("/v1/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    session: Session = Depends(get_session),
) -> JSONResponse:
    scan = session.scalar(
        select(Scan).where(
            or_(Scan.scan_id == scan_id, Scan.scanner_scan_id == scan_id)
        )
    )
    if scan is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "Scan not found", "code": "SCAN_NOT_FOUND"},
        )
    if scan.status == "failed":
        raise HTTPException(
            status_code=500,
            detail={"error": "Scanner job failed", "code": "SCAN_FAILED"},
        )
    if scan.result_json is None:
        raise HTTPException(
            status_code=409,
            detail={"error": "Scan is still in progress", "code": "SCAN_IN_PROGRESS"},
        )
    # Return the scanner document directly to preserve its JSON contract.
    return JSONResponse(content=scan.result_json)


@app.get("/v1/attestations/{attestation_id}")
async def get_attestation(attestation_id: str, session: Session = Depends(get_session)) -> dict:
    record = session.get(AttestationRecord, attestation_id)
    if record is None:
        raise HTTPException(status_code=404, detail={"error": "Attestation not found", "code": "ATTESTATION_NOT_FOUND"})
    return record.document


@app.get("/v1/assets/{asset_id}/bom")
async def get_asset_bom(asset_id: str, session: Session = Depends(get_session)) -> dict:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail={"error": "Asset not found", "code": "ASSET_NOT_FOUND"})
    attestation = session.scalar(
        select(AttestationRecord)
        .where(AttestationRecord.asset_id == asset_id)
        .order_by(AttestationRecord.created_at.desc())
        .limit(1)
    )
    if attestation is not None and "bom" in attestation.document:
        return attestation.document["bom"]
    scan = session.scalar(select(Scan).where(Scan.asset_id == asset_id, Scan.status == "completed").order_by(Scan.completed_at.desc()).limit(1))
    if scan is None:
        raise HTTPException(status_code=409, detail={"error": "Asset has no completed scan", "code": "SCAN_NOT_AVAILABLE"})
    from .services.attestation import build_bom

    return build_bom(asset, scan)


@app.post("/v1/verify")
async def verify_asset(request: VerifyRequest, session: Session = Depends(get_session)) -> dict:
    verified_at = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
    asset = session.scalar(select(Asset).where(Asset.sha256 == request.sha256.lower()).limit(1))
    if asset is None:
        return {"valid": False, "reason": "No asset with this SHA-256 digest is registered", "verified_at": verified_at}
    attestation = session.scalar(
        select(AttestationRecord).where(AttestationRecord.asset_id == asset.asset_id).order_by(AttestationRecord.created_at.desc()).limit(1)
    )
    if attestation is None:
        return {"valid": False, "reason": "No signed attestation exists for this artifact", "verified_at": verified_at}
    valid, reason = verify_dsse(attestation.document, request.sha256)
    if not valid:
        return {"valid": False, "reason": reason or "Attestation signature is invalid", "verified_at": verified_at}
    statement = attestation.document["statement"]
    predicate = statement["predicate"]
    decision = session.scalar(select(Decision).where(Decision.scan_id == attestation.scan_id).limit(1))
    return {
        "valid": True,
        "subject_digest": statement["subject"][0]["digest"]["sha256"],
        "bom_digest": predicate["bomDigest"]["sha256"],
        "verdict": decision.verdict if decision else predicate["verdict"],
        "attestation_id": attestation.attestation_id,
        "key_id": attestation.document["signatures"][0]["keyid"],
        "verified_at": verified_at,
    }

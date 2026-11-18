"""FastAPI entry point for the Traceon backend."""

import logging

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .config import cors_origins
from .db.models import Asset, Scan, utc_now
from .db.session import get_session
from .models import (
    AssetImportResponse,
    ErrorResponse,
    HealthResponse,
    ImportAssetRequest,
    ScanAcceptedResponse,
    StartScanRequest,
)
from .services.scan_runner import new_scan_id, run_scan
from .services.huggingface import import_model_file

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

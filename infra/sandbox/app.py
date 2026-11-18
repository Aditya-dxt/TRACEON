"""Internal Cloud Run worker that runs scanner jobs inside Cloud Run sandboxes."""

import json
import logging
import os
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from google.api_core.exceptions import NotFound
from google.cloud import storage
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

MAX_ARTIFACT_BYTES = int(os.getenv("TRACEON_MAX_ARTIFACT_BYTES", str(512 * 1024 * 1024)))
MAX_RESULT_BYTES = 16 * 1024 * 1024
SCAN_TIMEOUT_SECONDS = int(os.getenv("TRACEON_SANDBOX_TIMEOUT_SECONDS", "195"))
SANDBOX_CLI = os.getenv("TRACEON_SANDBOX_CLI", "/usr/local/gcp/bin/sandbox")
QUARANTINE_BUCKET = os.getenv("TRACEON_QUARANTINE_BUCKET", "")
WORKER_ROOT = Path(__file__).resolve().parent
SCANNER_SCRIPT = WORKER_ROOT / "run_scanner.py"

app = FastAPI(title="Traceon isolated scanner worker", version="1.0.0")


class ScanRequest(BaseModel):
    object_name: str = Field(min_length=1, max_length=1024)
    generation: int | None = Field(default=None, gt=0)


def error_response(status_code: int, error: str, code: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": error, "code": code})


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict):
        error = str(exc.detail.get("error", "Request failed"))
        code = str(exc.detail.get("code", "HTTP_ERROR"))
    else:
        error = exc.detail if isinstance(exc.detail, str) else "Request failed"
        code = "HTTP_ERROR"
    return error_response(exc.status_code, error, code)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return error_response(422, "Request validation failed", "VALIDATION_ERROR")


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unexpected scanner worker failure", exc_info=(type(exc), exc, exc.__traceback__))
    return error_response(500, "Internal server error", "INTERNAL_SERVER_ERROR")


def _download_quarantined_object(request: ScanRequest, artifact_path: Path) -> None:
    if not QUARANTINE_BUCKET:
        raise HTTPException(
            status_code=503,
            detail={"error": "Quarantine bucket is not configured", "code": "STORAGE_UNAVAILABLE"},
        )
    blob = storage.Client().bucket(QUARANTINE_BUCKET).blob(
        request.object_name,
        generation=request.generation,
    )
    try:
        blob.reload()
    except NotFound as exc:
        raise HTTPException(
            status_code=404,
            detail={"error": "Quarantined artifact not found", "code": "ARTIFACT_NOT_FOUND"},
        ) from exc
    if blob.size is None or blob.size == 0:
        raise HTTPException(
            status_code=422,
            detail={"error": "Artifact is empty or has unknown size", "code": "INVALID_ARTIFACT"},
        )
    if blob.size > MAX_ARTIFACT_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"error": "Artifact exceeds the worker size limit", "code": "ARTIFACT_TOO_LARGE"},
        )
    blob.download_to_filename(str(artifact_path))


def _sandbox_scan(artifact_path: Path) -> dict[str, Any]:
    cli = Path(SANDBOX_CLI)
    if not cli.is_file():
        raise HTTPException(
            status_code=503,
            detail={"error": "Cloud Run sandbox launcher is unavailable", "code": "SANDBOX_UNAVAILABLE"},
        )

    command = [
        str(cli),
        "do",
        "--",
        "/usr/local/bin/python",
        str(SCANNER_SCRIPT),
        str(artifact_path),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=WORKER_ROOT.parent.parent,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(
            status_code=504,
            detail={"error": "Scanner exceeded its time limit", "code": "SCAN_TIMEOUT"},
        ) from exc
    except OSError as exc:
        logger.error("Unable to launch sandbox CLI")
        raise HTTPException(
            status_code=503,
            detail={"error": "Unable to start isolated scanner", "code": "SANDBOX_LAUNCH_FAILED"},
        ) from exc

    if completed.returncode != 0:
        logger.error("Sandbox scanner exited with code %s", completed.returncode)
        raise HTTPException(
            status_code=502,
            detail={"error": "Isolated scanner failed", "code": "SCANNER_FAILED"},
        )
    if len(completed.stdout.encode("utf-8")) > MAX_RESULT_BYTES:
        raise HTTPException(
            status_code=502,
            detail={"error": "Scanner output exceeded the response limit", "code": "RESULT_TOO_LARGE"},
        )
    try:
        result = json.loads(completed.stdout)
        if not isinstance(result, dict):
            raise ValueError("scanner output must be a JSON object")
        return result
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error("Sandbox scanner returned invalid JSON")
        raise HTTPException(
            status_code=502,
            detail={"error": "Scanner returned an invalid result", "code": "INVALID_SCANNER_RESULT"},
        ) from exc


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
def scan_object(request: ScanRequest) -> dict[str, Any]:
    """Download a fixed-bucket object, then scan it with no sandbox egress."""

    temp_dir = Path(tempfile.mkdtemp(prefix="traceon-scan-", dir=tempfile.gettempdir()))
    os.chmod(temp_dir, 0o755)
    artifact_path = temp_dir / f"{uuid.uuid4().hex}.artifact"
    try:
        _download_quarantined_object(request, artifact_path)
        os.chmod(artifact_path, 0o444)
        return _sandbox_scan(artifact_path)
    finally:
        try:
            if artifact_path.exists():
                os.chmod(artifact_path, 0o600)
            artifact_path.unlink(missing_ok=True)
            temp_dir.rmdir()
        except OSError:
            logger.warning("Could not remove temporary scanner input")

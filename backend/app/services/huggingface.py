"""Hugging Face model file import into private quarantine storage."""

import hashlib
import os
import uuid
from pathlib import Path, PurePosixPath

from fastapi import HTTPException
MAX_IMPORT_BYTES = int(os.getenv("TRACEON_MAX_IMPORT_BYTES", str(512 * 1024 * 1024)))
QUARANTINE_BUCKET = os.getenv("TRACEON_QUARANTINE_BUCKET", "")
LOCAL_QUARANTINE_DIR = Path(
    os.getenv("TRACEON_LOCAL_QUARANTINE_DIR", str(Path(__file__).resolve().parents[2] / "data" / "quarantine"))
)


def import_model_file(repo_id: str, revision: str, file_path: str) -> tuple[str, str, int, str, str]:
    """Resolve a moving ref once and import the exact file from that commit."""

    from huggingface_hub import HfApi, hf_hub_download

    normalized = PurePosixPath(file_path)
    if normalized.is_absolute() or ".." in normalized.parts or "" in normalized.parts:
        raise HTTPException(status_code=422, detail={"error": "Invalid repository file path", "code": "INVALID_FILE_PATH"})
    token = os.getenv("HF_TOKEN") or None
    try:
        info = HfApi().model_info(repo_id=repo_id, revision=revision, files_metadata=True, token=token)
        commit = info.sha
        sibling = next((item for item in info.siblings if item.rfilename == normalized.as_posix()), None)
        if sibling is None:
            raise HTTPException(status_code=404, detail={"error": "Model file not found", "code": "MODEL_FILE_NOT_FOUND"})
        if sibling.size is None or sibling.size <= 0:
            raise HTTPException(status_code=422, detail={"error": "Model file has invalid size metadata", "code": "INVALID_ARTIFACT"})
        if sibling.size > MAX_IMPORT_BYTES:
            raise HTTPException(status_code=413, detail={"error": "Model file exceeds the import size limit", "code": "ARTIFACT_TOO_LARGE"})
        local_file = Path(hf_hub_download(repo_id=repo_id, filename=normalized.as_posix(), revision=commit, token=token))
    except HTTPException:
        raise
    except Exception as exc:
        # Keep provider details/tokens out of API responses and logs.
        raise HTTPException(status_code=502, detail={"error": "Hugging Face repository could not be imported", "code": "HUGGING_FACE_IMPORT_FAILED"}) from exc

    if local_file.stat().st_size != sibling.size:
        raise HTTPException(status_code=502, detail={"error": "Downloaded file size does not match repository metadata", "code": "ARTIFACT_METADATA_MISMATCH"})
    digest = hashlib.sha256()
    with local_file.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    asset_id = f"a_{uuid.uuid4().hex[:16]}"
    object_name = f"{asset_id}/{normalized.name}"
    if QUARANTINE_BUCKET:
        from google.cloud import storage

        blob = storage.Client().bucket(QUARANTINE_BUCKET).blob(object_name)
        blob.upload_from_filename(str(local_file), if_generation_match=0)
        storage_path = f"gs://{QUARANTINE_BUCKET}/{object_name}#{blob.generation}"
    else:
        LOCAL_QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        target = LOCAL_QUARANTINE_DIR / object_name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(local_file.read_bytes())
        storage_path = str(target)
    return asset_id, commit, sibling.size, digest.hexdigest(), storage_path

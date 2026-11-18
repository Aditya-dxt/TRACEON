# Traceon backend

## Local setup

From the repository root, install the backend dependencies and apply the database migration:

```powershell
python -m pip install -r backend/requirements.txt
alembic -c backend/alembic.ini upgrade head
uvicorn app.main:app --app-dir backend --reload
```

The API defaults to a SQLite database at `backend/traceon.db`. That local database is ignored by Git. To use PostgreSQL, set `TRACEON_DATABASE_URL` before running Alembic or the API:

```powershell
$env:TRACEON_DATABASE_URL = "postgresql+psycopg://<user>:<password>@localhost:5432/traceon"
```

Keep credentials in your local environment or secret manager. Do not commit them.

## Database migrations

Apply the current schema:

```powershell
alembic -c backend/alembic.ini upgrade head
```

Create a new migration after changing a database model:

```powershell
alembic -c backend/alembic.ini revision --autogenerate -m "describe the schema change"
```

Review generated migrations before applying them. SQLite is intended for local development; PostgreSQL uses the same SQLAlchemy models.

## Seed a harmless local asset

After applying migrations, add the clean scanner corpus sample to the local database. The command is idempotent and does not overwrite an existing row:

```powershell
python backend/seed.py
```

Then queue it with `POST /v1/scans` using `{"asset_id":"a_seed_clean"}`.

## Health endpoint

```powershell
Invoke-RestMethod http://localhost:8000/v1/health
```

Expected response:

```json
{"status":"ok"}
```

## Scanner jobs

`POST /v1/scans` accepts an `asset_id` and queues a lightweight in-process task. An asset must already have a backend-managed `storage_path`; the path is not accepted from API callers or returned to them. The task calls `scanner.scan_artifact`, keeps its result document unchanged in the database, and indexes its findings. Poll `GET /v1/scans/{scan_id}` for the completed scanner result. This in-process runner is an MVP step; the sandbox worker will replace it for isolated scanning.

## Hugging Face quarantine import

`POST /v1/assets/import` accepts a Hugging Face model repository, revision, and repository-relative file path. The backend resolves the requested branch or tag to a commit SHA, enforces `TRACEON_MAX_IMPORT_BYTES` (default 512 MiB), hashes the downloaded bytes, and records the immutable source revision. Set `HF_TOKEN` only in the runtime secret manager when private repositories are needed. If `TRACEON_QUARANTINE_BUCKET` is configured, imported bytes go to that private bucket; otherwise local development stores them under `backend/data/quarantine`. The public API never returns the private storage location.

## AI-BOM, attestations, and verification

Completed `APPROVE` and `CONDITIONAL` scans are eligible for an in-toto DSSE attestation. The backend generates a CycloneDX 1.7 AI-BOM with the scanner's public generator, hashes canonical JSON, and asks Cloud KMS to sign the DSSE pre-authentication encoding. Set `TRACEON_KMS_KEY_VERSION` from the Terraform `signing_key_version_name` output and grant the API service identity access to that key. The document keeps the base64 DSSE payload and decoded statement together for inspection. `GET /v1/attestations/{id}`, `GET /v1/assets/{id}/bom`, and `POST /v1/verify` expose the contract routes. The CLI checks a registered SHA-256 through the API:

```powershell
python backend/verify_cli.py <sha256> --api-url https://<traceon-api-url>
```

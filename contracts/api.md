# Traceon REST API Specification (contracts/api.md)

Version: `1.0.0`  
Standardized Contract for DeepTrace AI / Traceon Platform.  
This document defines all endpoints, input parameters, request payloads, and response JSON shapes agreed across `scanner/`, `backend/`, and `frontend/`.

---

## General Rules & Standards
1. **Error Response Format**:
   All errors (4xx, 5xx) must return a standardized JSON structure:
   ```json
   {
     "error": "Human readable error description",
     "code": "ERROR_CODE_STRING"
   }
   ```
2. **CORS**: CORS must be enabled for frontend origins (`http://localhost:3000`, production frontend domains).
3. **Timestamp Format**: ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
4. **Verdicts**: `BLOCK`, `QUARANTINE`, `CONDITIONAL`, `APPROVE`.
5. **Severities**: `informational`, `low`, `medium`, `high`, `critical`.
6. **Confidences**: `low`, `medium`, `high`.

---

## Endpoints

### 1. Health Check
- **Path**: `GET /v1/health`
- **Description**: Verify backend status.
- **Response**: `200 OK`
```json
{
  "status": "ok"
}
```

---

### 2. Import Asset
- **Path**: `POST /v1/assets/import`
- **Description**: Import an asset by Hugging Face repository ID or direct upload reference.
- **Request Body**:
```json
{
  "source": "huggingface",
  "repo_id": "google/gemma-2-2b",
  "revision": "main",
  "file_path": "model.safetensors"
}
```
- **Response**: `201 Created`
```json
{
  "asset_id": "a_001",
  "name": "model.safetensors",
  "source": "huggingface:google/gemma-2-2b@main",
  "format": "safetensors",
  "size_bytes": 4821034,
  "sha256": "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a",
  "status": "quarantined",
  "created_at": "2026-11-20T10:00:00Z"
}
```

---

### 3. List Assets
- **Path**: `GET /v1/assets`
- **Query Parameters**:
  - `limit` (int, default 50)
  - `offset` (int, default 0)
  - `verdict` (optional: `BLOCK`, `QUARANTINE`, `CONDITIONAL`, `APPROVE`)
- **Response**: `200 OK`
```json
[
  {
    "asset_id": "a_001",
    "name": "model.safetensors",
    "source": "huggingface:google/gemma-2-2b@main",
    "format": "safetensors",
    "size_bytes": 4821034,
    "sha256": "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a",
    "latest_verdict": "APPROVE",
    "latest_scan_id": "sc_001",
    "attestation_id": "att_001",
    "created_at": "2026-11-20T10:00:00Z"
  }
]
```

---

### 4. Get Asset Detail
- **Path**: `GET /v1/assets/{id}`
- **Description**: Returns detailed info for an asset, its findings, verdict, and attestation id.
- **Response**: `200 OK`
```json
{
  "asset_id": "a_001",
  "name": "model.safetensors",
  "source": "huggingface:google/gemma-2-2b@main",
  "format": "safetensors",
  "size_bytes": 4821034,
  "sha256": "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a",
  "verdict": {
    "decision_id": "d_001",
    "verdict": "APPROVE",
    "reasons": ["No findings above informational"],
    "decided_at": "2026-11-20T10:02:00Z"
  },
  "findings_summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "informational": 1
  },
  "attestation_id": "att_001",
  "created_at": "2026-11-20T10:00:00Z"
}
```

---

### 5. Get Asset AI-BOM
- **Path**: `GET /v1/assets/{id}/bom`
- **Description**: Exports the CycloneDX 1.7 AI-BOM JSON for the asset.
- **Response**: `200 OK` (CycloneDX 1.7 JSON format with `traceon:*` properties)

---

### 6. Trigger Scan
- **Path**: `POST /v1/scans`
- **Request Body**:
```json
{
  "asset_id": "a_001"
}
```
- **Response**: `202 Accepted`
```json
{
  "scan_id": "sc_001",
  "asset_id": "a_001",
  "status": "queued",
  "queued_at": "2026-11-20T10:00:00Z"
}
```

---

### 7. Get Scan Result
- **Path**: `GET /v1/scans/{id}`
- **Response**: `200 OK` (Matches `scan_result.schema.json`)

---

### 8. List Findings
- **Path**: `GET /v1/findings?asset_id={asset_id}`
- **Query Parameters**:
  - `asset_id` (optional, string)
  - `severity` (optional, enum)
- **Response**: `200 OK`
```json
[
  {
    "finding_id": "f_001",
    "check": "pickle_opcode",
    "category": "serialization",
    "severity": "critical",
    "confidence": "high",
    "deterministic": true,
    "title": "Deny-listed import in pickle",
    "evidence": {
      "module": "posix",
      "callable": "system",
      "offset": "0x01A4",
      "file": "model.bin",
      "sha256": "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"
    },
    "recommendation": "Do not load this file. Request a Safetensors version."
  }
]
```

---

### 9. Get Attestation
- **Path**: `GET /v1/attestations/{id}`
- **Response**: `200 OK` (Matches `attestation.schema.json` with in-toto Statement and DSSE signatures)

---

### 10. Verify File / Attestation
- **Path**: `POST /v1/verify`
- **Description**: Takes a file sha256 digest or uploaded file, re-verifies attestation and signature validity.
- **Request Body**:
```json
{
  "sha256": "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a"
}
```
- **Response (Valid)**: `200 OK`
```json
{
  "valid": true,
  "subject_digest": "4b5d1a8e99b24b89c3e414c718fa65f242d5f072979fb63dcf8b394931a7c86a",
  "bom_digest": "7a9b0c...e1f2",
  "verdict": "APPROVE",
  "attestation_id": "att_001",
  "key_id": "gcp-kms-traceon-signing-key-1",
  "verified_at": "2026-11-20T10:10:00Z"
}
```
- **Response (Mismatch / Invalid)**: `200 OK`
```json
{
  "valid": false,
  "reason": "Digest mismatch: file sha256 does not match signed subject digest in attestation",
  "verified_at": "2026-11-20T10:10:00Z"
}
```

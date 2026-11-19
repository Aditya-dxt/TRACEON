"""CycloneDX AI-BOM and DSSE in-toto signing/verification helpers."""

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://traceon.dev/attestation/v1"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Return DSSE pre-authentication encoding (PAE) bytes."""

    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(type_bytes)).encode() + b" " + type_bytes + b" " + str(len(payload)).encode() + b" " + payload


def build_bom(asset: Any, scan: Any) -> dict[str, Any]:
    """Use the repository scanner's CycloneDX 1.7 generator for backend assets."""

    from scanner import generate_bom

    revision = asset.source.rsplit("@", 1)[-1] if "@" in asset.source else "unknown"
    return generate_bom(
        {
            "name": asset.name,
            "version": revision,
            "format": asset.file_format,
            "sha256": asset.sha256,
        },
        [scan.result_json or {}],
    )


def build_statement(asset: Any, scan: Any, decision: Any, bom: dict[str, Any]) -> dict[str, Any]:
    from ..db.models import utc_now

    issued_at = utc_now()
    expires_at = issued_at + timedelta(days=90)
    fmt = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": asset.name, "digest": {"sha256": asset.sha256}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "bomDigest": {"sha256": hashlib.sha256(canonical_json(bom)).hexdigest()},
            "scanId": scan.scanner_scan_id or scan.scan_id,
            "engineVersion": scan.engine_version or "unknown",
            "policyId": decision.policy_id,
            "policyVersion": decision.policy_version,
            "verdict": decision.verdict,
            "issuedAt": fmt(issued_at),
            "expiresAt": fmt(expires_at),
            "checks": (scan.result_json or {}).get("checks_run", []),
        },
    }
    if decision.verdict == "CONDITIONAL":
        statement["predicate"]["conditions"] = decision.reasons
    return statement


def sign_dsse(statement: dict[str, Any]) -> dict[str, Any]:
    key_name = os.getenv("TRACEON_KMS_KEY_VERSION", "")
    if not key_name:
        raise RuntimeError("TRACEON_KMS_KEY_VERSION is not configured")
    from google.cloud import kms_v1

    payload = canonical_json(statement)
    digest = hashlib.sha256(dsse_pae(PAYLOAD_TYPE, payload)).digest()
    signature = kms_v1.KeyManagementServiceClient().asymmetric_sign(
        request={"name": key_name, "digest": {"sha256": digest}}
    ).signature
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "statement": statement,
        "signatures": [{"keyid": key_name, "sig": base64.b64encode(signature).decode("ascii")}],
    }


def verify_signature(public_key: Any, algorithm: str, signature: bytes, pae_digest: bytes) -> None:
    """Verify KMS RSA-PSS/PKCS1 or ECDSA SHA-256 signature bytes."""

    if isinstance(public_key, rsa.RSAPublicKey):
        if "PSS" in algorithm:
            verifier = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size)
        else:
            verifier = padding.PKCS1v15()
        public_key.verify(signature, pae_digest, verifier, utils.Prehashed(hashes.SHA256()))
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, pae_digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    else:
        raise TypeError("Unsupported attestation public key type")


def verify_dsse(envelope: dict[str, Any], expected_sha256: str | None = None) -> tuple[bool, str | None]:
    """Verify the DSSE PAE using the public key for the envelope's Cloud KMS key."""

    try:
        if envelope.get("payloadType") != PAYLOAD_TYPE:
            return False, "Unsupported DSSE payload type"
        payload = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(payload)
        if canonical_json(statement) != payload or statement != envelope.get("statement"):
            return False, "Attestation payload and decoded statement do not match"
        subject_digest = statement["subject"][0]["digest"]["sha256"]
        bom = envelope.get("bom")
        if not isinstance(bom, dict):
            return False, "Attestation is missing its AI-BOM"
        bom_digest = hashlib.sha256(canonical_json(bom)).hexdigest()
        if bom_digest != statement["predicate"]["bomDigest"]["sha256"]:
            return False, "AI-BOM digest does not match the signed statement"
        expires_at = datetime.fromisoformat(statement["predicate"]["expiresAt"].replace("Z", "+00:00"))
        if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
            return False, "Attestation is expired or has an invalid expiry timestamp"
        if expected_sha256 is not None and subject_digest.lower() != expected_sha256.lower():
            return False, "Digest mismatch: artifact does not match the signed subject digest"
        signature_record = envelope["signatures"][0]
        key_name = signature_record["keyid"]
        from google.cloud import kms_v1

        public_key_response = kms_v1.KeyManagementServiceClient().get_public_key(request={"name": key_name})
        public_key = serialization.load_pem_public_key(public_key_response.pem.encode("ascii"))
        signature = base64.b64decode(signature_record["sig"], validate=True)
        payload_digest = hashlib.sha256(dsse_pae(PAYLOAD_TYPE, payload)).digest()
        verify_signature(public_key, public_key_response.algorithm.name, signature, payload_digest)
        return True, None
    except (KeyError, IndexError, ValueError, TypeError, InvalidSignature) as exc:
        return False, f"Invalid DSSE envelope: {type(exc).__name__}"

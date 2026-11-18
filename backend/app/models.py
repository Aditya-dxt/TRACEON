"""Pydantic models matching the current shared Traceon JSON schemas."""

from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, PlainSerializer


def _normalize_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(timezone.utc)


UtcTimestamp = Annotated[
    datetime,
    AfterValidator(_normalize_utc),
    PlainSerializer(
        lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ"),
        return_type=str,
    ),
]


class ContractModel(BaseModel):
    """Keep additive schema properties accepted, as the JSON Schemas do."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class FindingCategory(StrEnum):
    SERIALIZATION = "serialization"
    WEIGHTS = "weights"
    DATASET = "dataset"
    DEPENDENCY = "dependency"
    PROVENANCE = "provenance"
    LICENCE = "licence"
    SECRETS = "secrets"
    IAM = "iam"
    RUNTIME = "runtime"
    AGENT = "agent"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerdictKind(StrEnum):
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    CONDITIONAL = "CONDITIONAL"
    APPROVE = "APPROVE"


class AttestationVerdictKind(StrEnum):
    """Values currently declared by attestation.schema.json."""

    APPROVE = "APPROVE"
    APPROVED_WITH_CONDITIONS = "approved_with_conditions"
    CONDITIONAL = "CONDITIONAL"


class CheckStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIPPED = "skipped"
    ERROR = "error"


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"


class ErrorResponse(BaseModel):
    error: str
    code: str


class Finding(ContractModel):
    finding_id: str
    check: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    deterministic: bool
    title: str
    evidence: dict[str, Any]
    recommendation: str


class ArtifactMetadata(ContractModel):
    name: str
    size_bytes: int = Field(ge=0)
    sha256: str
    detected_format: str


class ScanCheck(ContractModel):
    name: str
    status: CheckStatus
    details: str | None = None


class ScanResult(ContractModel):
    scan_id: str
    engine_version: str
    artifact: ArtifactMetadata
    checks_run: list[ScanCheck]
    findings: list[Finding]
    started_at: UtcTimestamp
    completed_at: UtcTimestamp


class Verdict(ContractModel):
    decision_id: str
    asset_id: str
    verdict: VerdictKind
    reasons: list[str]
    policy_id: str
    policy_version: int
    decided_at: UtcTimestamp


class Digest(ContractModel):
    sha256: str


class AttestationSubject(ContractModel):
    name: str
    digest: Digest


class AttestationPredicate(ContractModel):
    bomDigest: Digest
    scanId: str
    engineVersion: str
    policyId: str
    policyVersion: int
    verdict: AttestationVerdictKind
    issuedAt: UtcTimestamp
    expiresAt: UtcTimestamp
    conditions: list[str] | None = None
    checks: list[dict[str, Any]] | None = None


class InTotoStatement(ContractModel):
    type_: Literal["https://in-toto.io/Statement/v1"] = Field(alias="_type")
    subject: list[AttestationSubject]
    predicateType: str
    predicate: AttestationPredicate


class AttestationSignature(ContractModel):
    keyid: str
    sig: str


class Attestation(ContractModel):
    payloadType: str | None = None
    payload: str | None = None
    statement: InTotoStatement | None = None
    signatures: list[AttestationSignature]

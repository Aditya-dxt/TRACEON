"""Relational persistence models for Traceon's current backend records."""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from .types import UTCDateTime


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Asset(Base):
    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    source: Mapped[str] = mapped_column(String(2048), nullable=False)
    file_format: Mapped[str] = mapped_column("format", String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # Private backend location; it is never part of an API response.
    storage_path: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="quarantined")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", passive_deletes=True
    )
    decisions: Mapped[list["Decision"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", passive_deletes=True
    )
    attestations: Mapped[list["AttestationRecord"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        CheckConstraint("size_bytes >= 0", name="ck_assets_nonnegative_size"),
        CheckConstraint("length(sha256) = 64", name="ck_assets_sha256_length"),
        Index("ix_assets_sha256", "sha256"),
        Index("ix_assets_created_at", "created_at"),
    )


class Scan(Base):
    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scanner_scan_id: Mapped[str | None] = mapped_column(String(64), unique=True)
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    engine_version: Mapped[str | None] = mapped_column(String(64))
    queued_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    # Preserve the scanner payload without transforming its contract shape.
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    asset: Mapped[Asset] = relationship(back_populates="scans")
    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    decisions: Mapped[list["Decision"]] = relationship(
        back_populates="scan",
        foreign_keys="Decision.scan_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    attestations: Mapped[list["AttestationRecord"]] = relationship(
        back_populates="scan",
        foreign_keys="AttestationRecord.scan_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        UniqueConstraint("scan_id", "asset_id", name="uq_scans_scan_asset"),
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="ck_scans_status",
        ),
        Index("ix_scans_asset_queued", "asset_id", "queued_at"),
    )


class FindingRecord(Base):
    __tablename__ = "findings"

    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.scan_id", ondelete="CASCADE"), primary_key=True
    )
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    check: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    deterministic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    title: Mapped[str] = mapped_column(String(1024), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="findings")

    __table_args__ = (
        CheckConstraint(
            "severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_findings_severity",
        ),
        CheckConstraint(
            "confidence IN ('low', 'medium', 'high')",
            name="ck_findings_confidence",
        ),
        CheckConstraint(
            "category IN ('serialization', 'weights', 'dataset', 'dependency', 'provenance', 'licence', 'secrets', 'iam', 'runtime', 'agent')",
            name="ck_findings_category",
        ),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_category", "category"),
    )


class Decision(Base):
    __tablename__ = "decisions"

    decision_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    decided_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)

    asset: Mapped[Asset] = relationship(back_populates="decisions")
    scan: Mapped[Scan] = relationship(
        back_populates="decisions", foreign_keys=[scan_id]
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["scan_id", "asset_id"],
            ["scans.scan_id", "scans.asset_id"],
            ondelete="CASCADE",
            name="fk_decisions_scan_asset",
        ),
        ForeignKeyConstraint(
            ["asset_id"], ["assets.asset_id"], ondelete="CASCADE", name="fk_decisions_asset"
        ),
        CheckConstraint(
            "verdict IN ('BLOCK', 'QUARANTINE', 'CONDITIONAL', 'APPROVE')",
            name="ck_decisions_verdict",
        ),
        CheckConstraint("policy_version >= 1", name="ck_decisions_policy_version"),
        Index("ix_decisions_asset_decided", "asset_id", "decided_at"),
    )


class AttestationRecord(Base):
    __tablename__ = "attestations"

    attestation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)

    asset: Mapped[Asset] = relationship(back_populates="attestations")
    scan: Mapped[Scan] = relationship(
        back_populates="attestations", foreign_keys=[scan_id]
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["scan_id", "asset_id"],
            ["scans.scan_id", "scans.asset_id"],
            ondelete="CASCADE",
            name="fk_attestations_scan_asset",
        ),
        ForeignKeyConstraint(
            ["asset_id"], ["assets.asset_id"], ondelete="CASCADE", name="fk_attestations_asset"
        ),
        Index("ix_attestations_asset_created", "asset_id", "created_at"),
    )


class AuditLogEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    __table_args__ = (
        CheckConstraint("length(entry_hash) = 64", name="ck_audit_entry_hash_length"),
        CheckConstraint(
            "previous_hash IS NULL OR length(previous_hash) = 64",
            name="ck_audit_previous_hash_length",
        ),
        Index("ix_audit_log_occurred_at", "occurred_at"),
    )

"""Create the initial Traceon persistence tables."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0001_initial_database"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("asset_id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("source", sa.String(length=2048), nullable=False),
        sa.Column("format", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("size_bytes >= 0", name="ck_assets_nonnegative_size"),
        sa.CheckConstraint("length(sha256) = 64", name="ck_assets_sha256_length"),
    )
    op.create_index("ix_assets_sha256", "assets", ["sha256"])
    op.create_index("ix_assets_created_at", "assets", ["created_at"])

    op.create_table(
        "scans",
        sa.Column("scan_id", sa.String(length=64), primary_key=True),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("engine_version", sa.String(length=64), nullable=True),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.asset_id"], ondelete="CASCADE"),
        sa.UniqueConstraint("scan_id", "asset_id", name="uq_scans_scan_asset"),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="ck_scans_status",
        ),
    )
    op.create_index("ix_scans_asset_queued", "scans", ["asset_id", "queued_at"])

    op.create_table(
        "findings",
        sa.Column("scan_id", sa.String(length=64), primary_key=True),
        sa.Column("finding_id", sa.String(length=64), primary_key=True),
        sa.Column("check", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("deterministic", sa.Boolean(), nullable=False),
        sa.Column("title", sa.String(length=1024), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.scan_id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_findings_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('low', 'medium', 'high')",
            name="ck_findings_confidence",
        ),
        sa.CheckConstraint(
            "category IN ('serialization', 'weights', 'dataset', 'dependency', 'provenance', 'licence', 'secrets', 'iam', 'runtime', 'agent')",
            name="ck_findings_category",
        ),
    )
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_category", "findings", ["category"])

    op.create_table(
        "decisions",
        sa.Column("decision_id", sa.String(length=64), primary_key=True),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("policy_id", sa.String(length=128), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id", "asset_id"],
            ["scans.scan_id", "scans.asset_id"],
            ondelete="CASCADE",
            name="fk_decisions_scan_asset",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.asset_id"], ondelete="CASCADE", name="fk_decisions_asset"
        ),
        sa.CheckConstraint(
            "verdict IN ('BLOCK', 'QUARANTINE', 'CONDITIONAL', 'APPROVE')",
            name="ck_decisions_verdict",
        ),
        sa.CheckConstraint("policy_version >= 1", name="ck_decisions_policy_version"),
    )
    op.create_index("ix_decisions_asset_decided", "decisions", ["asset_id", "decided_at"])

    op.create_table(
        "attestations",
        sa.Column("attestation_id", sa.String(length=64), primary_key=True),
        sa.Column("asset_id", sa.String(length=64), nullable=False),
        sa.Column("scan_id", sa.String(length=64), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id", "asset_id"],
            ["scans.scan_id", "scans.asset_id"],
            ondelete="CASCADE",
            name="fk_attestations_scan_asset",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.asset_id"], ondelete="CASCADE", name="fk_attestations_asset"
        ),
    )
    op.create_index(
        "ix_attestations_asset_created", "attestations", ["asset_id", "created_at"]
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("entry_hash", sa.String(length=64), nullable=False, unique=True),
        sa.CheckConstraint(
            "length(entry_hash) = 64", name="ck_audit_entry_hash_length"
        ),
        sa.CheckConstraint(
            "previous_hash IS NULL OR length(previous_hash) = 64",
            name="ck_audit_previous_hash_length",
        ),
    )
    op.create_index("ix_audit_log_occurred_at", "audit_log", ["occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_occurred_at", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index("ix_attestations_asset_created", table_name="attestations")
    op.drop_table("attestations")
    op.drop_index("ix_decisions_asset_decided", table_name="decisions")
    op.drop_table("decisions")
    op.drop_index("ix_findings_category", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_scans_asset_queued", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_assets_created_at", table_name="assets")
    op.drop_index("ix_assets_sha256", table_name="assets")
    op.drop_table("assets")
